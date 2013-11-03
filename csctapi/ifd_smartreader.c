/*
    ifd_smartreader.c
    This module provides IFD handling functions for for Argolis smartreader+.
*/

#include "../globals.h"

#ifdef CARDREADER_SMART
#include <memory.h>
#if defined(__FreeBSD__)
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif
#include "../oscam-lock.h"
#include "../oscam-string.h"
#include "../oscam-time.h"
#include "icc_async.h" // atr.h included in icc_async.h
#include "ifd_smartreader_types.h"

#if defined(__CYGWIN__)
#undef OK
#undef ERROR
#undef LOBYTE
#undef HIBYTE
#endif

#define OK 0
#define ERROR 1
#define LOBYTE(w) ((unsigned char)((w) & 0xff))
#define HIBYTE(w) ((unsigned char)((w) >> 8))

#define NUM_TXFERS 2

// to debug rdrtype in logs instead off the enumarated value
static const char *const rdrtype_str[6] = {"SR","Infinity", "SRv2", "TripleP1", "TripleP2", "TripleP3"};

struct sr_data
{
	int32_t F;
	float D;
	int32_t fs;
	int32_t N;
	int32_t T;
	int32_t inv;
	int32_t parity;
	int32_t irdeto;
	int32_t running;
	libusb_device *usb_dev;
	libusb_device_handle *usb_dev_handle;
	enum smartreader_chip_type type;
	enum smartreader_rdrtypename rdrtype;
	uint8_t in_ep;
	uint8_t out_ep;
	int32_t index;
	/** usb read timeout */
	int32_t usb_read_timeout;
	/** usb write timeout */
	int32_t usb_write_timeout;
	uint32_t  writebuffer_chunksize;
	unsigned char bitbang_enabled;
	int baudrate;
	int32_t interface;   // 0 ,1 or 2
	/** maximum packet size. Needed for filtering modem status bytes every n packets. */
	uint32_t  max_packet_size;
	unsigned char g_read_buffer[4096];
	uint32_t  g_read_buffer_size;
	pthread_mutex_t g_read_mutex;
	pthread_cond_t g_read_cond;
	pthread_mutex_t g_usb_mutex;
	pthread_cond_t g_usb_cond;
	int32_t poll;
	pthread_t rt;
	unsigned char modem_status;
	uint16_t tripledelay;
	int detectstart ;
};

static int32_t init_count;

static int32_t smart_read(struct s_reader *reader, unsigned char *buff, uint32_t  size, int32_t timeout_sec)
{
	struct sr_data *crdr_data = reader->crdr_data;
	int32_t ret = 0;
	uint32_t  total_read = 0;
	struct timeval start, now, dif;
	struct timespec timeout;

	memset(&dif, 0, sizeof(struct timeval));

	gettimeofday(&start, NULL);
	timeout.tv_sec = start.tv_sec + timeout_sec;
	timeout.tv_nsec = start.tv_usec * 1000;

	while(total_read < size && dif.tv_sec < timeout_sec)
	{
		pthread_mutex_lock(&crdr_data->g_read_mutex);

		while(crdr_data->g_read_buffer_size == 0 && dif.tv_sec < timeout_sec)
		{
			pthread_cond_timedwait(&crdr_data->g_read_cond, &crdr_data->g_read_mutex, &timeout);
			gettimeofday(&now, NULL);
			timersub(&now, &start, &dif);
		}

		ret = (crdr_data->g_read_buffer_size > size - total_read ? size - total_read : crdr_data->g_read_buffer_size);
		memcpy(buff + total_read, crdr_data->g_read_buffer, ret);
		crdr_data->g_read_buffer_size -= ret;

		if(crdr_data->g_read_buffer_size > 0)
			{ memmove(crdr_data->g_read_buffer, crdr_data->g_read_buffer + ret, crdr_data->g_read_buffer_size); }

		total_read += ret;
		pthread_mutex_unlock(&crdr_data->g_read_mutex);

		gettimeofday(&now, NULL);
		timersub(&now, &start, &dif);
	}

	rdr_ddump_mask(reader, D_DEVICE, buff, total_read, "SR: Receive:");
	return total_read;
}

static int32_t smart_write(struct s_reader *reader, unsigned char *buff, uint32_t size)
{
	struct sr_data *crdr_data = reader->crdr_data;
	int32_t write_size;
	uint32_t offset = 0;
	int32_t total_written = 0;
	int32_t written;

	if(size < crdr_data->writebuffer_chunksize)
		{ write_size = size; }
	else
		{ write_size = crdr_data->writebuffer_chunksize; }

	while(offset < size)
	{
		if(offset + write_size > size)
			{ write_size = size - offset; }

		int32_t ret = libusb_bulk_transfer(crdr_data->usb_dev_handle,
										   crdr_data->in_ep,
										   buff + offset,
										   write_size,
										   &written,
										   crdr_data->usb_write_timeout);
		if(ret < 0)
		{
			rdr_log(reader, "usb bulk write failed : ret = %d", ret);
			cs_writeunlock(&reader->sr_lock);
			return (ret);
		}
		rdr_ddump_mask(reader, D_DEVICE, buff + offset, written, "SR: Transmit:");
		total_written += written;
		offset += write_size;
	}
	return total_written;
}

static bool smartreader_check_endpoint(libusb_device *usb_dev, uint8_t in_endpoint, uint8_t out_endpoint)
{
	struct libusb_device_descriptor usbdesc;
	struct libusb_config_descriptor *configDesc;
	int32_t ret;
	int32_t j, k, l;
	uint8_t tmpEndpointAddress;
	int32_t nb_endpoint_ok;


	nb_endpoint_ok = 0;
	ret = libusb_get_device_descriptor(usb_dev, &usbdesc);
	if(ret < 0)
	{
		cs_log("Smartreader : couldn't read device descriptor, assuming this is not a smartreader");
		return 0;
	}
	if(usbdesc.bNumConfigurations)
	{
		ret = libusb_get_active_config_descriptor(usb_dev, &configDesc);
		if(ret)
		{
			cs_log("Smartreader : couldn't read config descriptor , assuming this is not a smartreader");
			return 0;
		}

		for(j = 0; j < configDesc->bNumInterfaces; j++)
			for(k = 0; k < configDesc->interface[j].num_altsetting; k++)
				for(l = 0; l < configDesc->interface[j].altsetting[k].bNumEndpoints; l++)
				{
					tmpEndpointAddress = configDesc->interface[j].altsetting[k].endpoint[l].bEndpointAddress;
					if((tmpEndpointAddress == in_endpoint) || (tmpEndpointAddress == out_endpoint))
						{ nb_endpoint_ok++; }
				}
	}
	if(nb_endpoint_ok != 2)
		{ return 0; }
	return 1;
}

static struct libusb_device *find_smartreader(struct s_reader *rdr, const char *busname, const char *dev_name, uint8_t in_endpoint, uint8_t out_endpoint)
{
	rdr->smartdev_found = 0;
	libusb_device *dev;
	libusb_device_handle *usb_dev_handle;
	libusb_device **devs;
	ssize_t cnt;
	int32_t i = 0;
	int32_t ret;
	struct libusb_device_descriptor usbdesc;

	cnt = libusb_get_device_list(NULL, &devs);
	if(cnt < 0)
		{ return NULL; }

	while((dev = devs[i++]) != NULL)
	{
		rdr->smartdev_found = 0;
		ret = libusb_get_device_descriptor(dev, &usbdesc);
		if(ret < 0)
		{
			cs_log("failed to get device descriptor for device %s on bus %s", dev_name, busname);
			return NULL;
		}

		if(usbdesc.idVendor == 0x0403 && (usbdesc.idProduct == 0x6001 || usbdesc.idProduct == 0x6011))
		{
			ret = libusb_open(dev, &usb_dev_handle);
			if(ret)
			{
				cs_log("coulnd't open device %03d:%03d", libusb_get_bus_number(dev), libusb_get_device_address(dev));
				switch(ret)
				{
				case LIBUSB_ERROR_NO_MEM:
					cs_log("libusb_open error LIBUSB_ERROR_NO_MEM : memory allocation failure");
					break;
				case LIBUSB_ERROR_ACCESS:
					cs_log("libusb_open error LIBUSB_ERROR_ACCESS : the user has insufficient permissions");
					break;
				case LIBUSB_ERROR_NO_DEVICE:
					cs_log("libusb_open error LIBUSB_ERROR_NO_DEVICE : the device has been disconnected");
					break;
				default:
					cs_log("libusb_open unknown error : %d", ret);
					break;
				}
				continue;
			}

			// If the device is specified as "Serial:number", check iSerial
			if(!strcasecmp(busname, "Serial"))
			{
				char iserialbuffer[128];
				if(libusb_get_string_descriptor_ascii(usb_dev_handle, usbdesc.iSerialNumber, (unsigned char *)iserialbuffer, sizeof(iserialbuffer)) > 0)
				{
					if(!strcmp(trim(iserialbuffer), dev_name))
					{
						cs_log("Found reader with serial %s at %03d:%03d", dev_name, libusb_get_bus_number(dev), libusb_get_device_address(dev));
						if(smartreader_check_endpoint(dev, in_endpoint, out_endpoint)) {
							if(out_endpoint == 0x82 && in_endpoint == 0x01 && usbdesc.idProduct == 0x6001) { rdr->smart_type = 0; rdr->smartdev_found = 1;} else
							if(out_endpoint == 0x81 && in_endpoint == 0x01) { rdr->smart_type = 1; rdr->smartdev_found = 2;} else
							if(out_endpoint == 0x81 && in_endpoint == 0x02 && usbdesc.idProduct == 0x6001) { rdr->smart_type = 2; rdr->smartdev_found = 3;} else
							if(out_endpoint == 0x81 && in_endpoint == 0x02 && usbdesc.idProduct == 0x6011) { rdr->smart_type = 3; rdr->smartdev_found = 4;} else
							if(out_endpoint == 0x83 && in_endpoint == 0x04 && usbdesc.idProduct == 0x6011) { rdr->smart_type = 4; rdr->smartdev_found = 5;} else
							if(out_endpoint == 0x85 && in_endpoint == 0x06 && usbdesc.idProduct == 0x6011) { rdr->smart_type = 5; rdr->smartdev_found = 6;} else
								rdr->smartdev_found = 0;
						} 
					}
				}
			}
			else if(libusb_get_bus_number(dev) == atoi(busname) && libusb_get_device_address(dev) == atoi(dev_name))
			{
				cs_debug_mask(D_DEVICE, "SR: Checking FTDI device: %03d on bus %03d", libusb_get_device_address(dev), libusb_get_bus_number(dev));
				// check for smargo endpoints.
						if(smartreader_check_endpoint(dev, in_endpoint, out_endpoint)) {
							if(out_endpoint == 0x82 && in_endpoint == 0x01 && usbdesc.idProduct == 0x6001) { rdr->smart_type = 0; rdr->smartdev_found = 1;} else
							if(out_endpoint == 0x81 && in_endpoint == 0x01) { rdr->smart_type = 1; rdr->smartdev_found = 2;} else
							if(out_endpoint == 0x81 && in_endpoint == 0x02 && usbdesc.idProduct == 0x6001) { rdr->smart_type = 2; rdr->smartdev_found = 3;} else
							if(out_endpoint == 0x81 && in_endpoint == 0x02 && usbdesc.idProduct == 0x6011) { rdr->smart_type = 3; rdr->smartdev_found = 4;} else
							if(out_endpoint == 0x83 && in_endpoint == 0x04 && usbdesc.idProduct == 0x6011) { rdr->smart_type = 4; rdr->smartdev_found = 5;} else
							if(out_endpoint == 0x85 && in_endpoint == 0x06 && usbdesc.idProduct == 0x6011) { rdr->smart_type = 5; rdr->smartdev_found = 6;} else
								rdr->smartdev_found = 0;
						} 
			}
			libusb_close(usb_dev_handle);
		}

		if(rdr->smartdev_found >= 1)
			{ break; }
	}

	if(!rdr->smartdev_found)
	{
		cs_log("Smartreader device %s:%s not found", busname, dev_name);
		return NULL;
	}
	else
		{ cs_log("Found smartreader device %s:%s", busname, dev_name); }

	return dev;
}

void smartreader_init(struct s_reader *reader)
{
	uint32_t i;
	struct sr_data *crdr_data = reader->crdr_data;

	crdr_data->usb_dev = NULL;
	crdr_data->usb_dev_handle = NULL;
	crdr_data->usb_read_timeout = 20000;
	crdr_data->usb_write_timeout = 10000;

	crdr_data->type = TYPE_BM;    /* chip type */
	crdr_data->baudrate = -1;
	crdr_data->bitbang_enabled = 0;  /* 0: normal mode 1: any of the bitbang modes enabled */

	crdr_data->writebuffer_chunksize = 4096;
	crdr_data->max_packet_size = 0;
	rdr_log(reader,"initing smargo type %s", rdrtype_str[crdr_data->rdrtype]);
	if(crdr_data->rdrtype)
	{
		for(i = 0; i < sizeof(reader_types) / sizeof(struct s_reader_types); ++i)
		{
			if(reader_types[i].rdrtypename == crdr_data->rdrtype)
			{
				crdr_data->in_ep = reader_types[i].in_ep;
				crdr_data->out_ep = reader_types[i].out_ep;
				crdr_data->index = reader_types[i].index;
				crdr_data->interface = reader_types[i].interface;
				return;
			}
		}
		rdr_log(reader, "Smartreader: The defined reader type %u is unknown. Using default Smartreader values.", crdr_data->rdrtype);
	}
	crdr_data->in_ep = 0x01;
	crdr_data->out_ep = 0x82;
	crdr_data->index = INTERFACE_A;
	crdr_data->interface = 0;
}


static uint32_t  smartreader_determine_max_packet_size(struct s_reader *reader)
{
	struct sr_data *crdr_data = reader->crdr_data;
	uint32_t  packet_size;
	struct libusb_device_descriptor usbdesc;
	struct libusb_config_descriptor *configDesc;
	struct libusb_interface interface;
	struct libusb_interface_descriptor intDesc;

	int32_t ret;
	// Determine maximum packet size. Init with default value.
	// New hi-speed devices from FTDI use a packet size of 512 bytes
	// but could be connected to a normal speed USB hub -> 64 bytes packet size.
	rdr_log(reader,"DE PACKET SIZE DETERMINATION USES READER TYPE %u", crdr_data->type);
	if(crdr_data->type == TYPE_2232H || crdr_data->type == TYPE_4232H)
		{ packet_size = 512; }
	else
		{ packet_size = 64; }

	ret = libusb_get_device_descriptor(crdr_data->usb_dev, &usbdesc);
	if(ret < 0)
	{
		rdr_log(reader, "Smartreader : couldn't read device descriptor , using default packet size");
		return packet_size;
	}
	if(usbdesc.bNumConfigurations)
	{
		ret = libusb_get_active_config_descriptor(crdr_data->usb_dev, &configDesc);
		if(ret)
		{
			rdr_log(reader, "Smartreader : couldn't read config descriptor , using default packet size");
			return packet_size;
		}

		if(crdr_data->interface < configDesc->bNumInterfaces)
		{
			interface = configDesc->interface[crdr_data->interface];
			if(interface.num_altsetting > 0)
			{
				intDesc = interface.altsetting[0];
				if(intDesc.bNumEndpoints > 0)
				{
					packet_size = intDesc.endpoint[0].wMaxPacketSize;
				}
			}
		}
	}

	if (crdr_data->rdrtype >= 3) packet_size = 512;
	return packet_size;
}


static int32_t smartreader_usb_close_internal(struct s_reader *reader)
{
	struct sr_data *crdr_data = reader->crdr_data;
	int32_t ret = 0;

	if(crdr_data->usb_dev_handle)
	{
		libusb_close(crdr_data->usb_dev_handle);
		crdr_data->usb_dev_handle = NULL;
	}

	return ret;
}


static int32_t smartreader_usb_reset(struct s_reader *reader)
{
	struct sr_data *crdr_data = reader->crdr_data;
	if(libusb_control_transfer(crdr_data->usb_dev_handle,
							   FTDI_DEVICE_OUT_REQTYPE,
							   SIO_RESET_REQUEST,
							   SIO_RESET_SIO,
							   crdr_data->index,
							   NULL,
							   0,
							   crdr_data->usb_write_timeout) != 0)
	{
		rdr_log(reader, "Smartreader reset failed");
		return (-1);
	}
	
	return 0;
}


static int32_t smartreader_usb_purge_rx_buffer(struct s_reader *reader)
{
	struct sr_data *crdr_data = reader->crdr_data;
	if(libusb_control_transfer(crdr_data->usb_dev_handle,
							   FTDI_DEVICE_OUT_REQTYPE,
							   SIO_RESET_REQUEST,
							   SIO_RESET_PURGE_RX,
							   crdr_data->index,
							   NULL,
							   0,
							   crdr_data->usb_write_timeout) != 0)
	{
		rdr_log(reader, "FTDI purge of RX buffer failed");
		return (-1);
	}


	return 0;
}

static int32_t smartreader_usb_purge_tx_buffer(struct s_reader *reader)
{
	struct sr_data *crdr_data = reader->crdr_data;
	if(libusb_control_transfer(crdr_data->usb_dev_handle,
							   FTDI_DEVICE_OUT_REQTYPE,
							   SIO_RESET_REQUEST,
							   SIO_RESET_PURGE_TX,
							   crdr_data->index,
							   NULL,
							   0,
							   crdr_data->usb_write_timeout) != 0)
	{
		rdr_log(reader, "FTDI purge of TX buffer failed");
		return (-1);
	}

	return 0;
}

static int32_t smartreader_usb_purge_buffers(struct s_reader *reader)
{
	int32_t result;

	result = smartreader_usb_purge_rx_buffer(reader);
	if(result < 0)
		{ return -1; }

	result = smartreader_usb_purge_tx_buffer(reader);
	if(result < 0)
		{ return -2; }

	return 0;
}

static int smartreader_to_clkbits_AM(int baudrate, unsigned long *encoded_divisor)

{
    static const char frac_code[8] = {0, 3, 2, 4, 1, 5, 6, 7};
    static const char am_adjust_up[8] = {0, 0, 0, 1, 0, 3, 2, 1};
    static const char am_adjust_dn[8] = {0, 0, 0, 1, 0, 1, 2, 3};
    int divisor, best_divisor, best_baud, best_baud_diff;
    divisor = 24000000 / baudrate;
    int i;

    // Round down to supported fraction (AM only)
    divisor -= am_adjust_dn[divisor & 7];

    // Try this divisor and the one above it (because division rounds down)
    best_divisor = 0;
    best_baud = 0;
    best_baud_diff = 0;
    for (i = 0; i < 2; i++)
    {
        int try_divisor = divisor + i;
        int baud_estimate;
        int baud_diff;

        // Round up to supported divisor value
        if (try_divisor <= 8)
        {
            // Round up to minimum supported divisor
            try_divisor = 8;
        }
        else if (divisor < 16)
        {
            // AM doesn't support divisors 9 through 15 inclusive
            try_divisor = 16;
        }
        else
        {
            // Round up to supported fraction (AM only)
            try_divisor += am_adjust_up[try_divisor & 7];
            if (try_divisor > 0x1FFF8)
            {
                // Round down to maximum supported divisor value (for AM)
                try_divisor = 0x1FFF8;
            }
        }
        // Get estimated baud rate (to nearest integer)
        baud_estimate = (24000000 + (try_divisor / 2)) / try_divisor;
        // Get absolute difference from requested baud rate
        if (baud_estimate < baudrate)
        {
            baud_diff = baudrate - baud_estimate;
        }
        else
        {
            baud_diff = baud_estimate - baudrate;
        }
        if (i == 0 || baud_diff < best_baud_diff)
        {
            // Closest to requested baud rate so far
            best_divisor = try_divisor;
            best_baud = baud_estimate;
            best_baud_diff = baud_diff;
            if (baud_diff == 0)
            {
                // Spot on! No point trying
                break;
            }
        }
    }
    // Encode the best divisor value
    *encoded_divisor = (best_divisor >> 3) | (frac_code[best_divisor & 7] << 14);
    // Deal with special cases for encoded value
    if (*encoded_divisor == 1)
    {
        *encoded_divisor = 0;    // 3000000 baud
    }
    else if (*encoded_divisor == 0x4001)
    {
        *encoded_divisor = 1;    // 2000000 baud (BM only)
    }
    return best_baud;
}

/*  ftdi_to_clkbits Convert a requested baudrate for a given system clock  and predivisor
                    to encoded divisor and the achievable baudrate
    Function is only used internally
    \internal

    See AN120
   clk/1   -> 0
   clk/1.5 -> 1
   clk/2   -> 2
   From /2, 0.125 steps may be taken.
   The fractional part has frac_code encoding

   value[13:0] of value is the divisor
   index[9] mean 12 MHz Base(120 MHz/10) rate versus 3 MHz (48 MHz/16) else

   H Type have all features above with
   {index[8],value[15:14]} is the encoded subdivisor

   FT232R, FT2232 and FT232BM have no option for 12 MHz and with 
   {index[0],value[15:14]} is the encoded subdivisor

   AM Type chips have only four fractional subdivisors at value[15:14]
   for subdivisors 0, 0.5, 0.25, 0.125
*/
static int smartreader_to_clkbits(int baudrate, int clk, int clk_div, unsigned long *encoded_divisor)
{
    static const char frac_code[8] = {0, 3, 2, 4, 1, 5, 6, 7};
    int best_baud = 0;
    int divisor, best_divisor;
    if (baudrate >=  clk/clk_div)
    {
        *encoded_divisor = 0;
        best_baud = clk/clk_div;
    }
    else if (baudrate >=  clk/(clk_div + clk_div/2))
    {
        *encoded_divisor = 1;
        best_baud = clk/(clk_div + clk_div/2);
    }
    else if (baudrate >=  clk/(2*clk_div))
    {
        *encoded_divisor = 2;
        best_baud = clk/(2*clk_div);
    }
    else
    {
        /* We divide by 16 to have 3 fractional bits and one bit for rounding */
        divisor = clk*16/clk_div / baudrate;
        if (divisor & 1) /* Decide if to round up or down*/
            best_divisor = divisor /2 +1;
        else
            best_divisor = divisor/2;
        if(best_divisor > 0x20000)
            best_divisor = 0x1ffff;
        best_baud = clk*16/clk_div/best_divisor;
        if (best_baud & 1) /* Decide if to round up or down*/
            best_baud = best_baud /2 +1;
        else
            best_baud = best_baud /2;
        *encoded_divisor = (best_divisor >> 3) | (frac_code[best_divisor & 0x7] << 14);
    }
    return best_baud;
} 
/**
    ftdi_convert_baudrate returns nearest supported baud rate to that requested.
    Function is only used internally
    \internal
*/
static int smartreader_convert_baudrate(int baudrate, struct s_reader *reader, unsigned short  *value, unsigned short  *idx)
{
    int best_baud;
	unsigned long encoded_divisor;
	struct sr_data *crdr_data = reader->crdr_data;

    if (baudrate <= 0)
    {
        // Return error
        return -1;
    }

#define H_CLK 120000000
#define C_CLK  48000000
    if ((crdr_data->type == TYPE_2232H) || (crdr_data->type == TYPE_4232H) || (crdr_data->type == TYPE_232H))
    {
		if(baudrate*10 > H_CLK /0x3fff)
        {
            /* On H Devices, use 12 000 000 Baudrate when possible
               We have a 14 bit divisor, a 1 bit divisor switch (10 or 16) 
               three fractional bits and a 120 MHz clock
               Assume AN_120 "Sub-integer divisors between 0 and 2 are not allowed" holds for
               DIV/10 CLK too, so /1, /1.5 and /2 can be handled the same*/
            best_baud = smartreader_to_clkbits(baudrate, H_CLK, 10, &encoded_divisor);
            encoded_divisor |= 0x20000; /* switch on CLK/10*/
        }
        else
            best_baud = smartreader_to_clkbits(baudrate, C_CLK, 16, &encoded_divisor);
    }
    else if ((crdr_data->type == TYPE_BM) || (crdr_data->type == TYPE_2232C) || (crdr_data->type == TYPE_R ))
    {
        best_baud = smartreader_to_clkbits(baudrate, C_CLK, 16, &encoded_divisor);
    }
    else
    {
        best_baud = smartreader_to_clkbits_AM(baudrate, &encoded_divisor);
    }
    // Split into "value" and "index" values
    *value = (unsigned short)(encoded_divisor & 0xFFFF);
    if (crdr_data->type == TYPE_2232H || 
        crdr_data->type == TYPE_4232H || crdr_data->type == TYPE_232H)
    {
 		*idx = (unsigned short)(encoded_divisor >> 8);
		*idx &= 0xFF00;
		*idx |= crdr_data->index;
    }
    else
        *idx = (unsigned short)(encoded_divisor >> 16);

    // Return the nearest baud rate
    return best_baud;
}

/**
    Sets the chip baud rate

    \param ftdi pointer to ftdi_context
    \param baudrate baud rate to set

    \retval  0: all fine
    \retval -1: invalid baudrate
    \retval -2: setting baudrate failed
    \retval -3: USB device unavailable
*/
int smartreader_set_baudrate(struct s_reader *reader, int baudrate)
{
	struct sr_data *crdr_data = reader->crdr_data;
	unsigned short  value, idx;
	int actual_baudrate;

    if (crdr_data->usb_dev == NULL){
        rdr_log(reader, "USB device unavailable");
		return ERROR;
	}

    if (crdr_data->bitbang_enabled)
    {
        baudrate = baudrate*4;
    }

    actual_baudrate = smartreader_convert_baudrate(baudrate, reader, &value, &idx);
    if (actual_baudrate <= 0) {
        rdr_log(reader, "Silly baudrate <= 0.");
		return (-1);
	}

    // Check within tolerance (about 5%)
    if ((actual_baudrate * 2 < baudrate /* Catch overflows */ )
            || ((actual_baudrate < baudrate)
                ? (actual_baudrate * 21 < baudrate * 20)
                : (baudrate * 21 < actual_baudrate * 20))) {
        rdr_log(reader, "Unsupported baudrate. Note: bitbang baudrates are automatically multiplied by 4");
		return (-1);
	}
    if (libusb_control_transfer(crdr_data->usb_dev_handle, 
								FTDI_DEVICE_OUT_REQTYPE,
                                SIO_SET_BAUDRATE_REQUEST, 
								value,
                                idx, 
								NULL, 
								0, 
								crdr_data->usb_write_timeout) < 0) {
        rdr_log(reader, "Setting new baudrate failed");
		return (-2);
	}
//	rdr_log(reader,"De baudrate is set on %u baud de value = %u  de idx = %u", baudrate, value, idx);
    crdr_data->baudrate = baudrate;
    return 0;
}

static int32_t smartreader_setdtr_rts(struct s_reader *reader, int32_t dtr, int32_t rts)
{
	struct sr_data *crdr_data = reader->crdr_data;
	uint16_t  usb_val;


	if(dtr)
		{ usb_val = SIO_SET_DTR_HIGH; }
	else
		{ usb_val = SIO_SET_DTR_LOW; }

	if(rts)
		{ usb_val |= SIO_SET_RTS_HIGH; }
	else
		{ usb_val |= SIO_SET_RTS_LOW; }
	if(libusb_control_transfer(crdr_data->usb_dev_handle,
							   FTDI_DEVICE_OUT_REQTYPE,
							   SIO_SET_MODEM_CTRL_REQUEST,
							   usb_val,
							   crdr_data->index,
							   NULL,
							   0,
							   crdr_data->usb_write_timeout) != 0)
	{
		rdr_log(reader, "set of rts/dtr failed");
		return (-1);
	}
	return 0;
}

static int32_t smartreader_setflowctrl(struct s_reader *reader, int32_t flowctrl)
{
	struct sr_data *crdr_data = reader->crdr_data;
	if(libusb_control_transfer(crdr_data->usb_dev_handle,
							   FTDI_DEVICE_OUT_REQTYPE,
							   SIO_SET_FLOW_CTRL_REQUEST,
							   0,
							   (flowctrl | crdr_data->index),
							   NULL,
							   0,
							   crdr_data->usb_write_timeout) != 0)
	{
		rdr_log(reader, "set flow control failed");
		return (-1);
	}
	return 0;
}

static int32_t smartreader_set_line_property2(struct s_reader *reader, enum smartreader_bits_type bits,
		enum smartreader_stopbits_type sbit, enum smartreader_parity_type parity,
		enum smartreader_break_type break_type)
{
	struct sr_data *crdr_data = reader->crdr_data;
	uint16_t  value = bits;

	switch(parity)
	{
	case NONE:
		value |= (0x00 << 8);
		break;
	case ODD:
		value |= (0x01 << 8);
		break;
	case EVEN:
		value |= (0x02 << 8);
		break;
	case MARK:
		value |= (0x03 << 8);
		break;
	case SPACE:
		value |= (0x04 << 8);
		break;
	}

	switch(sbit)
	{
	case STOP_BIT_1:
		value |= (0x00 << 11);
		break;
	case STOP_BIT_15:
		value |= (0x01 << 11);
		break;
	case STOP_BIT_2:
		value |= (0x02 << 11);
		break;
	}

	switch(break_type)
	{
	case BREAK_OFF:
		value |= (0x00 << 14);
		break;
	case BREAK_ON:
		value |= (0x01 << 14);
		break;
	}
	if(libusb_control_transfer(crdr_data->usb_dev_handle,
							   FTDI_DEVICE_OUT_REQTYPE,
							   SIO_SET_DATA_REQUEST,
							   value,
							   crdr_data->index,
							   NULL,
							   0,
							   crdr_data->usb_write_timeout) != 0)
	{
		rdr_log(reader, "Setting new line property failed");
		return (-1);
	}
	return 0;
}


static int32_t smartreader_set_line_property(struct s_reader *reader, enum smartreader_bits_type bits,
		enum smartreader_stopbits_type sbit, enum smartreader_parity_type parity)
{
	return smartreader_set_line_property2(reader, bits, sbit, parity, BREAK_OFF);
}



static void smart_flush(struct s_reader *reader)
{
	smartreader_usb_purge_buffers(reader);

	struct sr_data *crdr_data = reader->crdr_data;
	pthread_mutex_lock(&crdr_data->g_read_mutex);
	crdr_data->g_read_buffer_size = 0;
	pthread_mutex_unlock(&crdr_data->g_read_mutex);
}

static int32_t smartreader_set_latency_timer(struct s_reader *reader, uint16_t  latency)
{
	struct sr_data *crdr_data = reader->crdr_data;
	uint16_t  usb_val;

	if(latency < 1)
	{
		rdr_log(reader, "latency out of range. Only valid for 1-255");
		return (-1);
	}

	usb_val = latency;
	if(libusb_control_transfer(crdr_data->usb_dev_handle,
							   FTDI_DEVICE_OUT_REQTYPE,
							   SIO_SET_LATENCY_TIMER_REQUEST,
							   usb_val,
							   crdr_data->index,
							   NULL,
							   0,
							   crdr_data->usb_write_timeout) != 0)
	{
		rdr_log(reader, "unable to set latency timer");
		return (-2);
	}
	return 0;
}

#if defined(__CYGWIN__)
static WINAPI read_callback(struct libusb_transfer *transfer)
{
#else
static void read_callback(struct libusb_transfer *transfer)
{
#endif
	struct s_reader *reader = (struct s_reader *)transfer->user_data;
	struct sr_data *crdr_data = reader->crdr_data;
	int32_t copy_size;
	int32_t ret;

	if(transfer->status == LIBUSB_TRANSFER_COMPLETED)
	{
		if(transfer->actual_length > 2)    //FTDI always sends modem status bytes as first 2 chars with the 232BM
		{
			pthread_mutex_lock(&crdr_data->g_read_mutex);

			if(crdr_data->g_read_buffer_size == sizeof(crdr_data->g_read_buffer))
			{
				rdr_log(reader, "SR: buffer full");
				//if out read buffer is full then delay
				//slightly and go around again
				ret = libusb_submit_transfer(transfer);
				if(ret != 0)
					{ rdr_log(reader, "SR: submit async transfer failed with error %d", ret); }
				pthread_cond_signal(&crdr_data->g_read_cond);
				pthread_mutex_unlock(&crdr_data->g_read_mutex);
				return;
			}
			crdr_data->modem_status = transfer->buffer[0];

			copy_size = sizeof(crdr_data->g_read_buffer) - crdr_data->g_read_buffer_size > (uint32_t)transfer->actual_length - 2 ? (uint32_t)transfer->actual_length - 2 : sizeof(crdr_data->g_read_buffer) - crdr_data->g_read_buffer_size;
			memcpy(crdr_data->g_read_buffer + crdr_data->g_read_buffer_size, transfer->buffer + 2, copy_size);
			crdr_data->g_read_buffer_size += copy_size;

			pthread_cond_signal(&crdr_data->g_read_cond);
			pthread_mutex_unlock(&crdr_data->g_read_mutex);
		}
		else
		{
			if(transfer->actual_length == 2)
			{
				pthread_mutex_lock(&crdr_data->g_read_mutex);
				crdr_data->modem_status = transfer->buffer[0];
				pthread_mutex_unlock(&crdr_data->g_read_mutex);
			}
		}

		ret = libusb_submit_transfer(transfer);

		if(ret != 0)
			{ rdr_log(reader, "SR: submit async transfer failed with error %d", ret); }

	}
	else
		{ rdr_log(reader, "SR: USB bulk read failed with error %d", transfer->status); }
}

static int32_t smartreader_usb_open_dev(struct s_reader *reader)
{
	struct sr_data *crdr_data = reader->crdr_data;
	int32_t detach_errno = 0;
	struct libusb_device_descriptor usbdesc;
	int32_t ret;

#ifdef __WIN32__
	int32_t config;
	int32_t config_val = 1;
#endif

	ret = libusb_open(crdr_data->usb_dev, &crdr_data->usb_dev_handle);
	if(ret)
	{
		rdr_log(reader, "coulnd't open SmartReader device %03d:%03d", libusb_get_bus_number(crdr_data->usb_dev), libusb_get_device_address(crdr_data->usb_dev));
		switch(ret)
		{
		case LIBUSB_ERROR_NO_MEM:
			rdr_log(reader, "libusb_open error LIBUSB_ERROR_NO_MEM : memory allocation failure");
			break;
		case LIBUSB_ERROR_ACCESS:
			rdr_log(reader, "libusb_open error LIBUSB_ERROR_ACCESS : the user has insufficient permissions");
			break;
		case LIBUSB_ERROR_NO_DEVICE:
			rdr_log(reader, "libusb_open error LIBUSB_ERROR_NO_DEVICE : the device has been disconnected");
			break;
		default:
			rdr_log(reader, "libusb_open unknown error : %d", ret);
			break;
		}
		return (-4);
	}

#if defined(__linux__)
	// Try to detach ftdi_sio kernel module.
	// Returns ENODATA if driver is not loaded.
	//
	// The return code is kept in a separate variable and only parsed
	// if usb_set_configuration() or usb_claim_interface() fails as the
	// detach operation might be denied and everything still works fine.
	// Likely scenario is a static smartreader_sio kernel module.
	if(libusb_detach_kernel_driver(crdr_data->usb_dev_handle, crdr_data->interface) != 0 && errno != ENODATA)
	{
		detach_errno = errno;
		smartreader_usb_close_internal(reader);
		rdr_log(reader, "Couldn't detach interface from kernel. Please unload the FTDI drivers");
		return (LIBUSB_ERROR_NOT_SUPPORTED);
	} 
#endif
	ret = libusb_get_device_descriptor(crdr_data->usb_dev, &usbdesc);

#ifdef __WIN32__
	// set configuration (needed especially for windows)
	// tolerate EBUSY: one device with one configuration, but two interfaces
	//    and libftdi sessions to both interfaces (e.g. FT2232)

	if(usbdesc.bNumConfigurations > 0)
	{
		ret = libusb_get_configuration(crdr_data->usb_dev_handle, &config);

		// libusb-win32 on Windows 64 can return a null pointer for a valid device
		if(libusb_set_configuration(crdr_data->usb_dev_handle, config) &&
				errno != EBUSY)
		{
#if defined(__linux__)
			if(detach_errno == 0) { libusb_attach_kernel_driver(crdr_data->usb_dev_handle, crdr_data->interface); }
#endif
			smartreader_usb_close_internal(reader);
			if(detach_errno == EPERM)
			{
				rdr_log(reader, "inappropriate permissions on device!");
				return (-8);
			}
			else
			{
				rdr_log(reader, "unable to set usb configuration. Make sure smartreader_sio is unloaded!");
				return (-3);
			}
		}
	}
#endif

	ret = libusb_claim_interface(crdr_data->usb_dev_handle, crdr_data->interface) ;
	if(ret != 0)
	{
#if defined(__linux__)
		if(detach_errno == 0) { libusb_attach_kernel_driver(crdr_data->usb_dev_handle, crdr_data->interface); }
#endif
		smartreader_usb_close_internal(reader);
		if(detach_errno == EPERM)
		{
			rdr_log(reader, "inappropriate permissions on device!");
			return (-8);
		}
		else
		{
			rdr_log(reader, "unable to claim usb device. Make sure smartreader_sio is unloaded!");
			return (-5);
		}
	}
	if(smartreader_usb_reset(reader) != 0)
	{
		libusb_release_interface(crdr_data->usb_dev_handle, crdr_data->interface);
#if defined(__linux__)
		if(detach_errno == 0) { libusb_attach_kernel_driver(crdr_data->usb_dev_handle, crdr_data->interface); }
#endif
		smartreader_usb_close_internal(reader);
		rdr_log(reader, "smartreader_usb_reset failed");
		return (-6);
	}

	// Try to guess chip type
	// Bug in the BM type chips: bcdDevice is 0x200 for serial == 0
	if(usbdesc.bcdDevice == 0x400 || (usbdesc.bcdDevice == 0x200
									  && usbdesc.iSerialNumber == 0))
		{ crdr_data->type = TYPE_BM; }
	else if(usbdesc.bcdDevice == 0x200)
		{ crdr_data->type = TYPE_AM; }
	else if((usbdesc.bcdDevice == 0x500) && (usbdesc.idProduct == 0x6011))
		{ crdr_data->type = TYPE_4232H; }
	else if((usbdesc.bcdDevice == 0x500) && (usbdesc.idProduct != 0x6011))
		{ crdr_data->type = TYPE_2232C; }
	else if(usbdesc.bcdDevice == 0x600)
		{ crdr_data->type = TYPE_R; }
	else if(usbdesc.bcdDevice == 0x700)
		{ crdr_data->type = TYPE_2232H; }
	else if(usbdesc.bcdDevice == 0x800)
		{ crdr_data->type = TYPE_4232H; }

	// Determine maximum packet size
	crdr_data->max_packet_size = smartreader_determine_max_packet_size(reader);
	rdr_log(reader,"reader type is %u", crdr_data->type);
	rdr_log(reader,"maw packet size is %u", crdr_data->max_packet_size);

	if(smartreader_set_baudrate(reader, 9600) != 0)
	{
		libusb_release_interface(crdr_data->usb_dev_handle, crdr_data->interface);
#if defined(__linux__)
		if(detach_errno == 0) { libusb_attach_kernel_driver(crdr_data->usb_dev_handle, crdr_data->interface); }
#endif
		smartreader_usb_close_internal(reader);
		rdr_log(reader, "set baudrate failed");
		return (-7);
	} 

	return (0);
}

static void EnableSmartReader(struct s_reader *reader, uint32_t baud_temp, int32_t clock_val, uint16_t  Fi, unsigned char Di, unsigned char Ni, unsigned char T, unsigned char inv, int32_t parity)
{
	struct sr_data *crdr_data = reader->crdr_data;
	unsigned char FiDi[4];
	uint16_t  freqk;
	unsigned char Freq[3];
	unsigned char N[2];
	unsigned char Prot[2];
	unsigned char Invert[2];
	unsigned char temp_T;

	smartreader_set_baudrate(reader, baud_temp);
	smartreader_setflowctrl(reader, 0);
//	cs_sleepms(150);
	smartreader_set_line_property(reader, (enum smartreader_bits_type) 5, STOP_BIT_2, NONE);

	// command 1, set F and D parameter
	if(!crdr_data->irdeto)
	{
		rdr_debug_mask(reader, D_DEVICE, "SR: sending F=%04X (%d) to smartreader", Fi, Fi);
		rdr_debug_mask(reader, D_DEVICE, "SR: sending D=%02X (%d) to smartreader", Di, Di);
		FiDi[0] = 0x01;
		FiDi[1] = HIBYTE(Fi);
		FiDi[2] = LOBYTE(Fi);
		FiDi[3] = Di;
		smart_write(reader, FiDi, sizeof(FiDi));
	}
	else
	{
		rdr_debug_mask(reader, D_ATR, "Not setting F and D as we're in Irdeto mode");
	}

	// command 2, set the frequency in KHz
	// direct from the source .. 4MHz is the best init frequency for T=0 card, but looks like it's causing issue with some nagra card, reveting to 3.69MHz
	freqk = clock_val * 10; //clock with type int32_t couldnt hold freq in Hz on all platforms, so I reverted to 10khz units (like mhz) - dingo
	rdr_debug_mask(reader, D_DEVICE, "SR: sending Freq=%04X (%d) to smartreader", freqk, freqk);
	Freq[0] = 0x02;
	Freq[1] = HIBYTE(freqk);
	Freq[2] = LOBYTE(freqk);
	smart_write(reader, Freq, sizeof(Freq));

	// command 3, set paramter N
	rdr_debug_mask(reader, D_DEVICE, "SR: sending N=%02X (%d) to smartreader", Ni, Ni);
	N[0] = 0x03;
	N[1] = Ni;
	smart_write(reader, N, sizeof(N));

	// command 4 , set parameter T
	temp_T = T;
	if(T == 2)  // special trick to get ATR for Irdeto card, we need T=1 at reset, after that oscam takes care of T1 protocol, so we need T=0
		//if(crdr_data->irdeto) // special trick to get ATR for Irdeto card, we need T=1 at reset, after that oscam takes care of T1 protocol, so we need T=0
	{
		T = 1;
		crdr_data->T = 1;
		temp_T = 1;
	}
	else if(T == 1)
		{ T = 0; } // T=1 protocol is handled by oscam

	rdr_debug_mask(reader, D_DEVICE, "SR: sending T=%02X (%d) to smartreader", T, T);
	Prot[0] = 0x04;
	Prot[1] = T;
	smart_write(reader, Prot, sizeof(Prot));

	// command 5, set invert y/n
	rdr_debug_mask(reader, D_DEVICE, "SR: sending inv=%02X to smartreader", inv);
	Invert[0] = 0x05;
	Invert[1] = inv;
	smart_write(reader, Invert, sizeof(Invert));

	smartreader_set_line_property2(reader, BITS_8, STOP_BIT_2, parity, BREAK_ON);
	//  send break for 350ms, also comes from JoePub debugging.
	cs_sleepms(400);

	if(temp_T == 1)
		{ smartreader_set_line_property2(reader, BITS_8, STOP_BIT_1, parity, BREAK_OFF); }
	else
		{ smartreader_set_line_property2(reader, BITS_8, STOP_BIT_2, parity,BREAK_OFF); }

    
	smart_flush(reader);
}


static void *ReaderThread(void *p)
{
	struct libusb_transfer *usbt[NUM_TXFERS];
//	unsigned char usb_buffers[NUM_TXFERS][512];
	struct s_reader *reader;
	int32_t ret, idx, size;

	reader = (struct s_reader *)p;
	struct sr_data *crdr_data = reader->crdr_data;
	if (crdr_data->rdrtype >= 3) size = 512; else size = 64;
	unsigned char usb_buffers[NUM_TXFERS][size];
	crdr_data->running = 1;

	set_thread_name(__func__);

	for(idx = 0; idx < NUM_TXFERS; idx++)
	{
		usbt[idx] = libusb_alloc_transfer(0);
		libusb_fill_bulk_transfer(usbt[idx],
								  crdr_data->usb_dev_handle,
								  crdr_data->out_ep,
								  usb_buffers[idx],
								  size,
								  (void *)(&read_callback),
								  p,
								  0);

		ret = libusb_submit_transfer(usbt[idx]);
	}

	while(crdr_data->running)
	{
		ret = libusb_handle_events(NULL);
		if(ret != 0)
			{ rdr_log(reader, "libusb_handle_events returned with %d", ret); }

		pthread_mutex_lock(&crdr_data->g_usb_mutex);

		if(!crdr_data->poll)
		{
			struct timeval start;
			struct timespec timeout;

			gettimeofday(&start, NULL);
			timeout.tv_sec = start.tv_sec + 1;
			timeout.tv_nsec = start.tv_usec * 1000;

			pthread_cond_timedwait(&crdr_data->g_usb_cond, &crdr_data->g_usb_mutex, &timeout);
		}
		pthread_mutex_unlock(&crdr_data->g_usb_mutex);
	}

	pthread_exit(NULL);
}

static void smart_fastpoll(struct s_reader *reader, int32_t on)
{
	struct sr_data *crdr_data = reader->crdr_data;
	pthread_mutex_lock(&crdr_data->g_usb_mutex);
	//printf("poll stat: %d\n", on);
	crdr_data->poll = on;
	pthread_cond_signal(&crdr_data->g_usb_cond);
	pthread_mutex_unlock(&crdr_data->g_usb_mutex);
}

static int32_t SR_Init(struct s_reader *reader)
{
	int32_t ret;
	char device[strlen(reader->device) + 1];
	char *rdrtype, *busname, *dev, *search = ":", *saveptr1 = NULL;
	memcpy(device, reader->device, strlen(reader->device) + 1);
	// split the device name from the reader conf into devname and busname. rdrtype is optional
	rdrtype = strtok_r(device, ";", &saveptr1);
	busname = strtok_r(NULL, ":", &saveptr1);
	dev = strtok_r(NULL, ":", &saveptr1);
	rdr_log(reader, "De SR_init");
	if(!busname)
	{
		rdrtype = "SR";
		memcpy(device, reader->device, strlen(reader->device) + 1);
		busname = strtok_r(device, ":", &saveptr1);
		dev = strtok_r(NULL, search, &saveptr1);
		rdr_log(reader, "TYPE IS SET ON %s", rdrtype);
	}

	if(!busname || !dev)
	{
		rdr_log(reader, "Wrong device format (%s), it should be Device=bus:dev", reader->device);
		return ERROR;
	}
//	cs_writelock(&reader->sr_lock);
	if(!reader->crdr_data && !cs_malloc(&reader->crdr_data, sizeof(struct sr_data)))
		{ return ERROR; }
	struct sr_data *crdr_data = reader->crdr_data;
	crdr_data->detectstart = 0;
	crdr_data->tripledelay = 0;
	if (!strcasecmp(rdrtype, "SR")) {
			crdr_data->rdrtype = SR;			
	}
		if (!strcasecmp(rdrtype, "Infinity")) {
			crdr_data->rdrtype = Infinity;			
	}
	if (!strcasecmp(rdrtype, "SRv2")) {
			crdr_data->tripledelay = 0;
			crdr_data->rdrtype = SRv2;			
	}
 	if (!strcasecmp(rdrtype, "TripleP1")) {
			crdr_data->tripledelay = 0;
			crdr_data->rdrtype = TripleP1;
	}
	if (!strcasecmp(rdrtype, "TripleP2")) {
			crdr_data->tripledelay = 0;
			crdr_data->rdrtype = TripleP2;
	}
	if (!strcasecmp(rdrtype, "TripleP3")) {
			crdr_data->tripledelay = 0;
			crdr_data->rdrtype = TripleP3;
	}
	

	rdr_debug_mask(reader, D_DEVICE, "SR: Looking for device %s on bus %s", dev, busname);
	smartreader_init(reader);

	if(!init_count)
	{
		ret = libusb_init(NULL);
		if(ret < 0)
		{
			cs_writeunlock(&reader->sr_lock);
			rdr_log(reader, "Libusb init error : %d", ret);
			return ret;
		}
	}
	init_count++;

	rdr_log(reader, "Using 0x%02X/0x%02X as endpoint for smartreader hardware detection", crdr_data->in_ep, crdr_data->out_ep);

	crdr_data->usb_dev = find_smartreader(reader, busname, dev, crdr_data->in_ep, crdr_data->out_ep);
	if(!crdr_data->usb_dev)
	{
		--init_count;
		if(!init_count)
			{ libusb_exit(NULL); }
		cs_writeunlock(&reader->sr_lock);
		return ERROR;
	}

	rdr_debug_mask(reader, D_DEVICE, "SR: Opening smartreader device %s on bus %s endpoint in 0x%02X out 0x%02X", dev, busname, crdr_data->in_ep, crdr_data->out_ep);

	if((ret = smartreader_usb_open_dev(reader)))
	{
		--init_count;
		if(!init_count)
			{ libusb_exit(NULL); }
		cs_writeunlock(&reader->sr_lock);
		rdr_log(reader, "unable to open smartreader device %s in bus %s endpoint in 0x%02X out 0x%02X (ret=%d)\n", dev, busname, crdr_data->in_ep, crdr_data->out_ep, ret);
		return ERROR;
	}
	if (crdr_data->rdrtype >= 2) {

//		cs_writeunlock(&reader->sr_lock);
//		rdr_log(reader, "I'M SLEEPING FOR %u ms", crdr_data->tripledelay);
//		cs_sleepms(crdr_data->tripledelay);
//		cs_writelock(&reader->sr_lock);

		rdr_debug_mask(reader, D_DEVICE, "SR: Setting smartreader latency timer to 2 ms");
		//Set the FTDI latency timer to 2 ms is ftdi default latency.
		ret = smartreader_set_latency_timer(reader, 2);
	} else {
		rdr_debug_mask(reader, D_DEVICE, "SR: Setting smartreader latency timer to 1 ms");
		//Set the FTDI latency timer to 1 ms is ftdi default latency.
		ret = smartreader_set_latency_timer(reader, 1);
	}

	//Set databits to 8o2
	ret = smartreader_set_line_property(reader, BITS_8, STOP_BIT_2, ODD);

	//Set the DTR HIGH and RTS LOW
	ret = smartreader_setdtr_rts(reader, 0, 0);

	//Disable flow control
	ret = smartreader_setflowctrl(reader, 0);

	// start the reading thread
	crdr_data->g_read_buffer_size = 0;
	crdr_data->modem_status = 0 ;
	pthread_mutex_init(&crdr_data->g_read_mutex, NULL);
	pthread_cond_init(&crdr_data->g_read_cond, NULL);
	pthread_mutex_init(&crdr_data->g_usb_mutex, NULL);
	pthread_cond_init(&crdr_data->g_usb_cond, NULL);

//	cs_writeunlock(&reader->sr_lock);
	rdr_log(reader," Pthread Wordt gecreeerd");
	ret = pthread_create(&crdr_data->rt, NULL, ReaderThread, (void *)(reader));
	if(ret)
	{
		rdr_log(reader, "ERROR: Can't create smartreader thread (errno=%d %s)", ret, strerror(ret));
		return ERROR;
	}
//	crdr_data->detectstart = 1;
	return OK;
}

static int32_t SR_Reset(struct s_reader *reader, ATR *atr)
{
	struct sr_data *crdr_data = reader->crdr_data;
	unsigned char data[ATR_MAX_SIZE];
	uint32_t baud_temp;
	int32_t ret;
	int32_t atr_ok;
	int32_t  i;
	int32_t parity[4] = {EVEN, ODD, NONE, EVEN};    // the last EVEN is to try with different F, D values for irdeto card.
	static const char *const parity_str[5] = {"NONE", "ODD", "EVEN", "MARK", "SPACE"};
	rdr_log(reader," SR_reset wordt gerund");

	if(reader->mhz == reader->cardmhz && reader->cardmhz * 10000 > 3690000)
		{ crdr_data->fs = reader->cardmhz * 10000; }
	else {
		if (crdr_data->rdrtype >= 2) crdr_data->fs = reader->cardmhz * 10000; 
		else crdr_data->fs = reader->cardmhz * 10000;
		}

	smart_fastpoll(reader, 1);
	// set smartreader+ default values
	crdr_data->F = 372;
	crdr_data->D = 1;
	crdr_data->N = 1;
	crdr_data->T = 1;
	crdr_data->inv = 0;
	baud_temp = (double)(crdr_data->D * crdr_data->fs / (double)crdr_data->F); 

	for(i = 0 ; i < 4 ; i++)
	{
		crdr_data->irdeto = 0;
		atr_ok = ERROR;
		memset(data, 0, sizeof(data));
		rdr_debug_mask(reader, D_DEVICE, "SR: Trying with parity %s", parity_str[parity[i]]);
		
		// special irdeto case
		if(i == 3)
		{
			rdr_debug_mask(reader, D_DEVICE, "SR: Trying irdeto");
			crdr_data->F = 618; /// magic smartreader value
			crdr_data->D = 1;
			crdr_data->T = 2; // will be set to T=1 in EnableSmartReader
			crdr_data->fs = 6000000;
			baud_temp = (double)(crdr_data->D * crdr_data->fs / (double)crdr_data->F);
		}
		smart_flush(reader);
		crdr_data->parity = parity[i];
		EnableSmartReader(reader, baud_temp, crdr_data->fs / 10000, crdr_data->F, (unsigned char)crdr_data->D, crdr_data->N, crdr_data->T, crdr_data->inv, parity[i]);

		//Reset smartcard

		//Set the DTR HIGH and RTS HIGH
		smartreader_setdtr_rts(reader, 1, 1);
		// A card with an active low reset is reset by maintaining RST in state L for at least 40 000 clock cycles
		// so if we have a base freq of 3.5712MHz : 40000/3690000 = .0112007168458781 seconds, aka 11ms
		// so if we have a base freq of 6.00MHz : 40000/6000000 = .0066666666666666 seconds, aka 6ms
		cs_sleepms(20);

		//Set the DTR HIGH and RTS LOW
		smartreader_setdtr_rts(reader, 1, 0);


		//Read the ATR
		ret = smart_read(reader, data, ATR_MAX_SIZE, 1);
		rdr_debug_mask(reader, D_DEVICE, "SR: get ATR ret = %d" , ret);
		if(ret)
			{ rdr_ddump_mask(reader, D_DEVICE, data, ATR_MAX_SIZE * 2, "SR:"); }

		// this is to make sure we don't think this 03 FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00  is a valid ATR.
		if((data[0] != 0x3B && data[0] != 0x03 && data[0] != 0x3F) || (data[1] == 0xFF && data[2] == 0x00))
		{
			crdr_data->irdeto = 0;
			continue; // this is not a valid ATR.
		}

		if(data[0] == 0x03)
		{
			rdr_debug_mask(reader, D_DEVICE, "SR: Inverse convention detected, setting smartreader inv to 1");

			crdr_data->inv = 1;
			smart_flush(reader);
			crdr_data->parity = parity[i];
			EnableSmartReader(reader, baud_temp, crdr_data->fs / 10000, crdr_data->F, (unsigned char)crdr_data->D, crdr_data->N, crdr_data->T, crdr_data->inv, parity[i]);
		}
		// parse atr
		if(ATR_InitFromArray(atr, data, ret) != ERROR)
		{
			rdr_debug_mask(reader, D_DEVICE, "SR: ATR parsing OK");
			atr_ok = OK;
			if(i == 3)
			{
				rdr_debug_mask(reader, D_DEVICE, "SR: Locking F and D for Irdeto mode");
				crdr_data->irdeto = 1;
			}
		}
		
		if(atr_ok == OK) {break;}
	}

	smart_fastpoll(reader, 0);
	
	return atr_ok;
}

static int32_t SR_Transmit(struct s_reader *reader, unsigned char *buffer, uint32_t size, uint32_t UNUSED(expectedlen), uint32_t delay, uint32_t timeout)   // delay and timeout not used (yet)!
{
	(void) delay; // delay not used (yet)!
	(void) timeout; // timeout not used (yet)!
	uint32_t  ret;

	smart_fastpoll(reader, 1);
	ret = smart_write(reader, buffer, size);
	smart_fastpoll(reader, 0);
	if(ret != size)
		{ return ERROR; }

	return OK;
}

static int32_t SR_GetStatus(struct s_reader *reader, int32_t *in)
{
	struct sr_data *crdr_data = reader->crdr_data;
	if (crdr_data->rdrtype == 2 || crdr_data->rdrtype == 3 || crdr_data->rdrtype == 4 || crdr_data->rdrtype == 5) {
		if (crdr_data->rdrtype == 2 || crdr_data->rdrtype == 3 || crdr_data->rdrtype == 4 || crdr_data->rdrtype == 5) crdr_data->detectstart = 1;
	char usb_val[2];
	int32_t state2;

    if (crdr_data->usb_dev == NULL) {
	rdr_log(reader,"usb device unavailable");
	return ERROR;
	}
	rdr_debug_mask(reader, D_IFD, "THE DETECT START = %u card status is %u", crdr_data->detectstart, reader->card_status);
	if (crdr_data->detectstart == 0) { *in = 1; return OK;} else
	if (((crdr_data->detectstart == 1) && (reader->card_status != 1)) && ((crdr_data->detectstart == 1) && (reader->card_status != 0))) {
//	if (((detectstart == 1) && (reader->card_status == CARD_INSERTED)) || ((detectstart == 1) &&  (reader->card_status == CARD_FAILURE)) || ((detectstart == 1) &&  (reader->card_status == 4))) {
//	cs_writelock(&reader->sr_lock);
    if (libusb_control_transfer(crdr_data->usb_dev_handle, 
								FTDI_DEVICE_IN_REQTYPE, 
								SIO_POLL_MODEM_STATUS_REQUEST, 
								2, crdr_data->index, 
								(unsigned char *)usb_val, 
								2, crdr_data->usb_read_timeout) != 1){
	rdr_log(reader, "getting modem status failed ");
	return ERROR;
	}
	state2 = (usb_val[1] << 8) | (usb_val[0] & 0xFF);
//	cs_writeunlock(&reader->sr_lock);
	rdr_debug_mask(reader, D_IFD, "the status of card in or out %u  ( 192 means card OUT)", state2);
    if (state2 == 192) {
        *in = 0; //NOCARD reader will be set to off
	}
    else {
        *in = 1; //Card is in Aktivation should be ok if card is activated
	}
	return OK;
	} else {*in = 1;rdr_log(reader,"CARD STILL IN AKTIVATION PROCESS NO DETECTION"); return OK;}
	} else {
	int32_t state;

	smart_fastpoll(reader, 1);
	pthread_mutex_lock(&crdr_data->g_read_mutex);
	state = (crdr_data->modem_status & 0x80) == 0x80 ? 0 : 2;
	pthread_mutex_unlock(&crdr_data->g_read_mutex);
	smart_fastpoll(reader, 0);
	rdr_debug_mask(reader, D_IFD, "the status of card in or out old procedure for v1 %u ", state);
	//state = 0 no card, 1 = not ready, 2 = ready
	if(state)
		{ *in = 1; } //CARD, even if not ready report card is in, or it will never get activated
	else
		{ *in = 0; } //NOCARD

	return OK;
	}
 }

static int32_t SR_Receive(struct s_reader *reader, unsigned char *buffer, uint32_t size, uint32_t delay, uint32_t timeout)   // delay and timeout not used (yet)!
{
	(void) delay; // delay not used (yet)!
	(void) timeout; // timeout not used (yet)!
	uint32_t  ret;

	smart_fastpoll(reader, 1);
	ret = smart_read(reader, buffer, size, 2);
	smart_fastpoll(reader, 0);
	if(ret != size)
		{ return ERROR; }

	return OK;
}

int32_t SR_WriteSettings(struct s_reader *reader, uint16_t  F, unsigned char D, unsigned char N, unsigned char T, uint16_t  convention)
{
	// smartreader supports 3.20, 3.43, 3.69, 4.00, 4.36, 4.80, 5.34, 6.00, 6.86, 8.00, 9.61, 12.0, 16.0 MHz
	struct sr_data *crdr_data = reader->crdr_data;
	crdr_data->inv = convention;//FIXME this one is set by icc_async and local smartreader reset routine
	rdr_log(reader, "the SR_WriteSettings is called");

	if(reader->mhz >= 1600) { reader->mhz = 1600; }
	else if(reader->mhz >= 1200) { reader->mhz = 1200; }
	else if(reader->mhz >= 961)  { reader->mhz =  961; }
	else if(reader->mhz >= 800)  { reader->mhz =  800; }
	else if(reader->mhz >= 686)  { reader->mhz =  686; }
	else if(reader->mhz >= 600)  { reader->mhz =  600; }
	else if(reader->mhz >= 534)  { reader->mhz =  534; }
	else if(reader->mhz >= 480)  { reader->mhz =  480; }
	else if(reader->mhz >= 436)  { reader->mhz =  436; }
	else if(reader->mhz >= 400)  { reader->mhz =  400; }
	else if(reader->mhz >= 369)  { reader->mhz =  369; }
	else if(reader->mhz == 368)  { reader->mhz =  369; }
	else if(reader->mhz >= 343)  { reader->mhz =  343; }
	else
		{ reader->mhz =  320; }
	smart_fastpoll(reader, 1);
	uint32_t baud_temp = (double)(D * (reader->mhz * 10000) / (double)F);
	smart_flush(reader);
	EnableSmartReader(reader, baud_temp, reader->mhz, F, D, N, T, crdr_data->inv, crdr_data->parity);
	smartreader_set_baudrate(reader, baud_temp);
	smart_fastpoll(reader, 0);
	rdr_log(reader,"de baudrate set = %u", baud_temp);
	cs_writeunlock(&reader->sr_lock);

	return OK;
}

static int32_t SR_SetParity(struct s_reader *reader, uchar parity)
{
	struct sr_data *crdr_data = reader->crdr_data;
	int32_t ret;

	static const char *const parity_str[5] = {"NONE", "ODD", "EVEN", "MARK", "SPACE"};
	rdr_debug_mask(reader, D_DEVICE, "SR: Setting parity to %s", parity_str[parity]);

	crdr_data->parity = parity;
	smart_fastpoll(reader, 1);
	ret = smartreader_set_line_property(reader, (enum smartreader_bits_type) 8, STOP_BIT_2, parity);
	smart_fastpoll(reader, 0);
	if(ret)
		{ return ERROR; }

	return OK;
}

static int32_t SR_Close(struct s_reader *reader)
{
	struct sr_data *crdr_data = reader->crdr_data;
	if(!crdr_data) { return OK; }
	rdr_debug_mask(reader, D_DEVICE, "SR: Closing smartreader");
	cs_writelock(&reader->sr_lock);
	crdr_data->running = 0;
	if(crdr_data->usb_dev_handle)
	{

		smart_fastpoll(reader, 1);
		pthread_join(crdr_data->rt, NULL);
		smart_fastpoll(reader, 0);
		libusb_release_interface(crdr_data->usb_dev_handle, crdr_data->interface);
#if defined(__linux__)
//		libusb_attach_kernel_driver(crdr_data->usb_dev_handle, crdr_data->interface); // attaching ftdio kernel driver may cause segfault on web if reader restart
#endif
		libusb_close(crdr_data->usb_dev_handle);
		init_count--;
		if(!init_count)
			{ libusb_exit(NULL); }
	}
	cs_writeunlock(&reader->sr_lock);
	return OK;
}

/*static int32_t SR_FastReset(struct s_reader *reader, int32_t delay)
{
    unsigned char data[ATR_MAX_SIZE];

    smart_fastpoll(reader, 1);
    //Set the DTR HIGH and RTS HIGH
    smartreader_setdtr_rts(reader, 1, 1);
    // A card with an active low reset is reset by maintaining RST in state L for at least 40 000 clock cycles
    // so if we have a base freq of 3.5712MHz : 40000/3690000 = .0112007168458781 seconds, aka 11ms
    // so if we have a base freq of 6.00MHz : 40000/6000000 = .0066666666666666 seconds, aka 6ms
    cs_sleepms(delay);

    //Set the DTR HIGH and RTS LOW
    smartreader_setdtr_rts(reader, 1, 0);

    //Read the ATR
    smart_read(reader,data, ATR_MAX_SIZE,1);
    smart_fastpoll(reader, 0);
    return 0;
} */

static int32_t SR_FastReset_With_ATR(struct s_reader *reader, ATR *atr)
{
	unsigned char data[ATR_MAX_SIZE];
	int32_t ret;
	int32_t atr_ok = ERROR;

	smart_fastpoll(reader, 1);
	//Set the DTR HIGH and RTS HIGH
	smartreader_setdtr_rts(reader, 1, 1);
	// A card with an active low reset is reset by maintaining RST in state L for at least 40 000 clock cycles
	// so if we have a base freq of 3.5712MHz : 40000/3690000 = .0112007168458781 seconds, aka 11ms
	// so if we have a base freq of 6.00MHz : 40000/6000000 = .0066666666666666 seconds, aka 6ms
	cs_sleepms(25);

	//Set the DTR HIGH and RTS LOW
	smartreader_setdtr_rts(reader, 1, 0);

	//Read the ATR
	ret = smart_read(reader, data, ATR_MAX_SIZE, 1);

	// parse atr
	if(ATR_InitFromArray(atr, data, ret) != ERROR)
	{
		rdr_debug_mask(reader, D_DEVICE, "SR: ATR parsing OK");
		atr_ok = OK;
	}

	smart_fastpoll(reader, 0);
	return atr_ok;
}

int32_t SR_Activate(struct s_reader *reader, struct s_ATR *atr)
{
	if(!reader->ins7e11_fast_reset)
	{
		call(SR_Reset(reader, atr));
	}
	else
	{
		rdr_log(reader, "Doing fast reset");
		call(SR_FastReset_With_ATR(reader, atr));
	}
	return OK;
}

int32_t sr_write_settings(struct s_reader *reader,
						  uint32_t UNUSED(ETU),
						  uint32_t EGT,
						  unsigned char UNUSED(P),
						  unsigned char UNUSED(I),
						  uint16_t Fi,
						  unsigned char Di,
						  unsigned char UNUSED(Ni))
{
	SR_WriteSettings(reader, Fi, Di, (unsigned char)EGT, (unsigned char)reader->protocol_type, reader->convention);
	return OK;
}


static int32_t sr_init_locks(struct s_reader *reader)
{

	cs_writelock(&reader->sr_lock);

	return 0;
}
	

void cardreader_smartreader(struct s_cardreader *crdr)
{
	crdr->desc           = "smartreader";
	crdr->typ            = R_SMART;
	crdr->reader_init    = SR_Init;
	crdr->get_status     = SR_GetStatus;
	crdr->set_parity     = SR_SetParity;
	crdr->activate       = SR_Activate;
	crdr->transmit       = SR_Transmit;
	crdr->receive        = SR_Receive;
	crdr->close          = SR_Close;
	crdr->write_settings = sr_write_settings;
	crdr->lock_init      = sr_init_locks;
}

#endif
