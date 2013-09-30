   /*
    io_serial.c
    Serial port input/output functions

    This file is part of the Unix driver for Towitoko smartcard readers
    Copyright (C) 2000 2001 Carlos Prados <cprados@yahoo.com>

    This version is modified by doz21 to work in a special manner ;)

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "../globals.h"
#ifdef WITH_CARDREADER

#if defined(__HPUX__)
#include <sys/modem.h>
#endif

#include <sys/poll.h>

#if defined(__linux__) && !defined(__ANDROID__)
#include <linux/serial.h>
#endif

#if defined(__ANDROID__)
#include "../extapi/linux/serial.h"
#endif

#include "../oscam-time.h"
#include "icc_async.h"
#include "io_serial.h"

#define OK 0
#define ERROR 1

#define IO_SERIAL_FILENAME_LENGTH 	32

/*
 * Internal functions declaration
 */

static int32_t IO_Serial_Bitrate(int32_t bitrate);

static bool IO_Serial_WaitToWrite (struct s_reader * reader, uint32_t delay_us, uint32_t timeout_us);

static int32_t oscam_sem;

void IO_Serial_Ioctl_Lock(struct s_reader * reader, int32_t flag)
{
  if ((reader->typ != R_DB2COM1) && (reader->typ != R_DB2COM2)) return;
  if (!flag)
    oscam_sem=0;
  else while (oscam_sem!=reader->typ)
  {
    while (oscam_sem)
			if (reader->typ == R_DB2COM1)
				cs_sleepms(6);
			else
				cs_sleepms(8);
    oscam_sem=reader->typ;
    cs_sleepms(1);
  }
}

bool IO_Serial_DTR_RTS(struct s_reader * reader, int32_t * dtr, int32_t * rts)
{
	if (reader->crdr.set_DTS_RTS)
		return reader->crdr.set_DTS_RTS(reader, dtr, rts);

	uint32_t msr;
	uint32_t mbit;
  
  if(dtr)
  {
    mbit = TIOCM_DTR;
#if defined(TIOCMBIS) && defined(TIOBMBIC)
    if (ioctl (reader->handle, *dtr ? TIOCMBIS : TIOCMBIC, &mbit) < 0)
      return ERROR;
#else
    if (ioctl(reader->handle, TIOCMGET, &msr) < 0)
      return ERROR;
    if (*dtr)
      msr|=mbit;
    else
      msr&=~mbit;
    if (ioctl(reader->handle, TIOCMSET, &msr)<0)
      return ERROR;
#endif
    rdr_debug_mask(reader, D_DEVICE, "Setting %s=%i", "DTR", *dtr);
  }  

  if(rts)
  {
    mbit = TIOCM_RTS;
#if defined(TIOCMBIS) && defined(TIOBMBIC)
    if (ioctl (reader->handle, *rts ? TIOCMBIS : TIOCMBIC, &mbit) < 0)
      return ERROR;
#else
    if (ioctl(reader->handle, TIOCMGET, &msr) < 0)
      return ERROR;
    if (*rts)
      msr|=mbit;
    else
      msr&=~mbit;
    if (ioctl(reader->handle, TIOCMSET, &msr)<0)
      return ERROR;
#endif
    rdr_debug_mask(reader, D_DEVICE, "Setting %s=%i", "RTS", *rts);
  }  

	return OK;
}

/*
 * Public functions definition
 */

bool IO_Serial_SetBitrate (struct s_reader * reader, uint32_t bitrate, struct termios * tio)
{
   /* Set the bitrate */
#if defined(__linux__)
  //FIXME workaround for Smargo until native mode works
  if ((reader->mhz == reader->cardmhz) && (reader->smargopatch != 1) && IO_Serial_Bitrate(bitrate) != B0)
#else
  if(IO_Serial_Bitrate(bitrate) == B0)
  {
    rdr_log(reader, "Baudrate %u not supported", bitrate);
    return ERROR;
  }
  else
#endif
  { //no overclocking
    cfsetospeed(tio, IO_Serial_Bitrate(bitrate));
    cfsetispeed(tio, IO_Serial_Bitrate(bitrate));
    rdr_debug_mask(reader, D_DEVICE, "standard baudrate: cardmhz=%d mhz=%d -> effective baudrate %u",
      reader->cardmhz, reader->mhz, bitrate);
  }
#if defined(__linux__)
  else
  { //over or underclocking
    /* these structures are only available on linux */
    struct serial_struct nuts;
    // This makes valgrind happy, because it doesn't know what TIOCGSERIAL does
    // Without this there are lots of misleading errors of type:
    // "Conditional jump or move depends on uninitialised value(s)"
    nuts.baud_base = 0;
    nuts.custom_divisor = 0;
    ioctl(reader->handle, TIOCGSERIAL, &nuts);
    int32_t custom_baud_asked = bitrate * reader->mhz / reader->cardmhz;
    nuts.custom_divisor = (nuts.baud_base + (custom_baud_asked/2))/ custom_baud_asked;
		int32_t custom_baud_delivered =  nuts.baud_base / nuts.custom_divisor;
		rdr_debug_mask(reader, D_DEVICE, "custom baudrate: cardmhz=%d mhz=%d custom_baud=%d baud_base=%d divisor=%d -> effective baudrate %d",
			reader->cardmhz, reader->mhz, custom_baud_asked, nuts.baud_base, nuts.custom_divisor, custom_baud_delivered);
		int32_t baud_diff = custom_baud_delivered - custom_baud_asked;
		if (baud_diff < 0)
			baud_diff = (-baud_diff);
		if (baud_diff  > 0.05 * custom_baud_asked) {
			rdr_log(reader, "WARNING: your card is asking for custom_baudrate = %i, but your configuration can only deliver custom_baudrate = %i",custom_baud_asked, custom_baud_delivered);
			rdr_log(reader, "You are over- or underclocking, try OSCam when running your reader at normal clockspeed as required by your card, and setting mhz and cardmhz parameters accordingly.");
			if (nuts.baud_base <= 115200)
				rdr_log(reader, "You are probably connecting your reader via a serial port, OSCam has more flexibility switching to custom_baudrates when using an USB->serial converter, preferably based on FTDI chip.");
		}
    nuts.flags &= ~ASYNC_SPD_MASK;
    nuts.flags |= ASYNC_SPD_CUST;
    ioctl(reader->handle, TIOCSSERIAL, &nuts);
    cfsetospeed(tio, IO_Serial_Bitrate(38400));
    cfsetispeed(tio, IO_Serial_Bitrate(38400));
  }
#endif
	return OK;
}

bool IO_Serial_SetParams (struct s_reader * reader, uint32_t bitrate, uint32_t bits, int32_t parity, uint32_t stopbits, int32_t * dtr, int32_t * rts)
{
	 struct termios newtio;
	
	 if(reader->typ == R_INTERNAL)
			return ERROR;
	 
	 memset (&newtio, 0, sizeof (newtio));

	if (IO_Serial_SetBitrate (reader, bitrate, & newtio))
		return ERROR;
				
	 /* Set the character size */
	 switch (bits)
	 {
		case 5:
			newtio.c_cflag |= CS5;
			break;
		
		case 6:
			newtio.c_cflag |= CS6;
			break;
		
		case 7:
			newtio.c_cflag |= CS7;
			break;
		
		case 8:
			newtio.c_cflag |= CS8;
			break;
	}
	
	/* Set the parity */
	switch (parity)
	{
		case PARITY_ODD:
			newtio.c_cflag |= PARENB;
			newtio.c_cflag |= PARODD;
			break;
		
		case PARITY_EVEN:	
			newtio.c_cflag |= PARENB;
			newtio.c_cflag &= ~PARODD;
			break;
		
		case PARITY_NONE:
			newtio.c_cflag &= ~PARENB;
			break;
	}
	
	/* Set the number of stop bits */
	switch (stopbits)
	{
		case 1:
			newtio.c_cflag &= (~CSTOPB);
			break;
		case 2:
			newtio.c_cflag |= CSTOPB;
			break;
	}
	
	/* Selects raw (non-canonical) input and output */
	newtio.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	newtio.c_oflag &= ~OPOST;
#if 1
	newtio.c_iflag |= IGNPAR;
	/* Ignore parity errors!!! Windows driver does so why shouldn't I? */
#endif
	/* Enable receiver, hang on close, ignore control line */
	newtio.c_cflag |= CREAD | HUPCL | CLOCAL;
	
	/* Read 1 byte minimun, no timeout specified */
	newtio.c_cc[VMIN] = 1;
	newtio.c_cc[VTIME] = 0;

	if (IO_Serial_SetProperties(reader, newtio))
		return ERROR;

	reader->current_baudrate = bitrate;

	IO_Serial_Ioctl_Lock(reader, 1);
	IO_Serial_DTR_RTS(reader, dtr, rts);
	IO_Serial_Ioctl_Lock(reader, 0);
	return OK;
}

bool IO_Serial_SetProperties (struct s_reader * reader, struct termios newtio)
{
	if(reader->typ == R_INTERNAL)
		return OK;

	if (tcsetattr (reader->handle, TCSANOW, &newtio) < 0)  // set terminal attributes.
		return ERROR;
	                 
	int32_t mctl;
	rdr_debug_mask(reader, D_DEVICE, "Getting readerstatus..."); 
	if (ioctl (reader->handle, TIOCMGET, &mctl) >= 0) {  // get reader statusbits 
		mctl &= ~TIOCM_RTS;
		rdr_debug_mask(reader, D_DEVICE, "Set reader ready to Send"); 
		ioctl (reader->handle, TIOCMSET, &mctl);  // set reader ready to send.
	} 
	else rdr_log(reader, "WARNING: Cant get readerstatus!"); 

	return OK;
}

int32_t IO_Serial_SetParity (struct s_reader * reader, unsigned char parity)
{
	struct termios tio;
	int32_t current_parity;
	// Get current parity
	if (tcgetattr (reader->handle, &tio) != 0){
		rdr_log(reader, "ERROR: Could not get current parity, %s (errno=%d %s)", __func__, errno, strerror(errno));
		current_parity = 5; // set to unknown (5 is not predefined!)
	}
	else {
		if (((tio.c_cflag) & PARENB) == PARENB)
		{
			if (((tio.c_cflag) & PARODD) == PARODD)
				current_parity = PARITY_ODD;
			else
				current_parity = PARITY_EVEN;
		}
		else
		{
			current_parity = PARITY_NONE;
		}
	}
	
	if (current_parity != parity)
	{
		rdr_debug_mask(reader, D_IFD, "Setting parity from %s to %s",
		current_parity == PARITY_ODD ? "Odd" :
		current_parity == PARITY_NONE ? "None" :
		current_parity == PARITY_EVEN ? "Even" : "Unknown",
		
		parity == PARITY_ODD ? "Odd" :
		parity == PARITY_NONE ? "None" :
		parity == PARITY_EVEN ? "Even" : "Invalid");
		
		// Set the parity
		switch (parity)
		{
			case PARITY_ODD:
				tio.c_cflag |= PARENB;
				tio.c_cflag |= PARODD;
				break;
			
			case PARITY_EVEN:	
				tio.c_cflag |= PARENB;
				tio.c_cflag &= ~PARODD;
				break;
			
			case PARITY_NONE:
				tio.c_cflag &= ~PARENB;
				break;
		}
		if (IO_Serial_SetProperties (reader, tio)){
			rdr_debug_mask(reader, D_IFD, "ERROR: could set parity!");
			return ERROR;
		}
	}

	return OK;
}

void IO_Serial_Flush (struct s_reader * reader)
{
  unsigned char b;
  tcflush(reader->handle, TCIOFLUSH);
  while(!IO_Serial_Read(reader, 0, 75000, 1, &b)); // first appears between 9~75ms
}

void IO_Serial_Sendbreak(struct s_reader * reader, int32_t duration)
{
	tcsendbreak (reader->handle, duration / 1000);
}

bool IO_Serial_Read (struct s_reader * reader, uint32_t delay, uint32_t timeout, uint32_t size, unsigned char * data)
{
	uint32_t count = 0;
	
	if (timeout == 0){ // General fix for readers not communicating timeout and delay
		if (reader->read_timeout != 0) timeout = reader->read_timeout; else timeout = 9990000; // hope 99990000 is long enough!
		rdr_debug_mask(reader, D_DEVICE,"Warning: read timeout 0 changed to %d us", timeout);
	}
	
	rdr_debug_mask(reader, D_DEVICE,"Read timeout %d us, read delay %d us, to read %d char(s), chunksize %d char(s)", timeout, delay, size, size);

#if defined(WITH_STAPI) || defined(__SH4__)	//internal stapi and sh4 readers need special treatment as they don't respond correctly to poll and some sh4 boxes only can read 1 byte at once
	if(reader->typ == R_INTERNAL){
		int32_t readed;
#if defined(WITH_STAPI)
		const uint32_t chunksize = INT_MAX;
#elif defined(__SH4__)
		const uint32_t chunksize = 1;
#endif
		struct timeval tv, tv_spent;
		gettimeofday(&tv,0);
		memcpy(&tv_spent,&tv,sizeof(struct timeval));
		readed=0;

		while((((tv_spent.tv_sec-tv.tv_sec)*1000000) + ((tv_spent.tv_usec-tv.tv_usec)/1000000L)) < (time_t)(timeout))
		{		
	 		readed = read(reader->handle, &data[count], size-count>=chunksize?chunksize:size-count);
	 		gettimeofday(&tv_spent,0);
			if(readed > 0){
				count +=readed;
				gettimeofday(&tv,0);  // reset timeout again since card is responsive!
				memcpy(&tv_spent,&tv,sizeof(struct timeval));
			}
				
			if(count < size){
				if(readed < (int32_t)chunksize) cs_sleepus(1);
				continue;
			} else break;
		}	
		if(count < size) {
			rdr_ddump_mask(reader, D_DEVICE, data, count, "Receiving:");
			return ERROR;
		}
	} else	
#endif  // read all chars at once for all other boxes
	{
		while(count < size){
			int32_t readed = -1, errorcount=0;
			AGAIN:
			if(IO_Serial_WaitToRead (reader, delay, timeout)) {
				rdr_debug_mask(reader, D_DEVICE, "Timeout in IO_Serial_WaitToRead, timeout=%d us", timeout);
				return ERROR;
			}
				
			while (readed <0 && errorcount < 10) {
				readed = read (reader->handle, &data[count], size-count);
				if (readed < 0) {
					if (errno == EINTR) continue; // try again in case of interrupt
					if (errno == EAGAIN) goto AGAIN; //EAGAIN needs select procedure again
					rdr_log(reader, "ERROR: %s (errno=%d %s)", __func__, errno, strerror(errno));
					errorcount++;
				}
			} 
				
			if (readed == 0) {
				rdr_ddump_mask(reader, D_DEVICE, data, count, "Receiving:");
				rdr_debug_mask(reader, D_DEVICE, "Received End of transmission");
				return ERROR;
			}
			count +=readed;
		}
	}
	rdr_ddump_mask(reader, D_DEVICE, data, count, "Receiving:");
	return OK;
}

int32_t IO_Serial_Receive(struct s_reader * reader, unsigned char * buffer, uint32_t size, uint32_t delay, uint32_t timeout)
{
	return IO_Serial_Read(reader, delay, timeout, size, buffer);
}

bool IO_Serial_Write (struct s_reader * reader, uint32_t delay, uint32_t timeout, uint32_t size, const unsigned char * data)
{
	if (timeout == 0){ // General fix for readers not communicating timeout and delay
		if (reader->char_delay != 0) timeout = reader->char_delay; else timeout = 1000000;
		rdr_debug_mask(reader, D_DEVICE,"Warning: write timeout 0 changed to %d us", timeout);
	}
	uint32_t count, to_send, i_w;
	unsigned char data_w[512];
	
	to_send = (delay? 1: size); // calculate chars to send at one
	rdr_debug_mask(reader, D_DEVICE,"Write timeout %d us, write delay %d us, to send %d char(s), chunksize %d char(s)", timeout, delay, size, to_send);
	
	for (count = 0; count < size; count += to_send)
	{
		if (count + to_send > size){
			to_send = size - count;
			}
		uint16_t errorcount=0, to_do=to_send;
		for (i_w=0; i_w < to_send; i_w++)
				data_w [i_w] = data [count + i_w];
		rdr_ddump_mask(reader, D_DEVICE, data_w+(to_send-to_do), to_do, "Sending:");
		AGAIN:		
		if (!IO_Serial_WaitToWrite (reader, delay, timeout))
		{
			while (to_do !=0){
				int32_t u = write (reader->handle, data_w+(to_send-to_do), to_do);
				if (u < 1) {
					if (errno==EINTR) continue; //try again in case of Interrupted system call
					if (errno==EAGAIN) goto AGAIN; //EAGAIN needs a select procedure again
					errorcount++;
					int16_t written = count + to_send - to_do;
					if (u != 0) {
						rdr_log(reader, "ERROR: %s: Written=%d of %d (errno=%d %s)",
							__func__, written , size, errno, strerror(errno));
					}
					if (errorcount > 10){ //exit if more than 10 errors
						return ERROR;
					}
				}
				else {
					to_do -= u;
					errorcount = 0;
					if (reader->crdr.read_written)
						reader->written += u; // these readers echo transmitted chars
					}
			}
		}
		else
		{
			rdr_log(reader, "Timeout in IO_Serial_WaitToWrite, delay=%d us, timeout=%d us", delay, timeout);
			if (reader->crdr.read_written && reader->written > 0) { // these readers need to read all transmitted chars before they can receive!
				unsigned char buf[256];
				rdr_debug_mask(reader, D_DEVICE,"Reading %d echoed transmitted chars...", reader->written); 
				int32_t n = reader->written;
				if(IO_Serial_Read (reader, 0, 9990000, n, buf)) // use 9990000 = aprox 10 seconds (since written chars could be hughe!)
					return ERROR;
				reader->written=0;
				rdr_debug_mask(reader, D_DEVICE,"Reading of echoed transmitted chars done!");
			}
			return ERROR;
		}
	}
	if (reader->crdr.read_written && reader->written > 0) { // these readers need to read all transmitted chars before they can receive!
		unsigned char buf[256];
		rdr_debug_mask(reader, D_DEVICE,"Reading %d echoed transmitted chars...", reader->written); 
		int32_t n = reader->written;
		if(IO_Serial_Read (reader, 0, 9990000, n, buf)) // use 9990000 = aprox 10 seconds (since written chars could be hughe!)
			return ERROR;
		reader->written=0;
		rdr_debug_mask(reader, D_DEVICE,"Reading of echoed transmitted chars done!");
	}
	return OK;
}

#define MAX_TRANSMIT 255

int32_t IO_Serial_Transmit(struct s_reader * reader, unsigned char * buffer, uint32_t size, uint32_t UNUSED(expectedlen), uint32_t delay, uint32_t timeout)
{
	uint32_t sent, to_send;
	for (sent = 0; sent < size; sent = sent + to_send) {
		to_send = MIN(size, MAX_TRANSMIT);
		if (IO_Serial_Write(reader, delay, timeout , to_send, buffer+sent))
			return ERROR;
	}
	return OK;
}

int32_t IO_Serial_Close (struct s_reader * reader)
{
	
	rdr_debug_mask(reader, D_DEVICE, "Closing serial port %s", reader->device);
	cs_sleepms(100); // maybe a dirty fix for the restart problem posted by wonderdoc
	if(reader->fdmc >= 0) close(reader->fdmc);
	if (reader->handle >= 0 && close (reader->handle) != 0)
		return ERROR;
	
	reader->written = 0;
	
	return OK;
}

/*
 * Internal functions definition
 */

static int32_t IO_Serial_Bitrate(int32_t bitrate)
{
	static const struct BaudRates { int32_t real; speed_t apival; } BaudRateTab[] = {
#ifdef B230400
		{ 230400, B230400 },
#endif
#ifdef B115200
		{ 115200, B115200 },
#endif
#ifdef B76800	
		{ 76800, B76800 },
#endif
#ifdef B57600
		{  57600, B57600  },
#endif
#ifdef B38400
		{  38400, B38400  },
#endif
#ifdef B28800
		{  28800, B28800  },
#endif
#ifdef B19200
		{  19200, B19200  },
#endif
#ifdef B14400
		{  14400, B14400  },
#endif
#ifdef B9600
		{   9600, B9600   },
#endif
#ifdef B7200
		{   7200, B7200   },
#endif
#ifdef B4800
		{   4800, B4800   },
#endif
#ifdef B2400
		{   2400, B2400   },
#endif
#ifdef B1200
		{   1200, B1200   },
#endif
#ifdef B600
        {    600, B600    },
#endif
#ifdef B300
        {    300, B300    },
#endif
#ifdef B200
		{    200, B200    },
#endif
#ifdef B150
		{    150, B150    },
#endif
#ifdef B134
		{    134, B134    },
#endif
#ifdef B110
		{    110, B110    },
#endif
#ifdef B75
		{     75, B75     },
#endif
#ifdef B50
		{     50, B50     },
#endif
		};

	int32_t i;
	
	for(i=0; i<(int)(sizeof(BaudRateTab)/sizeof(struct BaudRates)); i++)
	{
		int32_t b=BaudRateTab[i].real;
		int32_t d=((b-bitrate)*10000)/b;
		if(abs(d)<=350)
		{
			return BaudRateTab[i].apival;
		}
	}
	return B0;
}

bool IO_Serial_WaitToRead (struct s_reader * reader, uint32_t delay_us, uint32_t timeout_us)
{
	struct pollfd ufds;
	struct timeb start, end;
	int32_t ret_val;
	int32_t in_fd;
	int32_t polltimeout = timeout_us / 1000;

	if (delay_us > 0)
		cs_sleepus (delay_us); // wait in us
	in_fd = reader->handle;

	ufds.fd = in_fd;
	ufds.events = POLLIN | POLLPRI;
	ufds.revents = 0x0000;
	cs_ftime(&start); // register start time
	while (1){
		ret_val = poll(&ufds, 1, polltimeout);
		cs_ftime(&end); // register end time
		switch (ret_val){
			case -1:
				if (errno == EINTR || errno == EAGAIN){
					cs_sleepus(1);
					if (timeout_us>0){
						polltimeout = (timeout_us/1000) - (1000*(end.time-start.time)+end.millitm-start.millitm);
						if (polltimeout<0) polltimeout=0;
					}
					continue;
				}
				rdr_log(reader, "ERROR: %s: timeout=%ld ms (errno=%d %s)", __func__, 1000*(end.time-start.time)+end.millitm-start.millitm,errno, strerror(errno));
				return ERROR;
			default:
				if (ufds.revents &(POLLIN | POLLPRI))
					return OK;
				else
					return ERROR;
		}
	}
}

static bool IO_Serial_WaitToWrite (struct s_reader * reader, uint32_t delay_us, uint32_t timeout_us)
{
	struct pollfd ufds;
	struct timeb start, end;
	int32_t ret_val;
	int32_t out_fd;
	int32_t polltimeout = timeout_us / 1000;

#if !defined(WITH_COOLAPI) && !defined(WITH_AZBOX) 
	if(reader->typ == R_INTERNAL) return OK; // needed for internal readers, otherwise error!
#endif
	if (delay_us > 0)
		cs_sleepus (delay_us); // wait in us
	out_fd = reader->handle;

	ufds.fd = out_fd;
	ufds.events = POLLOUT;
	ufds.revents = 0x0000;
	cs_ftime(&start); // register start time
	while (1){
		ret_val = poll(&ufds, 1, polltimeout);
		cs_ftime(&end); // register end time
		switch (ret_val){
			case 0:
				rdr_log(reader, "ERROR: not ready to write, timeout=%ld ms", 1000*(end.time-start.time)+end.millitm-start.millitm);
				return ERROR;
			case -1:
				if (errno == EINTR || errno == EAGAIN){
					cs_sleepus(1);
					if (timeout_us>0){
						polltimeout = (timeout_us/1000) - (1000*(end.time-start.time)+end.millitm-start.millitm);
						if (polltimeout<0) polltimeout=0;
					}
					continue;
				}
				rdr_log(reader, "ERROR: %s: timeout=%ld ms (errno=%d %s)",__func__, 1000*(end.time-start.time)+end.millitm-start.millitm, errno, strerror(errno));
				return ERROR;
			default:
				if (((ufds.revents) & POLLOUT) == POLLOUT)
					return OK;
				else
					return ERROR;
		}
    }
}

bool IO_Serial_InitPnP (struct s_reader * reader)
{
	uint32_t PnP_id_size = 0;
	unsigned char PnP_id[IO_SERIAL_PNPID_SIZE];	/* PnP Id of the serial device */
	int32_t dtr = IO_SERIAL_HIGH;
	int32_t cts = IO_SERIAL_LOW;

  if (IO_Serial_SetParams (reader, 1200, 7, PARITY_NONE, 1, &dtr, &cts))
		return ERROR;

	while ((PnP_id_size < IO_SERIAL_PNPID_SIZE) && !IO_Serial_Read (reader, 0, 200000, 1, &(PnP_id[PnP_id_size])))
      PnP_id_size++;

		return OK;
}

int32_t IO_Serial_GetStatus(struct s_reader *reader, int32_t *status)
{
	uint32_t modembits = 0;
	if (ioctl(reader->handle, TIOCMGET, &modembits) == -1) {
		rdr_log(reader, "ERROR: %s: ioctl(TIOCMGET): %s", __func__, strerror(errno));
		return ERROR;
	}
	*status = 0;
	switch(reader->detect & 0x7f) {
	case 0: *status = modembits & TIOCM_CAR; break;
	case 1: *status = modembits & TIOCM_DSR; break;
	case 2: *status = modembits & TIOCM_CTS; break;
	case 3: *status = modembits & TIOCM_RNG; break;
	}
	if (!(reader->detect & 0x80))
		*status = !*status;
	return OK;
}

int32_t IO_Serial_SetBaudrate(struct s_reader * reader, uint32_t baudrate)
{
	rdr_debug_mask(reader, D_IFD, "Setting baudrate to %u", baudrate);
	// Get current settings
	struct termios tio;
	call (tcgetattr (reader->handle, &tio) != 0);
	// Set new baudrate
	call (IO_Serial_SetBitrate (reader, baudrate, &tio));
	call (IO_Serial_SetProperties(reader, tio));
	reader->current_baudrate = baudrate; //so if update fails, reader->current_baudrate is not changed either
	return OK;
}

#endif
