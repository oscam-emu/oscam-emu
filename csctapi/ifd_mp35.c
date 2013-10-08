#include "../globals.h"

#ifdef CARDREADER_MP35
#include "../oscam-time.h"
#include "atr.h"
#include "ifd_phoenix.h"
#include "io_serial.h"

#define OK 0
#define ERROR 1

#define ACK 0x06
#define MP35_WRITE_DELAY 100000
#define MP35_READ_DELAY 200000
#define MP35_BREAK_LENGTH 1200000

typedef struct
{
	unsigned char current_product;
	uint16_t product_fw_version;
} MP35_info;

// Common command for AD-Teknik readers
static const unsigned char fw_version[] = {0x2a, 0x41};

// Commands for AD-Teknik MP3.5 and MP3.6
static const unsigned char power_always_on[] = {0x2a, 0x8a};
static const unsigned char set_vpp[] = {0x2a, 0x42};
static const unsigned char set_data[] = {0x2a, 0x43};
static const unsigned char set_oscillator[] = {0x2a, 0x5e};
static const unsigned char terminate_com[] = {0x2a, 0x7b};
static const unsigned char transthrough_mode[] = {0x2a, 0x7c};
static const unsigned char phoenix_mode[] = {0x2a, 0x7d};
static const unsigned char smartmouse_mode[] = {0x2a, 0x7e};
static const unsigned char phoenix_6mhz_mode[] = {0x2a, 0x9a};
static const unsigned char smartmouse_6mhz_mode[] = {0x2a, 0x9b};
static const unsigned char fw_info[] = {0x2a, 0xa2};

// Commands for AD-Teknik USB Phoenix
static const unsigned char set_mode_osc[] = {0x2a, 0x42};
static const unsigned char exit_program_mode[] = {0x2a, 0x43};

static const struct product
{
	unsigned char code;
	const char *product_name;
} product_codes[] =
{
	{0x10, "USB Phoenix"},
	{0x40, "MP3.4"},
	{0x41, "MP3.5"},
	{0x42, "MP3.6 USB"}
};

static int32_t mp35_product_info(struct s_reader *reader, unsigned char high, unsigned char low, unsigned char code, MP35_info *info)
{
	int32_t i;

	for(i = 0; i < (int)(sizeof(product_codes) / sizeof(struct product)); i++)
	{
		if(product_codes[i].code == code)
		{
			rdr_log(reader, "%s: %s - FW:%02d.%02d", __func__, product_codes[i].product_name, high, low);
			info->current_product = code;
			info->product_fw_version = (high << 8) | low;
			return OK;
		}
	}

	return ERROR;
}

static int32_t mp35_reader_init(struct s_reader *reader)
{
	MP35_info reader_info;
	unsigned char rec_buf[32];
	unsigned char parameter;
	int32_t original_mhz;
	int32_t original_cardmhz;

	rdr_log(reader, "%s: started", __func__);

	original_mhz = reader->mhz;
	original_cardmhz = reader->cardmhz;

	// MP3.5 commands should be always be written using 9600 baud at 3.57MHz
	reader->mhz = 357;
	reader->cardmhz = 357;

	int32_t dtr = IO_SERIAL_HIGH;
	int32_t cts = IO_SERIAL_HIGH;

	call(IO_Serial_SetParams(reader, 9600, 8, PARITY_NONE, 1, &dtr, &cts));

	IO_Serial_Sendbreak(reader, MP35_BREAK_LENGTH);
	IO_Serial_DTR_Clr(reader);
	IO_Serial_DTR_Set(reader);
	cs_sleepms(200);
	IO_Serial_RTS_Set(reader);
	IO_Serial_Flush(reader);

	memset(rec_buf, 0x00, sizeof(rec_buf));
	call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 1000000, 2, fw_version));
	call(IO_Serial_Read(reader, MP35_READ_DELAY, 1000000, 4, rec_buf));
	if(rec_buf[3] != ACK)
	{
		rdr_debug_mask(reader, D_IFD, "Failed MP35 command: fw_version");
		return ERROR;
	}

	if(mp35_product_info(reader, rec_buf[1], rec_buf[0], rec_buf[2], &reader_info) != OK)
	{
		rdr_log(reader, "%s: unknown product code", __func__);
		return ERROR;
	}

	if(reader_info.current_product == 0x10)  // USB Phoenix
	{
		if(original_mhz == 357)
		{
			rdr_log(reader, "%s: Using oscillator 1 (3.57MHz)", __func__);
			parameter = 0x01;
		}
		else if(original_mhz == 368)
		{
			rdr_log(reader, "%s: Using oscillator 2 (3.68MHz)", __func__);
			parameter = 0x02;
		}
		else if(original_mhz == 600)
		{
			rdr_log(reader, "%s: Using oscillator 3 (6.00MHz)", __func__);
			parameter = 0x03;
		}
		else
		{
			rdr_log(reader, "%s: MP35 support only mhz=357, mhz=368 or mhz=600", __func__);
			rdr_log(reader, "%s: Forced oscillator 1 (3.57MHz)", __func__);
			parameter = 0x01;
			original_mhz = 357;
		}
		memset(rec_buf, 0x00, sizeof(rec_buf));
		call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 1000000, 2, set_mode_osc));
		call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 1000000, 1, &parameter));
		call(IO_Serial_Read(reader, MP35_READ_DELAY, 1000000, 1, rec_buf)); // Read ACK from previous command
		if(rec_buf[0] != ACK)
		{
			rdr_debug_mask(reader, D_IFD, "Failed MP35 command: set_mode_osc");
			return ERROR;
		}
		rdr_debug_mask(reader, D_IFD, "%s: Leaving programming mode", __func__);
		memset(rec_buf, 0x00, sizeof(rec_buf));
		call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 1000000, 2, exit_program_mode));
		call(IO_Serial_Read(reader, MP35_READ_DELAY, 1000000, 1, rec_buf));
		if(rec_buf[0] != ACK)
		{
			rdr_debug_mask(reader, D_IFD, "Failed MP35 command: exit_program_mode");
			return ERROR;
		}
	}
	else //MP3.5 or MP3.6
	{
		if(reader_info.product_fw_version >= 0x0500)
		{
			int32_t info_len;
			char info[sizeof(rec_buf) - 2];

			memset(rec_buf, 0x00, sizeof(rec_buf));
			call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 1000000, 2,  fw_info));
			call(IO_Serial_Read(reader, MP35_READ_DELAY, 1000000, 1, rec_buf));
			info_len = rec_buf[0];
			call(IO_Serial_Read(reader, MP35_READ_DELAY, 1000000, info_len + 1, rec_buf));
			if(rec_buf[info_len] != ACK)
			{
				rdr_debug_mask(reader, D_IFD, "Failed MP35 command: fw_info");
				return ERROR;
			}
			memcpy(info, rec_buf, info_len);
			info[info_len] = '\0';
			rdr_log(reader, "%s: FW Info - %s", __func__, info);
		}

		memset(rec_buf, 0x00, sizeof(rec_buf));
		if(original_mhz == 357)
		{
			rdr_log(reader, "%s: Using oscillator 1 (3.57MHz)", __func__);
			call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 1000000, 2, phoenix_mode));
		}
		else if(original_mhz == 600)
		{
			rdr_log(reader, "%s: Using oscillator 2 (6.00MHz)", __func__);
			call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 1000000, 2, phoenix_6mhz_mode));
		}
		else
		{
			rdr_log(reader, "%s: MP35 support only mhz=357 or mhz=600", __func__);
			rdr_log(reader, "%s: Forced oscillator 1 (3.57MHz)", __func__);
			call(IO_Serial_Write(reader, MP35_WRITE_DELAY, 1000000, 2, phoenix_mode));
			original_mhz = 357;
		}
		tcdrain(reader->handle);
	}

	// We might have switched oscillator here
	reader->mhz = original_mhz;
	reader->cardmhz = original_cardmhz;

	/* Default serial port settings */
	if(reader->atr[0] == 0)
	{
		IO_Serial_Flush(reader);
		call(IO_Serial_SetParams(reader, DEFAULT_BAUDRATE, 8, PARITY_EVEN, 2, NULL, NULL));
	}

	return OK;
}

static int32_t mp35_close(struct s_reader *reader)
{
	rdr_debug_mask(reader, D_IFD, "Closing MP35 device %s", reader->device);

	IO_Serial_DTR_Clr(reader);
	IO_Serial_Close(reader);

	return OK;
}

static int32_t mp35_init(struct s_reader *reader)
{
	reader->handle = open(reader->device,  O_RDWR | O_NOCTTY | O_NONBLOCK);
	if(reader->handle < 0)
	{
		rdr_log(reader, "ERROR: Opening device %s (errno=%d %s)",
				reader->device, errno, strerror(errno));
		return ERROR;
	}
	if(IO_Serial_SetParams(reader, DEFAULT_BAUDRATE, 8, PARITY_EVEN, 2, NULL, NULL))
		{ return ERROR; }

	if(mp35_reader_init(reader))
	{
		rdr_log(reader, "ERROR: mp35_reader_init returned error");
		mp35_close(reader);
		return ERROR;
	}
	return OK;
}

void cardreader_mp35(struct s_cardreader *crdr)
{
	crdr->desc         = "mp35";
	crdr->typ          = R_MOUSE;
	crdr->flush        = 1;
	crdr->need_inverse = 1;
	crdr->read_written = 1;
	crdr->reader_init  = mp35_init;
	crdr->get_status   = IO_Serial_GetStatus;
	crdr->activate     = Phoenix_Reset;
	crdr->transmit     = IO_Serial_Transmit;
	crdr->receive      = IO_Serial_Receive;
	crdr->close        = mp35_close;
	crdr->set_parity   = IO_Serial_SetParity;
	crdr->set_baudrate = IO_Serial_SetBaudrate;
}

#endif
