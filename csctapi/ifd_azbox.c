#include"../globals.h"

#ifdef CARDREADER_INTERNAL_AZBOX
#include "../extapi/openxcas/openxcas_api.h"
#include "../extapi/openxcas/openxcas_smartcard.h"
#include "../oscam-time.h"
#include "atr.h"

#define OK 0
#define ERROR 1

#define AZBOX_MODES 16

static int32_t sc_mode;

static int32_t _GetStatus(struct s_reader *reader, int32_t *UNUSED(in))
{
	unsigned char tmp[512];
	memset(tmp, 0, sizeof(tmp));

	return ioctl(reader->handle, SCARD_IOC_CHECKCARD, &tmp);
}

static int32_t Azbox_Init(struct s_reader *reader)
{
	rdr_debug_mask(reader, D_DEVICE, "openxcas sc: init");

	if((reader->handle = openxcas_get_smartcard_device(0)) < 0)
	{
		rdr_debug_mask(reader, D_DEVICE, "openxcas sc: init failed (%d)", reader->handle);
		return 0;
	}

	rdr_debug_mask(reader, D_DEVICE, "openxcas sc: init succeeded");

	return OK;
}

static void Azbox_SetMode(struct s_reader *reader, int32_t mode)
{
	sc_mode = mode;
	rdr_log(reader, "openxcas sc: set mode %d", sc_mode);
}

static int32_t Azbox_GetStatus(struct s_reader *reader, int32_t *in)
{
	unsigned char tmp[512];
	memset(tmp, 0, sizeof(tmp));

	int32_t status = _GetStatus(reader, in);

	if(in)
	{
		if(status != 1 && status != 3)
			{ *in = 0; }
		else
			{ *in = 1; }

		//rdr_debug_mask(reader, D_DEVICE, "openxcas sc: get status = %d", *in);
	}

	return OK;
}

static int32_t Azbox_Reset(struct s_reader *reader, ATR *atr)
{
	int32_t status;
	unsigned char tmp[512];

	memset(tmp, 0, sizeof(tmp));
	tmp[0] = 3;
	tmp[1] = 1;

	ioctl(reader->handle, SCARD_IOC_WARMRESET, &tmp);

	cs_sleepms(500);

	while((status = _GetStatus(reader, NULL)) != 3)
		{ cs_sleepms(50); }

	tmp[0] = 0x02;
	tmp[1] = sc_mode;
	status = ioctl(reader->handle, SCARD_IOC_CHECKCARD, &tmp);

	memset(tmp, 0, sizeof(tmp));
	tmp[0] = 1;

	int32_t atr_len = ioctl(reader->handle, SCARD_IOC_CHECKCARD, &tmp);
	if(ATR_InitFromArray(atr, tmp, atr_len) == ERROR)
		{ return 0; }

	cs_sleepms(500);

	return OK;
}

static int32_t Azbox_Transmit(struct s_reader *reader, unsigned char *buffer, uint32_t size, uint32_t UNUSED(expectedlen), uint32_t UNUSED(delay), uint32_t UNUSED(timeout))
{
	if(write(reader->handle, buffer, size) != (ssize_t)size)
		{ return 0; }

	return OK;
}

static int32_t Azbox_Receive(struct s_reader *reader, unsigned char *buffer, uint32_t size, uint32_t UNUSED(delay), uint32_t UNUSED(timeout))
{
	if(read(reader->handle, buffer, size) != (ssize_t)size)
		{ return 0; }

	return OK;
}

static int32_t Azbox_Close(struct s_reader *UNUSED(reader))
{
	openxcas_release_smartcard_device(0);

	return OK;
}

static int32_t Azbox_do_reset(struct s_reader *reader, struct s_ATR *atr,
							  int32_t (*rdr_activate_card)(struct s_reader *, struct s_ATR *, uint16_t deprecated),
							  int32_t (*rdr_get_cardsystem)(struct s_reader *, struct s_ATR *))
{
	int32_t ret = 0;
	int32_t i;
	if(reader->azbox_mode != -1)
	{
		Azbox_SetMode(reader, reader->azbox_mode);
		if(!rdr_activate_card(reader, atr, 0))
			{ return -1; }
		ret = rdr_get_cardsystem(reader, atr);
	}
	else
	{
		for(i = 0; i < AZBOX_MODES; i++)
		{
			Azbox_SetMode(reader, i);
			if(!rdr_activate_card(reader, atr, 0))
				{ return -1; }
			ret = rdr_get_cardsystem(reader, atr);
			if(ret)
				{ break; }
		}
	}
	return ret;
}

void cardreader_internal_azbox(struct s_cardreader *crdr)
{
	crdr->desc         = "internal";
	crdr->typ          = R_INTERNAL;
	crdr->max_clock_speed = 1;
	crdr->reader_init  = Azbox_Init;
	crdr->get_status   = Azbox_GetStatus;
	crdr->activate     = Azbox_Reset;
	crdr->transmit     = Azbox_Transmit;
	crdr->receive      = Azbox_Receive;
	crdr->close        = Azbox_Close;
	// crdr->write_settings3 = sci_write_settings3; // FIXME: before conversion Azbox support used Sci_WriteSettings code path
	crdr->do_reset     = Azbox_do_reset;
}
#endif
