/*
 This module provides IFD handling functions for Coolstream internal reader.
*/

#include"../globals.h"

#ifdef CARDREADER_INTERNAL_COOLAPI
#include "../extapi/coolapi.h"
#include "../oscam-string.h"
#include "../oscam-time.h"
#include "atr.h"

#define OK 0
#define ERROR 1

extern int32_t cool_kal_opened;

struct cool_data
{
	void        *handle; //device handle for coolstream
	uint8_t     cardbuffer[512];
	uint32_t    cardbuflen;
	int8_t      pps;
};

static int32_t Cool_Init(struct s_reader *reader)
{
	char *device = reader->device;
	int32_t reader_nb = 0;
	// this is to stay compatible with older config.
	if(strlen(device))
		{ reader_nb = atoi((const char *)device); }
	if(reader_nb > 1)
	{
		// there are only 2 readers in the coolstream : 0 or 1
		rdr_log(reader, "Coolstream reader device can only be 0 or 1");
		return 0;
	}
	if(!cs_malloc(&reader->crdr_data, sizeof(struct cool_data)))
		{ return ERROR; }
	struct cool_data *crdr_data = reader->crdr_data;
	if(cnxt_smc_open(&crdr_data->handle, &reader_nb, NULL, NULL))
		{ return 0; }

	int32_t ret = cnxt_smc_enable_flow_control(crdr_data->handle, 0);
	coolapi_check_error("cnxt_smc_enable_flow_control", ret);

	crdr_data->cardbuflen = 0;
	crdr_data->pps = 0;
	return OK;
}

static int32_t Cool_FastReset(struct s_reader *reader)
{
	struct cool_data *crdr_data = reader->crdr_data;
	int32_t n = ATR_MAX_SIZE, ret;
	unsigned char buf[ATR_MAX_SIZE];

	//reset card
	ret = cnxt_smc_reset_card(crdr_data->handle, ATR_TIMEOUT, NULL, NULL);
	coolapi_check_error("cnxt_smc_reset_card", ret);
	cs_sleepms(50);
	ret = cnxt_smc_get_atr(crdr_data->handle, buf, &n);
	coolapi_check_error("cnxt_smc_get_atr", ret);

	return OK;
}

static int32_t Cool_SetClockrate(struct s_reader *reader, int32_t mhz)
{
	struct cool_data *crdr_data = reader->crdr_data;
	uint32_t clk;
	clk = mhz * 10000;
	int32_t ret = cnxt_smc_set_clock_freq(crdr_data->handle, clk);
	coolapi_check_error("cnxt_smc_set_clock_freq", ret);
	call(Cool_FastReset(reader));
	rdr_debug_mask(reader, D_DEVICE, "COOL: clock succesfully set to %i", clk);
	return OK;
}

static int32_t Cool_GetStatus(struct s_reader *reader, int32_t *in)
{
	struct cool_data *crdr_data = reader->crdr_data;
	if(cool_kal_opened)
	{
		int32_t state;
		int32_t ret = cnxt_smc_get_state(crdr_data->handle, &state);
		if(ret)
		{
			coolapi_check_error("cnxt_smc_get_state", ret);
			return ERROR;
		}
		//state = 0 no card, 1 = not ready, 2 = ready
		if(state)
			{ *in = 1; } //CARD, even if not ready report card is in, or it will never get activated
		else
			{ *in = 0; } //NOCARD
	}
	else
	{
		*in = 0;
	}
	return OK;
}

static int32_t Cool_Reset(struct s_reader *reader, ATR *atr)
{
	struct cool_data *crdr_data = reader->crdr_data;
	int32_t ret;

	if(!reader->ins7e11_fast_reset)
	{
		//set freq to reader->cardmhz if necessary
		uint32_t clk;

		ret = cnxt_smc_get_clock_freq(crdr_data->handle, &clk);
		coolapi_check_error("cnxt_smc_get_clock_freq", ret);
		if(clk / 10000 != (uint32_t)reader->cardmhz)
		{
			rdr_debug_mask(reader, D_DEVICE, "COOL: clock freq: %i, scheduling change to %i for card reset",
						   clk, reader->cardmhz * 10000);
			call(Cool_SetClockrate(reader, reader->cardmhz));
		}
	}
	else
	{
		rdr_log(reader, "Doing fast reset");
	}

	//reset card
	ret = cnxt_smc_reset_card(crdr_data->handle, ATR_TIMEOUT, NULL, NULL);
	coolapi_check_error("cnxt_smc_reset_card", ret);
	cs_sleepms(50);
	int32_t n = ATR_MAX_SIZE;
	unsigned char buf[ATR_MAX_SIZE];
	ret = cnxt_smc_get_atr(crdr_data->handle, buf, &n);
	coolapi_check_error("cnxt_smc_get_atr", ret);

	call(!ATR_InitFromArray(atr, buf, n) != ERROR);
	{
		cs_sleepms(50);
		return OK;
	}
}

static int32_t Cool_Transmit(struct s_reader *reader, unsigned char *sent, uint32_t size, uint32_t expectedlen, uint32_t UNUSED(delay), uint32_t UNUSED(timeout))
{
	struct cool_data *crdr_data = reader->crdr_data;
	int32_t ret;
	memset(crdr_data->cardbuffer, 0, 512);

	if(reader->protocol_type == ATR_PROTOCOL_TYPE_T0)
	{
		crdr_data->cardbuflen = expectedlen;
		ret = cnxt_smc_read_write(crdr_data->handle, 0, sent, size, crdr_data->cardbuffer, &crdr_data->cardbuflen, 0, NULL);
	}
	else
	{
		crdr_data->cardbuflen = 512;
		ret = cnxt_smc_read_write(crdr_data->handle, 0, sent, size, crdr_data->cardbuffer, &crdr_data->cardbuflen, 4000, NULL);
	}

	coolapi_check_error("cnxt_smc_read_write", ret);

	rdr_ddump_mask(reader, D_DEVICE, sent, size, "COOL Transmit:");

	if(ret)
		{ return ERROR; }
	return OK;
}

static int32_t Cool_Receive(struct s_reader *reader, unsigned char *data, uint32_t size, uint32_t UNUSED(delay), uint32_t UNUSED(timeout))
{
	struct cool_data *crdr_data = reader->crdr_data;
	if(size > crdr_data->cardbuflen)
		{ size = crdr_data->cardbuflen; } //never read past end of buffer
	memcpy(data, crdr_data->cardbuffer, size);
	crdr_data->cardbuflen -= size;
	memmove(crdr_data->cardbuffer, crdr_data->cardbuffer + size, crdr_data->cardbuflen);
	rdr_ddump_mask(reader, D_DEVICE, data, size, "COOL Receive:");
	return OK;
}

static void Cool_Print_Comm_Parameters(struct s_reader *reader)
{
	struct cool_data *crdr_data = reader->crdr_data;
	uint16_t F;
	uint8_t D;
	int32_t ret = cnxt_smc_get_F_D_factors(crdr_data->handle, &F, &D);
	coolapi_check_error("cnxt_smc_get_F_D_factors", ret);

	char *protocol;
	CNXT_SMC_COMM comm;
	ret = cnxt_smc_get_comm_parameters(crdr_data->handle, &comm);
	coolapi_check_error("cnxt_smc_get_comm_parameters", ret);
	if(comm.protocol == 0x01)
		{ protocol = "T0"; }
	else if(comm.protocol == 0x02)
		{ protocol = "T1"; }
	else if(comm.protocol == 0x04)
		{ protocol = "T14"; }
	else
		{ protocol = "unknown"; }

	rdr_log(reader, "Driver Settings: Convention=%s, Protocol=%s, FI=%i, F=%i, N=%i, DI=%i, D=%i, PI1=%i, PI2=%i, II=%i, TXRetries=%i, RXRetries=%i, FilterProtocolBytes=%i", comm.convention ? "Inverse" : "Direct", protocol, comm.FI, F, comm.N, comm.DI, D, comm.PI1, comm.PI2, comm.II, comm.retries.TXRetries, comm.retries.RXRetries, comm.filterprotocolbytes);

	CNXT_SMC_TIMEOUT timeout;
	ret = cnxt_smc_get_config_timeout(crdr_data->handle, &timeout);
	coolapi_check_error("cnxt_smc_get_config_timeout", ret);

	rdr_log(reader, "Driver Timeouts: CardActTime=%i, CardDeactTime=%i, ATRSTime=%i, ATRDTime=%i, BLKTime=%i, CHTime=%i, CHGuardTime=%i, BKGuardTime=%i", timeout.CardActTime, timeout.CardDeactTime, timeout.ATRSTime, timeout.ATRDTime, timeout.BLKTime, timeout.CHTime, timeout.CHGuardTime, timeout.BKGuardTime);

}

static int32_t Cool_WriteSettings(struct s_reader *reader, uint16_t F, uint8_t D, uint32_t WWT, uint32_t EGT, uint32_t BGT)
{
	struct cool_data *crdr_data = reader->crdr_data;
	//first set freq back to reader->mhz if necessary
	uint32_t clk;
	int32_t ret = cnxt_smc_get_clock_freq(crdr_data->handle, &clk);
	coolapi_check_error("cnxt_smc_get_clock_freq", ret);
	if(clk / 10000 != (uint32_t)reader->mhz)
	{
		rdr_debug_mask(reader, D_DEVICE, "COOL: clock freq: %i, scheduling change to %i", clk, reader->mhz * 10000);
		call(Cool_SetClockrate(reader, reader->mhz));
	}

	uint32_t BLKTime = 0, CHTime = 0;
	uint8_t BKGuardTime = 0;
	switch(reader->protocol_type)
	{
	case ATR_PROTOCOL_TYPE_T1:
		if(reader->BWT > 11)
			{ BLKTime = (reader->BWT - 11); }
		if(reader->CWT > 11)
			{ CHTime = (reader->CWT - 11); }
		if(BGT > 11)
			{ BKGuardTime = (BGT - 11); }
		else
			{ BKGuardTime = 11; } //For T1, the BGT minimum time shall be 22 work etus. BGT is effectively offset by 11 etus internally.
		if(!crdr_data->pps)
		{
			ret = cnxt_smc_set_F_D_factors(crdr_data->handle, F, D);
			coolapi_check_error("cnxt_smc_set_F_D_factors", ret);
		}
		break;
	case ATR_PROTOCOL_TYPE_T0:
	case ATR_PROTOCOL_TYPE_T14:
	default:
		BLKTime = 0;
		if(WWT > 12)
			{ CHTime = (WWT - 12); }
		if(BGT > 12)
			{ BKGuardTime = (BGT - 12); }
		if(BKGuardTime < 4)
			{ BKGuardTime = 4; } //For T0, the BGT minimum time shall be 16 work etus. BGT is effectively offset by 12 etus internally.
		if(!crdr_data->pps)
		{
			if(reader->protocol_type == ATR_PROTOCOL_TYPE_T14)
			{
				ret = cnxt_smc_set_F_D_factors(crdr_data->handle, 620, 1);
			}
			else
			{
				ret = cnxt_smc_set_F_D_factors(crdr_data->handle, F, D);
			}
			coolapi_check_error("cnxt_smc_set_F_D_factors", ret);
		}
		break;
	}
	ret = cnxt_smc_set_convention(crdr_data->handle, reader->convention);
	coolapi_check_error("cnxt_smc_set_convention", ret);

	CNXT_SMC_TIMEOUT timeout;
	ret = cnxt_smc_get_config_timeout(crdr_data->handle, &timeout);
	coolapi_check_error("cnxt_smc_get_config_timeout", ret);
	timeout.BLKTime = BLKTime;
	timeout.CHTime = CHTime;
	timeout.CHGuardTime = EGT;
	timeout.BKGuardTime = BKGuardTime;
	ret = cnxt_smc_set_config_timeout(crdr_data->handle, timeout);
	coolapi_check_error("cnxt_smc_set_config_timeout", ret);

	Cool_Print_Comm_Parameters(reader);

	return OK;
}

static int32_t Cool_Close(struct s_reader *reader)
{
	struct cool_data *crdr_data = reader->crdr_data;
	if(cool_kal_opened)
	{
		int32_t ret = cnxt_smc_close(crdr_data->handle);
		coolapi_check_error("cnxt_smc_close", ret);
	}
	return OK;
}

static int32_t Cool_SetProtocol(struct s_reader *reader, unsigned char *params, uint32_t *UNUSED(length), uint32_t UNUSED(len_request))
{
	struct cool_data *crdr_data = reader->crdr_data;
	unsigned char pps[4], response[6];
	uint8_t len = 0;

	//Driver sets PTSS and PCK on its own
	pps[0] = params[1]; //PPS0
	pps[1] = params[2]; //PPS1

	int32_t ret = cnxt_smc_start_pps(crdr_data->handle, pps, response, &len, 1);
	coolapi_check_error("cnxt_smc_start_pps", ret);
	if(ret)
		{ return ERROR; }
	crdr_data->pps = 1;
	return OK;
}

void cardreader_internal_cool(struct s_cardreader *crdr)
{
	crdr->desc         = "internal";
	crdr->typ          = R_INTERNAL;
	crdr->max_clock_speed = 1;
	crdr->reader_init  = Cool_Init;
	crdr->get_status   = Cool_GetStatus;
	crdr->activate     = Cool_Reset;
	crdr->transmit     = Cool_Transmit;
	crdr->receive      = Cool_Receive;
	crdr->close        = Cool_Close;
	crdr->write_settings2 = Cool_WriteSettings;
	crdr->set_protocol  = Cool_SetProtocol;
}

#endif
