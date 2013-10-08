#include "globals.h"
#ifdef READER_TONGFANG
#include "reader-common.h"

static int32_t cw_is_valid(unsigned char *cw) //returns 1 if cw_is_valid, returns 0 if cw is all zeros
{
	int32_t i;

	for(i = 0; i < 8; i++)
	{
		if(cw[i] != 0)  //test if cw = 00
		{
			return OK;
		}
	}
	return ERROR;
}

static int32_t tongfang_read_data(struct s_reader *reader, uchar size, uchar *cta_res, uint16_t *status)
{
	uchar read_data_cmd[] = {0x00, 0xc0, 0x00, 0x00, 0xff};
	uint16_t cta_lr;

	read_data_cmd[4] = size;
	write_cmd(read_data_cmd, NULL);

	*status = (cta_res[cta_lr - 2] << 8) | cta_res[cta_lr - 1];

	return (cta_lr - 2);
}

static int32_t tongfang_card_init(struct s_reader *reader, ATR *newatr)
{
	static const uchar begin_cmd[] = {0x00, 0xa4, 0x04, 0x00, 0x05, 0xf9, 0x5a, 0x54, 0x00, 0x06};
	static const uchar get_serial_cmd[] = {0x80, 0x46, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x04};
	uchar pairing_cmd[] = {0x80, 0x4c, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF};

	uchar data[257];
	int32_t data_len = 0;
	uint16_t status = 0;
	uchar boxID[] = {0xFF, 0xFF, 0xFF, 0xFF};
	int32_t i;

	def_resp;
	get_hist;

	if((hist_size < 4) || (memcmp(hist, "NTIC", 4))) { return ERROR; }

	reader->caid = 0x4A02;
	// For now, only one provider, 0000
	reader->nprov = 1;
	memset(reader->prid, 0x00, sizeof(reader->prid));

	rdr_log(reader, "Tongfang card detected");

	write_cmd(begin_cmd, begin_cmd + 5);
	if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) { return ERROR; }

	write_cmd(get_serial_cmd, get_serial_cmd + 5);
	if((cta_res[cta_lr - 2] & 0xf0) != 0x60) { return ERROR; }
	data_len = tongfang_read_data(reader, cta_res[cta_lr - 1], data, &status);

	if(data_len < 0) { return ERROR; }
	if(status != 0x9000) { return ERROR; }

	memset(reader->hexserial, 0, 8);
	memcpy(reader->hexserial + 2, data, 4); // might be incorrect offset

	if(reader->boxid > 0)
	{
		/* the boxid is specified in the config */
		for(i = 0; i < 4; i++)
		{
			boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
		}
	}
	memcpy(pairing_cmd + 5, boxID, sizeof(boxID));
	write_cmd(pairing_cmd, pairing_cmd + 5);

	rdr_log_sensitive(reader, "type: Tongfang, caid: %04X, serial: {%llu}, hex serial: {%02x%02x%02x%02x}, BoxID: {%02X%02X%02X%02X}",
					  reader->caid, (unsigned long long) b2ll(6, reader->hexserial), reader->hexserial[2],
					  reader->hexserial[3], reader->hexserial[4], reader->hexserial[5],
					  boxID[0], boxID[1], boxID[2], boxID[3]);

	return OK;
}

/*
Example ecm:
03 85 80 70 61 8E 2A 16 4F 00 12 0F 21 5A E5 6A
8F 4D C1 57 4E 24 2A 38 3C 26 8A 4C C2 74 A1 23
9F 12 43 80 3A 16 4F 3E 8E 2A C0 40 0F 22 94 E4
6A 89 F1 09 38 8F DF 3D 08 A6 29 1A 61 98 31 82
7F 34 55 74 0E A3 54 38 01 09 00 01 00 01 D9 31
A5 1B 8B CA A8 95 E0 D1 24 7D 36 8C F6 89 4A F7
B2 3A 74 3D D1 D4
*/
static int32_t tongfang_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	uchar ecm_cmd[200];
	int32_t ecm_len;
	const uchar *pbuf = er->ecm;
	char *tmp;
	int32_t i = 0;
	int32_t write_len = 0;
	def_resp;
	int32_t read_size = 0;
	uchar data[100];
	int32_t data_len = 0;
	uint16_t status = 0;

	if((ecm_len = check_sct_len(er->ecm, 3)) < 0) { return ERROR; }
	if(cs_malloc(&tmp, ecm_len * 3 + 1))
	{
		rdr_debug_mask(reader, D_IFD, "ECM: %s", cs_hexdump(1, er->ecm, ecm_len, tmp, ecm_len * 3 + 1));
		free(tmp);
	}

	for(i = 0; i < (ecm_len - 1); i++)
	{
		if((pbuf[0] == 0x80) && (pbuf[1] == 0x3a))
		{
			break;
		}
		pbuf++;
	}
	write_len = pbuf[4] + 5;

	memcpy(ecm_cmd, pbuf, write_len);

	write_cmd(ecm_cmd, ecm_cmd + 5);

	if((cta_lr - 2) >= 2)
	{
		read_size = cta_res[1];
	}
	else
	{
		if((cta_res[cta_lr - 2] & 0xf0) == 0x60)
		{
			read_size = cta_res[cta_lr - 1];
		}
		else
		{
			return ERROR;
		}
	}

	data_len = tongfang_read_data(reader, read_size, data, &status);

	if(data_len < 23) { return ERROR; }

	if(!(er->ecm[0] & 0x01))
	{
		memcpy(ea->cw, data + 8, 16);
	}
	else
	{
		memcpy(ea->cw, data + 16, 8);
		memcpy(ea->cw + 8, data + 8, 8);
	}

	// All zeroes is no valid CW, can be a result of wrong boxid
	if(!cw_is_valid(ea->cw) || !cw_is_valid(ea->cw + 8)) { return ERROR; }

	return OK;
}

static int32_t tongfang_get_emm_type(EMM_PACKET *ep, struct s_reader *UNUSED(reader))
{
	ep->type = UNKNOWN;
	return 1;
}

static int32_t tongfang_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	uchar emm_cmd[200];
	def_resp;
	int32_t write_len;

	if(ep->emm[2] < 5) { return ERROR; }

	write_len = ep->emm[15] + 5;
	memcpy(emm_cmd, ep->emm + 11, write_len);

	write_cmd(emm_cmd, emm_cmd + 5);

	return OK;
}

static int32_t tongfang_card_info(struct s_reader *reader)
{
	static const uchar get_provider_cmd[] = {0x80, 0x44, 0x00, 0x00, 0x08};
	def_resp;
	int32_t i;

	write_cmd(get_provider_cmd, NULL);
	if((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00)) { return ERROR; }

	for(i = 0; i < 4; i++)
	{
		rdr_log(reader, "Provider:%02x%02x", cta_res[i * 2], cta_res[i * 2 + 1]);
	}
	return OK;
}

void reader_tongfang(struct s_cardsystem *ph)
{
	ph->do_emm = tongfang_do_emm;
	ph->do_ecm = tongfang_do_ecm;
	ph->card_info = tongfang_card_info;
	ph->card_init = tongfang_card_init;
	ph->get_emm_type = tongfang_get_emm_type;
	ph->caids[0] = 0x4B;
	ph->desc = "tongfang";
}
#endif
