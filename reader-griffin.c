/*
 * Griffin card reader for OSCAM
 * Copyright (C) 2013 Unix Solutions Ltd.
 *
 * Author(s): Georgi Chorbadzhiyski (gf@unixsol.org)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * =========================================================================
 * Once upon a time Bulsatcom in Bulgaria used Griffin CAS. Their cards were
 * known as "strawberry cards" because they had a strawberry picture on the
 * front. These cards have CAID 0x5501. You can't get EMM and ECM stream
 * for these cards but if you can, then the reader would probably work.
 *
 * This reader is tested with working card that have CAID 0x5504. This card
 * is used by KaTe Nova Gorica provider in Slovenia.
 * =========================================================================
 *
 * Griffin reader card protocol:
 *   ATR from CAID 0x5501
 *     3B 08 01 01 xx xx xx xx 10 00
 *       (01 - last two octets in caid (0x01 = CAID 0x5501)
 *       (xx - card hex serial number)
 *       (10 - command base)
 *
 *   ATR from CAID 0x5504
 *     3B 08 04 01 xx xx xx xx 20 00
 *       (04 - last two octets in caid (0x04 = CAID 0x5504)
 *       (xx - card hex serial number)
 *       (20 - command base)
 *
 *   The basic card conversation looks like this:
 *      Send DC xx 00 00 yy zz zz zz (xx = command op, yy payload length, zz - payload if payload_len > 0)
 *      Recv 90 03                   (90 = command ok, 03 = length of the response)
 *      Send DC 12 00 00 xx          (Read response  , xx = length of the response)
 *      Recv xx yy zz 90 00          (Response       , xx = response code, yy - data length, zz - data, 90 00 at the end)
 *
 *   Command ops (hex), these commands are for card with base == 20:
 *     02 - read command response (for base cards with base 10)
 *     12 - read command response (for base cards with base 20)
 *
 *   The command number is (base + number, the numbers bellow are for base==20)
 *     20 - card init
 *     22 - get hex serial
 *     24 - get ascii serial
 *     26 - get caid
 *     28 - get card addresses
 *     30 - unknown command
 *     34 - unknown command
 *     36 - send_ecm
 *     32 - send_emm
 *     40 - get subscription info
 *     42 - unknown command
 *     4a - unknown command
 *     50 - unknown command
 *
 *   Perform card INIT
 *     DC 20 00 00 00 -- 90 03 (card init /get base/)
 *     DC 12 00 00 03 -- 11 01 20 90 00 (20 == cmd base)
 *
 *     DC 22 00 00 00 -- 90 06 (get hex serial)
 *     DC 12 00 00 06 -- 12 04 xx xx xx xx 90 00 (xx - hex serial)
 *
 *     DC 24 00 00 00 -- 90 0E (get ascii serial)
 *     DC 12 00 00 0E -- 13 0C 47 43 30 34 53 xx xx xx xx xx xx 00 90 00 (xx - ascii serial - GC04S......)
 *
 *     DC 26 00 00 00 -- 90 04 (get caid)
 *     DC 12 00 00 04 -- 14 02 xx xx 90 00 (xx xx = 55 04 /the caid/)
 *
 *     DC 28 00 00 00 -- 90 32
 *     DC 12 00 00 32 -- 15 30 \
 *        80 00 00 00 00 00 00 00 F0 FF FF FF FF 00 00 00 \
 *        80 yy yy yy yy 00 00 00 F0 FF FF FF FF 00 00 00 \     (yy = shared card address)
 *        80 xx xx xx xx 00 00 00 F0 FF FF FF FF 00 00 00 90 00 (xx = card hex serial)
 *
 *     DC 42 00 00 00 -- 90 03
 *     DC 12 00 00 03 -- 1C 01 00 90 00
 *
 *     DC 34 00 00 00 -- 90 00
 *     DC 30 00 00 00 -- 90 00
 *
 *   Send ECMs
 *     DC 36 00 00 42 -- 81 70 3F C6 71 A3 97 A3 91 36 76 C9 69 EC A8 46 CA FB 0B 31 D2 4B 2A BD 43 FF 5E A4 C0 CD 06 A9 48 1B 2B 6C 3D 28 B2 92 3A C0 C2 1C 38 35 29 D0 9D B2 16 6D 26 E3 27 A3 20 6F 8E 72 5D 0B A3 00 65 EC 90 18
 *     DC 36 00 00 42 -- 80 70 3F 09 D2 9B F3 03 E3 81 5A E4 44 F4 18 9E 84 18 D5 6E 81 D8 1F A2 E8 CB 1B B6 A9 3D 5D C2 CA FE 6A C2 69 1A CD 15 7F 2C A6 77 8B CF 0C 4E 4F 74 04 97 17 15 93 4F 2E 93 10 B8 6B B0 FF 1C 20 7D 90 18
 *
 *     DC 36 00 00 41 -- 81 70 3E 09 EC 39 F4 35 CF 45 80 AB 17 56 56 64 F0 BB 39 97 BE 7F 9E D3 F7 70 6A B2 8A 52 56 BD B4 B3 77 14 22 13 70 7F 9D 03 2A BB 88 85 3E 1D AB 9D E1 C7 A1 CB B9 99 34 F6 EB 2C 15 7F 52 E5 1C 90 18
 *     DC 36 00 00 41 -- 80 70 3E F4 7E B1 C4 30 56 C2 61 AA 31 29 FB 09 1C 79 13 14 8E 64 43 5F 4B 97 71 A0 D3 BA A4 08 AC 8B E4 21 B7 C6 8A A5 9F 72 19 A5 51 75 9B F2 40 B2 C9 8F E8 63 98 2C 5D 84 21 88 8F F1 DA CF 32 90 18
 *
 *     DC 36 00 00 3E -- 81 70 3B 07 76 06 C8 8D 9F 57 C8 19 30 1C 3B 93 9B A1 E1 88 E7 82 C3 E5 7A 05 44 DF 7D 90 CB F9 E1 43 C7 6F 39 75 3A A5 15 73 AA 5F 8C 1D 5B B6 52 2B 0B C2 02 88 7C C2 E8 4F D6 6A 73 A6 90 18
 *     DC 36 00 00 3E -- 80 70 3B CE B9 CC BC 95 D8 BB 4A C0 7B 7C 7E 9C 39 00 10 47 E1 67 A7 CD 34 9F E6 43 CB 50 2E 77 9A 54 87 54 25 49 FC 4F 6A A6 56 FD 51 74 08 37 C3 00 04 BD 72 04 CB DB D9 7C 37 76 71 A7 90 18
 *
 *     DC 36 00 00 3D -- 81 70 3A 22 06 2B 48 2A 99 4B 82 20 C4 80 B4 55 72 CD B3 C9 FD BA 84 89 66 F4 F8 51 7F CD AC 38 4E 0E 6A 91 11 E9 E1 A4 0E 8D E7 56 43 11 56 F5 DA 78 19 42 37 B3 CA BA 33 11 69 B9 96 90 18
 *     DC 36 00 00 3D -- 80 70 3A FB 09 20 41 48 2D 12 4F E8 13 E3 23 AD B9 25 CE DA 95 F2 C8 ED D6 08 2E 23 6A 13 19 A8 A7 9F 9A 8B 12 F3 97 95 09 5B F6 F6 AA 64 EA 46 3C AD 62 93 DC B5 07 FB 16 81 F8 A6 D3 90 18
 *
 *     DC 36 00 00 3A -- 81 70 37 16 21 7A 01 9A A5 BB C8 9E 93 88 79 56 C1 41 B4 37 5F 1F 3A 69 1E 4A CA DB 56 77 98 3A 02 9E 2C 8A FE 24 51 DD 5E F9 23 79 AF 4D 63 27 34 A0 28 44 11 45 BA 72 F2 92 90 18
 *     DC 36 00 00 3A -- 80 70 37 79 E6 26 6E 93 D8 8E F1 DC A1 70 7A 36 77 6D 68 AE 36 1B 85 E4 85 EE 35 E8 33 5A 4D 84 AC AA 87 5B 7B EF F3 DF 76 20 7B 0A 91 B3 B1 3D 97 FE 21 8C 52 E2 8F 01 5D 50 90 18
 *
 *   Read DCWs (after sending ECM)
 *     DC 12 00 00 18 -- 19 04 00 00 00 00 1A 10 F9 EE 8F 76 A9 85 DC 0A E3 92 51 C6 40 B4 B0 A4 90 00
 *     DC 12 00 00 18 -- 19 04 00 00 00 00 1A 10 F9 EE 8F 76 A9 85 DC 0A 51 AB 96 92 7C A0 7F 9B 90 00
 *     DC 12 00 00 18 -- 19 04 00 00 00 00 1A 10 F6 51 8F D6 E6 F0 5E 34 AA 41 86 71 CC C0 29 B5 90 00
 *     DC 12 00 00 18 -- 19 04 00 00 00 00 1A 10 F6 51 8F D6 E6 F0 5E 34 51 AB 96 92 7C A0 7F 9B 90 00
 *
 *   Send EMMs
 *     DC 32 00 00 B2 -- 83 70 AF -- -- -- -- 3F 38 ED 59 0B 52 7D 8B D9 43 B5 51 6F C5 1D F2 36 35 C4 90 92 83 92 3E A2 99 47 76 3A CF 81 79 5C A1 4E B3 5D 09 D0 7E 86 3F DD C8 56 30 72 B4 E0 DE 0F 76 03 6F 16 F4 1F 4E 35 DC 6F 36 E8 DB E8 F3 75 BB CF 7B FE 46 91 8F F9 1C 7D 18 27 98 27 31 5A A4 39 44 E5 62 B0 DA 81 73 65 58 08 0B 44 20 57 37 DA 20 19 6B 35 F4 07 74 BA 42 75 AD 4A C5 86 C1 E3 03 C1 A2 05 C2 A3 C2 4C 57 B8 7E 3E DE 74 FB 5D 32 4A 7F 68 2B 74 E8 84 B6 33 52 6A B8 3D FD 3F 14 C4 39 39 39 28 80 B1 AC 77 39 A0 EF 8A 3C F5 4F F6 99 67 90 A4 90 0A
 *     DC 12 00 00 0A -- 1F 04 51 06 B5 B5 16 02 01 00 90 00
 *
 *     DC 32 00 00 AF -- 82 70 AC -- -- -- -- C6 94 A0 54 68 47 D0 3F FB 05 C6 A3 C5 FA 5F F0 A7 56 96 19 A5 F6 31 95 CD F1 8D 71 C3 FE 96 FD 75 2A DE 1F 12 08 8C 53 5D B6 4E FC 34 5D F0 BB 52 84 6C 71 C3 EA CE 4C 8A 08 45 22 E3 74 4A 37 48 39 75 37 0C 4A A9 8B 62 D8 F5 EE EC 28 E2 92 66 2D DA FF 8C 2B BD 97 C5 95 6B A0 6F 8B 82 79 09 79 E6 63 66 77 0A AB 8F EC 65 4F EC 05 75 2B FD DF 78 85 48 6C 2C A0 4D 4C 96 B6 08 21 A1 01 8D 74 CC F3 92 04 D2 15 49 F7 CE 74 6B 38 D9 22 66 2D 7E D6 78 BB 3D 0B 30 A7 64 A1 DC AE 0E 54 90 D0 83 BC 89 9F CA 50 90 00
 *
 *   Get subscription info (for base 20 cards - CAID 5504)
 *     DC 40 00 00 00 -- 90 3C
 *     DC 12 00 00 3C -- 1B 02 07 FF 1B 02 07 FF 1B 02 07 FF 1B 02 07 FF 1B 02 00 0F 1B 02 00 00 \
 *                       1B 02 00 00 1B 02 00 00 1B 02 00 00 1B 02 00 00 1B 02 00 00 1B 02 00 00 \
 *                       1B 02 00 00 1B 02 00 00 1B 02 00 00 90 00
 *
 *   Get subscription info (for base 10 cards - CAID 5501)
 *     DC 30 00 00 00 -- 90 2D
 *     DC 02 00 00 2D -- 0B 07 30 30 30 30 36 30 00 0B 07 30 30 30 30 36 30 00 \
 *                       0B 07 30 30 30 30 36 30 00 0B 07 30 30 30 30 36 30 00 \
 *                       0B 07 30 30 30 30 31 32 00 90 00
 *
 *   Unknown commands
 *     DC 4A 00 00 00 -- 90 06
 *     DC 12 00 00 06 -- 1D 04 00 00 00 00 90 00
 *
 *     DC 50 00 00 00 -- 90 0E
 *     DC 12 00 00 0E -- 1E 0C 00 0F 42 40 00 3D 09 00 00 1F 01 74 90 00
 *
 */

#include "globals.h"

#ifdef READER_GRIFFIN
#include "reader-common.h"

#define DEBUG 0

#define GRIFFIN_CMD_INIT              0x00
#define GRIFFIN_CMD_GET_HEX_SERIAL    0x02
#define GRIFFIN_CMD_GET_ASCII_SERIAL  0x04
#define GRIFFIN_CMD_GET_CAID          0x06
#define GRIFFIN_CMD_GET_CARD_ADDRESS  0x08
#define GRIFFIN_CMD_SEND_EMM          0x12
#define GRIFFIN_CMD_SEND_ECM          0x16
#define GRIFFIN_CMD_SUBSCRIPTION_INFO 0x20

#define cmd_buf_len  512

struct griffin_data {
	uint8_t			cmd_base; // Command base, depends on the card
};

// Sets cmd_buf and returns buf_len
static uint32_t griffin_init_cmd(struct s_reader *rdr, uint8_t *cmd_buf, uint8_t cmd_op, const uint8_t *data, uint8_t data_len)
{
	#define cmd_len 5
	memset(cmd_buf, 0, cmd_buf_len);
	cmd_buf[0] = 0xDC; // Command start
	cmd_buf[1] = cmd_op;
	cmd_buf[2] = 0x00;
	cmd_buf[3] = 0x00;
	cmd_buf[4] = data_len; // Set payload length
	if (data && data_len)
		memcpy(cmd_buf + cmd_len, data, data_len);
	uint32_t len = cmd_len + (data ? data_len : 0);
	if (DEBUG) {
		char tmp[1024];
		rdr_log(rdr, "SEND[-] -> %s", cs_hexdump(1, cmd_buf, len, tmp, sizeof(tmp)));
	}
	return len;
}

static int32_t griffin_exec_cmd(struct s_reader *rdr, uint8_t cmd_op, const uint8_t *data, uint8_t data_len, uint8_t *response, uint16_t *response_length)
{
	struct griffin_data *csystem_data = rdr->csystem_data;
	uint8_t buf[cmd_buf_len];

	int32_t ret = reader_cmd2icc(rdr, buf,
		griffin_init_cmd(rdr, buf, csystem_data->cmd_base + cmd_op, data, data_len),
		response, response_length);
	if (DEBUG) {
		char tmp[1024];
		rdr_log(rdr, "RECV[1] <- %s (ret=%d resp_len=%d)", cs_hexdump(1, response, *response_length, tmp, sizeof(tmp)), ret, *response_length);
	}
	if (ret || *response_length < 2) return ERROR; // Response is two short
	if (response[0] != 0x90)         return ERROR; // Invalid response
	if (response[1] == 0)            return OK;    // Nothing to retrieve, command OK

	// Retrieve response
	uint8_t cmd_read_response = 0x02;
	if (csystem_data->cmd_base > 0x10)
		cmd_read_response += csystem_data->cmd_base - 0x10;

	ret = reader_cmd2icc(rdr, buf,
		griffin_init_cmd(rdr, buf, cmd_read_response, NULL, response[1]),
		response, response_length);

	if (DEBUG) {
		char tmp[1024];
		rdr_log(rdr, "RECV[2] <- %s (ret=%d resp_len=%d)", cs_hexdump(1, response, *response_length, tmp, sizeof(tmp)), ret, *response_length);
	}
	if (ret || *response_length < 2)            return ERROR; // Response is two short
	if (response[*response_length - 2] != 0x90) return ERROR; // Invalid response
	if (response[*response_length - 1] != 0x00) return ERROR; // We don't expect command_op 0x12 to return more data
	return OK;
}

#define griffin_cmd(_cmd_op, _data, _data_len, _min_resp_len) \
	do { \
		if (!griffin_exec_cmd(rdr, _cmd_op, _data, _data_len, cta_res, &cta_lr) || cta_lr < _min_resp_len) \
			return ERROR; \
	} while(0)

static int32_t griffin_card_init(struct s_reader *rdr, ATR *newatr)
{
	int32_t i;
	get_atr
	def_resp

	if (atr_size < 10)
		return ERROR;

	//       0  1  2  3  4  5  6  7  8  9
	// ATR: 3B 08 yy 01 xx xx xx xx 10 00
	if (atr[0] != 0x3b || atr[1] != 0x08 || atr[3] != 0x01 || atr[9] != 0x00)
		return ERROR;

	if (!cs_malloc(&rdr->csystem_data, sizeof(struct griffin_data)))
		return ERROR;
	struct griffin_data *csystem_data = rdr->csystem_data;

	rdr->nprov = 1;
	memset(rdr->sa, 0, sizeof(rdr->sa));
	memset(rdr->prid, 0, sizeof(rdr->prid));
	memset(rdr->hexserial, 0, sizeof(rdr->hexserial));

	rdr->caid = (0x55 << 8) | atr[2];
	memcpy(rdr->hexserial, atr + 4, 4);
	csystem_data->cmd_base = atr[8];

	rdr_log_sensitive(rdr, "[griffin-reader] card detected, cmd_base: %02X caid: %04X hexserial: {%02X %02X %02X %02X}",
		csystem_data->cmd_base,
		rdr->caid,
		rdr->hexserial[0], rdr->hexserial[1], rdr->hexserial[2], rdr->hexserial[3]
	);

	griffin_cmd(GRIFFIN_CMD_INIT, NULL, 0, 2);
	csystem_data->cmd_base = cta_res[2]; // already set from ATR

	griffin_cmd(GRIFFIN_CMD_GET_HEX_SERIAL, NULL, 0, 6);
	memcpy(rdr->hexserial, cta_res + 2, 4);

	char serial[16];
	memset(serial, 0, sizeof(serial));
	griffin_cmd(GRIFFIN_CMD_GET_ASCII_SERIAL, NULL, 0, 14);
	memcpy(serial, cta_res + 2, 12);

	griffin_cmd(GRIFFIN_CMD_GET_CAID, NULL, 0, 4);
	rdr->caid = (cta_res[2] << 8) | cta_res[3];

	griffin_cmd(GRIFFIN_CMD_GET_CARD_ADDRESS, NULL, 0, 48);
	for (i = 1 ; i < CS_MAXPROV; i++) {
		if (3 + (i * 16) + 4 > cta_lr)
			break;
		memcpy(rdr->sa[i - 1], cta_res + 3 + (i * 16), 4);
	}

	// Unknown commands
	griffin_cmd(0x22, NULL, 0, 2);
	griffin_cmd(0x10, NULL, 0, 2);
	griffin_cmd(0x14, NULL, 0, 2);
	//griffin_cmd(0x2a, NULL, 0, 2);
	//griffin_cmd(0x30, NULL, 0, 2);

	for (i = 0 ; i < CS_MAXPROV; i++) {
		if (check_filled(rdr->sa[i], 4)) {
			rdr_log_sensitive(rdr, "CAID: 0x%04X, Serial: {%s}, HexSerial: {%02X %02X %02X %02X} Addr: {%02X %02X %02X %02X}",
				rdr->caid, serial,
				rdr->hexserial[0], rdr->hexserial[1], rdr->hexserial[2], rdr->hexserial[3],
				rdr->sa[i][0], rdr->sa[i][1], rdr->sa[i][2], rdr->sa[i][3]);
		}
	}

	rdr_log(rdr, "Ready for requests.");
	return OK;
}

static int32_t griffin_do_ecm(struct s_reader *rdr, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	def_resp
	griffin_cmd(GRIFFIN_CMD_SEND_ECM, er->ecm, er->ecm[2] + 3, 24);
	memcpy(ea->cw, cta_res + 8, 16);
	return OK;
}

static int32_t griffin_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr) {
	memcpy(ep->hexserial, ep->emm + 3, 4);
	switch (ep->emm[0]) {
	case 0x82:
	case 0x83:
		if (memcmp(ep->hexserial, rdr->sa[0], 4) == 0) {
			if (DEBUG)
				rdr_log_sensitive(rdr, "SHARED EMM TYPE:%02X SA:{%02X %02X %02X %02X}",
					ep->emm[0], ep->emm[3], ep->emm[4],ep->emm[5], ep->emm[6]);
			ep->type = SHARED;
		}
		if (memcmp(ep->hexserial, rdr->sa[1], 4) == 0) {
			if (DEBUG)
				rdr_log_sensitive(rdr, "UNIQUE EMM TYPE:%02X SA:{%02X %02X %02X %02X}",
					ep->emm[0], ep->emm[3], ep->emm[4],ep->emm[5], ep->emm[6]);
			ep->type = UNIQUE;
		}
		break;
	default:
		ep->type = UNKNOWN;
		rdr_debug_mask(rdr, D_EMM, "UNKNOWN EMM TYPE:%02X SA:%02X %02X %02X %02X",
			ep->emm[0],
			ep->emm[3], ep->emm[4], ep->emm[5], ep->emm[6]);
	}
	return OK;
}

static int32_t griffin_do_emm(struct s_reader *rdr, EMM_PACKET *ep)
{
	def_resp
	griffin_cmd(GRIFFIN_CMD_SEND_EMM, ep->emm, ep->emm[2] + 3, 2);
	return OK;
}

static int32_t griffin_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter** emm_filters, unsigned int* filter_count)
{
  if (*emm_filters == NULL) {
    const unsigned int max_filter_count = 4;
    if (!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
      return ERROR;

    struct s_csystem_emm_filter* filters = *emm_filters;
    *filter_count = 0;

    int32_t idx = 0;

    filters[idx].type = EMM_SHARED;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x82;
    filters[idx].filter[1] = rdr->sa[0][0];
    filters[idx].filter[2] = rdr->sa[0][1];
    filters[idx].filter[3] = rdr->sa[0][2];
    filters[idx].filter[4] = rdr->sa[0][3];
    filters[idx].mask[0]   = 0xFF;
    filters[idx].mask[1]   = 0xFF;
    filters[idx].mask[2]   = 0xFF;
    filters[idx].mask[3]   = 0xFF;
    filters[idx].mask[4]   = 0xFF;
    idx++;

    filters[idx].type = EMM_SHARED;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x82;
    filters[idx].filter[1] = rdr->sa[1][0];
    filters[idx].filter[2] = rdr->sa[1][1];
    filters[idx].filter[3] = rdr->sa[1][2];
    filters[idx].filter[4] = rdr->sa[1][3];
    filters[idx].mask[0]   = 0xFF;
    filters[idx].mask[1]   = 0xFF;
    filters[idx].mask[2]   = 0xFF;
    filters[idx].mask[3]   = 0xFF;
    filters[idx].mask[4]   = 0xFF;
    idx++;

    filters[idx].type = EMM_UNIQUE;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x83;
    filters[idx].filter[1] = rdr->sa[0][0];
    filters[idx].filter[2] = rdr->sa[0][1];
    filters[idx].filter[3] = rdr->sa[0][2];
    filters[idx].filter[4] = rdr->sa[0][3];
    filters[idx].mask[0]   = 0xF0;
    filters[idx].mask[1]   = 0xFF;
    filters[idx].mask[2]   = 0xFF;
    filters[idx].mask[3]   = 0xFF;
    filters[idx].mask[4]   = 0xFF;
    idx++;

    filters[idx].type = EMM_UNIQUE;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x83;
    filters[idx].filter[1] = rdr->sa[1][0];
    filters[idx].filter[2] = rdr->sa[1][1];
    filters[idx].filter[3] = rdr->sa[1][2];
    filters[idx].filter[4] = rdr->sa[1][3];
    filters[idx].mask[0]   = 0xF0;
    filters[idx].mask[1]   = 0xFF;
    filters[idx].mask[2]   = 0xFF;
    filters[idx].mask[3]   = 0xFF;
    filters[idx].mask[4]   = 0xFF;
    idx++;

    *filter_count = idx;
  }

  return OK;
}

static int32_t griffin_card_info(struct s_reader *rdr)
{
	def_resp
	int i, r = 0;
	rdr_log(rdr, "Reading subscription info.");

	griffin_cmd(GRIFFIN_CMD_SUBSCRIPTION_INFO, NULL, 0, 16);
	if (cta_res[0] == 0x0b) { // Old cards
		for (i = 0; i < cta_lr - 8; i += 9) {
			rdr_log(rdr, " Subscription stream #%d - %c%c%c%c%c%c",
				r++, cta_res[i + 2], cta_res[i + 3], cta_res[i + 4],
				     cta_res[i + 5], cta_res[i + 6], cta_res[i + 7]);
		}
	} else if (cta_res[0] == 0x1b) { // Newer cards
		for (i = 0; i < cta_lr; i += 4) {
			rdr_log(rdr, " Subscription stream #%02d - 0x%04x",
				r++, b2i(2, cta_res + i + 2));
		}
	}

	rdr_log(rdr, "End subscription info.");
	return OK;
}

void reader_griffin(struct s_cardsystem *ph)
{
	ph->do_emm         = griffin_do_emm;
	ph->do_ecm         = griffin_do_ecm;
	ph->card_info      = griffin_card_info;
	ph->card_init      = griffin_card_init;
	ph->get_emm_type   = griffin_get_emm_type;
	ph->get_emm_filter = griffin_get_emm_filter;
	ph->desc           = "griffin";
	ph->caids[0]       = 0x5501;
	ph->caids[1]       = 0x5502;
	ph->caids[2]       = 0x5504;
	ph->caids[3]       = 0x5506;
	ph->caids[4]       = 0x5508;
	ph->caids[5]       = 0x5509;
	ph->caids[6]       = 0x550E;
	ph->caids[7]       = 0x5511;
}
#endif
