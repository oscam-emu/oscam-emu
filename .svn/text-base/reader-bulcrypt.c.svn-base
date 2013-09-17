/*
 * Bulcrypt card reader for OSCAM
 * Copyright (C) 2012 Unix Solutions Ltd.
 *
 * Authors: Anton Tinchev (atl@unixsol.org)
 *          Georgi Chorbadzhiyski (gf@unixsol.org)
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
 *
 * For more information read the code and the comments. We have tried to
 * write clear code with lots of comments so it is easy for others to
 * understand what is going on. There are some things marked *FIXME*,
 * that are mostly unknown or not fully understand.
 *
 * WHAT WAS TESTED AND WAS WORKING:
 *   - Cards with bulcrypt v1 ("cherga"/carpet) are working (we have cards
 *     that report CardType: 0x4c and 0x75.
 *   - Cards return valid code words for subscribed channels.
 *      - Tested with channels encrypted with CAID 0x5581 and 0x4aee on
 *         Hellas 39E. Both MPEG2 (SD) and H.264 (SD and HD) channels were
 *         decrypted.
 *   - Brand new cards were inited without ever being put into providers STBs.
 *     as long the protocol you are using is sending EMMs to the card.
 *   - AU was working (subscription dates and packages were updated)
 *     as long the protocol you are using is sending EMMs to the card.
 *
 * WHAT WE DON'T KNOW (YET!):
 *   - How to deobfuscate v2 codewords.
 *
 * PERSONAL MESSAGES:
 *   - Many thanks to ilian_71 @ satfriends forum for the protocol info.
 *   - Shouts to yuriks for oscam-ymod, pity it is violating the GPL.
 *
 */

#include "globals.h"

#ifdef READER_BULCRYPT
#include "oscam-work.h"
#include "reader-common.h"

static const uchar atr_carpet[]    = { 0x3b, 0x20, 0x00 };

// *FIXME* We do not know how every 4th byte of the sess_key is calculated.
// Currently they are correct thou and code words checksums are correct are
// the deobfuscation.
static const uchar sess_key[]      = { 0xF2, 0x21, 0xC5, 0x69,
                                       0x28, 0x86, 0xFB, 0x9E,
                                       0xC0, 0x20, 0x28, 0x06,
                                       0xD2, 0x23, 0x72, 0x31 };

static const uchar cmd_set_key[]   = { 0xDE, 0x1C, 0x00, 0x00, 0x0A,
                                       0x12, 0x08,
                                       0x56, 0x47, 0x38, 0x29,
                                       0x10, 0xAF, 0xBE, 0xCD };

static const uchar cmd_set_key_v2[]= { 0xDE, 0x1C, 0x00, 0x00, 0x0A,
                                       0x12, 0x08,
                                       0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00 };
// Response: 90 00

// V2
static const uchar cmd_card_v2_key1[] = { 0xDE, 0x12, 0x00, 0x00, 0x00, 0x00 };
static const uchar cmd_card_v2_key2[] = { 0xDE, 0x1E, 0x00, 0x00, 0x12, 0x00 };

static const uchar cmd_cardtype1[] = { 0xDE, 0x16, 0x00, 0x00, 0x00, 0x00 };
static const uchar cmd_cardtype2[] = { 0xDE, 0x1E, 0x00, 0x00, 0x03, 0x00 };
// Response1: 90 03
// Response2: 01 01 4C 90 00 or 01 01 xx 90 00
//   xx - 4C or 75 (Card type)

static const uchar cmd_unkn_0a1[]  = { 0xDE, 0x0A, 0x00, 0x00, 0x00, 0x00 };
static const uchar cmd_unkn_0a2[]  = { 0xDE, 0x1E, 0x00, 0x00, 0x03, 0x00 };
// Response1: 90 03
// Response2: 08 01 00 90 00

static const uchar cmd_cardsn1[]   = { 0xDE, 0x18, 0x00, 0x00, 0x00, 0x00 };
static const uchar cmd_cardsn2[]   = { 0xDE, 0x1E, 0x00, 0x00, 0x06, 0x00 };
// Response1: 90 06
// Response2: 02 04 xx xx xx xy 90 00
//   xx - Card HEX serial
//    y - Unknown *FIXME*

static const uchar cmd_ascsn1[]    = { 0xDE, 0x1A, 0x00, 0x00, 0x00, 0x00 };
static const uchar cmd_ascsn2[]    = { 0xDE, 0x1E, 0x00, 0x00, 0x0F, 0x00 };
// Response1: 90 0F
// Response2: 05 0D xx xx 20 xx xx xx xx xx xx 20 xx xx xx 90 00
//   xx - Card ASCII serial

static const uchar cmd_ecm_empty[] = { 0xDE, 0x20, 0x00, 0x00, 0x00, 0x00 };
// Response: 90 00

static const uchar cmd_ecm[]       = { 0xDE, 0x20, 0x00, 0x00, 0x4c };
// The last byte is ECM length

static const uchar cmd_ecm_get_cw[]= { 0xDE, 0x1E, 0x00, 0x00, 0x13, 0x00 };
// Response: 0A 11 80 xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx 90 00
//   80 - Returned codeword type? *FIXME*
//   xx - Obfuscated CW

static const uchar cmd_emm1[]      = { 0xDE, 0x02, 0x82, 0x00, 0xb0 };
// Response: 90 00 (EMM written OK) or
// Response: 90 0A (Subscription data was updated)
// The last byte is EMM length (0xb0)

static const uchar cmd_emm2[]      = { 0xDE, 0x04, 0x00, 0x00, 0xb0 };
// Response: 90 00 (EMM written OK)
//   cmd_emm[2] = emm_cmd1
//   cmd_emm[3] = emm_cmd2
// The last byte is EMM length (0xb0)

static const uchar cmd_sub_info1[] = { 0xDE, 0x06, 0x00, 0x00, 0x00, 0x00 };
static const uchar cmd_sub_info2[] = { 0xDE, 0x1E, 0x00, 0x00, 0x2B, 0x00 };
// See bulcrypt_card_info() for reponse description

struct bulcrypt_data {
	uint8_t			bulcrypt_version;
};

static int32_t bulcrypt_card_init(struct s_reader *reader, ATR *newatr)
{
	int i;
	char tmp[1024];
	char card_serial[16];
	const uchar *set_key_command;
	uchar card_type;

	get_atr
	def_resp

	if (memcmp(atr, atr_carpet, MIN(sizeof(atr_carpet), atr_size)) != 0)
	{
		if (atr_size == 3) {
			rdr_log(reader, "ATR_len=3 but ATR is unknown: %s",
				cs_hexdump(1, atr, atr_size, tmp, sizeof(tmp)));
		}
		return ERROR;
	}

	if (!cs_malloc(&reader->csystem_data, sizeof(struct bulcrypt_data)))
		return ERROR;
	struct bulcrypt_data *csystem_data = reader->csystem_data;

	reader->nprov = 1;
	memset(reader->prid, 0, sizeof(reader->prid));
	memset(reader->hexserial, 0, sizeof(reader->hexserial));
	memset(card_serial, 0, sizeof(card_serial));

	rdr_log(reader, "Bulcrypt card detected, checking card version.");

	// Do we have Bulcrypt V2 card?
	write_cmd(cmd_card_v2_key1, NULL);
	write_cmd(cmd_card_v2_key2, NULL);
	if (cta_lr < 18 || (cta_res[0] != 0x11 && cta_res[1] != 0x10))
	{
		// The card is v1
		csystem_data->bulcrypt_version = 1;
		set_key_command = cmd_set_key;
	} else {
		// The card is v2
		csystem_data->bulcrypt_version = 2;
		set_key_command = cmd_set_key_v2;
	}

	// Set CW obfuscation key
	write_cmd(set_key_command, set_key_command + 5);
	if (cta_lr < 2 || (cta_res[0] != 0x90 && cta_res[1] != 0x00))
	{
		rdr_log(reader, "(cmd_set_key) Unexpected card answer: %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		return ERROR;
	}

	rdr_log(reader, "Bulcrypt v%d card detected.%s", csystem_data->bulcrypt_version,
		csystem_data->bulcrypt_version != 1 ? " *UNSUPPORTED CARD VERSION*" : "");

	// Read card type
	write_cmd(cmd_cardtype1, NULL);
	write_cmd(cmd_cardtype2, NULL);
	if (cta_lr < 5 || (cta_res[0] != 0x01 && cta_res[1] != 0x01))
	{
		rdr_log(reader, "(cmd_cardtype) Unexpected card answer: %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		return ERROR;
	}
	card_type = cta_res[2]; // We have seen 0x4c and 0x75

	// *FIXME* Unknown command
	write_cmd(cmd_unkn_0a1, NULL);
	write_cmd(cmd_unkn_0a2, NULL);

	// Read card HEX serial
	write_cmd(cmd_cardsn1, NULL);
	write_cmd(cmd_cardsn2, NULL);
	if (cta_lr < 6 || (cta_res[0] != 0x02 && cta_res[1] != 0x04))
	{
		rdr_log(reader, "(card_sn) Unexpected card answer: %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		return ERROR;
	}
	memcpy(reader->hexserial, cta_res + 2, 4);
	// Skip bottom four bits (they are 0x0b on our cards)
	reader->hexserial[3] = reader->hexserial[3] & 0xF0;

	// Read card ASCII serial
	write_cmd(cmd_ascsn1, NULL);
	write_cmd(cmd_ascsn2, NULL);
	if (cta_lr < 15 || (cta_res[0] != 0x05 && cta_res[1] != 0x0d))
	{
		rdr_log(reader, "(asc_sn) Unexpected card answer: %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		return ERROR;
	}
	memcpy(card_serial, cta_res + 2, 13);
	cta_lr = strlen(card_serial);
	for (i = 0; i < cta_lr; i++)
	{
		if (card_serial[i] == ' ')
			continue;
		// Sanity check
		if (!isdigit(card_serial[i]))
			card_serial[i] = '*';
	}

	// Write empty ECM, *FIXME* why are we doing this? To prepare the card somehow?
	write_cmd(cmd_ecm_empty, NULL);

	// The HEX serial have nothing to do with Serial (they do not match)
	rdr_log_sensitive(reader, "CAID: 0x4AEE|0x5581, CardType: 0x%02x, Serial: {%s}, HexSerial: {%02X %02X %02X %02X}",
		card_type,
		card_serial,
		reader->hexserial[0], reader->hexserial[1], reader->hexserial[2], reader->hexserial[3]);

	rdr_log(reader, "Ready for requests.");

	return OK;
}

static int cw_is_valid(struct s_reader * reader, unsigned char *cw)
{
	unsigned int i = 0, cnt = 0;
	do {
		if (cw[i++] == 0)
			cnt++;
	} while(i < 8);

	if (cnt == 8)
	{
		rdr_log(reader, "Invalid CW (all zeroes)");
		return ERROR;
	}

	uchar cksum1 = cw[0] + cw[1] + cw[2];
	uchar cksum2 = cw[4] + cw[5] + cw[6];
	if (cksum1 != cw[3] || cksum2 != cw[7])
	{
		if (cksum1 != cw[3])
			rdr_log(reader, "Invalid CW (cksum1 mismatch expected 0x%02x got 0x%02x)", cksum1, cw[3]);
		if (cksum2 != cw[7])
			rdr_log(reader, "Invalid CW (cksum2 mismatch expected 0x%02x got 0x%02x)", cksum2, cw[7]);
		return ERROR;
	}

	return OK;
}

/*
Bulcrypt ECM structure:

  80 70       - ECM header (80 | 81)
  4c          - ECM length after this field (0x4c == 76 bytes)
  4f 8d 87 0b - unixts == 1334675211 == Tue Apr 17 18:06:51 EEST 2012
  00 66       - *FIXME* Program number?
  00 7d       - *FIXME*
  ce 70       - ECM counter
  0b 88       - ECM type
  xx yy zz .. - Encrypted ECM payload (64 bytes)

*/
static int32_t bulcrypt_do_ecm(struct s_reader * reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	char tmp[512];
	uchar ecm_cmd[256];
	struct bulcrypt_data *csystem_data = reader->csystem_data;

	def_resp

	int32_t ecm_len = check_sct_len(er->ecm, 3);
	if (ecm_len < 64 || ecm_len > 188)
	{
		rdr_log(reader, "Wrong ECM length: %d", ecm_len);
		return ERROR;
	}

	// CMD: DE 20 00 00 4C
	memcpy(ecm_cmd, cmd_ecm, sizeof(cmd_ecm));
	ecm_cmd[4] = er->ecm[2]; // Set ECM length
	memcpy(ecm_cmd + sizeof(cmd_ecm), er->ecm + 3, ecm_cmd[4]);

	// Send ECM
	write_cmd(ecm_cmd, ecm_cmd + 5);
	if (cta_lr != 2)
	{
		rdr_log(reader, "(ecm_cmd) Unexpected card answer: %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		return ERROR;
	}

	if (cta_res[0] == 0x90 && cta_res[1] == 0x03)
	{
		rdr_log(reader, "No active subscription.");
		return ERROR;
	}

	if ( !(cta_res[0] == 0x90 && cta_res[1] == 0x13) )
	{
		rdr_log(reader, "(ecm_cmd) Unexpected card answer: %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		return ERROR;
	}

	// Call get_cw
	write_cmd(cmd_ecm_get_cw, NULL);

	// rdr_log(reader, "CW_LOG: %s", cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
	if (cta_lr < 20 || (cta_res[0] != 0x0a && cta_res[1] != 0x11))
	{
		rdr_log(reader, "(get_cw) Unexpected card answer: %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		return ERROR;
	}

	// *FIXME* is the bellow info true?
	//   0x80 (ver 1) is supported
	//   0xc0 (ver 2) is *NOT* supported currently
	if (cta_res[2] == 0xc0)
	{
		rdr_log(reader, "Possibly unsupported codeword (bulcrypt v2): %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		// *FIXME* commented for testing, this really should be an error
		//return ERROR;
	}

	// Remove code word obfuscation
	uchar *cw = cta_res + 3;
	if (csystem_data->bulcrypt_version == 1) {
		int i;
		for (i = 0 ; i < 16; i++) {
			cw[i] = cw[i] ^ sess_key[i];
		}
	}

	if (er->ecm[0] == 0x81)
	{
		// Even/Odd CWs should be exchanged
		memcpy(ea->cw, cw + 8, 8);
		memcpy(ea->cw + 8, cw, 8);
	} else {
		memcpy(ea->cw, cw, 8);
		memcpy(ea->cw + 8, cw + 8, 8);
	}

	// Check if DCW is valid
	if (!cw_is_valid(reader, ea->cw) || !cw_is_valid(reader, ea->cw + 8))
		return ERROR;

	return OK;
}

/*
Bulcrypt EMMs structure

All EMMs are with section length 183 (0xb7)
     3 bytes section header
     7 bytes EMM header
   173 bytes payload

  82 70       - UNUQUE_EMM_82|8a
  b4          - Payload length (0xb4 == 180)
  xx xx xx xy - Card HEX SN (the last 4 bits (y) must be masked)
  payload

  85 70       - GLOBAL_EMM_85|8b
  b4          - Payload length (0xb4 == 180)
  xx xx yy yy - Card HEX SN (the last 16 bits (y) must be masked)
  payload

  84 70       - SHARED_EMM_84
  b4          - Payload length  (0xb4 == 180)
  xx xx       - Card HEX SN Prefix
  yy          -
  zz          -
  payload

 Padding EMM:
  8f 70 b4 ff ff ff ff ff ff ff ff ff .. .. (ff to the end)

Stats for EMMs collected for a period of 1 hours and 24 minutes

  2279742 - 82 70 b4 - unique_82
    19051 - 8a 70 b4 - unique_8a (polaris equivallent of 0x82)
   199949 - 84 70 b4 - shared_84
   595309 - 85 70 b4 - global_85
     6417 - 8b 70 b4 - global_8b (polaris equivallent of 0x85)
    74850 - 8f 70 b4 - filler

Total EMMs for the period: 3175317
*/

#define BULCRYPT_EMM_UNIQUE_82  0x82 // Addressed at single card (updates subscription info)
#define BULCRYPT_EMM_UNIQUE_8a  0x8a // Addressed at single card (like 0x82) used for Polaris
#define BULCRYPT_EMM_SHARED_84  0x84 // Addressed to 4096 cards (updates keys)
#define BULCRYPT_EMM_GLOBAL_85  0x85 // Addressed at 4096 cards (updates packages)
#define BULCRYPT_EMM_GLOBAL_8b  0x8b // Addressed at 4096 cards (like 0x85) used for Polaris
#define BULCRYPT_EMM_FILLER     0x8f // Filler to pad the EMM stream

static int32_t bulcrypt_get_emm_type(EMM_PACKET *ep, struct s_reader *reader)
{
	char dump_emm_sn[64];
	int32_t emm_len = check_sct_len(ep->emm, 3);

	memset(ep->hexserial, 0, 8);

	if (emm_len < 176)
	{
		rdr_debug_mask(reader, D_TRACE | D_EMM, "emm_len < 176 (%u): %s",
			emm_len, cs_hexdump(1, ep->emm, 12, dump_emm_sn, sizeof(dump_emm_sn)));
		ep->type = UNKNOWN;
		return 0;
	}

	ep->type = UNKNOWN;
	switch (ep->emm[0]) {
	case BULCRYPT_EMM_UNIQUE_82: ep->type = UNIQUE; break; // Bulsatcom
	case BULCRYPT_EMM_UNIQUE_8a: ep->type = UNIQUE; break; // Polaris
	case BULCRYPT_EMM_SHARED_84: ep->type = SHARED; break;
	case BULCRYPT_EMM_GLOBAL_85: ep->type = GLOBAL; break; // Bulsatcom
	case BULCRYPT_EMM_GLOBAL_8b: ep->type = GLOBAL; break; // Polaris
	}

	bool ret = false;
	if (ep->type == UNIQUE) {
		// The serial numbers looks like this:
		//   aa bb cc dd
		memcpy(ep->hexserial, ep->emm + 3, 4);
		ret = reader->hexserial[0] == ep->hexserial[0] &&
			  reader->hexserial[1] == ep->hexserial[1] &&
			  reader->hexserial[2] == ep->hexserial[2] &&
			  ((reader->hexserial[3] & 0xF0) == (ep->hexserial[3] & 0xF0));
	} else {
		// To match EMM_84, EMM_85, EMM_8b
		//   aa bb -- --
		memcpy(ep->hexserial, ep->emm + 3, 2);
		ret = reader->hexserial[0] == ep->hexserial[0] &&
			  reader->hexserial[1] == ep->hexserial[1];
	}

	if (ret) {
		char dump_card_sn[64];
		cs_hexdump(1, reader->hexserial, 4, dump_card_sn, sizeof(dump_card_sn));
		cs_hexdump(1, ep->hexserial, 4, dump_emm_sn, sizeof(dump_emm_sn));
		rdr_log_sensitive(reader, "EMM_%s-%02x, emm_sn = {%s}, card_sn = {%s}",
			ep->type == UNIQUE ? "UNIQUE" :
			ep->type == SHARED ? "SHARED" :
			ep->type == GLOBAL ? "GLOBAL" : "??????",
			ep->emm[0],
			dump_emm_sn,
			dump_card_sn);
	}

	return ret;
}

static int32_t bulcrypt_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter** emm_filters, unsigned int* filter_count)
{
  if (*emm_filters == NULL) {
    const unsigned int max_filter_count = 5;
    if (!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
      return ERROR;

    struct s_csystem_emm_filter* filters = *emm_filters;
    *filter_count = 0;

    int32_t idx = 0;

    filters[idx].type = EMM_UNIQUE;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x82;
    filters[idx].filter[1] = rdr->hexserial[0];
    filters[idx].filter[2] = rdr->hexserial[1];
    filters[idx].filter[3] = rdr->hexserial[2];
    filters[idx].filter[4] = rdr->hexserial[3];
    filters[idx].mask[0]   = 0xFF;
    filters[idx].mask[1]   = 0xFF;
    filters[idx].mask[2]   = 0xFF;
    filters[idx].mask[3]   = 0xFF;
    filters[idx].mask[4]   = 0xF0;
    idx++;

    filters[idx].type = EMM_UNIQUE;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x8a;
    filters[idx].filter[1] = rdr->hexserial[0];
    filters[idx].filter[2] = rdr->hexserial[1];
    filters[idx].filter[3] = rdr->hexserial[2];
    filters[idx].filter[4] = rdr->hexserial[3];
    filters[idx].mask[0]   = 0xFF;
    filters[idx].mask[1]   = 0xFF;
    filters[idx].mask[2]   = 0xFF;
    filters[idx].mask[3]   = 0xFF;
    filters[idx].mask[4]   = 0xF0;
    idx++;

    filters[idx].type = EMM_SHARED;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x84;
    filters[idx].filter[1] = rdr->hexserial[0];
    filters[idx].filter[2] = rdr->hexserial[1];
    filters[idx].mask[0]   = 0xFF;
    filters[idx].mask[1]   = 0xFF;
    filters[idx].mask[2]   = 0xFF;
    idx++;

    filters[idx].type = EMM_GLOBAL;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x85;
    filters[idx].filter[1] = rdr->hexserial[0];
    filters[idx].filter[2] = rdr->hexserial[1];
    filters[idx].mask[0]   = 0xFF;
    filters[idx].mask[1]   = 0xFF;
    filters[idx].mask[2]   = 0xFF;
    idx++;

    filters[idx].type = EMM_GLOBAL;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x8b;
    filters[idx].filter[1] = rdr->hexserial[0];
    filters[idx].filter[2] = rdr->hexserial[1];
    filters[idx].mask[0]   = 0xFF;
    filters[idx].mask[1]   = 0xFF;
    filters[idx].mask[2]   = 0xFF;
    idx++;

    *filter_count = idx;
  }

  return OK;
}

static int32_t bulcrypt_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	char tmp[512];
	uchar emm_cmd[1024];

	def_resp

	// DE 04 xx yy B0
	//  xx == EMM type   (emm[0])
	//  yy == EMM type2  (emm[5])
	//  B0 == EMM len    (176)
	memcpy(emm_cmd, cmd_emm1, sizeof(cmd_emm1));
	memcpy(emm_cmd + sizeof(cmd_emm1), ep->emm + 7, 176);

	switch (ep->emm[0]) {
	case BULCRYPT_EMM_UNIQUE_82:
		emm_cmd[2] = ep->emm[0]; // 0x82
		break;
	case BULCRYPT_EMM_UNIQUE_8a: // Polaris equivallent of 0x82
		emm_cmd[2] = 0x82;
		emm_cmd[3] = 0x0b;
		break;
	case BULCRYPT_EMM_SHARED_84:
		emm_cmd[2] = ep->emm[0]; // 0x84
		emm_cmd[3] = ep->emm[5]; // 0x0b
		break;
	case BULCRYPT_EMM_GLOBAL_85:
	case BULCRYPT_EMM_GLOBAL_8b: // Polaris 0x85 equivallent of 0x85
		memcpy(emm_cmd, cmd_emm2, sizeof(cmd_emm2));
		emm_cmd[2] = ep->emm[5]; // 0xXX (Last bytes of the serial)
		emm_cmd[3] = ep->emm[6]; // 0x0b
		break;
	}

	// Write emm
	write_cmd(emm_cmd, emm_cmd + 5);
	if (cta_lr != 2 || cta_res[0] != 0x90 || (cta_res[1] != 0x00 && cta_res[1] != 0x0a))
	{
		rdr_log(reader, "(emm_cmd) Unexpected card answer: %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		return ERROR;
	}

	if (ep->emm[0] == BULCRYPT_EMM_UNIQUE_82 && cta_res[0] == 0x90 && cta_res[1] == 0x0a) {
		rdr_log(reader, "Your subscription data was updated.");
		add_job(reader->client, ACTION_READER_CARDINFO, NULL, 0);
	}

	return OK;
}

static char *dec2bin_str(unsigned int d, char *s)
{
	unsigned int i, r = 8;
	memset(s, 0, 9);
	for (i = 1; i < 256; i <<= 1)
		s[--r] = (d & i) == i ? '+' : '-';
	return s;
}

static int32_t bulcrypt_card_info(struct s_reader *reader)
{
	char tmp[512];
	time_t last_upd_ts, subs_end_ts;
	struct tm tm;
	def_resp

	rdr_log(reader, "Reading subscription info.");

	cs_clear_entitlement(reader);

	write_cmd(cmd_sub_info1, NULL);
	write_cmd(cmd_sub_info2, NULL);

	if (cta_lr < 45)
	{
		rdr_log(reader, "(info_cmd) Unexpected card answer: %s",
			cs_hexdump(1, cta_res, cta_lr, tmp, sizeof(tmp)));
		return ERROR;
	}

	// Response contains:
	//  13 29 0B
	//  4F 8F 00 E9 - Unix ts set by UNIQUE_EMM_82
	//  3C 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 BF
	//  3C 84 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 BF
	//  90 2B

	last_upd_ts = b2i(4, cta_res + 3);
	subs_end_ts = last_upd_ts + (31 * 86400); // *FIXME* this is just a guess

	reader->card_valid_to = subs_end_ts;

	gmtime_r(&last_upd_ts, &tm);
	memset(tmp, 0, sizeof(tmp));
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S %Z", &tm);
	rdr_log(reader, "Subscription data last update    : %s", tmp);

	gmtime_r(&subs_end_ts, &tm);
	memset(tmp, 0, sizeof(tmp));
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S %Z", &tm);
	rdr_log(reader, "Subscription should be active to : %s", tmp);

	unsigned int subs1 = b2i(2, cta_res + 3 + 4 + 16);
	unsigned int subs2 = b2i(2, cta_res + 3 + 4 + 16 + 18);

	if (subs1 == 0xffff) {
		rdr_log(reader, "No active subscriptions (0x%04x, 0x%04x)", subs1, subs2);
	} else {
		unsigned int i;
		rdr_log(reader, "Subscription data 1 (0x%04x): %s",
			subs1, dec2bin_str(subs1, tmp));
		rdr_log(reader, "Subscription data 2 (0x%04x): %s",
			subs2, dec2bin_str(subs2, tmp));

		// Configure your tiers to get subscription packets name resolution
// # Example oscam.tiers file
// 5581:0001|Economic
// 5581:0002|Standard
// 5581:0004|Premium
// 5581:0008|HBO
// 5581:0010|Unknown Package 10
// 5581:0020|Unknown Package 20
// 5581:0040|Unknown Package 40
// 5581:0080|Unknown Package 80
		for (i = 1; i < 256; i <<= 1)
		{
			if ((subs1 & i) == i) {
				cs_add_entitlement(reader, 0x4AEE,
					0, /* provid */
					i, /* id  */
					0, /* class */
					last_upd_ts, /* start_ts */
					subs_end_ts, /* end_ts */
					4 /* type: Tier */
				);
				cs_add_entitlement(reader, 0x5581,
					0, /* provid */
					i, /* id  */
					0, /* class */
					last_upd_ts, /* start_ts */
					subs_end_ts, /* end_ts */
					4 /* type: Tier */
				);
				get_tiername(i, 0x4aee, tmp);
				if (tmp[0] == 0x00)
					get_tiername(i, 0x5581, tmp);
				rdr_log(reader, "  Package %02x is active: %s", i, tmp);
			}
		}
	}

	rdr_log(reader, "End subscription info.");
	return OK;
}

void reader_bulcrypt(struct s_cardsystem *ph)
{
	ph->do_emm			= bulcrypt_do_emm;
	ph->do_ecm			= bulcrypt_do_ecm;
	ph->card_info		= bulcrypt_card_info;
	ph->card_init		= bulcrypt_card_init;
	ph->get_emm_type	= bulcrypt_get_emm_type;
	ph->get_emm_filter	= bulcrypt_get_emm_filter;
	ph->desc			= "bulcrypt";
	ph->caids[0]		= 0x5581;
	ph->caids[1]		= 0x4aee;
}
#endif
