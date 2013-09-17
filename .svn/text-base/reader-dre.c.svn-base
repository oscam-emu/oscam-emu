#include "globals.h"
#ifdef READER_DRE
#include "cscrypt/des.h"
#include "reader-common.h"

struct dre_data {
	uint8_t		provider;
};

#define OK_RESPONSE 0x61
#define CMD_BYTE 0x59

static uchar xor (const uchar * cmd, int32_t cmdlen)
{
  int32_t i;
  uchar checksum = 0x00;
  for (i = 0; i < cmdlen; i++)
    checksum ^= cmd[i];
  return checksum;
}

static int32_t dre_command (struct s_reader * reader, const uchar * cmd, int32_t cmdlen, unsigned char * cta_res, uint16_t * p_cta_lr)	//attention: inputcommand will be changed!!!! answer will be in cta_res, length cta_lr ; returning 1 = no error, return ERROR = err
{
  uchar startcmd[] = { 0x80, 0xFF, 0x10, 0x01, 0x05 };	//any command starts with this,
  //last byte is nr of bytes of the command that will be sent
  //after the startcmd
//response on startcmd+cmd:     = { 0x61, 0x05 }  //0x61 = "OK", last byte is nr. of bytes card will send
  uchar reqans[] = { 0x00, 0xC0, 0x00, 0x00, 0x08 };	//after command answer has to be requested,
  //last byte must be nr. of bytes that card has reported to send
  uchar command[256];
  char tmp[256];
  int32_t headerlen = sizeof (startcmd);
  startcmd[4] = cmdlen + 3;	//commandlength + type + len + checksum bytes
  memcpy (command, startcmd, headerlen);
  command[headerlen++] = CMD_BYTE;	//type
  command[headerlen++] = cmdlen + 1;	//len = command + 1 checksum byte
  memcpy (command + headerlen, cmd, cmdlen);

  uchar checksum = ~xor (cmd, cmdlen);
  //rdr_debug_mask(reader, D_READER, "Checksum: %02x", checksum);
  cmdlen += headerlen;
  command[cmdlen++] = checksum;

  reader_cmd2icc (reader, command, cmdlen, cta_res, p_cta_lr);

  if ((*p_cta_lr != 2) || (cta_res[0] != OK_RESPONSE)) {
    rdr_log(reader, "command sent to card: %s", cs_hexdump(0, command, cmdlen, tmp, sizeof(tmp)));
    rdr_log(reader, "unexpected answer from card: %s", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
    return ERROR;			//error
  }

  reqans[4] = cta_res[1];	//adapt length byte
  reader_cmd2icc (reader, reqans, 5, cta_res, p_cta_lr);

  if (cta_res[0] != CMD_BYTE) {
    rdr_log(reader, "unknown response: cta_res[0] expected to be %02x, is %02x", CMD_BYTE, cta_res[0]);
    return ERROR;
  }
  if ((cta_res[1] == 0x03) && (cta_res[2] == 0xe2)) {
    switch (cta_res[3]) {
    case 0xe1:
      rdr_log(reader, "checksum error: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
      break;
    case 0xe2:
      rdr_log(reader, "wrong provider: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
      break;
    case 0xe3:
      rdr_log(reader, "illegal command: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
      break;
    case 0xec:
      rdr_log(reader, "wrong signature: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
      break;
    default:
      rdr_debug_mask(reader, D_READER, "unknown error: %s.", cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
      break;
    }
    return ERROR;			//error
  }
  int32_t length_excl_leader = *p_cta_lr;
  if ((cta_res[*p_cta_lr - 2] == 0x90) && (cta_res[*p_cta_lr - 1] == 0x00))
    length_excl_leader -= 2;

  checksum = ~xor (cta_res + 2, length_excl_leader - 3);

  if (cta_res[length_excl_leader - 1] != checksum) {
    rdr_log(reader, "checksum does not match, expected %02x received %02x:%s", checksum,
	    cta_res[length_excl_leader - 1], cs_hexdump(0, cta_res, *p_cta_lr, tmp, sizeof(tmp)));
    return ERROR;			//error
  }
  return OK;
}

#define dre_cmd(cmd) \
{ \
  	dre_command(reader, cmd, sizeof(cmd),cta_res,&cta_lr); \
}

static int32_t dre_set_provider_info (struct s_reader * reader)
{
  def_resp;
  int32_t i;
  uchar cmd59[] = { 0x59, 0x14 };	// subscriptions
  uchar cmd5b[] = { 0x5b, 0x00, 0x14 };	//validity dates
  struct dre_data *csystem_data = reader->csystem_data;

  cs_clear_entitlement(reader);

  cmd59[1] = csystem_data->provider;
  if ((dre_cmd (cmd59))) {	//ask subscription packages, returns error on 0x11 card
    uchar pbm[32];
    char tmp_dbg[65];
    memcpy (pbm, cta_res + 3, cta_lr - 6);
    rdr_debug_mask(reader, D_READER, "pbm: %s", cs_hexdump(0, pbm, 32, tmp_dbg, sizeof(tmp_dbg)));

    if (pbm[0] == 0xff)
      rdr_log (reader, "no active packages");
    else
      for (i = 0; i < 32; i++)
	if (pbm[i] != 0xff) {
	  cmd5b[1] = i;
	  cmd5b[2] = csystem_data->provider;
	  dre_cmd (cmd5b);	//ask for validity dates

	  time_t start;
	  time_t end;
	  start = (cta_res[3] << 24) | (cta_res[4] << 16) | (cta_res[5] << 8) | cta_res[6];
	  end = (cta_res[7] << 24) | (cta_res[8] << 16) | (cta_res[9] << 8) | cta_res[10];

	  struct tm temp;

	  localtime_r (&start, &temp);
	  int32_t startyear = temp.tm_year + 1900;
	  int32_t startmonth = temp.tm_mon + 1;
	  int32_t startday = temp.tm_mday;
	  localtime_r (&end, &temp);
	  int32_t endyear = temp.tm_year + 1900;
	  int32_t endmonth = temp.tm_mon + 1;
	  int32_t endday = temp.tm_mday;
	  rdr_log (reader, "active package %i valid from %04i/%02i/%02i to %04i/%02i/%02i", i, startyear, startmonth, startday,
		  endyear, endmonth, endday);
	  cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[0]), 0, 0, start, end, 1);
	}
  }
  return OK;
}

static int32_t dre_card_init (struct s_reader * reader, ATR *newatr)
{
	get_atr;
  def_resp;
  uchar ua[] = { 0x43, 0x15 };	// get serial number (UA)
  uchar providers[] = { 0x49, 0x15 };	// get providers
  int32_t i;
	char *card;
	char tmp[9];

  if ((atr[0] != 0x3b) || (atr[1] != 0x15) || (atr[2] != 0x11) || (atr[3] != 0x12) || (
		((atr[4] != 0xca) || (atr[5] != 0x07)) &&
		((atr[4] != 0x01) || (atr[5] != 0x01))
	))
    return ERROR;

  if (!cs_malloc(&reader->csystem_data, sizeof(struct dre_data)))
    return ERROR;
  struct dre_data *csystem_data = reader->csystem_data;

  csystem_data->provider = atr[6];
  uchar checksum = xor (atr + 1, 6);

  if (checksum != atr[7])
    rdr_log(reader, "warning: expected ATR checksum %02x, smartcard reports %02x", checksum, atr[7]);

  switch (atr[6]) {
  case 0x11:
    card = "Tricolor Centr";
    reader->caid = 0x4ae1;
    break;			//59 type card = MSP (74 type = ATMEL)
  case 0x12:
    card = "Cable TV";
    reader->caid = 0x4ae1;	//TODO not sure about this one
    break;
  case 0x14:
    card = "Tricolor Syberia / Platforma HD new";
    reader->caid = 0x4ae1;
    break;			//59 type card
  case 0x15:
    card = "Platforma HD / DW old";
    reader->caid = 0x4ae1;
    break;			//59 type card
  default:
    card = "Unknown";
    reader->caid = 0x4ae1;
    break;
  }

  memset (reader->prid, 0x00, 8);

  static const uchar cmd30[] =
    { 0x30, 0x81, 0x00, 0x81, 0x82, 0x03, 0x84, 0x05, 0x06, 0x87, 0x08, 0x09, 0x00, 0x81, 0x82, 0x03, 0x84, 0x05,
    0x00
  };
  dre_cmd (cmd30);		//unknown command, generates error on card 0x11 and 0x14
/*
response:
59 03 E2 E3
FE 48 */

  uchar cmd54[] = { 0x54, 0x14 };	// geocode
  cmd54[1] = csystem_data->provider;
  uchar geocode = 0;
  if ((dre_cmd (cmd54)))	//error would not be fatal, like on 0x11 cards
    geocode = cta_res[3];

  providers[1] = csystem_data->provider;
  if (!(dre_cmd (providers)))
    return ERROR;			//fatal error
  if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
    return ERROR;
  uchar provname[128];
  for (i = 0; ((i < cta_res[2] - 6) && (i < 128)); i++) {
    provname[i] = cta_res[6 + i];
    if (provname[i] == 0x00)
      break;
  }
  int32_t major_version = cta_res[3];
  int32_t minor_version = cta_res[4];

  ua[1] = csystem_data->provider;
  dre_cmd (ua);			//error would not be fatal

  int32_t hexlength = cta_res[1] - 2;	//discard first and last byte, last byte is always checksum, first is answer code

  reader->hexserial[0] = 0;
  reader->hexserial[1] = 0;
  memcpy (reader->hexserial + 2, cta_res + 3, hexlength);

  int32_t low_dre_id = ((cta_res[4] << 16) | (cta_res[5] << 8) | cta_res[6]) - 48608;
  int32_t dre_chksum = 0;
  uchar buf[32];
  snprintf ((char *)buf, sizeof(buf), "%i%i%08i", csystem_data->provider - 16, major_version + 1, low_dre_id);
  for (i = 0; i < 32; i++) {
    if (buf[i] == 0x00)
      break;
    dre_chksum += buf[i] - 48;
  }

  rdr_log (reader, "type: DRE Crypt, caid: %04X, serial: {%s}, dre id: %i%i%i%08i, geocode %i, card: %s v%i.%i",
	  reader->caid, cs_hexdump(0, reader->hexserial + 2, 4, tmp, sizeof(tmp)), dre_chksum, csystem_data->provider - 16,
	  major_version + 1, low_dre_id, geocode, card, major_version, minor_version);
  rdr_log (reader, "Provider name:%s.", provname);


  memset (reader->sa, 0, sizeof (reader->sa));
  memcpy (reader->sa[0], reader->hexserial + 2, 1);	//copy first byte of unique address also in shared address, because we dont know what it is...

  rdr_log_sensitive(reader, "SA = %02X%02X%02X%02X, UA = {%s}", reader->sa[0][0], reader->sa[0][1], reader->sa[0][2],
	  reader->sa[0][3], cs_hexdump(0, reader->hexserial + 2, 4, tmp, sizeof(tmp)));

  reader->nprov = 1;

  if (!dre_set_provider_info (reader))
    return ERROR;			//fatal error

  rdr_log(reader, "ready for requests");
  return OK;
}

static unsigned char DESkeys[16*8]=
{
  0x4A,0x11,0x23,0xB1,0x45,0x99,0xCF,0x10, // 00
  0x21,0x1B,0x18,0xCD,0x02,0xD4,0xA1,0x1F, // 01
  0x07,0x56,0xAB,0xB4,0x45,0x31,0xAA,0x23, // 02
  0xCD,0xF2,0x55,0xA1,0x13,0x4C,0xF1,0x76, // 03
  0x57,0xD9,0x31,0x75,0x13,0x98,0x89,0xC8, // 04
  0xA3,0x36,0x5B,0x18,0xC2,0x83,0x45,0xE2, // 05
  0x19,0xF7,0x35,0x08,0xC3,0xDA,0xE1,0x28, // 06
  0xE7,0x19,0xB5,0xD8,0x8D,0xE3,0x23,0xA4, // 07
  0xA7,0xEC,0xD2,0x15,0x8B,0x42,0x59,0xC5, // 08
  0x13,0x49,0x83,0x2E,0xFB,0xAD,0x7C,0xD3, // 09
  0x37,0x25,0x78,0xE3,0x72,0x19,0x53,0xD9, // 0A
  0x7A,0x15,0xA4,0xC7,0x15,0x49,0x32,0xE8, // 0B
  0x63,0xD5,0x96,0xA7,0x27,0xD8,0xB2,0x68, // 0C
  0x42,0x5E,0x1A,0x8C,0x41,0x69,0x8E,0xE8, // 0D
  0xC2,0xAB,0x37,0x29,0xD3,0xCF,0x93,0xA7, // 0E
  0x49,0xD3,0x33,0xC2,0xEB,0x71,0xD3,0x14  // 0F
};

static void DREover(const unsigned char *ECMdata, unsigned char *DW)
{
	uchar key[8];
	if(ECMdata[2] >= (43+4) && ECMdata[40] == 0x3A && ECMdata[41] == 0x4B)
	{
		memcpy(key, &DESkeys[(ECMdata[42] & 0x0F) * 8], 8);

		doPC1(key);

		des(key, DES_ECS2_DECRYPT, DW); // even DW post-process
		des(key, DES_ECS2_DECRYPT, DW+8); // odd DW post-process
	};
};

static int32_t dre_do_ecm(struct s_reader * reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
  def_resp;
  char tmp_dbg[256];
  struct dre_data *csystem_data = reader->csystem_data;
  if (reader->caid == 0x4ae0) {
    uchar ecmcmd41[] = { 0x41,
      0x58, 0x1f, 0x00,		//fixed part, dont change
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	//0x01 - 0x08: next key
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,	//0x11 - 0x18: current key
      0x3b, 0x59, 0x11		//0x3b = keynumber, can be a value 56 ;; 0x59 number of package = 58+1 - Pay Package ;; 0x11 = provider
    };
    ecmcmd41[22] = csystem_data->provider;
    memcpy (ecmcmd41 + 4, er->ecm + 8, 16);
    ecmcmd41[20] = er->ecm[6];	//keynumber
    ecmcmd41[21] = 0x58 + er->ecm[25];	//package number
    rdr_debug_mask(reader, D_READER, "unused ECM info front:%s", cs_hexdump(0, er->ecm, 8, tmp_dbg, sizeof(tmp_dbg)));
    rdr_debug_mask(reader, D_READER, "unused ECM info back:%s", cs_hexdump(0, er->ecm + 24, er->ecm[2] + 2 - 24, tmp_dbg, sizeof(tmp_dbg)));
    if ((dre_cmd (ecmcmd41))) {	//ecm request
      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
				return ERROR;		//exit if response is not 90 00
      memcpy (ea->cw, cta_res + 11, 8);
      memcpy (ea->cw + 8, cta_res + 3, 8);

      return OK;
    }
  }
  else {

    uchar ecmcmd51[] = { 0x51, 0x02, 0x56, 0x05, 0x00, 0x4A, 0xE3,	//fixed header?
      0x9C, 0xDA,		//first three nibbles count up, fourth nibble counts down; all ECMs sent twice
      0xC1, 0x71, 0x21, 0x06, 0xF0, 0x14, 0xA7, 0x0E,	//next key?
      0x89, 0xDA, 0xC9, 0xD7, 0xFD, 0xB9, 0x06, 0xFD,	//current key?
      0xD5, 0x1E, 0x2A, 0xA3, 0xB5, 0xA0, 0x82, 0x11,	//key or signature?
      0x14			//provider
    };
    memcpy (ecmcmd51 + 1, er->ecm + 5, 0x21);
    rdr_debug_mask(reader, D_READER, "unused ECM info front:%s", cs_hexdump(0, er->ecm, 5, tmp_dbg, sizeof(tmp_dbg)));
    rdr_debug_mask(reader, D_READER, "unused ECM info back:%s", cs_hexdump(0, er->ecm + 37, 4, tmp_dbg, sizeof(tmp_dbg)));
    ecmcmd51[33] = csystem_data->provider;	//no part of sig
    if ((dre_cmd (ecmcmd51))) {	//ecm request
      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
				return ERROR;		//exit if response is not 90 00
      DREover(er->ecm, cta_res + 3);
      memcpy (ea->cw, cta_res + 11, 8);
      memcpy (ea->cw + 8, cta_res + 3, 8);
      return OK;
    }
  }
  return ERROR;
}

static int32_t dre_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr)
{
  switch (ep->emm[0]) {
		case 0x87:
			ep->type = UNIQUE;
			return 1; //FIXME: no filling of ep->hexserial

		case 0x83:
		case 0x89:
			ep->type = SHARED;
			// FIXME: Seems to be that SA is only used with caid 0x4ae1
			if (rdr->caid == 0x4ae1) {
				memset(ep->hexserial, 0, 8);
				memcpy(ep->hexserial, ep->emm + 3, 4);
				return (!memcmp(&rdr->sa[0][0], ep->emm + 3, 4));
			}
			else
				return 1;

		case 0x80:
		case 0x82:
		case 0x86:
		case 0x8c:
			ep->type = SHARED;
			memset(ep->hexserial, 0, 8);
			ep->hexserial[0] = ep->emm[3];
			return ep->hexserial[0] == rdr->sa[0][0];

		default:
			ep->type = UNKNOWN;
			return 1;
	}
}

static int32_t dre_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter** emm_filters, unsigned int* filter_count)
{
  if (*emm_filters == NULL) {
    const unsigned int max_filter_count = 7;
    if (!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
      return ERROR;

    struct s_csystem_emm_filter* filters = *emm_filters;
    *filter_count = 0;

    int32_t idx = 0;

    filters[idx].type = EMM_SHARED;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x80;
    filters[idx].filter[1] = rdr->sa[0][0];
    filters[idx].mask[0]   = 0xF2;
    filters[idx].mask[1]   = 0xFF;
    idx++;

    filters[idx].type = EMM_SHARED;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x82;
    filters[idx].filter[1] = rdr->sa[0][0];
    filters[idx].mask[0]   = 0xF3;
    filters[idx].mask[1]   = 0xFF;
    idx++;

    filters[idx].type = EMM_SHARED;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x83;
    filters[idx].filter[1] = rdr->sa[0][0];
    filters[idx].mask[0]   = 0xF3;
    if (rdr->caid == 0x4ae1) {
      memcpy(&filters[idx].filter[1], &rdr->sa[0][0], 4);
      memset(&filters[idx].mask[1], 0xFF, 4);
    }
    filters[idx].mask[1]   = 0xFF;
    idx++;

    filters[idx].type = EMM_SHARED;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x86;
    filters[idx].filter[1] = rdr->sa[0][0];
    filters[idx].mask[0]   = 0xFF;
    filters[idx].mask[1]   = 0xFF;
    idx++;

    filters[idx].type = EMM_SHARED;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x8c;
    filters[idx].filter[1] = rdr->sa[0][0];
    filters[idx].mask[0]   = 0xFF;
    filters[idx].mask[1]   = 0xFF;
    idx++;

    filters[idx].type = EMM_SHARED;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x89;
    filters[idx].mask[0]   = 0xFF;
    // FIXME: Seems to be that SA is only used with caid 0x4ae1
    if (rdr->caid == 0x4ae1) {
      memcpy(&filters[idx].filter[1], &rdr->sa[0][0], 4);
      memset(&filters[idx].mask[1], 0xFF, 4);
    }
    idx++;

    filters[idx].type = EMM_UNIQUE;
    filters[idx].enabled   = 1;
    filters[idx].filter[0] = 0x87;
    filters[idx].mask[0]   = 0xFF;
    //FIXME: No filter for hexserial
    idx++;

    *filter_count = idx;
  }

  return OK;
}

static int32_t dre_do_emm (struct s_reader * reader, EMM_PACKET * ep)
{
  def_resp;
  struct dre_data *csystem_data = reader->csystem_data;

  if (reader->caid == 0x4ae1) {
    if(ep->type == UNIQUE && ep->emm[39] == 0x3d)
    { /* For new package activation. */
        uchar emmcmd58[26];
        emmcmd58[0] = 0x58;
        memcpy(&emmcmd58[1], &ep->emm[40], 24);
        emmcmd58[25] = 0x15;
        if ((dre_cmd (emmcmd58)))
            if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
                return ERROR;
    }
    else
    {
        uchar emmcmd52[0x3a];
        emmcmd52[0] = 0x52;
        int32_t i;
        for (i = 0; i < 2; i++) {
            memcpy (emmcmd52 + 1, ep->emm + 5 + 32 + i * 56, 56);
            // check for shared address
            if(ep->emm[3]!=reader->sa[0][0])
                return OK; // ignore, wrong address
            emmcmd52[0x39] = csystem_data->provider;
            if ((dre_cmd (emmcmd52)))
                if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
                    return ERROR; //exit if response is not 90 00
        }
    }
  }
  else {
    uchar emmcmd42[] =
      { 0x42, 0x85, 0x58, 0x01, 0xC8, 0x00, 0x00, 0x00, 0x05, 0xB8, 0x0C, 0xBD, 0x7B, 0x07, 0x04, 0xC8,
      0x77, 0x31, 0x95, 0xF2, 0x30, 0xB7, 0xE9, 0xEE, 0x0F, 0x81, 0x39, 0x1C, 0x1F, 0xA9, 0x11, 0x3E,
      0xE5, 0x0E, 0x8E, 0x50, 0xA4, 0x31, 0xBB, 0x01, 0x00, 0xD6, 0xAF, 0x69, 0x60, 0x04, 0x70, 0x3A,
      0x91,
      0x56, 0x58, 0x11
    };
		int32_t i;
		switch (ep->type) {
			case UNIQUE:
	    	for (i = 0; i < 2; i++) {
					memcpy (emmcmd42 + 1, ep->emm + 42 + i*49, 48);
					emmcmd42[49] = ep->emm[i*49 + 41]; //keynr
					emmcmd42[50] = 0x58 + ep->emm[40]; //package nr
			    emmcmd42[51] = csystem_data->provider;
			    if ((dre_cmd (emmcmd42))) {
			      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
							return ERROR;		//exit if response is not 90 00
					}
				}
				break;
			case SHARED:
			default:
		    memcpy (emmcmd42 + 1, ep->emm + 6, 48);
		    emmcmd42[51] = csystem_data->provider;
		    //emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
		    emmcmd42[50] = 0x58;
		    emmcmd42[49] = ep->emm[5];	//keynr
		    /* response:
		       59 05 A2 02 05 01 5B
		       90 00 */
		    if ((dre_cmd (emmcmd42))) {	//first emm request
		      if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
						return ERROR;		//exit if response is not 90 00

		      memcpy (emmcmd42 + 1, ep->emm + 55, 7);	//TODO OR next two lines?
		      /*memcpy (emmcmd42 + 1, ep->emm + 55, 7);  //FIXME either I cant count or my EMM log contains errors
		         memcpy (emmcmd42 + 8, ep->emm + 67, 41); */
		      emmcmd42[51] = csystem_data->provider;
		      //emmcmd42[50] = ecmcmd42[2]; //TODO package nr could also be fixed 0x58
		      emmcmd42[50] = 0x58;
		      emmcmd42[49] = ep->emm[54];	//keynr
		      if ((dre_cmd (emmcmd42))) {	//second emm request
						if ((cta_res[cta_lr - 2] != 0x90) || (cta_res[cta_lr - 1] != 0x00))
							return ERROR;		//exit if response is not 90 00
		      }
		    }
		}
  }
  return OK;			//success
}

static int32_t dre_card_info (struct s_reader *UNUSED(rdr))
{
  return OK;
}

void reader_dre(struct s_cardsystem *ph)
{
	ph->do_emm=dre_do_emm;
	ph->do_ecm=dre_do_ecm;
	ph->card_info=dre_card_info;
	ph->card_init=dre_card_init;
	ph->get_emm_type=dre_get_emm_type;
	ph->get_emm_filter=dre_get_emm_filter;
	ph->caids[0]=0x4AE0;
	ph->caids[1]=0x4AE1;
	ph->caids[2]=0x7BE0;
	ph->caids[3]=0x7BE1;
	ph->desc="dre";
}
#endif
