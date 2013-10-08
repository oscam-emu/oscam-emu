#include "globals.h"
#ifdef READER_VIDEOGUARD
#include "reader-common.h"
#include "reader-videoguard-common.h"

static int32_t vg12_do_cmd(struct s_reader *reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff, unsigned char *cta_res)
{
	uint16_t cta_lr;
	unsigned char ins2[5];
	memcpy(ins2, ins, 5);
	unsigned char len = 0;
	len = ins2[4];


	if(txbuff == NULL)
	{
		if(!write_cmd_vg(ins2, NULL) || !status_ok(cta_res + len))
		{
			return -1;
		}
		if(rxbuff != NULL)
		{
			memcpy(rxbuff, ins2, 5);
			memcpy(rxbuff + 5, cta_res, len);
			memcpy(rxbuff + 5 + len, cta_res + len, 2);
		}
	}
	else
	{
		if(!write_cmd_vg(ins2, (uchar *) txbuff) || !status_ok(cta_res))
		{
			return -2;
		}
		if(rxbuff != NULL)
		{
			memcpy(rxbuff, ins2, 5);
			memcpy(rxbuff + 5, txbuff, len);
			memcpy(rxbuff + 5 + len, cta_res, 2);
		}
	}
	return len;
}

static void read_tiers(struct s_reader *reader)
{
	def_resp;

	static const unsigned char ins2A[5] = {  0x48, 0x2A, 0x00, 0x00, 0x90  };
	int32_t l;

	if(!write_cmd_vg(ins2A, NULL) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class48 ins2A: failed");
		return;
	}

	// return at present as not sure how to parse this
	return;

	unsigned char ins76[5] = { 0x48, 0x76, 0x00, 0x00, 0x00 };
	ins76[3] = 0x7f;
	ins76[4] = 2;
	if(!write_cmd_vg(ins76, NULL) || !status_ok(cta_res + 2))
	{
		return;
	}
	ins76[3] = 0;
	ins76[4] = 0x0a;
	int32_t num = cta_res[1];
	int32_t i;

	cs_clear_entitlement(reader); //reset the entitlements

	struct videoguard_data *csystem_data = reader->csystem_data;
	for(i = 0; i < num; i++)
	{
		ins76[2] = i;
		l = vg12_do_cmd(reader, ins76, NULL, NULL, cta_res);
		if(l < 0 || !status_ok(cta_res + l))
		{
			return;
		}
		if(cta_res[2] == 0 && cta_res[3] == 0)
		{
			break;
		}
		uint16_t tier_id = (cta_res[2] << 8) | cta_res[3];
		struct tm timeinfo;
		memset(&timeinfo, 0, sizeof(struct tm));
		rev_date_calc_tm(&cta_res[4], &timeinfo, csystem_data->card_baseyear);
		cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[0]), tier_id, 0, 0, mktime(&timeinfo), 4);
		char tiername[83];
		rdr_log(reader, "tier: %04x, expiry date: %04d/%02d/%02d-%02d:%02d:%02d %s", tier_id, timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, get_tiername(tier_id, reader->caid, tiername));
	}
}

static int32_t videoguard12_card_init(struct s_reader *reader, ATR *newatr)
{

	get_hist;

	if((hist_size < 7) || (hist[1] != 0xB0) || (hist[4] != 0xFF) || (hist[5] != 0x4A) || (hist[6] != 0x50))
	{
		rdr_debug_mask(reader, D_READER, "failed history check");
		return ERROR;
	}
	rdr_debug_mask(reader, D_READER, "passed history check");

	get_atr;
	def_resp;

	if(!cs_malloc(&reader->csystem_data, sizeof(struct videoguard_data)))
		{ return ERROR; }
	struct videoguard_data *csystem_data = reader->csystem_data;

	/* set information on the card stored in reader-videoguard-common.c */
	set_known_card_info(reader, atr, &atr_size);

	if((reader->ndsversion != NDS12) && ((csystem_data->card_system_version != NDS12) || (reader->ndsversion != NDSAUTO)))
	{
		/* known ATR and not NDS12
		   or unknown ATR and not forced to NDS12
		   or known NDS12 ATR and forced to another NDS version
		   ... probably not NDS12 */
		return ERROR;
	}

	rdr_log(reader, "type: %s, baseyear: %i", csystem_data->card_desc, csystem_data->card_baseyear);
	if(reader->ndsversion == NDS12)
	{
		rdr_log(reader, "forced to NDS12");
	}

	/* NDS12 Class 48/49/4A/4B cards only need a very basic initialisation
	   NDS12 Class 48/49/4A/4B cards do not respond to ins7416
	   nor do they return list of valid command therefore do not even try
	   NDS12 Class 48/49/4A/4B cards need to be told the length as (48, ins, 00, 80, 01)
	   does not return the length */

	static const unsigned char ins4852[5] = { 0x48, 0x52, 0x00, 0x00, 0x14 };
	if(!write_cmd_vg(ins4852, NULL) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class48 ins52: failed");
		//return ERROR;
	}
	if(!write_cmd_vg(ins4852, NULL) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class48 ins52: failed");
		//return ERROR;
	}

	unsigned char boxID[4];
	int32_t boxidOK = 0;

	/*
	  // Try to get the boxid from the card, even if BoxID specified in the config file
	  unsigned char ins36[5] = { 0x48, 0x36, 0x00, 0x00, 0x53 };

	  // get the length of ins36
	  static const unsigned char ins38[5] = { 0x48, 0x38, 0x80, 0x00, 0x02 };
	  if (!write_cmd_vg(ins38,NULL) || !status_ok(cta_res+cta_lr-2)) {
	    rdr_log(reader, "class48 ins38: failed");
	    //return ERROR;
	  } else {
	    ins36[3] = cta_res[0];
	    ins36[4] = cta_res[1];
	  }


	  if (!write_cmd_vg(ins36,NULL) || !status_ok(cta_res+cta_lr-2)) {
	    rdr_log(reader, "class48 ins36: failed");
	    //return ERROR;
	  }

	  if (cta_res[2] > 0x0F) {
	    rdr_log(reader, "class48 ins36: encrypted - therefore not an NDS12 card");
	    // return ERROR;
	  } else {
	    // skipping the initial fixed fields: encr/rev++ (4)
	    int32_t i = 4;
	    int32_t gotUA = 0;
	    while (i < (cta_lr-2)) {
	      if (!gotUA && cta_res[i] < 0xF0) {    // then we guess that the next 4 bytes is the UA
	        gotUA = 1;
	        i += 4;
	      } else {
	        switch (cta_res[i]) {   // object length vary depending on type
	          case 0x00:        // padding
	            {
	              i += 1;
	              break;
	            }
	          case 0xEF:        // card status
	            {
	              i += 3;
	              break;
	            }
	          case 0xD1:
	            {
	              i += 4;
	              break;
	            }
	          case 0xDF:        // next server contact
	            {
	              i += 5;
	              break;
	            }
	          case 0xF3:        // boxID
	            {
	              memcpy(&boxID, &cta_res[i + 1], sizeof(boxID));
	              boxidOK = 1;
	              i += 5;
	              break;
	            }
	          case 0xF6:
	            {
	              i += 6;
	              break;
	            }
	          case 0xFC:        // No idea NDS1/NDS12
	            {
	              i += 14;
	              break;
	            }
	          case 0x01:        // date & time
	            {
	              i += 7;
	              break;
	            }
	          case 0xFA:
	            {
	              i += 9;
	              break;
	            }
	          case 0x5E:
	          case 0x67:        // signature
	          case 0xDE:
	          case 0xE2:
	          case 0xE9:        // tier dates
	          case 0xF8:        // Old PPV Event Record
	          case 0xFD:
	            {
	              i += cta_res[i + 1] + 2;  // skip length + 2 bytes (type and length)
	              break;
	            }
	          default:      // default to assume a length byte
	            {
	              rdr_log(reader, "class48 ins36: returned unknown type=0x%02X - parsing may fail", cta_res[i]);
	              i += cta_res[i + 1] + 2;
	            }
	          } //switch
	        }//else
	      }//while
	    }//ele

	  rdr_debug_mask(reader, D_READER, "calculated BoxID: %02X%02X%02X%02X", boxID[0], boxID[1], boxID[2], boxID[3]);
	*/

	/* the boxid is specified in the config */
	if(reader->boxid > 0)
	{
		int32_t i;
		for(i = 0; i < 4; i++)
		{
			boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
		}
		rdr_debug_mask(reader, D_READER, "oscam.server BoxID: %02X%02X%02X%02X", boxID[0], boxID[1], boxID[2], boxID[3]);
	}

	if(!boxidOK)
	{
		rdr_log(reader, "no boxID available");
		return ERROR;
	}

	// Send BoxID
	static const unsigned char ins484C[5] = { 0x48, 0x4C, 0x00, 0x00, 0x09 };
	unsigned char payload4C[9] = { 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02 };
	memcpy(payload4C, boxID, 4);
	if(!write_cmd_vg(ins484C, payload4C) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class48 ins4C: sending boxid failed");
		//return ERROR;
	}

	static const unsigned char ins4858[5] = { 0x48, 0x58, 0x00, 0x00, 0x35 };
	if(!write_cmd_vg(ins4858, NULL) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class48 ins58: failed");
		return ERROR;
	}

	memset(reader->hexserial, 0, 8);
	memcpy(reader->hexserial + 2, cta_res + 4, 4);
	memcpy(reader->sa, cta_res + 4, 3);
	reader->caid = cta_res[2] * 0x100 + cta_res[3];

	/* we have one provider, 0x0000 */
	reader->nprov = 1;
	memset(reader->prid, 0x00, sizeof(reader->prid));

	static const unsigned char insBE[5] = { 0x4B, 0xBE, 0x00, 0x00, 0x12 };
	if(!write_cmd_vg(insBE, NULL) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class4B ins52: failed");
		//return ERROR;
	}

	static const unsigned char ins4952[5] = { 0x49, 0x52, 0x00, 0x00, 0x14 };
	if(!write_cmd_vg(ins4952, NULL) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class49 ins52: failed");
		//return ERROR;
	}

	static const unsigned char ins4958[5] = { 0x49, 0x58, 0x00, 0x00, 0x35 };
	if(!write_cmd_vg(ins4958, NULL) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class49 ins58: failed");
		//return ERROR;
	}

	// Send BoxID class 49
	static const unsigned char ins494C[5] = { 0x49, 0x4C, 0x00, 0x00, 0x09 };
	if(!write_cmd_vg(ins494C, payload4C) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class49 ins4C: sending boxid failed");
		//return ERROR;
	}

	static const unsigned char ins0C[5] = { 0x49, 0x0C, 0x00, 0x00, 0x0A };
	if(!write_cmd_vg(ins0C, NULL) || !status_ok(cta_res + cta_lr - 2))
	{
		rdr_log(reader, "class49 ins0C: failed");
		//return ERROR;
	}

	rdr_log_sensitive(reader,
					  "type: VideoGuard, caid: %04X, serial: {%02X%02X%02X%02X}, BoxID: {%02X%02X%02X%02X}",
					  reader->caid, reader->hexserial[2], reader->hexserial[3], reader->hexserial[4], reader->hexserial[5], boxID[0], boxID[1], boxID[2], boxID[3]);
	rdr_log(reader, "ready for requests - this is in testing please send -d 255 logs to rebdog");

	return OK;
}

static int32_t videoguard12_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
	unsigned char cta_res[CTA_RES_LEN];
	unsigned char ins40[5] = { 0x49, 0x40, 0x40, 0x80, 0xFF };
	static const unsigned char ins54[5] = { 0x4B, 0x54, 0x00, 0x00, 0x17 };
	int32_t posECMpart2 = er->ecm[6] + 7;
	int32_t lenECMpart2 = er->ecm[posECMpart2];
	unsigned char tbuff[264];
	unsigned char rbuff[264];
	memcpy(&tbuff[0], &(er->ecm[posECMpart2 + 1]), lenECMpart2);
	ins40[4] = lenECMpart2;
	int32_t l;
	l = vg12_do_cmd(reader, ins40, tbuff, NULL, cta_res);
	if(l > 0 && status_ok(cta_res))
	{
		l = vg12_do_cmd(reader, ins54, NULL, rbuff, cta_res);
		if(l > 0 && status_ok(cta_res + l))
		{
			if(!cw_is_valid(rbuff + 5))   //sky cards report 90 00 = ok but send cw = 00 when channel not subscribed
			{
				rdr_log(reader, "class4B ins54 status 90 00 but cw=00 -> channel not subscribed");
				return ERROR;
			}

			if(er->ecm[0] & 1)
			{
				memset(ea->cw + 0, 0, 8);
				memcpy(ea->cw + 8, rbuff + 5, 8);
			}
			else
			{
				memcpy(ea->cw + 0, rbuff + 5, 8);
				memset(ea->cw + 8, 0, 8);
			}
			return OK;
		}
	}
	rdr_log(reader, "class4B ins54 (%d) status not ok %02x %02x", l, cta_res[0], cta_res[1]);
	return ERROR;
}

static int32_t videoguard12_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
	return videoguard_do_emm(reader, ep, 0x49, read_tiers, vg12_do_cmd);
}

static int32_t videoguard12_card_info(struct s_reader *reader)
{
	/* info is displayed in init, or when processing info */
	struct videoguard_data *csystem_data = reader->csystem_data;
	rdr_log(reader, "card detected");
	rdr_log(reader, "type: %s", csystem_data->card_desc);
	read_tiers(reader);
	return OK;
}

void reader_videoguard12(struct s_cardsystem *ph)
{
	ph->do_emm = videoguard12_do_emm;
	ph->do_ecm = videoguard12_do_ecm;
	ph->card_info = videoguard12_card_info;
	ph->card_init = videoguard12_card_init;
	ph->get_emm_type = videoguard_get_emm_type;
	ph->get_emm_filter = videoguard_get_emm_filter;
	ph->caids[0] = 0x09;
}
#endif
