#include "globals.h"
#include "module-cccam.h"
#include "module-led.h"
#include "module-stat.h"
#include "module-dvbapi.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-work.h"
#include "reader-common.h"
#include "oscam-config.h"

extern CS_MUTEX_LOCK system_lock;
extern CS_MUTEX_LOCK ecmcache_lock;
extern struct ecm_request_t *ecmcwcache;
extern struct s_cardsystem cardsystems[CS_MAX_MOD];

const char *RDR_CD_TXT[] =
{
	"cd", "dsr", "cts", "ring", "none",
	"gpio1", "gpio2", "gpio3", "gpio4", "gpio5", "gpio6", "gpio7",
	NULL
};

static int32_t ecm_ratelimit_findspace(struct s_reader *reader, ECM_REQUEST *er, struct ecmrl rl, int32_t reader_mode)
{

	int32_t h, foundspace = -1;
	int32_t maxecms = MAXECMRATELIMIT; // init maxecms
	int32_t totalecms = 0; // init totalecms
	time_t actualtime = time(NULL);
	for(h = 0; h < MAXECMRATELIMIT; h++)    // release slots with srvid that are overtime, even if not called from reader module to maximize available slots!
	{
		if(reader->rlecmh[h].last == -1) { continue; }
		if((actualtime - reader->rlecmh[h].last) >= (reader->rlecmh[h].ratelimitseconds + reader->rlecmh[h].srvidholdseconds))
		{
			cs_debug_mask(D_TRACE, "ratelimiter srvid %04X released from slot #%d/%d of reader %s (%d>=%d ratelimitsec + %d sec srvidhold!)",
						  reader->rlecmh[h].srvid, h + 1, MAXECMRATELIMIT, reader->label, (int)(actualtime - reader->rlecmh[h].last),
						  reader->rlecmh[h].ratelimitseconds, reader->rlecmh[h].srvidholdseconds);
			reader->rlecmh[h].last = -1;
			reader->rlecmh[h].srvid = -1;
			reader->rlecmh[h].kindecm = 0;
		}
		if(reader->rlecmh[h].last == -1) { continue; }
		if(reader->rlecmh[h].ratelimitecm < maxecms) { maxecms = reader->rlecmh[h].ratelimitecm; }  // we found a more critical ratelimit srvid
		totalecms++;
	}

	cs_debug_mask(D_TRACE, "ratelimiter found total of %d srvid for reader %s most critical is limited to %d requests", totalecms, reader->label, maxecms);

	if(reader->cooldown[0] && reader->cooldownstate != 1) { maxecms = MAXECMRATELIMIT; }  // dont apply ratelimits if cooldown isnt in use or not in effect

	for(h = 0; h < MAXECMRATELIMIT; h++)    // check if srvid is already in a slot
	{
		if(reader->rlecmh[h].last == -1) { continue; }
		if(reader->rlecmh[h].srvid == er->srvid && reader->rlecmh[h].caid == rl.caid && reader->rlecmh[h].provid == rl.provid
				&& (!reader->rlecmh[h].chid || (reader->rlecmh[h].chid == rl.chid)))
		{
			cs_debug_mask(D_TRACE, "ratelimiter found srvid %04X for %d sec in slot #%d/%d of reader %s", er->srvid,
						  (int)(actualtime - reader->rlecmh[h].last), h + 1, MAXECMRATELIMIT, reader->label);

			// check ecmunique if enabled and ecmunique time is done
			if(reader_mode && reader->ecmunique)
			{
				if(actualtime - reader->rlecmh[h].last < reader->ratelimitseconds)
				{
					if(memcmp(reader->rlecmh[h].ecmd5, er->ecmd5, CS_ECMSTORESIZE))
					{
						if(er->ecm[0] == reader->rlecmh[h].kindecm)
						{
							char ecmd5[17 * 3];
							cs_hexdump(0, reader->rlecmh[h].ecmd5, 16, ecmd5, sizeof(ecmd5));
							cs_debug_mask(D_TRACE, "ratelimiter ecm %s in this slot for next %d seconds!", ecmd5,
										  (int)(reader->rlecmh[h].ratelimitseconds - (actualtime - reader->rlecmh[h].last)));

							struct ecm_request_t *erold = NULL;
							if(!cs_malloc(&erold, sizeof(struct ecm_request_t)))
								{ return -2; }
							memcpy(erold, er, sizeof(struct ecm_request_t)); // copy ecm all
							memcpy(erold->ecmd5, reader->rlecmh[h].ecmd5, CS_ECMSTORESIZE); // replace md5 hash
							struct ecm_request_t *ecm = NULL;
							ecm = check_cwcache(erold, erold->client); //CHECK IF FOUND ECM IN CACHE
							free(erold);
							if(ecm)   //found in cache
								{ write_ecm_answer(reader, er, ecm->rc, ecm->rcEx, ecm->cw, NULL); }
							else
								{ write_ecm_answer(reader, er, E_NOTFOUND, E2_RATELIMIT, NULL, "Ratelimiter: no slots free!"); }
							return -2;
						}
						continue;
					}
				}
				if((er->ecm[0] == reader->rlecmh[h].kindecm)
						&& ((actualtime - reader->rlecmh[h].last) <= (reader->ratelimitseconds + reader->srvidholdseconds)))
				{

					cs_debug_mask(D_TRACE, "ratelimiter srvid %04X ecm type %s, only allowing %s for next %d seconds in slot #%d/%d of reader %s -> skipping this slot!", reader->rlecmh[h].srvid, (reader->rlecmh[h].kindecm == 0x80 ? "even" : "odd"), (reader->rlecmh[h].kindecm == 0x80 ? "odd" : "even"),
								  (int)(reader->rlecmh[h].ratelimitseconds + reader->rlecmh[h].srvidholdseconds - (actualtime - reader->rlecmh[h].last)),
								  h + 1, maxecms, reader->label);
					continue;
				}
			}

			if(h > 0)
			{
				for(foundspace = 0; foundspace < h; foundspace++)    // check for free lower slot
				{
					if(reader->rlecmh[foundspace].last == -1)
					{
						reader->rlecmh[foundspace] = reader->rlecmh[h]; // replace ecm request info
						reader->rlecmh[h].srvid = -1;
						reader->rlecmh[h].last = -1;
						if(foundspace < maxecms)
						{
							cs_debug_mask(D_TRACE, "ratelimiter moved srvid %04X to slot #%d/%d of reader %s", er->srvid, foundspace + 1, maxecms, reader->label);
							return foundspace; // moving to lower free slot!
						}
						else
						{
							cs_debug_mask(D_TRACE, "ratelimiter removed srvid %04X from slot #%d/%d of reader %s", er->srvid, foundspace + 1, maxecms, reader->label);
							reader->rlecmh[foundspace].last = -1; // free this slot since we are over ratelimit!
							return -1; // sorry, ratelimit!
						}
					}
				}
			}
			if(h < maxecms)    // found but cant move to lower position!
			{
				return h; // return position if within ratelimits!
			}
			else
			{
				reader->rlecmh[h].last = -1; // free this slot since we are over ratelimit!
				cs_debug_mask(D_TRACE, "ratelimiter removed srvid %04X from slot #%d/%d of reader %s", er->srvid, h + 1, maxecms, reader->label);
				return -1; // sorry, ratelimit!
			}
		}
	}

	// srvid not found in slots!

	if((reader->cooldown[0] && reader->cooldownstate == 1) || !reader->cooldown[0])
	{
		; // do we use cooldown at all, are we in cooldown fase?

		// we are in cooldown or no cooldown configured!
		if(totalecms + 1 > maxecms || totalecms + 1 > rl.ratelimitecm)  // check if this channel fits in!
		{
			cs_debug_mask(D_TRACE, "ratelimiter for reader %s has no free slots!", reader->label);
			return -1;
		}
	}
	else
	{
		maxecms = MAXECMRATELIMIT; // no limits right now!
	}

	for(h = 0; h < maxecms; h++)    // check for free slot
	{
		if(reader->rlecmh[h].last == -1)
		{
			if(reader_mode) { cs_debug_mask(D_TRACE, "ratelimiter added srvid %04X to slot #%d/%d of reader %s", er->srvid, h + 1, maxecms, reader->label); }
			return h; // free slot found -> assign it!
		}
		else { cs_debug_mask(D_TRACE, "ratelimiter srvid %04X for %d seconds present in slot #%d/%d of reader %s", reader->rlecmh[h].srvid, (int)(actualtime - reader->rlecmh[h].last), h + 1, maxecms, reader->label); }  //occupied slots
	}

#ifdef HAVE_DVBAPI
	/* Overide ratelimit priority for dvbapi request */

	foundspace = -1;
	if((cfg.dvbapi_enabled == 1) && streq(er->client->account->usr, cfg.dvbapi_usr))
	{
		if((reader->lastdvbapirateoverride) < (actualtime - reader->ratelimitseconds))
		{
			time_t minecmtime = actualtime;
			for(h = 0; h < MAXECMRATELIMIT; h++)
			{
				if(reader->rlecmh[h].last < minecmtime)
				{
					minecmtime = reader->rlecmh[h].last;
					foundspace = h;
				}
			}
			reader->lastdvbapirateoverride = actualtime;
			cs_debug_mask(D_TRACE, "prioritizing DVBAPI user %s over other watching client", er->client->account->usr);
			cs_debug_mask(D_TRACE, "ratelimiter forcing srvid %04X into slot #%d/%d of reader %s", er->srvid, foundspace + 1, maxecms, reader->label);
			return foundspace;
		}
		else cs_debug_mask(D_TRACE, "DVBAPI User %s is switching too fast for ratelimit and can't be prioritized!",
							   er->client->account->usr);
	}

#endif

	return (-1); // no slot found
}

static void sort_ecmrl(struct s_reader *reader)
{
	int32_t i, j, loc;
	struct ecmrl tmp;

	for(i = 0; i < reader->ratelimitecm; i++)   // inspect all slots
	{
		if(reader->rlecmh[i].last == -1) { continue; }  // skip empty slots
		loc = i;
		tmp = reader->rlecmh[i]; // tmp is ecm in slot to evaluate

		for(j = i + 1; j < MAXECMRATELIMIT; j++)   // inspect all slots above the slot to be inspected
		{
			if(reader->rlecmh[j].last == -1) { continue; }  // skip empty slots
			if(reader->rlecmh[j].last > tmp.last)   // is higher slot holding a younger ecmrequest?
			{
				loc = j; // found a younger one
				tmp = reader->rlecmh[j]; // copy the ecm in younger slot
			}
		}

		if(loc != i)   // Did we find a younger ecmrequest?
		{
			reader->rlecmh[loc] = reader->rlecmh[i]; // place older request in slot of younger one we found
			reader->rlecmh[i] = tmp; // place younger request in slot of older request
		}
	}

	// release all slots above ratelimit ecm
	for(i = reader->ratelimitecm; i < MAXECMRATELIMIT; i++)
	{
		reader->rlecmh[i].last = -1;
		reader->rlecmh[i].srvid = -1;
	}

}

int32_t ecm_ratelimit_check(struct s_reader *reader, ECM_REQUEST *er, int32_t reader_mode)
// If reader_mode is 1, ECM_REQUEST need to be assigned to reader and slot.
// Else just report if a free slot is available.
{
	// No rate limit set
	if(!reader->ratelimitecm)
	{
		return OK;
	}

	int32_t foundspace = -1, h, maxslots = MAXECMRATELIMIT; //init slots to oscam global maximums
	struct ecmrl rl;
	rl = get_ratelimit(er);

	if(rl.ratelimitecm > 0)
	{
		cs_debug_mask(D_TRACE, "Ratelimit found for CAID: %04X PROVID: %06X SRVID: %04X CHID: %04X maxecms: %d cycle: %ds srvidhold: %ds",
					  rl.caid, rl.provid, rl.srvid, rl.chid, rl.ratelimitecm, rl.ratelimitseconds, rl.srvidholdseconds);
	}
	else   // nothing found: apply general reader limits
	{
		rl.ratelimitecm = reader->ratelimitecm;
		rl.ratelimitseconds = reader->ratelimitseconds;
		rl.srvidholdseconds = reader->srvidholdseconds;
		rl.caid = er->caid;
		rl.provid = er->prid;
		rl.chid = er->chid;
		rl.srvid = er->srvid;
		cs_debug_mask(D_TRACE, "Ratelimit apply readerdefault for CAID: %04X PROVID: %06X SRVID: %04X CHID: %04X maxecms: %d cycle: %ds srvidhold: %ds",
					  rl.caid, rl.provid, rl.srvid, rl.chid, rl.ratelimitecm, rl.ratelimitseconds, rl.srvidholdseconds);
	}
	// Below this line: rate limit functionality.
	// No cooldown set
	if(!reader->cooldown[0])
	{
		cs_debug_mask(D_TRACE, "ratelimiter find a slot for srvid %04X on reader %s", er->srvid, reader->label);
		foundspace = ecm_ratelimit_findspace(reader, er, rl, reader_mode);
		if(foundspace < 0)
		{
			if(reader_mode)
			{
				if(foundspace != -2)
				{
					cs_debug_mask(D_TRACE, "ratelimiter no free slot for srvid %04X on reader %s -> dropping!", er->srvid, reader->label);
					write_ecm_answer(reader, er, E_NOTFOUND, E2_RATELIMIT, NULL, "Ratelimiter: no slots free!");
				}
			}

			return ERROR; // not even trowing an error... obvious reason ;)
		}
		else  //we are within ecmratelimits
		{
			if(reader_mode)
			{
				// Register new slot
				//reader->rlecmh[foundspace].srvid=er->srvid; // register srvid
				reader->rlecmh[foundspace] = rl; // register this srvid ratelimit params
				reader->rlecmh[foundspace].last = time(NULL); // register request time
				memcpy(reader->rlecmh[foundspace].ecmd5, er->ecmd5, CS_ECMSTORESIZE);// register ecmhash
				reader->rlecmh[foundspace].kindecm = er->ecm[0]; // register kind of ecm
			}

			return OK;
		}
	}

	// Below this line: rate limit functionality with cooldown option.

	// Cooldown state cycle:
	// state = 0: Cooldown setup phase. No rate limit set.
	//  If number of ecm request exceed reader->ratelimitecm, cooldownstate goes to 2.
	// state = 2: Cooldown delay phase. No rate limit set.
	//  If number of ecm request still exceed reader->ratelimitecm at end of cooldown delay phase,
	//      cooldownstate goes to 1 (rate limit phase).
	//  Else return back to setup phase (state 0).
	// state = 1: Cooldown ratelimit phase. Rate limit set.
	//  If cooldowntime reader->cooldown[1] is elapsed, return to cooldown setup phase (state 0).

	if(reader->cooldownstate == 1)    // Cooldown in ratelimit phase
	{
		if(time(NULL) - reader->cooldowntime <= reader->cooldown[1])  // check if cooldowntime is elapsed
			{ maxslots = reader->ratelimitecm; } // use user defined ratelimitecm
		else   // Cooldown time is elapsed
		{
			reader->cooldownstate = 0; // set cooldown setup phase
			reader->cooldowntime = 0; // reset cooldowntime
			maxslots = MAXECMRATELIMIT; //use oscam defined max slots
			cs_log("Reader: %s ratelimiter returning to setup phase cooling down period of %d seconds is done!",
				   reader->label, reader->cooldown[1]);
		}
	} // if cooldownstate == 1

	if(reader->cooldownstate == 2 && time(NULL) - reader->cooldowntime > reader->cooldown[0])
	{
		// Need to check if the otherslots are not exceeding the ratelimit at the moment that
		// cooldown[0] time was exceeded!
		// time_t actualtime = reader->cooldowntime + reader->cooldown[0];
		maxslots = 0; // maxslots is used as counter
		for(h = 0; h < MAXECMRATELIMIT; h++)
		{
			if(reader->rlecmh[h].last == -1) { continue; }  // skip empty slots
			// how many active slots are registered at end of cooldown delay period
			if(reader->cooldowntime + reader->cooldown[0] - reader->rlecmh[h].last <= reader->ratelimitseconds)
			{
				maxslots++;
				if(maxslots >= reader->ratelimitecm) { break; }  // Need to go cooling down phase
			}
		}

		if(maxslots < reader->ratelimitecm)
		{
			reader->cooldownstate = 0; // set cooldown setup phase
			reader->cooldowntime = 0; // reset cooldowntime
			maxslots = MAXECMRATELIMIT; // maxslots is maxslots again
			cs_log("Reader: %s ratelimiter returning to setup phase after %d seconds cooldowndelay!",
				   reader->label, reader->cooldown[0]);
		}
		else
		{
			reader->cooldownstate = 1; // Entering ratelimit for cooldown ratelimitseconds
			reader->cooldowntime = time(NULL); // set time to enforce ecmratelimit for defined cooldowntime
			maxslots = reader->ratelimitecm; // maxslots is maxslots again
			sort_ecmrl(reader); // keep youngest ecm requests in list + housekeeping
			cs_log("Reader: %s ratelimiter starting cooling down period of %d seconds!", reader->label, reader->cooldown[1]);
		}
	} // if cooldownstate == 2

	cs_debug_mask(D_TRACE, "ratelimiter cooldownphase %d find a slot for srvid %04X on reader %s", reader->cooldownstate, er->srvid, reader->label);
	foundspace = ecm_ratelimit_findspace(reader, er, rl, reader_mode);

	if(foundspace < 0)
	{
		if(reader_mode)
		{
			if(foundspace != -2)
			{
				cs_debug_mask(D_TRACE, "ratelimiter cooldownphase %d no free slot for srvid %04X on reader %s -> dropping!",
							  reader->cooldownstate, er->srvid, reader->label);
				write_ecm_answer(reader, er, E_NOTFOUND, E2_RATELIMIT, NULL, "Ratelimiter: cooldown no slots free!");
			}
		}

		return ERROR; // not even trowing an error... obvious reason ;)
	}
	else  //we are within ecmratelimits
	{
		if(reader_mode)
		{
			// Register new slot
			//reader->rlecmh[foundspace].srvid=er->srvid; // register srvid
			reader->rlecmh[foundspace] = rl; // register this srvid ratelimit params
			reader->rlecmh[foundspace].last = time(NULL); // register request time
			memcpy(reader->rlecmh[foundspace].ecmd5, er->ecmd5, CS_ECMSTORESIZE);// register ecmhash
			reader->rlecmh[foundspace].kindecm = er->ecm[0]; // register kind of ecm
		}
	}

	if(reader->cooldownstate == 0 && foundspace >= reader->ratelimitecm)
	{
		if(!reader_mode)    // No actual ecm request, just check
		{

			return OK;
		}
		cs_log("Reader: %s ratelimiter cooldown detected overrun ecmratelimit of %d during setup phase!",
			   reader->label, (foundspace - reader->ratelimitecm + 1));
		reader->cooldownstate = 2; // Entering cooldowndelay phase
		reader->cooldowntime = time(NULL); // Set cooldowntime to calculate delay
		cs_debug_mask(D_TRACE, "ratelimiter cooldowndelaying %d seconds", reader->cooldown[0]);
	}

	// Cooldown state housekeeping is done. There is a slot available.
	if(reader_mode)
	{
		// Register new slot
		//reader->rlecmh[foundspace].srvid=er->srvid; // register srvid
		reader->rlecmh[foundspace] = rl; // register this srvid ratelimit params
		reader->rlecmh[foundspace].last = time(NULL); // register request time
		memcpy(reader->rlecmh[foundspace].ecmd5, er->ecmd5, CS_ECMSTORESIZE);// register ecmhash
		reader->rlecmh[foundspace].kindecm = er->ecm[0]; // register kind of ecm
	}

	return OK;
}

struct s_cardsystem *get_cardsystem_by_caid(uint16_t caid)
{
	int32_t i, j;
	for(i = 0; i < CS_MAX_MOD; i++)
	{
		for(j = 0; j < (int)ARRAY_SIZE(cardsystems[i].caids); j++)
		{
			uint16_t cs_caid = cardsystems[i].caids[j];
			if(!cs_caid)
				{ continue; }
			if(cs_caid == caid || cs_caid == caid >> 8)
				{ return &cardsystems[i]; }
		}
	}
	return NULL;
}

struct s_reader *get_reader_by_label(char *lbl)
{
	struct s_reader *rdr;
	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	{
		if(streq(lbl, rdr->label))
			{ break; }
	}
	return rdr;
}

char *reader_get_type_desc(struct s_reader *rdr, int32_t extended)
{
	char *desc = "unknown";
	if(rdr->crdr.desc)
		{ return rdr->crdr.desc; }
	if(is_network_reader(rdr) || rdr->typ == R_SERIAL)
	{
		if(rdr->ph.desc)
			{ desc = rdr->ph.desc; }
	}
	if(rdr->typ == R_NEWCAMD && rdr->ncd_proto == NCD_524)
		{ desc = "newcamd524"; }
	else if(extended && rdr->typ == R_CCCAM && cccam_client_extended_mode(rdr->client))
	{
		desc = "cccam ext";
	}
	return desc;
}

bool hexserialset(struct s_reader *rdr)
{
	int i;
	if(!rdr)
		{ return false; }
	for(i = 0; i < 8; i++)
	{
		if(rdr->hexserial[i])
			{ return true; }
	}
	return false;
}

void hexserial_to_newcamd(uchar *source, uchar *dest, uint16_t caid)
{
	if(caid == 0x5581 || caid == 0x4aee)    // Bulcrypt
	{
		dest[0] = 0x00;
		dest[1] = 0x00;
		memcpy(dest + 2, source, 4);
		return;
	}
	caid = caid >> 8;
	if(caid == 0x17 || caid == 0x06)    // Betacrypt or Irdeto
	{
		// only 4 Bytes Hexserial for newcamd clients (Hex Base + Hex Serial)
		// first 2 Byte always 00
		dest[0] = 0x00; //serial only 4 bytes
		dest[1] = 0x00; //serial only 4 bytes
		// 1 Byte Hex Base (see reader-irdeto.c how this is stored in "source")
		dest[2] = source[3];
		// 3 Bytes Hex Serial (see reader-irdeto.c how this is stored in "source")
		dest[3] = source[0];
		dest[4] = source[1];
		dest[5] = source[2];
	}
	else if(caid == 0x05 || caid == 0x0D)
	{
		dest[0] = 0x00;
		memcpy(dest + 1, source, 5);
	}
	else
	{
		memcpy(dest, source, 6);
	}
}

void newcamd_to_hexserial(uchar *source, uchar *dest, uint16_t caid)
{
	caid = caid >> 8;
	if(caid == 0x17 || caid == 0x06)    // Betacrypt or Irdeto
	{
		memcpy(dest, source + 3, 3);
		dest[3] = source[2];
		dest[4] = 0;
		dest[5] = 0;
	}
	else if(caid == 0x05 || caid == 0x0D)
	{
		memcpy(dest, source + 1, 5);
		dest[5] = 0;
	}
	else
	{
		memcpy(dest, source, 6);
	}
}

/**
 * add one entitlement item to entitlements of reader.
 **/
void cs_add_entitlement(struct s_reader *rdr, uint16_t caid, uint32_t provid, uint64_t id, uint32_t class, time_t start, time_t end, uint8_t type)
{
	if(!rdr->ll_entitlements) { rdr->ll_entitlements = ll_create("ll_entitlements"); }

	S_ENTITLEMENT *item;
	if(cs_malloc(&item, sizeof(S_ENTITLEMENT)))
	{

		// fill item
		item->caid = caid;
		item->provid = provid;
		item->id = id;
		item->class = class;
		item->start = start;
		item->end = end;
		item->type = type;

		//add item
		ll_append(rdr->ll_entitlements, item);

		// cs_debug_mask(D_TRACE, "entitlement: Add caid %4X id %4X %s - %s ", item->caid, item->id, item->start, item->end);
	}

}

/**
 * clears entitlements of reader.
 **/
void cs_clear_entitlement(struct s_reader *rdr)
{
	if(!rdr->ll_entitlements)
		{ return; }

	ll_clear_data(rdr->ll_entitlements);
}


void casc_check_dcw(struct s_reader *reader, int32_t idx, int32_t rc, uchar *cw)
{
	int32_t i, pending = 0;
	time_t t = time(NULL);
	ECM_REQUEST *ecm;
	struct s_client *cl = reader->client;

	if(!check_client(cl)) { return; }

	for(i = 0; i < cfg.max_pending; i++)
	{
		ecm = &cl->ecmtask[i];
		if((ecm->rc >= 10) && ecm->caid == cl->ecmtask[idx].caid && (!memcmp(ecm->ecmd5, cl->ecmtask[idx].ecmd5, CS_ECMSTORESIZE)))
		{
			if(rc)
			{
				write_ecm_answer(reader, ecm, E_FOUND, 0, cw, NULL);
			}
			else
			{
				write_ecm_answer(reader, ecm, E_NOTFOUND, 0 , NULL, NULL);
			}
			ecm->idx = 0;
			ecm->rc = 0;
		}

		if(ecm->rc >= 10 && (t - (uint32_t)ecm->tps.time > ((cfg.ctimeout + 500) / 1000) + 1))  // drop timeouts
		{
			ecm->rc = 0;
		}

		if(ecm->rc >= 10)
			{ pending++; }
	}
	cl->pending = pending;
}

int32_t hostResolve(struct s_reader *rdr)
{
	struct s_client *cl = rdr->client;

	if(!cl) { return 0; }

	IN_ADDR_T last_ip;
	IP_ASSIGN(last_ip, cl->ip);
	cs_resolve(rdr->device, &cl->ip, &cl->udp_sa, &cl->udp_sa_len);
	IP_ASSIGN(SIN_GET_ADDR(cl->udp_sa), cl->ip);

	if(!IP_EQUAL(cl->ip, last_ip))
	{
		cs_log("%s: resolved ip=%s", rdr->device, cs_inet_ntoa(cl->ip));
	}

	return IP_ISSET(cl->ip);
}

void clear_block_delay(struct s_reader *rdr)
{
	rdr->tcp_block_delay = 0;
	cs_ftime(&rdr->tcp_block_connect_till);
}

void block_connect(struct s_reader *rdr)
{
	if(!rdr->tcp_block_delay)
		{ rdr->tcp_block_delay = 100; } //starting blocking time, 100ms
	cs_ftime(&rdr->tcp_block_connect_till);
	rdr->tcp_block_connect_till.time += rdr->tcp_block_delay / 1000;
	rdr->tcp_block_connect_till.millitm += rdr->tcp_block_delay % 1000;
	rdr->tcp_block_delay *= 4; //increment timeouts
	if(rdr->tcp_block_delay >= 60 * 1000)
		{ rdr->tcp_block_delay = 60 * 1000; } //max 1min, todo config
	rdr_debug_mask(rdr, D_TRACE, "tcp connect blocking delay set to %d", rdr->tcp_block_delay);
}

int32_t is_connect_blocked(struct s_reader *rdr)
{
	struct timeb cur_time;
	cs_ftime(&cur_time);
	int32_t blocked = (rdr->tcp_block_delay && comp_timeb(&cur_time, &rdr->tcp_block_connect_till) < 0);
	if(blocked)
	{
		int32_t ts = 1000 * (rdr->tcp_block_connect_till.time - cur_time.time)
					 + rdr->tcp_block_connect_till.millitm - cur_time.millitm;
		rdr_debug_mask(rdr, D_TRACE, "connection blocked, retrying in %ds", ts / 1000);
	}
	return blocked;
}

int32_t network_tcp_connection_open(struct s_reader *rdr)
{
	if(!rdr) { return -1; }
	struct s_client *client = rdr->client;
	struct SOCKADDR loc_sa;

	memset((char *)&client->udp_sa, 0, sizeof(client->udp_sa));

	IN_ADDR_T last_ip;
	IP_ASSIGN(last_ip, client->ip);
	if(!hostResolve(rdr))
		{ return -1; }

	if(!IP_EQUAL(last_ip, client->ip))  //clean blocking delay on ip change:
		{ clear_block_delay(rdr); }

	if(is_connect_blocked(rdr))    //inside of blocking delay, do not connect!
	{
		return -1;
	}

	if(client->reader->r_port <= 0)
	{
		rdr_log(client->reader, "invalid port %d for server %s", client->reader->r_port, client->reader->device);
		return -1;
	}

	client->is_udp = (rdr->typ == R_CAMD35);

	rdr_log(rdr, "connecting to %s:%d", rdr->device, rdr->r_port);

	if(client->udp_fd)
		{ rdr_log(rdr, "WARNING: client->udp_fd was not 0"); }

	int s_domain = PF_INET;
	int s_family = AF_INET;
#ifdef IPV6SUPPORT
	if(!IN6_IS_ADDR_V4MAPPED(&rdr->client->ip) && !IN6_IS_ADDR_V4COMPAT(&rdr->client->ip))
	{
		s_domain = PF_INET6;
		s_family = AF_INET6;
	}
#endif
	int s_type   = client->is_udp ? SOCK_DGRAM : SOCK_STREAM;
	int s_proto  = client->is_udp ? IPPROTO_UDP : IPPROTO_TCP;

	if((client->udp_fd = socket(s_domain, s_type, s_proto)) < 0)
	{
		rdr_log(rdr, "Socket creation failed (errno=%d %s)", errno, strerror(errno));
		client->udp_fd = 0;
		block_connect(rdr);
		return -1;
	}

	set_socket_priority(client->udp_fd, cfg.netprio);

	int32_t keep_alive = 1;
	setsockopt(client->udp_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keep_alive, sizeof(keep_alive));

	int32_t flag = 1;
	setsockopt(client->udp_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flag, sizeof(flag));

	if(setsockopt(client->udp_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&flag, sizeof(flag)) < 0)
	{
		rdr_log(rdr, "setsockopt failed (errno=%d: %s)", errno, strerror(errno));
		client->udp_fd = 0;
		block_connect(rdr);
		return -1;
	}

#ifdef SO_REUSEPORT
	setsockopt(client->udp_fd, SOL_SOCKET, SO_REUSEPORT, (void *)&flag, sizeof(flag));
#endif

	memset((char *)&loc_sa, 0, sizeof(loc_sa));
	SIN_GET_FAMILY(loc_sa) = s_family;
	if(IP_ISSET(cfg.srvip))
		{ IP_ASSIGN(SIN_GET_ADDR(loc_sa), cfg.srvip); }
	else
		{ SIN_GET_ADDR(loc_sa) = ADDR_ANY; }

	if(client->reader->l_port)
		{ SIN_GET_PORT(loc_sa) = htons(client->reader->l_port); }
	if(bind(client->udp_fd, (struct sockaddr *)&loc_sa, sizeof(loc_sa)) < 0)
	{
		rdr_log(rdr, "bind failed (errno=%d %s)", errno, strerror(errno));
		close(client->udp_fd);
		client->udp_fd = 0;
		block_connect(rdr);
		return -1;
	}

#ifdef IPV6SUPPORT
	if(IN6_IS_ADDR_V4MAPPED(&rdr->client->ip) || IN6_IS_ADDR_V4COMPAT(&rdr->client->ip))
	{
		((struct sockaddr_in *)(&client->udp_sa))->sin_family = AF_INET;
		((struct sockaddr_in *)(&client->udp_sa))->sin_port = htons((uint16_t)client->reader->r_port);
	}
	else
	{
		((struct sockaddr_in6 *)(&client->udp_sa))->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)(&client->udp_sa))->sin6_port = htons((uint16_t)client->reader->r_port);
	}
#else
	client->udp_sa.sin_family = AF_INET;
	client->udp_sa.sin_port = htons((uint16_t)client->reader->r_port);
#endif

	rdr_debug_mask(rdr, D_TRACE, "socket open for %s fd=%d", rdr->ph.desc, client->udp_fd);

	if(client->is_udp)
	{
		rdr->tcp_connected = 1;
		return client->udp_fd;
	}

	int32_t fl = fcntl(client->udp_fd, F_GETFL);
	fcntl(client->udp_fd, F_SETFL, O_NONBLOCK);

	int32_t res = connect(client->udp_fd, (struct sockaddr *)&client->udp_sa, client->udp_sa_len);
	if(res == -1)
	{
		int32_t r = -1;
		if(errno == EINPROGRESS || errno == EALREADY)
		{
			struct pollfd pfd;
			pfd.fd = client->udp_fd;
			pfd.events = POLLOUT;
			int32_t rc = poll(&pfd, 1, 3000);
			if(rc > 0)
			{
				uint32_t l = sizeof(r);
				if(getsockopt(client->udp_fd, SOL_SOCKET, SO_ERROR, &r, (socklen_t *)&l) != 0)
					{ r = -1; }
				else
					{ errno = r; }
			}
			else
			{
				errno = ETIMEDOUT;
			}
		}
		if(r != 0)
		{
			rdr_log(rdr, "connect failed: %s", strerror(errno));
			block_connect(rdr); //connect has failed. Block connect for a while
			close(client->udp_fd);
			client->udp_fd = 0;
			return -1;
		}
	}

	fcntl(client->udp_fd, F_SETFL, fl); //restore blocking mode

	setTCPTimeouts(client->udp_fd);
	clear_block_delay(rdr);
	client->last = client->login = time((time_t *)0);
	client->last_caid = client->last_srvid = 0;
	client->pfd = client->udp_fd;
	rdr->tcp_connected = 1;
	rdr_debug_mask(rdr, D_TRACE, "connect succesfull fd=%d", client->udp_fd);
	return client->udp_fd;
}

void network_tcp_connection_close(struct s_reader *reader, char *reason)
{
	if(!reader)
	{
		//only proxy reader should call this, client connections are closed on thread cleanup
		cs_log("WARNING: invalid client");
		cs_disconnect_client(cur_client());
		return;
	}

	struct s_client *cl = reader->client;
	if(!cl) { return; }
	int32_t fd = cl->udp_fd;

	int32_t i;

	if(fd)
	{
		rdr_log(reader, "disconnected: reason %s", reason ? reason : "undef");
		close(fd);

		cl->udp_fd = 0;
		cl->pfd = 0;
	}

	reader->tcp_connected = 0;
	reader->card_status = UNKNOWN;
	cl->logout = time((time_t *)0);

	if(cl->ecmtask)
	{
		for(i = 0; i < cfg.max_pending; i++)
		{
			cl->ecmtask[i].idx = 0;
			cl->ecmtask[i].rc = 0;
		}
	}
	// newcamd message ids are stored as a reference in ecmtask[].idx
	// so we need to reset them aswell
	if(reader->typ == R_NEWCAMD)
		{ cl->ncd_msgid = 0; }
}

int32_t casc_process_ecm(struct s_reader *reader, ECM_REQUEST *er)
{
	int32_t rc, n, i, sflag, pending = 0;
	time_t t;//, tls;
	struct s_client *cl = reader->client;

	if(!cl || !cl->ecmtask)
	{
		rdr_log(reader, "WARNING: ecmtask not a available");
		return -1;
	}

	uchar buf[512];

	t = time((time_t *)0);
	ECM_REQUEST *ecm;
	for(i = 0; i < cfg.max_pending; i++)
	{
		ecm = &cl->ecmtask[i];
		if((ecm->rc >= 10) && (t - (uint32_t)ecm->tps.time > ((cfg.ctimeout + 500) / 1000) + 1))  // drop timeouts
		{
			ecm->rc = 0;
		}
	}

	for(n = -1, i = 0, sflag = 1; i < cfg.max_pending; i++)
	{
		ecm = &cl->ecmtask[i];
		if(n < 0 && (ecm->rc < 10))  // free slot found
			{ n = i; }

		// ecm already pending
		// ... this level at least
		if((ecm->rc >= 10) &&  er->caid == ecm->caid && (!memcmp(er->ecmd5, ecm->ecmd5, CS_ECMSTORESIZE)))
			{ sflag = 0; }

		if(ecm->rc >= 10)
			{ pending++; }
	}
	cl->pending = pending;

	if(n < 0)
	{
		rdr_log(reader, "WARNING: reader ecm pending table overflow !!");
		return (-2);
	}

	memcpy(&cl->ecmtask[n], er, sizeof(ECM_REQUEST));
	cl->ecmtask[n].matching_rdr = NULL; //This avoids double free of matching_rdr!
#ifdef CS_CACHEEX
	cl->ecmtask[n].csp_lastnodes = NULL; //This avoids double free of csp_lastnodes!
#endif
	cl->ecmtask[n].parent = er;

	if(reader->typ == R_NEWCAMD)
		{ cl->ecmtask[n].idx = (cl->ncd_msgid == 0) ? 2 : cl->ncd_msgid + 1; }
	else
	{
		if(!cl->idx)
			{ cl->idx = 1; }
		cl->ecmtask[n].idx = cl->idx++;
	}

	cl->ecmtask[n].rc = 10;
	cs_debug_mask(D_TRACE, "---- ecm_task %d, idx %d, sflag=%d", n, cl->ecmtask[n].idx, sflag);

	cs_ddump_mask(D_ATR, er->ecm, er->ecmlen, "casc ecm (%s):", (reader) ? reader->label : "n/a");
	rc = 0;
	if(sflag)
	{
		if((rc = reader->ph.c_send_ecm(cl, &cl->ecmtask[n], buf)))
			{ casc_check_dcw(reader, n, 0, cl->ecmtask[n].cw); }  // simulate "not found"
		else
			{ cl->last_idx = cl->ecmtask[n].idx; }
		reader->last_s = t;   // used for inactive_timeout and reconnect_timeout in TCP reader
	}

	if(cl->idx > 0x1ffe) { cl->idx = 1; }

	return (rc);
}

void reader_get_ecm(struct s_reader *reader, ECM_REQUEST *er)
{
	if(!reader) { return; }
	struct s_client *cl = reader->client;
	if(!check_client(cl)) { return; }

	if(er->rc <= E_STOPPED)
	{
		//TODO: not sure what this is for, but it was in mpcs too.
		// ecm request was already answered when the request was started (this ECM_REQUEST is a copy of client->ecmtask[] ECM_REQUEST).
		// send_dcw is a client function but reader_get_ecm is only called from reader functions where client->ctyp is not set and so send_dcw() will segfault.
		// so we could use send_dcw(er->client, er) or write_ecm_answer(reader, er), but send_dcw wont be threadsafe from here cause there may be multiple threads accessing same s_client struct.
		// maybe rc should be checked before request is sent to reader but i could not find the reason why this is happening now and not in v1.10 (zetack)
		//send_dcw(cl, er);
		char ecmd5[17 * 3];
		cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
		rdr_debug_mask(reader, D_TRACE, "skip ecmhash %s, rc=%d", ecmd5, er->rc);
		return;
	}

	if(!chk_bcaid(er, &reader->ctab))
	{
		rdr_debug_mask(reader, D_READER, "caid %04X filtered", er->caid);
		write_ecm_answer(reader, er, E_NOTFOUND, E2_CAID, NULL, NULL);
		return;
	}

	//CHECK if ecm already sent to reader
	struct s_ecm_answer *ea_er = get_ecm_answer(reader, er);
	if(!ea_er) { return; }

	struct s_ecm_answer *ea = NULL, *ea_prev = NULL;
	struct ecm_request_t *ecm;
	time_t timeout = time(NULL) - cfg.max_cache_time;

	cs_readlock(&ecmcache_lock);
	for(ecm = ecmcwcache; ecm; ecm = ecm->next)
	{
		if(ecm->tps.time <= timeout)
			{ break; }

		if(!ecm->matching_rdr || ecm == er || ecm->rc == E_99) { continue; }

		//match same ecm
		if(er->caid == ecm->caid && (!memcmp(er->ecmd5, ecm->ecmd5, CS_ECMSTORESIZE)))
		{
			//check if ask this reader
			ea = get_ecm_answer(reader, ecm);
			if(ea && !ea->is_pending && (ea->status & REQUEST_SENT)) { break; }
			ea = NULL;
		}
	}
	cs_readunlock(&ecmcache_lock);
	if(ea)   //found ea in cached ecm, asking for this reader
	{
		ea_er->is_pending = true;

		cs_readlock(&ea->ecmanswer_lock);
		if(ea->rc < E_99)
		{
			cs_readunlock(&ea->ecmanswer_lock);
			cs_debug_mask(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [reader_get_ecm] ecm already sent to reader %s (rc %d)", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, reader ? reader->label : "-", ea->rc);
			write_ecm_answer(reader, er, ea->rc, ea->rcEx, ea->cw, NULL);
			return;
		}
		else
		{
			ea_prev = ea->pending;
			ea->pending = ea_er;
			ea->pending->pending_next = ea_prev;
			cs_debug_mask(D_LB, "{client %s, caid %04X, prid %06X, srvid %04X} [reader_get_ecm] ecm already sent to reader %s... set as pending", (check_client(er->client) ? er->client->account->usr : "-"), er->caid, er->prid, er->srvid, reader ? reader->label : "-");
		}
		cs_readunlock(&ea->ecmanswer_lock);
		return;
	}

#ifdef WITH_LB
	if(!(ea_er->status & READER_FALLBACK)) { cs_ftime(&reader->lb_last); }  //for lb oldest reader mode - not use for fallback readers
#endif

	if(ecm_ratelimit_check(reader, er, 1) != OK)
	{
		rdr_debug_mask(reader, D_READER, "ratelimiter has no space left -> skip!");
		return;
	}

	if(is_cascading_reader(reader))     // forward request to proxy reader
	{
		cl->last_srvid = er->srvid;
		cl->last_caid = er->caid;
		casc_process_ecm(reader, er);
		cl->lastecm = time((time_t *)0);
		return;
	}

	cardreader_process_ecm(reader, cl, er);  // forward request to physical reader
}

void reader_do_card_info(struct s_reader *reader)
{
	cardreader_get_card_info(reader);
	if(reader->ph.c_card_info)
		{ reader->ph.c_card_info(); }
}

void reader_do_idle(struct s_reader *reader)
{
	if(reader->ph.c_idle)
		{ reader->ph.c_idle(); }
	else
	{
		time_t now;
		int32_t time_diff;
		time(&now);
		time_diff = abs(now - reader->last_s);
		if(time_diff > (reader->tcp_ito * 60))
		{
			struct s_client *cl = reader->client;
			if(check_client(cl) && reader->tcp_connected && reader->ph.type == MOD_CONN_TCP)
			{
				cs_debug_mask(D_READER, "%s inactive_timeout, close connection (fd=%d)", reader->ph.desc, cl->pfd);
				network_tcp_connection_close(reader, "inactivity");
			}
			else
				{ reader->last_s = now; }
		}
	}
}
#ifdef HAVE_DVBAPI
static void reader_capmt_notify(struct s_client *client, struct demux_s *demux)
{
	if(client->reader->ph.c_capmt)
	{
		struct demux_s *curdemux;
		if(cs_malloc(&curdemux, sizeof(struct demux_s)))
		{
			memcpy(curdemux, demux, sizeof(struct demux_s));
			add_job(client, ACTION_READER_CAPMT_NOTIFY, curdemux, sizeof(struct demux_s));
		}
	}
}

void cs_capmt_notify(struct demux_s *demux)
{
	struct s_client *cl;
	for(cl = first_client->next; cl ; cl = cl->next)
	{
		if((cl->typ == 'p' || cl->typ == 'r') && cl->reader && cl->reader->ph.c_capmt)
		{
			reader_capmt_notify(cl, demux);
		}
	}
}
#endif

int32_t reader_init(struct s_reader *reader)
{
	struct s_client *client = reader->client;

	if(is_cascading_reader(reader))
	{
		client->typ = 'p';
		client->port = reader->r_port;
		set_null_ip(&client->ip);

		if(!(reader->ph.c_init))
		{
			rdr_log(reader, "FATAL: %s-protocol not supporting cascading", reader->ph.desc);
			return 0;
		}

		if(reader->ph.c_init(client))
		{
			//proxy reader start failed
			return 0;
		}

		if(!cs_malloc(&client->ecmtask, cfg.max_pending * sizeof(ECM_REQUEST)))
			{ return 0; }

		rdr_log(reader, "proxy initialized, server %s:%d", reader->device, reader->r_port);
	}
	else
	{
		if(!cardreader_init(reader))
			{ return 0; }
	}

	if(!cs_malloc(&client->emmcache, CS_EMMCACHESIZE * sizeof(struct s_emm)))
	{
		NULLFREE(client->ecmtask);
		return 0;
	}

	client->login = time((time_t *)0);
	client->init_done = 1;

	return 1;
}

#if !defined(WITH_CARDREADER) && defined(WITH_STAPI)
/* Dummy function stub for stapi compiles without cardreader as libstapi needs it. */
int32_t ATR_InitFromArray(ATR *atr, const unsigned char atr_buffer[ATR_MAX_SIZE], uint32_t length)
{
	(void)atr;
	(void)atr_buffer;
	(void)length;
	return 0;
}
#endif

void cs_card_info(void)
{
	struct s_client *cl;
	for(cl = first_client->next; cl ; cl = cl->next)
	{
		if(cl->typ == 'r' && cl->reader)
			{ add_job(cl, ACTION_READER_CARDINFO, NULL, 0); }
	}
}


/* Adds a reader to the list of active readers so that it can serve ecms. */
static void add_reader_to_active(struct s_reader *rdr)
{
	struct s_reader *rdr2, *rdr_prv = NULL, *rdr_tmp = NULL;
	int8_t at_first = 1;

	if(rdr->next)
		{ remove_reader_from_active(rdr); }

	cs_writelock(&readerlist_lock);
	cs_writelock(&clientlist_lock);

	// search configured position:
	LL_ITER it = ll_iter_create(configured_readers);
	while((rdr2 = ll_iter_next(&it)))
	{
		if(rdr2 == rdr)
			{ break; }
		if(rdr2->client && rdr2->enable)
		{
			rdr_prv = rdr2;
			at_first = 0;
		}
	}

	// insert at configured position:
	if(first_active_reader)
	{
		if(at_first)
		{
			rdr->next = first_active_reader;
			first_active_reader = rdr;
			//resort client list:
			struct s_client *prev, *cl;
			for(prev = first_client, cl = first_client->next;
					prev->next != NULL; prev = prev->next, cl = cl->next)
			{
				if(rdr->client == cl)
					{ break; }
			}
			if(cl && rdr->client == cl)
			{
				prev->next = cl->next; //remove client from list
				cl->next = first_client->next;
				first_client->next = cl;
			}
		}
		else
		{
			for(rdr2 = first_active_reader; rdr2->next && rdr2 != rdr_prv ; rdr2 = rdr2->next) { ; }  //search last element
			rdr_prv = rdr2;
			rdr_tmp = rdr2->next;
			rdr2->next = rdr;
			rdr->next = rdr_tmp;
			//resort client list:
			struct s_client *prev, *cl;
			for(prev = first_client, cl = first_client->next;
					prev->next != NULL; prev = prev->next, cl = cl->next)
			{
				if(rdr->client == cl)
					{ break; }
			}
			if(cl && rdr->client == cl)
			{
				prev->next = cl->next; //remove client from list
				cl->next = rdr_prv->client->next;
				rdr_prv->client->next = cl;
			}
		}
	}
	else
	{
		first_active_reader = rdr;
	}
	rdr->active = 1;
	cs_writeunlock(&clientlist_lock);
	cs_writeunlock(&readerlist_lock);
}

/* Removes a reader from the list of active readers so that no ecms can be requested anymore. */
void remove_reader_from_active(struct s_reader *rdr)
{
	struct s_reader *rdr2, *prv = NULL;
	//rdr_log(rdr, "CHECK: REMOVE READER FROM ACTIVE");
	cs_writelock(&readerlist_lock);
	for(rdr2 = first_active_reader; rdr2 ; prv = rdr2, rdr2 = rdr2->next)
	{
		if(rdr2 == rdr)
		{
			if(prv) { prv->next = rdr2->next; }
			else { first_active_reader = rdr2->next; }
			break;
		}
	}
	rdr->next = NULL;
	rdr->active = 0;
	cs_writeunlock(&readerlist_lock);
}

/* Starts or restarts a cardreader without locking. If restart=1, the existing thread is killed before restarting,
   if restart=0 the cardreader is only started. */
static int32_t restart_cardreader_int(struct s_reader *rdr, int32_t restart)
{
	struct s_client *cl = rdr->client;
	if(restart)
	{
		remove_reader_from_active(rdr); // remove from list
		kill_thread(cl); // kill old thread
		cs_sleepms(500);
	}

	while(restart && is_valid_client(cl))
	{
		// If we quick disable+enable a reader (webif), remove_reader_from_active is called from
		// cleanup. this could happen AFTER reader is restarted, so oscam crashes or reader is hidden
		// rdr_log(rdr, "CHECK: WAITING FOR CLEANUP");
		cs_sleepms(500);
	}

	rdr->client = NULL;
	rdr->tcp_connected = 0;
	rdr->card_status = UNKNOWN;
	rdr->tcp_block_delay = 100;
	cs_ftime(&rdr->tcp_block_connect_till);

	if(rdr->device[0] && is_cascading_reader(rdr))
	{
		if(!rdr->ph.num)
		{
			rdr_log(rdr, "Protocol Support missing. (typ=%d)", rdr->typ);
			return 0;
		}
		rdr_debug_mask(rdr, D_TRACE, "protocol: %s", rdr->ph.desc);
	}

	if(!rdr->enable)
		{ return 0; }

	if(rdr->device[0])
	{
		if(restart)
		{
			rdr_log(rdr, "Restarting reader");
		}
		cl = create_client(first_client->ip);
		if(cl == NULL)
			{ return 0; }
		cl->reader  = rdr;
		rdr_log(rdr, "creating thread for device %s", rdr->device);

		cl->sidtabs.ok = rdr->sidtabs.ok;
		cl->sidtabs.no = rdr->sidtabs.no;
		cl->lb_sidtabs.ok = rdr->lb_sidtabs.ok;
		cl->lb_sidtabs.no = rdr->lb_sidtabs.no;
		cl->grp = rdr->grp;

		rdr->client = cl;

		cl->typ = 'r';

		add_job(cl, ACTION_READER_INIT, NULL, 0);
		add_reader_to_active(rdr);

		return 1;
	}
	return 0;
}

/* Starts or restarts a cardreader with locking. If restart=1, the existing thread is killed before restarting,
   if restart=0 the cardreader is only started. */
int32_t restart_cardreader(struct s_reader *rdr, int32_t restart)
{
	cs_writelock(&system_lock);
	int32_t result = restart_cardreader_int(rdr, restart);
	cs_writeunlock(&system_lock);
	return result;
}

void init_cardreader(void)
{
	cs_debug_mask(D_TRACE, "cardreader: Initializing");
	cs_writelock(&system_lock);
	struct s_reader *rdr;

	cardreader_init_locks();

	LL_ITER itr = ll_iter_create(configured_readers);
	while((rdr = ll_iter_next(&itr)))
	{
		if(rdr->enable)
		{
			restart_cardreader_int(rdr, 0);
		}
	}

	load_stat_from_file();
	cs_writeunlock(&system_lock);
}

void kill_all_readers(void)
{
	struct s_reader *rdr;
	for(rdr = first_active_reader; rdr; rdr = rdr->next)
	{
		struct s_client *cl = rdr->client;
		if(!cl)
			{ continue; }
		rdr_log(rdr, "Killing reader");
		kill_thread(cl);
	}
	first_active_reader = NULL;
}

int32_t reader_slots_available(struct s_reader *reader, ECM_REQUEST *er)
{
	if(ecm_ratelimit_check(reader, er, 0) != OK)   //check ratelimiter & cooldown -> in check mode: dont register srvid!!!
	{
		return 0; // no slot free
	}
	else
	{
		return 1; // slots available!
	}
}
