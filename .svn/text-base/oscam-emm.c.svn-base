#include "globals.h"
#include "cscrypt/md5.h"
#include "module-led.h"
#include "oscam-client.h"
#include "oscam-config.h"
#include "oscam-emm.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-work.h"
#include "reader-common.h"

const char *entitlement_type[] = { "", "package", "PPV-Event", "chid", "tier", "class", "PBM", "admin" };

static int8_t cs_emmlen_is_blocked(struct s_reader *rdr, int16_t len)
{
	struct s_emmlen_range *blocklen;
	if (!rdr->blockemmbylen)
		return 0;
	LL_ITER it = ll_iter_create(rdr->blockemmbylen);
	while ((blocklen = ll_iter_next(&it))) {
		if (blocklen->min <= len
				&& (len <= blocklen->max || blocklen->max == 0))
			return 1;
	}
	return 0;
}

/**
 * Function to filter emm by cardsystem.
 * Every cardsystem can export a function "get_emm_filter"
 *
 * the emm is checked against it and returns 1 for a valid emm or 0 if not
 */
static int8_t do_simple_emm_filter(struct s_reader *rdr, struct s_cardsystem *cs, EMM_PACKET *ep, int8_t cl_dvbapi)
{
	if (is_network_reader(rdr)) return 1; // dont evaluate on network readers, server with local reader will check it
	
	//copied and enhanced from module-dvbapi.c
	//dvbapi_start_emm_filter()
	int32_t i, k, match;
	uint8_t flt, mask;
	struct s_csystem_emm_filter *dmx_filter = NULL;
	unsigned int j, filter_count = 0;

	// Call cardsystems emm filter
	cs->get_emm_filter(rdr, &dmx_filter, &filter_count);

	// Only check matching emmtypes:
	uint8_t org_emmtype;
	if (ep->type == UNKNOWN)
		org_emmtype = EMM_UNKNOWN;
	else
		org_emmtype = 1 << (ep->type-1);

	// Now check all filter values

	
	for (j = 0; j < filter_count; j++) {
		if (dmx_filter[j].enabled == 0)
			continue;

		uint8_t emmtype = dmx_filter[j].type;
		if (emmtype != org_emmtype)
			continue;

		match = 1;
		for (i = 0, k = 0; i < 16 && k < ep->emmlen && match; i++, k++) {
			mask = dmx_filter[j].mask[i];
			if (k == 1 && cl_dvbapi) // fixup for emms send by dvbapi
				k +=2; //skip emm len bytes
			if (!mask)
				continue;
			//cs_log("**** filter #%d [%d] = %02X, filter mask[%d] = %02X, flt&mask = %02X , ep->emm[%d] = %02X, ep->emm[%d] & mask = %02X ****", j, i,
			//	dmx_filter[j].filter[i], i, dmx_filter[j].mask[i], flt&mask, k, ep->emm[k], k, ep->emm[k] & mask);
			flt = (dmx_filter[j].filter[i] & mask);
			match = (flt == (ep->emm[k] & mask));
			if (!match)
				break;
		}
		if (match){
			return 1; //valid emm
		}
	}

	NULLFREE(dmx_filter);

	return 0; //emm filter does not match, illegal emm, return
}

static void reader_log_emm(struct s_reader * reader, EMM_PACKET *ep, int32_t i, int32_t rc, struct timeb *tps) {
	char *rtxt[] = {
		"error",
		is_cascading_reader(reader) ? "sent" : "written",
		"skipped",
		"blocked" };
	char *typedesc[] = { "unknown", "unique", "shared", "global" };
	struct s_client *cl = reader->client;
	struct timeb tpe;

	if (reader->logemm & (1 << rc)) {
		cs_ftime(&tpe);
		if (!tps)
			tps = &tpe;

		rdr_log(reader, "%s emmtype=%s, len=%d, idx=%d, cnt=%d: %s (%ld ms)",
				username(ep->client), typedesc[cl->emmcache[i].type], ep->emm[2],
				i, cl->emmcache[i].count, rtxt[rc],
				1000 * (tpe.time - tps->time) + tpe.millitm - tps->millitm);
	}

	if (rc) {
		cl->lastemm = time(NULL);
		led_status_emm_ok();
	}

#if defined(WEBIF) || defined(LCDSUPPORT)
	//counting results
	switch (rc) {
	case 0: reader->emmerror[ep->type]++; break;
	case 1: reader->emmwritten[ep->type]++; break;
	case 2: reader->emmskipped[ep->type]++; break;
	case 3: reader->emmblocked[ep->type]++; break;
	}
#endif
}

static int32_t reader_store_emm(uint8_t type, uint8_t *emmd5)
{
	int32_t rc;
	struct s_client *cl = cur_client();
	memcpy(cl->emmcache[cl->rotate].emmd5, emmd5, CS_EMMSTORESIZE);
	cl->emmcache[cl->rotate].type=type;
	cl->emmcache[cl->rotate].count=1;
//	cs_debug_mask(D_READER, "EMM stored (index %d)", rotate);
	rc = cl->rotate;
	cl->rotate = (++cl->rotate < CS_EMMCACHESIZE) ? cl->rotate : 0;
	return rc;
}

int32_t emm_reader_match(struct s_reader *reader, uint16_t caid, uint32_t provid) {
	int32_t i;

	// if physical reader a card needs to be inserted
	if (!is_network_reader(reader) && reader->card_status != CARD_INSERTED)
		return 0;

	if (reader->audisabled)
		return 0;

	if (reader->caid != caid) {
		int caid_found = 0;
		for (i = 0; i < (int)ARRAY_SIZE(reader->csystem.caids); i++) {
			if (reader->csystem.caids[i] == caid) {
				caid_found = 1;
				break;
			}
		}
		if (!caid_found) {
			rdr_debug_mask(reader, D_EMM, "reader_caid %04X != caid %04X", reader->caid, caid);
			return 0;
		}
	}
	
	//if (!hexserialset(reader)) { There are cards without serial, they should get emm of type global and shared!
	//	rdr_debug_mask(reader, D_EMM, "no hexserial is set");
	//	return 0;
	//}

	if (!provid) {
		rdr_debug_mask(reader, D_EMM, "caid %04X has no provider", caid);
		return 1;
	}

	if (reader->auprovid && reader->auprovid == provid) {
		rdr_debug_mask(reader, D_EMM, "matched auprovid %06X", reader->auprovid);
		return 1;
	}

	if (!reader->nprov) {
		rdr_debug_mask(reader, D_EMM, "no provider is set");
		return 1;
	}

	for (i=0; i<reader->nprov; i++) {
		uint32_t prid = b2i(4, reader->prid[i]);
		if (prid == provid || ( (reader->typ == R_CAMD35 || reader->typ == R_CS378X) && (prid & 0xFFFF) == (provid & 0xFFFF) )) {
			rdr_debug_mask(reader, D_EMM, "provider match %04X:%06X", caid, provid);
			return 1;
		}
	}
	rdr_debug_mask(reader, D_EMM, "skip provider %04X:%06X", caid, provid);
	return 0;
}

static char *get_emmlog_filename(char *dest, size_t destlen, const char *basefilename, const char *ext) {
	char filename[64 + 16];
	snprintf(filename, sizeof(filename), "%s_emm.%s", basefilename, ext);
	if (!cfg.emmlogdir) {
		get_config_filename(dest, destlen, filename);
	} else {
		const char *slash = "/";
		if (cfg.emmlogdir[strlen(cfg.emmlogdir) - 1] == '/') slash = "";
		snprintf(dest, destlen, "%s%s%s", cfg.emmlogdir, slash, filename);
	}
	return dest;
}

static void saveemm(struct s_reader *aureader, EMM_PACKET *ep)
{
	FILE *fp;
	char tmp[17];
	char buf[80];
	char token[256];
	char *tmp2;
	time_t rawtime;
	uint32_t emmtype;
	struct tm timeinfo;
	if (ep->type == UNKNOWN)
		emmtype = EMM_UNKNOWN;
	else
		emmtype = 1 << (ep->type - 1);
	// should this nano be saved?
	if (((1 << (ep->emm[0] % 0x80)) & aureader->s_nano) || (aureader->saveemm & emmtype))
	{
		time(&rawtime);
		localtime_r(&rawtime, &timeinfo); // to access LOCAL date/time info
		int32_t emm_length = ((ep->emm[1] & 0x0f) << 8) | ep->emm[2];
		strftime(buf, sizeof(buf), "%Y/%m/%d %H:%M:%S", &timeinfo);
		fp = fopen(get_emmlog_filename(token, sizeof(token), aureader->label, "log"), "a");
		if (!fp) {
			rdr_log(aureader, "ERROR: Cannot open file '%s' (errno=%d: %s)\n", token, errno, strerror(errno));
		} else {
			if (cs_malloc(&tmp2, (emm_length + 3) * 2 + 1)) {
				fprintf(fp, "%s   %s   ", buf, cs_hexdump(0, ep->hexserial, 8, tmp, sizeof(tmp)));
				fprintf(fp, "%s\n", cs_hexdump(0, ep->emm, emm_length + 3, tmp2, (emm_length + 3) * 2 + 1));
				free(tmp2);
				rdr_log(aureader, "Successfully added EMM to %s", token);
			}
			fclose(fp);
		}
		fp = fopen(get_emmlog_filename(token, sizeof(token), aureader->label, "bin"), "ab");
		if (!fp) {
			rdr_log(aureader, "ERROR: Cannot open file '%s' (errno=%d: %s)\n", token, errno, strerror(errno));
		} else {
			if ((int)fwrite(ep->emm, 1, emm_length + 3, fp) == emm_length + 3) {
				rdr_log(aureader, "Successfully added binary EMM to %s", token);
			} else {
				rdr_log(aureader, "ERROR: Cannot write binary EMM to %s (errno=%d: %s)\n", token, errno, strerror(errno));
			}
			fclose(fp);
		}
	}
}

void do_emm(struct s_client * client, EMM_PACKET *ep)
{
	char *typtext[]={"unknown", "unique", "shared", "global"};
	char tmp[17];
	int32_t emmnok=0;

	struct s_reader *aureader = NULL;
	cs_ddump_mask(D_EMM, ep->emm, ep->emmlen, "emm:");

	int8_t cl_dvbapi = 0, assemble = 0;
#ifdef HAVE_DVBAPI
	cl_dvbapi = streq(cfg.dvbapi_usr, client->account->usr);
#endif
	if (client->account->emm_reassembly > 1 || (client->account->emm_reassembly && cl_dvbapi))
		assemble = 1;

	LL_ITER itr = ll_iter_create(client->aureader_list);
	while ((aureader = ll_iter_next(&itr))) {
		if (!aureader->enable)
			continue;

		uint16_t caid = b2i(2, ep->caid);
		uint32_t provid = b2i(4, ep->provid);

		if (aureader->audisabled) {
			rdr_debug_mask(aureader, D_EMM, "AU is disabled");
			/* we have to write the log for blocked EMM here because
			 this EMM never reach the reader module where the rest
			 of EMM log is done. */
			if (aureader->logemm & 0x10)  {
				rdr_log(aureader, "%s emmtype=%s, len=%d, idx=0, cnt=1: audisabled (0 ms)",
						client->account->usr,
						typtext[ep->type],
						ep->emm[2]);
			}
			continue;
		}

		if (!(aureader->grp & client->grp)) {
			rdr_debug_mask(aureader, D_EMM, "skip emm, group mismatch");
			continue;
		}

		//TODO: provider possibly not set yet, this is done in get_emm_type()
		if (!emm_reader_match(aureader, caid, provid))
			continue;

		struct s_cardsystem *cs = NULL;

		if (is_cascading_reader(aureader)) { // network reader (R_CAMD35 R_NEWCAMD R_CS378X R_CCCAM)
			if (!aureader->ph.c_send_emm) // no emm support
				continue;

			cs = get_cardsystem_by_caid(caid);
			if (!cs) {
				rdr_debug_mask(aureader, D_EMM, "unable to find cardsystem for caid %04X", caid);
				continue;
			}
		} else { // local reader
			if (aureader->csystem.active)
				cs=&aureader->csystem;
		}

		if (cs && cs->get_emm_type) {
			if (!cs->get_emm_type(ep, aureader)) {
				rdr_debug_mask(aureader, D_EMM, "emm skipped, get_emm_type() returns error");
				emmnok++;
				continue;
			}
		}

		if (cs && cs->get_emm_filter) {
			if(!do_simple_emm_filter(aureader, cs, ep, 1)) { // do check with dvbapi fixup enabled
				if(!do_simple_emm_filter(aureader, cs, ep, 0)) { // do check with dvbapi fixup disabled
					rdr_debug_mask(aureader, D_EMM, "emm skipped, do_simple_emm_filter() returns invalid");
					emmnok++;
					continue;
				}
			}
		}

		if (cs && cs->do_emm_reassembly) {
			if (assemble) {
				if (!cs->do_emm_reassembly(client, ep))
					continue; // skip this reader
			} else {
				rdr_debug_mask(aureader, D_EMM, "processing raw emm");
			}
		}

		rdr_debug_mask_sensitive(aureader, D_EMM, "emmtype %s. Reader serial {%s}.", typtext[ep->type],
			cs_hexdump(0, aureader->hexserial, 8, tmp, sizeof(tmp)));
		rdr_debug_mask_sensitive(aureader, D_EMM, "emm UA/SA: {%s}.",
			cs_hexdump(0, ep->hexserial, 8, tmp, sizeof(tmp)));

		client->last = time(NULL);
		saveemm(aureader, ep);

		int32_t is_blocked = 0;
		switch (ep->type) {
			case UNKNOWN: is_blocked = (aureader->blockemm & EMM_UNKNOWN) == EMM_UNKNOWN; break;
			case UNIQUE : is_blocked = (aureader->blockemm & EMM_UNIQUE ) == EMM_UNIQUE;  break;
			case SHARED : is_blocked = (aureader->blockemm & EMM_SHARED ) == EMM_SHARED;  break;
			case GLOBAL : is_blocked = (aureader->blockemm & EMM_GLOBAL ) == EMM_GLOBAL;  break;
		}

		// if not already blocked we check for block by len
		if (!is_blocked) is_blocked = cs_emmlen_is_blocked( aureader, ep->emm[2] ) ;

		if (is_blocked != 0) {
#ifdef WEBIF
			aureader->emmblocked[ep->type]++;
			is_blocked = aureader->emmblocked[ep->type];
#endif
			/* we have to write the log for blocked EMM here because
			 this EMM never reach the reader module where the rest
			 of EMM log is done. */
			if (aureader->logemm & 0x08)  {
				rdr_log(aureader, "%s emmtype=%s, len=%d, idx=0, cnt=%d: blocked (0 ms)",
						client->account->usr,
						typtext[ep->type],
						ep->emm[2],
						is_blocked);
			}
			continue;
		}

		client->lastemm = time((time_t*)0);

		client->emmok++;
		if (client->account)
			client->account->emmok++;
		first_client->emmok++;

		//Check emmcache early:
		int32_t i;
		unsigned char md5tmp[CS_EMMSTORESIZE];
		struct s_client *au_cl = aureader->client;

		MD5(ep->emm, ep->emm[2], md5tmp);
		ep->client = client;
		
		int32_t writeemm=1; // 0= dont write emm, 1=write emm, default = write
		
		for (i=0; i<CS_EMMCACHESIZE; i++) { //check emm cache hits
			if (!memcmp(au_cl->emmcache[i].emmd5, md5tmp, CS_EMMSTORESIZE)) {
				rdr_debug_mask(aureader, D_EMM, "emm found in cache: count %d rewrite %d",
					au_cl->emmcache[i].count, aureader->rewritemm);
				if (aureader->cachemm && (au_cl->emmcache[i].count > aureader->rewritemm)) {
					reader_log_emm(aureader, ep, i, 2, NULL);
					writeemm = 0; // dont write emm!
					break; // found emm match needs no further handling, stop searching and proceed with next reader!
				}
				writeemm = 1; // found emm match but rewrite counter not reached: write emm! 
				break; 
			}
		}
		
		if (writeemm){ // only write on no cache hit or cache hit that needs further rewrite
			EMM_PACKET *emm_pack;
			if (cs_malloc(&emm_pack, sizeof(EMM_PACKET))) {
				rdr_debug_mask(aureader, D_EMM, "emm is being sent to reader");
				memcpy(emm_pack, ep, sizeof(EMM_PACKET));
				add_job(aureader->client, ACTION_READER_EMM, emm_pack, sizeof(EMM_PACKET));
			}
		}
		
	} // done with this reader, process next reader!
	
	if (emmnok > 0 && emmnok == ll_count(client->aureader_list)) {
		client->emmnok++;
		if (client->account)
			client->account->emmnok++;
		first_client->emmnok++;
	}
}


int32_t reader_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
	int32_t i, rc, ecs;
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	struct timeb tps;
	struct s_client *cl = reader->client;

	if(!cl)
		return 0;

	cs_ftime(&tps);

	MD5(ep->emm, ep->emm[2], md5tmp);

	for (i = ecs = 0; i < CS_EMMCACHESIZE; i++) {
		if (!memcmp(cl->emmcache[i].emmd5, md5tmp, CS_EMMSTORESIZE)) {
			cl->emmcache[i].count++;
			if (reader->cachemm) {
				if (cl->emmcache[i].count > reader->rewritemm) {
					ecs = 2; //skip emm
				} else {
					ecs = 1; //rewrite emm
				}
			}
			break;
		}
	}

	// Ecs=0 not found in cache
	// Ecs=1 found in cache, rewrite emm
	// Ecs=2 skip
	if ((rc = ecs) < 2) {
		if (is_cascading_reader(reader)) {
			rdr_debug_mask(reader, D_READER, "network emm reader");
			if (reader->ph.c_send_emm) {
				rc = reader->ph.c_send_emm(ep);
			} else {
				rdr_debug_mask(reader, D_READER, "send_emm() support missing");
				rc = 0;
			}
		} else {
			rdr_debug_mask(reader, D_READER, "local emm reader");
			rc = cardreader_do_emm(reader, ep);
		}
		if (!ecs)
			i = reader_store_emm(ep->type, md5tmp);
	}

	reader_log_emm(reader, ep, i, rc, &tps);

	return rc;
}

void do_emm_from_file(struct s_reader * reader)
{
	if (!reader->emmfile)
		return;

	char token[256];
	FILE *fp;

	if (reader->emmfile[0] == '/')
		snprintf(token, sizeof(token), "%s", reader->emmfile); //pathname included
	else
		get_config_filename(token, sizeof(token), reader->emmfile); //only file specified, look in confdir for this file

	if (!(fp = fopen (token, "rb"))) {
		rdr_log(reader, "ERROR: Cannot open EMM file '%s' (errno=%d %s)\n", token, errno, strerror(errno));
		return;
	}

	EMM_PACKET *eptmp;
	if (!cs_malloc(&eptmp, sizeof(EMM_PACKET))) {
		fclose (fp);
		return;
	}

	size_t ret = fread(eptmp, sizeof(EMM_PACKET), 1, fp);
	if (ret < 1 && ferror(fp)) {
		rdr_log(reader, "ERROR: Can't read EMM from file '%s' (errno=%d %s)", token, errno, strerror(errno));
		free(eptmp);
		fclose(fp);
		return;
	}
	fclose (fp);

	eptmp->caid[0] = (reader->caid >> 8) & 0xFF;
	eptmp->caid[1] = reader->caid & 0xFF;
	if (reader->nprov > 0)
		memcpy(eptmp->provid, reader->prid[0], sizeof(eptmp->provid));
	eptmp->emmlen = eptmp->emm[2] + 3;

	struct s_cardsystem *cs = get_cardsystem_by_caid(reader->caid);
	if (cs && cs->get_emm_type && !cs->get_emm_type(eptmp, reader)) {
		rdr_debug_mask(reader, D_EMM, "emm skipped, get_emm_type() returns error");
		free(eptmp);
		return;
	}

	//save old b_nano value
	//clear lsb and lsb+1, so no blocking, and no saving for this nano
	uint16_t save_s_nano = reader->s_nano;
	uint16_t save_b_nano = reader->b_nano;
	uint32_t save_saveemm = reader->saveemm;

	reader->s_nano = reader->b_nano = 0;
	reader->saveemm = 0;

	int32_t rc = cardreader_do_emm(reader, eptmp);
	if (rc == OK)
		rdr_log(reader, "EMM from file %s was successful written.", token);
	else
		rdr_log(reader, "ERROR: EMM read from file %s NOT processed correctly! (rc=%d)", token, rc);

	//restore old block/save settings
	reader->s_nano = save_s_nano;
	reader->b_nano = save_b_nano;
	reader->saveemm = save_saveemm;

	free(eptmp);
}

void emm_sort_nanos(unsigned char *dest, const unsigned char *src, int32_t len)
{
	int32_t w = 0, c = -1, j = 0;
	while(1) {
		int32_t n = 256;
		for (j = 0; j < len; ) {
			int32_t l = src[j + 1] + 2;
			if (src[j] == c) {
				if (w + l > len) {
					cs_debug_mask(D_EMM, "sortnanos: sanity check failed. Exceeding memory area. Probably corrupted nanos!");
					memset(dest, 0, len); // zero out everything
					return;
				}
				memcpy(&dest[w],&src[j],l);
				w += l;
			} else if (src[j] > c && src[j] < n) {
				n = src[j];
			}
			j += l;
		}
		if (n >= 256)
			break;
		c = n;
	}
}
