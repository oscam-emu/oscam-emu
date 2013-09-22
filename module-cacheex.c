#include "globals.h"

#ifdef CS_CACHEEX

#include "cscrypt/md5.h"
#include "module-cacheex.h"
#include "module-cw-cycle-check.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-conf.h"
#include "oscam-ecm.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-work.h"

#define cs_cacheex_matcher "oscam.cacheex"

extern uint8_t cc_node_id[8];
extern uint8_t camd35_node_id[8];
extern CS_MUTEX_LOCK ecmcache_lock;
extern struct ecm_request_t *ecmcwcache;
extern uint32_t ecmcwcache_size;
extern CS_MUTEX_LOCK hitcache_lock;

uint8_t cacheex_peer_id[8];

static LLIST *invalid_cws;
static struct csp_ce_hit_t *cspec_hitcache;
static uint32_t cspec_hitcache_size;


void cacheex_init(void) {
	// Init random node id
	get_random_bytes(cacheex_peer_id, 8);
#ifdef MODULE_CCCAM
	memcpy(cacheex_peer_id, cc_node_id, 8);
#endif
#ifdef MODULE_CAMD35_TCP
	memcpy(camd35_node_id, cacheex_peer_id, 8);
#endif
}

void cacheex_clear_account_stats(struct s_auth *account) {
	account->cwcacheexgot = 0;
	account->cwcacheexpush = 0;
	account->cwcacheexhit = 0;
}

void cacheex_clear_client_stats(struct s_client *client) {
	client->cwcacheexgot = 0;
	client->cwcacheexpush = 0;
	client->cwcacheexhit = 0;
}

int32_t cacheex_add_stats(struct s_client *cl, uint16_t caid, uint16_t srvid, uint32_t prid, uint8_t direction)
{
	if (!cfg.cacheex_enable_stats)
		return -1;

	// create list if doesn't exist
	if (!cl->ll_cacheex_stats)
		cl->ll_cacheex_stats = ll_create("ll_cacheex_stats");

	time_t now = time((time_t*)0);
	LL_ITER itr = ll_iter_create(cl->ll_cacheex_stats);
	S_CACHEEX_STAT_ENTRY *cacheex_stats_entry;

	// check for existing entry
	while ((cacheex_stats_entry = ll_iter_next(&itr))) {
		if (cacheex_stats_entry->cache_srvid == srvid &&
				cacheex_stats_entry->cache_caid == caid &&
				cacheex_stats_entry->cache_prid == prid &&
				cacheex_stats_entry->cache_direction == direction) {
			// we already have this entry - just add count and time
			cacheex_stats_entry->cache_count++;
			cacheex_stats_entry->cache_last = now;
			return cacheex_stats_entry->cache_count;
		}
	}

	// if we land here we have to add a new entry
	if (cs_malloc(&cacheex_stats_entry, sizeof(S_CACHEEX_STAT_ENTRY))) {
		cacheex_stats_entry->cache_caid = caid;
		cacheex_stats_entry->cache_srvid = srvid;
		cacheex_stats_entry->cache_prid = prid;
		cacheex_stats_entry->cache_count = 1;
		cacheex_stats_entry->cache_last = now;
		cacheex_stats_entry->cache_direction = direction;
		ll_iter_insert(&itr, cacheex_stats_entry);
		return 1;
	}
	return 0;
}


int8_t cacheex_maxhop(struct s_client *cl)
{
	int maxhop = 10;
	if (cl->reader && cl->reader->cacheex.maxhop)
		maxhop = cl->reader->cacheex.maxhop;
	else if (cl->account && cl->account->cacheex.maxhop)
		maxhop = cl->account->cacheex.maxhop;
	return maxhop;
}

static void cacheex_cache_push_to_client(struct s_client *cl, ECM_REQUEST *er)
{
	add_job(cl, ACTION_CACHE_PUSH_OUT, er, 0);
}

/**
 * cacheex modes:
 *
 * cacheex=1 CACHE PULL:
 * Situation: oscam A reader1 has cacheex=1, oscam B account1 has cacheex=1
 *   oscam A gets a ECM request, reader1 send this request to oscam B, oscam B checks his cache
 *   a. not found in cache: return NOK
 *   a. found in cache: return OK+CW
 *   b. not found in cache, but found pending request: wait max cacheexwaittime and check again
 *   oscam B never requests new ECMs
 *
 *   CW-flow: B->A
 *
 * cacheex=2 CACHE PUSH:
 * Situation: oscam A reader1 has cacheex=2, oscam B account1 has cacheex=2
 *   if oscam B gets a CW, its pushed to oscam A
 *   reader has normal functionality and can request ECMs
 *
 *   Problem: oscam B can only push if oscam A is connected
 *   Problem or feature?: oscam A reader can request ecms from oscam B
 *
 *   CW-flow: B->A
 *
 * cacheex=3 REVERSE CACHE PUSH:
 * Situation: oscam A reader1 has cacheex=3, oscam B account1 has cacheex=3
 *   if oscam A gets a CW, its pushed to oscam B
 *
 *   oscam A never requests new ECMs
 *
 *   CW-flow: A->B
 */
void cacheex_cache_push(ECM_REQUEST *er)
{
	if (er->rc >= E_NOTFOUND && er->rc != E_UNHANDLED) //Maybe later we could support other rcs
		return; //NOT FOUND/Invalid

	if (er->cacheex_pushed)
		return;

	int64_t grp;
	if (er->selected_reader)
		grp = er->selected_reader->grp;
	else
		grp = er->grp;

	//cacheex=2 mode: push (server->remote)
	struct s_client *cl;
	cs_readlock(&clientlist_lock);
	for (cl=first_client->next; cl; cl=cl->next) {
		if (er->cacheex_src != cl) {
			if (get_module(cl)->num == R_CSP) { // always send to csp cl
				if (!er->cacheex_src || cfg.csp.allow_reforward) cacheex_cache_push_to_client(cl, er); // but not if the origin was cacheex (might loop)
			} else if (cl->typ == 'c' && !cl->dup && cl->account && cl->account->cacheex.mode == 2) { //send cache over user
				if (get_module(cl)->c_cache_push // cache-push able
						&& (!grp || (cl->grp & grp)) //Group-check
						&& chk_srvid(cl, er) //Service-check
						&& (chk_caid(er->caid, &cl->ctab) > 0))  //Caid-check
				{
					cacheex_cache_push_to_client(cl, er);
				}
			}
		}
	}
	cs_readunlock(&clientlist_lock);

	//cacheex=3 mode: reverse push (reader->server)

	cs_readlock(&readerlist_lock);
	cs_readlock(&clientlist_lock);

	struct s_reader *rdr;
	for (rdr = first_active_reader; rdr; rdr = rdr->next) {
		cl = rdr->client;
		if (check_client(cl) && er->cacheex_src != cl && rdr->cacheex.mode == 3) { //send cache over reader
			if (rdr->ph.c_cache_push
				&& (!grp || (rdr->grp & grp)) //Group-check
				&& chk_srvid(cl, er) //Service-check
				&& chk_ctab(er->caid, &rdr->ctab))  //Caid-check
			{
				cacheex_cache_push_to_client(cl, er);
			}
		}
	}

	cs_readunlock(&clientlist_lock);
	cs_readunlock(&readerlist_lock);

	er->cacheex_pushed = 1;
}

static inline struct s_cacheex_matcher *is_cacheex_matcher_matching(ECM_REQUEST *from_er, ECM_REQUEST *to_er)
{
	struct s_cacheex_matcher *entry = cfg.cacheex_matcher;
	int8_t v_ok = (from_er && to_er)?2:1;
	while (entry) {
		int8_t ok = 0;
		if (from_er
				&& (!entry->caid || entry->caid == from_er->caid)
				&& (!entry->provid || entry->provid == from_er->prid)
				&& (!entry->srvid || entry->srvid == from_er->srvid)
				&& (!entry->chid || entry->chid == from_er->chid)
				&& (!entry->pid || entry->pid == from_er->pid)
				&& (!entry->ecmlen || entry->ecmlen == from_er->ecmlen))
			ok++;

		if (to_er
				&& (!entry->to_caid || entry->to_caid == to_er->caid)
				&& (!entry->to_provid || entry->to_provid == to_er->prid)
				&& (!entry->to_srvid || entry->to_srvid == to_er->srvid)
				&& (!entry->to_chid || entry->to_chid == to_er->chid)
				&& (!entry->to_pid || entry->to_pid == to_er->pid)
				&& (!entry->to_ecmlen || entry->to_ecmlen == to_er->ecmlen))
			ok++;

		if (ok == v_ok) {
			if (!from_er || !to_er || from_er->srvid == to_er->srvid)
				return entry;
		}
		entry = entry->next;
	}
	return NULL;
}

bool cacheex_is_match_alias(struct s_client *cl, ECM_REQUEST *er) {
	return check_client(cl) && cl->account && cl->account->cacheex.mode == 1 && is_cacheex_matcher_matching(NULL, er);
}

inline int8_t cacheex_match_alias(struct s_client *cl, ECM_REQUEST *er, ECM_REQUEST *ecm)
{
	if (check_client(cl) && cl->account && cl->account->cacheex.mode == 1) {
		struct s_cacheex_matcher *entry = is_cacheex_matcher_matching(ecm, er);
		if (entry) {
			int32_t diff = comp_timeb(&er->tps, &ecm->tps);
			if (diff > entry->valid_from && diff < entry->valid_to) {
#ifdef WITH_DEBUG
				if (D_CACHEEX & cs_dblevel){
					char result[CXM_FMT_LEN] = { 0 };
					int32_t s, size = CXM_FMT_LEN;
					s = ecmfmt(entry->caid, 0, entry->provid, entry->chid, entry->pid, entry->srvid, entry->ecmlen, 0, 0, 0, result, size, 0, 0);
					s += snprintf(result+s, size-s, " = ");
					s += ecmfmt(entry->to_caid, 0, entry->to_provid, entry->to_chid, entry->to_pid, entry->to_srvid, entry->to_ecmlen, 0, 0, 0, result+s, size-s, 0, 0);
					s += snprintf(result+s, size-s, " valid %d/%d", entry->valid_from, entry->valid_to);
					cs_debug_mask(D_CACHEEX, "cacheex-matching for: %s", result);
				}
#endif
				return 1;
			}
		}
	}
	return 0;
}

static pthread_mutex_t invalid_cws_mutex;

static void add_invalid_cw(uint8_t *cw) {
	pthread_mutex_lock(&invalid_cws_mutex);
	if (!invalid_cws)
		invalid_cws = ll_create("invalid cws");
	uint8_t *cw2;
	if (cs_malloc(&cw2, 16)) {
		memcpy(cw2, cw, 16);
		ll_append(invalid_cws, cw2);
		while (ll_count(invalid_cws) > 32) {
			ll_remove_first_data(invalid_cws);
		}
	}
	pthread_mutex_unlock(&invalid_cws_mutex);
}

static int32_t is_invalid_cw(uint8_t *cw) {
	if (!invalid_cws) return 0;

	pthread_mutex_lock(&invalid_cws_mutex);
	LL_LOCKITER *li = ll_li_create(invalid_cws, 0);
	uint8_t *cw2;
	int32_t invalid = 0;
	while ((cw2 = ll_li_next(li)) && !invalid) {
		invalid = (memcmp(cw, cw2, 16) == 0);
	}
	ll_li_destroy(li);
	pthread_mutex_unlock(&invalid_cws_mutex);
	return invalid;
}


static int32_t cacheex_add_to_cache_int(struct s_client *cl, ECM_REQUEST *er, int8_t csp)
{
	if (!cl)
		return 0;
	if (!csp && cl->reader && cl->reader->cacheex.mode!=2) { //from reader
		cs_debug_mask(D_CACHEEX, "CACHEX received, but disabled for %s", username(cl));
		return 0;
	}
	if (!csp && !cl->reader && cl->account && cl->account->cacheex.mode!=3) { //from user
		cs_debug_mask(D_CACHEEX, "CACHEX received, but disabled for %s", username(cl));
		return 0;
	}
	if (!csp && !cl->reader && !cl->account) { //not active!
		cs_debug_mask(D_CACHEEX, "CACHEX received, but invalid client state %s", username(cl));
		return 0;
	}

	if (er->rc < E_NOTFOUND) { //=FOUND Check CW:
		uint8_t i, c;
		uint8_t null=0;
		for (i = 0; i < 16; i += 4) {
			c = ((er->cw[i] + er->cw[i + 1] + er->cw[i + 2]) & 0xff);
			null |= (er->cw[i] | er->cw[i + 1] | er->cw[i + 2]);
			if (er->cw[i + 3] != c) {
				cs_ddump_mask(D_CACHEEX, er->cw, 16, "push received cw with chksum error from %s", csp ? "csp" : username(cl));
				cl->cwcacheexerr++;
				if (cl->account)
					cl->account->cwcacheexerr++;
				return 0;
			}
		}

		if (null==0 || chk_is_null_CW(er->cw)) {
			cs_ddump_mask(D_CACHEEX, er->cw, 16, "push received null cw from %s", csp ? "csp" : username(cl));
			cl->cwcacheexerr++;
			if (cl->account)
				cl->account->cwcacheexerr++;
			return 0;
		}

		if (is_invalid_cw(er->cw)) {
			cs_ddump_mask(D_TRACE, er->cw, 16, "push received invalid cw from %s", csp ? "csp" : username(cl));
			cl->cwcacheexerrcw++;
			if (cl->account)
				cl->account->cwcacheexerrcw++;
			return 0;
		}

	}

	er->grp |= cl->grp; //extend group instead overwriting, this fixes some funny not founds and timeouts when using more cacheex readers with different groups
//	er->ocaid = er->caid;
	if (er->rc < E_NOTFOUND) //map FOUND to CACHEEX
		er->rc = E_CACHEEX;
	er->cacheex_src = cl;
	er->client = NULL; //No Owner! So no fallback!

	if (er->ecmlen) {
		int32_t offset = 3;
		if ((er->caid >> 8) == 0x17)
			offset = 13;
		unsigned char md5tmp[MD5_DIGEST_LENGTH];
		memcpy(er->ecmd5, MD5(er->ecm+offset, er->ecmlen-offset, md5tmp), CS_ECMSTORESIZE);
		cacheex_update_hash(er);
		//csp has already initialized these hashcode

		update_chid(er);
	}


	bool ecm_found=false;
	bool add_to_cache=true;
	bool addhitcache_done=false;

	if(er->rc < E_NOTFOUND){

		if(check_client(cl)){
			cl->cwcacheexgot++;
			if (cl->account)
				cl->account->cwcacheexgot++;
			first_client->cwcacheexgot++;
		}

		/*
		 * Here we need cycling cache to found one or more matching ecm
		 *
		 */

		time_t timeout = time(NULL)-cfg.max_cache_time;
		struct ecm_request_t *ecm;

		cs_readlock(&ecmcache_lock);
		for (ecm = ecmcwcache; ecm; ecm = ecm->next) {
			if (ecm->tps.time <= timeout)
				break;

			//check for match ecm
			if(cmp_ecm(ecm, er) ){

				//*********************************************************************************

				if(	ecm->from_csp || ecm->from_cacheex   //skip ecm came from cacheex or csp
					||
					(er->from_csp && ecm->csp_answered)  //skip csp cache for ecm already answered by csp cache
					||
					(er->from_cacheex && (er->grp & ecm->grp))	//skip cacheex for ecm already answered by same cacheex client
				){

					add_to_cache=false;  //ecm (cw) already in cache, not add new one for same ecm hash!
					if (ecm->rc<E_NOTFOUND) {
						if (memcmp(er->cw, ecm->cw, sizeof(er->cw)) != 0) {
							add_invalid_cw(ecm->cw);
							add_invalid_cw(er->cw);

							if(check_client(cl)){
								cl->cwcacheexerrcw++;
								if (cl->account)
									cl->account->cwcacheexerrcw++;
							}

							char cw1[16*3+2], cw2[16*3+2];
							cs_hexdump(0, er->cw, 16, cw1, sizeof(cw1));
							cs_hexdump(0, ecm->cw, 16, cw2, sizeof(cw2));

							char ip1[20]="", ip2[20]="";
							if (check_client(cl))
								cs_strncpy(ip1, cs_inet_ntoa(cl->ip), sizeof(ip1));
							if (check_client(ecm->cacheex_src))
								cs_strncpy(ip2, cs_inet_ntoa(ecm->cacheex_src->ip), sizeof(ip2));
							else if (ecm->selected_reader && check_client(ecm->selected_reader->client))
								cs_strncpy(ip2, cs_inet_ntoa(ecm->selected_reader->client->ip), sizeof(ip2));

							void *el = ll_has_elements(er->csp_lastnodes);
							uint64_t node1 = el?(*(uint64_t*)el):0;

							el = ll_has_elements(ecm->csp_lastnodes);
							uint64_t node2 = el?(*(uint64_t*)el):0;

							el = ll_last_element(er->csp_lastnodes);
							uint64_t node3 = el?(*(uint64_t*)el):0;

							el = ll_last_element(ecm->csp_lastnodes);
							uint64_t node4 = el?(*(uint64_t*)el):0;

							debug_ecm(D_TRACE| D_CSPCWC, "WARNING: Different CWs %s from %s(%s)<>%s(%s): %s<>%s nodes %llX %llX %llX %llX", buf,
								csp ? "csp" : username(cl), ip1,
								ecm->cacheex_src?username(ecm->cacheex_src):(ecm->selected_reader?ecm->selected_reader->label:"unknown/csp"), ip2,
								cw1, cw2,
								(long long unsigned int)node1,
								(long long unsigned int)node2,
								(long long unsigned int)node3,
								(long long unsigned int)node4);
						} else {
							debug_ecm(D_CACHEEX| D_CSPCWC, "ignored duplicate pushed ECM %s from %s", buf, csp ? "csp" : username(cl));
						}
					}

				}else{

					//send cache to client
					if(check_client(ecm->client)){
							#ifdef CW_CYCLE_CHECK
								if (!checkcwcycle(ecm, cl->reader, er->cw, er->rc )) {   //if not valid, we don't add it to hit_cache and does not cascade push!!!
									continue;
								}
							#endif

							struct s_write_from_cache *wfc=NULL;
							if (!cs_malloc(&wfc, sizeof(struct s_write_from_cache)))
								continue;

							wfc->er_new=ecm;
							wfc->er_cache=er;
							wfc->type=3;

							int8_t rc_orig=ecm->rc;

							if(!add_job(ecm->client, ACTION_ECM_ANSWER_CACHE, wfc, sizeof(struct s_write_from_cache)))  //write_ecm_answer_fromcache
								continue;

							if(!ecm_found){
								if(rc_orig>=E_NOTFOUND) //if not already pushed
									cacheex_cache_push(er); //cascade push
								cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 1);  //add stat only for first ecm found
							}

							ecm_found=true;
					}

					//check for add_hitcache
					if(!addhitcache_done && ((ecm->cacheex_wait_time && !ecm->cacheex_wait_time_expired) || !ecm->cacheex_wait_time) ){  //only for first ecm found when no wait_time expires (or not wait_time), add hitcache

						uint8_t add_hitcache_er=1;
						struct s_reader *cl_rdr = cl->reader;
						if (cl_rdr && cl_rdr->cacheex.mode == 2) {
							struct s_reader *rdr;
							struct s_ecm_answer *ea;
							for(ea = ecm->matching_rdr; ea; ea = ea->next) {
								rdr = ea->reader;
								if (cl_rdr == rdr && ((ea->status & REQUEST_ANSWERED) == REQUEST_ANSWERED)){
									cs_debug_mask(D_CACHEEX|D_CSPCWC|D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [CACHEEX] skip ADD self request!", (check_client(ecm->client)?ecm->client->account->usr:"-"),ecm->caid, ecm->prid, ecm->srvid );
									add_hitcache_er=0; //don't add hit cache, reader requested self
								}
							}
						}

						if(add_hitcache_er){
							addhitcache_done=true;
							add_hitcache(cl, ecm);  //USE cacheex client (to get correct group) and ecm from requesting client (to get correct caid|prid|srvid)!!!
							if(ecm->prid!=er->prid || ecm->srvid!=er->srvid)
								add_hitcache(cl, er);  //we add_hitcache also original caid|prid|srvid
						}
					}
					//END check for add_hitcache
				}

				//*************************************************************************************
			}
		}
		cs_readunlock(&ecmcache_lock);
	}


	if(!ecm_found && add_to_cache){  //if not ecm (cw) already in cache
		uint8_t cwcycle_act = cwcycle_check_act(er->caid);
		if (er->rc < E_NOTFOUND) { // Do NOT add cacheex - not founds!
			add_hitcache(cl, er);

			er->selected_reader = cl->reader;

			if (!cwcycle_act) {
				cs_writelock(&ecmcache_lock);
				er->next = ecmcwcache;
				ecmcwcache = er;
				ecmcwcache_size++;
				cs_writeunlock(&ecmcache_lock);
			}

			cacheex_cache_push(er);  //cascade push!
			cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 1);

			if (cwcycle_act)
				er->rc = E_NOTFOUND; //need to free
		}
		debug_ecm(D_CACHEEX, "got pushed %sECM %s from %s (%s)", (er->rc == E_UNHANDLED)?"request ":"", buf, csp ? "csp" : username(cl),(cwcycle_act)?"on":"off");

		return er->rc < E_NOTFOUND ? 1 : 0;
	}

	return 0;
}

void cacheex_add_to_cache(struct s_client *cl, ECM_REQUEST *er)
{
	er->from_cacheex=1;

	if (!cacheex_add_to_cache_int(cl, er, 0))
		free_ecm(er);
}

void cacheex_add_to_cache_from_csp(struct s_client *cl, ECM_REQUEST *er)
{
	if (!cacheex_add_to_cache_int(cl, er, 1))
		free_ecm(er);
}

//Format:
//caid:prov:srvid:pid:chid:ecmlen=caid:prov:srvid:pid:chid:ecmlen[,validfrom,validto]
//validfrom: default=-2000
//validto: default=4000
//valid time if found in cache
static struct s_cacheex_matcher *cacheex_matcher_read_int(void) {
	FILE *fp = open_config_file(cs_cacheex_matcher);
	if (!fp)
		return NULL;

	char token[1024];
	unsigned char type;
	int32_t i, ret, count=0;
	struct s_cacheex_matcher *new_cacheex_matcher = NULL, *entry, *last=NULL;
	uint32_t line = 0;

	while (fgets(token, sizeof(token), fp)) {
		line++;
		if (strlen(token) <= 1) continue;
		if (token[0]=='#' || token[0]=='/') continue;
		if (strlen(token)>100) continue;

		for (i=0;i<(int)strlen(token);i++) {
			if ((token[i]==':' || token[i]==' ') && token[i+1]==':') {
				memmove(token+i+2, token+i+1, strlen(token)-i+1);
				token[i+1]='0';
			}
			if (token[i]=='#' || token[i]=='/') {
				token[i]='\0';
				break;
			}
		}

		type = 'm';
		uint32_t caid=0, provid=0, srvid=0, pid=0, chid=0, ecmlen=0;
		uint32_t to_caid=0, to_provid=0, to_srvid=0, to_pid=0, to_chid=0, to_ecmlen=0;
		int32_t valid_from=-2000, valid_to=4000;

		ret = sscanf(token, "%c:%4x:%6x:%4x:%4x:%4x:%4X=%4x:%6x:%4x:%4x:%4x:%4X,%4d,%4d",
				&type,
				&caid, &provid, &srvid, &pid, &chid, &ecmlen,
				&to_caid, &to_provid, &to_srvid, &to_pid, &to_chid, &to_ecmlen,
				&valid_from, &valid_to);

		type = tolower(type);

		if (ret<7 || type != 'm')
			continue;

		if (!cs_malloc(&entry, sizeof(struct s_cacheex_matcher))) {
			fclose(fp);
			return new_cacheex_matcher;
		}
		count++;
		entry->line=line;
		entry->type=type;
		entry->caid=caid;
		entry->provid=provid;
		entry->srvid=srvid;
		entry->pid=pid;
		entry->chid=chid;
		entry->ecmlen=ecmlen;
		entry->to_caid=to_caid;
		entry->to_provid=to_provid;
		entry->to_srvid=to_srvid;
		entry->to_pid=to_pid;
		entry->to_chid=to_chid;
		entry->to_ecmlen=to_ecmlen;
		entry->valid_from=valid_from;
		entry->valid_to=valid_to;

		cs_debug_mask(D_TRACE, "cacheex-matcher: %c: %04X:%06X:%04X:%04X:%04X:%02X = %04X:%06X:%04X:%04X:%04X:%02X valid %d/%d",
				entry->type, entry->caid, entry->provid, entry->srvid, entry->pid, entry->chid, entry->ecmlen,
				entry->to_caid, entry->to_provid, entry->to_srvid, entry->to_pid, entry->to_chid, entry->to_ecmlen,
				entry->valid_from, entry->valid_to);

		if (!new_cacheex_matcher) {
			new_cacheex_matcher=entry;
			last = new_cacheex_matcher;
		} else {
			last->next = entry;
			last = entry;
		}
	}

	if (count)
		cs_log("%d entries read from %s", count, cs_cacheex_matcher);

	fclose(fp);

	return new_cacheex_matcher;
}

void cacheex_load_config_file(void) {
	struct s_cacheex_matcher *entry, *old_list;

	old_list = cfg.cacheex_matcher;
	cfg.cacheex_matcher = cacheex_matcher_read_int();

	while (old_list) {
		entry = old_list->next;
		free(old_list);
		old_list = entry;
	}
}

static int32_t cacheex_ecm_hash_calc(uchar *buf, int32_t n) {
	int32_t i, h = 0;
	for (i = 0; i < n; i++) {
		h = 31 * h + buf[i];
	}
	return h;
}

void cacheex_update_hash(ECM_REQUEST *er) {
	er->csp_hash = cacheex_ecm_hash_calc(er->ecm+3, er->ecmlen-3);
}

/**
 * csp cacheex hit cache
 **/

void add_hitcache(struct s_client *cl, ECM_REQUEST *er) {
	bool upd_hit = true;
	if (!cfg.cacheex_wait_timetab.n)
		return;
	uint32_t cacheex_wait_time = get_cacheex_wait_time(er,NULL);
	if (!cacheex_wait_time)
		return;

	cs_writelock(&hitcache_lock);
	CSPCEHIT *ch = check_hitcache(er,cl,0);//, *ch_t = NULL;
	if (!ch && cs_malloc(&ch, sizeof(CSPCEHIT))) {
		upd_hit = false;
		ch->ecmlen = er->ecmlen;
		ch->caid = er->caid;
		ch->prid = er->prid;
		ch->srvid = er->srvid;
		ch->grp = 0;
		ch->prev = ch->next = NULL;
		if (cspec_hitcache) {
			cspec_hitcache->prev = ch;
			ch->next = cspec_hitcache;
		}
		cspec_hitcache = ch;
		cspec_hitcache_size++;
	}
	if (ch){

		cs_debug_mask(D_CACHEEX|D_CSPCWC,"[CSPCEHIT] add_hitcache %s entry ecmlen %d caid %04X provid %06X srvid %04X grp %"PRIu64" next %s size %d", upd_hit?"upd":"add", ch->ecmlen, ch->caid, ch->prid, ch->srvid, ch->grp, (ch->next)?"Yes":"No", cspec_hitcache_size);
		if(cl) ch->grp |= cl->grp;
		ch->time = time(NULL); //always update time;

		if (upd_hit && ch->prev){ //is ch->prev NULL we are top in list, no move
			if (ch->next) {
				ch->prev->next = ch->next;
				ch->next->prev = ch->prev;
			} else {
				ch->prev->next = NULL;
			}
			ch->prev = NULL;
			cspec_hitcache->prev = ch;
			ch->next = cspec_hitcache;
			cspec_hitcache = ch;
		}

	}
	cs_writeunlock(&hitcache_lock);
}

struct csp_ce_hit_t *check_hitcache(ECM_REQUEST *er, struct s_client *cl, uint8_t lock) {
	time_t now = time(NULL);
	time_t timeout = now-cfg.max_hitcache_time;
	CSPCEHIT *ch;
	uint64_t grp = cl?cl->grp:0;
	uint8_t  fs=0;

	if (lock) cs_readlock(&hitcache_lock);
	for (ch = cspec_hitcache; ch; ch = ch->next) {
		if (ch->time < timeout) {
			ch = NULL;
			break;
		}
		fs |= 1;
		if (!((er->caid == ch->caid) && (er->prid == ch->prid) && (er->srvid == ch->srvid)))
			continue;
		fs |= 2;
		if ((ch->ecmlen && er->ecmlen && ch->ecmlen != er->ecmlen))
			continue;
		if (lock) {
			fs |= 4;
			if ((grp && ch->grp && !(grp & ch->grp))){
				continue;
			}
		} else {
			fs |= 4;
		}
		fs |= 8;
		break;
	}
	if (lock) cs_readunlock(&hitcache_lock);

	if ((fs != 15) && ch) {
		cs_log("[CSPCEHIT] check_hitcache error on check hitcache");
		ch = NULL;
	}
	cs_debug_mask(D_CACHEEX| D_CSPCWC,"[CSPCEHIT] check_hitcache %s hit found max stage %d caid %04X prov %06X serv %04X grp %"PRIu64" lock %s", (fs == 15)?"yes":"no", fs, er->caid, er->prid, er->srvid, grp, lock?"yes":"no");

	return ch;
}

void cleanup_hitcache(void) {
	CSPCEHIT *current = NULL, *prv, *temp;
	int32_t count = 0;
	int32_t mct = cfg.max_hitcache_time + (cfg.max_hitcache_time / 2); // 1,5
	time_t now = time(NULL);

	cs_writelock(&hitcache_lock);
	/*for(current = cspec_hitcache, prv = NULL; current; prv=current, current = current->next, count++) {
		cs_debug_mask(D_CACHEEX,"[CSPCEHIT] cleanup time %d ecmlen %d caid %04X provid %06X srvid %04X grp %llu count %d", (int32_t)now-current->time, current->ecmlen, current->caid, current->prid, current->srvid, current->grp, count);
		if (count > 25)
			break;
	}*/

	for(current = cspec_hitcache, prv = NULL; current; prv=current, current = current->next, count++) {
		if ((now - current->time) < mct) { // delete old Entry to hold list small
			continue;
		}
		if (prv) {
			prv->next  = NULL;
		} else {
			cspec_hitcache = NULL;
		}
		break; //we need only once, all follow to old
	}
	cs_writeunlock(&hitcache_lock);
	cspec_hitcache_size = count;

	if (current)
		cs_debug_mask(D_CACHEEX|D_CSPCWC,"[CSPCEHIT] cleanup list new size %d ct %d", cspec_hitcache_size, mct);

	if (current) {
		while (current) {
			temp = current->next;
			free(current);
			current = NULL;
			current = temp;
		}
	}
}

uint32_t get_cacheex_wait_time(ECM_REQUEST *er, struct s_client *cl) {
	int32_t i,dwtime= -1,awtime=-1;
	CSPCEHIT *ch;

	for (i = 0; i < cfg.cacheex_wait_timetab.n; i++) {
		if (i == 0 && cfg.cacheex_wait_timetab.caid[i] <= 0) {
			dwtime = cfg.cacheex_wait_timetab.dwtime[i];
			awtime = cfg.cacheex_wait_timetab.awtime[i];
			continue; //check other, only valid for unset
		}

		if (cfg.cacheex_wait_timetab.caid[i] == er->caid || cfg.cacheex_wait_timetab.caid[i] == er->caid>>8 || ((cfg.cacheex_wait_timetab.cmask[i]>=0 && (er->caid & cfg.cacheex_wait_timetab.cmask[i]) == cfg.cacheex_wait_timetab.caid[i]) || cfg.cacheex_wait_timetab.caid[i] == -1)) {
			if ((cfg.cacheex_wait_timetab.prid[i]>=0 && cfg.cacheex_wait_timetab.prid[i] == (int32_t)er->prid) || cfg.cacheex_wait_timetab.prid[i] == -1) {
				if ((cfg.cacheex_wait_timetab.srvid[i]>=0 && cfg.cacheex_wait_timetab.srvid[i] == er->srvid) || cfg.cacheex_wait_timetab.srvid[i] == -1) {
					dwtime = cfg.cacheex_wait_timetab.dwtime[i];
					awtime = cfg.cacheex_wait_timetab.awtime[i];
					break;
				}
			}

		};

	}
	if (awtime > 0 && dwtime <= 0) {
		return awtime;
	}
	if (cl == NULL) {
		if (dwtime < 0)
			dwtime = 0;
		return dwtime;
	}
	if (awtime > 0 || dwtime > 0) {
		//if found last in cache return dynwaittime else alwayswaittime
		ch = check_hitcache(er,cl,1);
		if (ch)
			return dwtime>=awtime?dwtime:awtime;
		else
			return awtime>0?awtime:0;
	}
	return 0;
}

int32_t chk_csp_ctab(ECM_REQUEST *er, CECSPVALUETAB *tab) {
	if (!er->caid || !tab->n)
		return 1; // nothing setup we add all
	int32_t i;
	for (i = 0; i < tab->n; i++) {

	  if (tab->caid[i] > 0) {
		  if (tab->caid[i] == er->caid || tab->caid[i] == er->caid>>8 || ((tab->cmask[i]>=0 && (er->caid & tab->cmask[i]) == tab->caid[i]) || tab->caid[i] == -1)) {
			  if ((tab->prid[i]>=0 && tab->prid[i] == (int32_t)er->prid) || tab->prid[i] == -1) {
				  if ((tab->srvid[i]>=0 && tab->srvid[i] == er->srvid) || tab->srvid[i] == -1) {
					  return 1;
				  }
			  }
		  }
	  }
	}
	return 0;
}

uint8_t check_cacheex_filter(struct s_client *cl, ECM_REQUEST *er) {
	CECSP *ce_csp = NULL;
	uint8_t ret = 1;
	if (cl->typ == 'c') {
		if (cl->account &&	cl->account->cacheex.mode==3) {
			ce_csp = &cl->account->cacheex;
		}
	} else if (cl->typ == 'p'){
		if (cl->reader && cl->reader->cacheex.mode==2) {
			ce_csp = &cl->reader->cacheex;
		}
	}

	if (ce_csp) {
		if (!chk_csp_ctab(er, &ce_csp->filter_caidtab))
			ret = 0;
		if (er->rc != E_FOUND && !ce_csp->allow_request)
			ret = 0;
		if (ce_csp->drop_csp && !checkECMD5(er))
			ret = 0;
	}
	if (!ret)
		free(er);
	return ret;
}

#endif
