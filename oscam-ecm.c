#include "globals.h"
#include "cscrypt/md5.h"
#include "module-anticasc.h"
#include "module-cacheex.h"
#include "module-led.h"
#include "module-stat.h"
#include "module-webif.h"
#include "module-ird-guess.h"
#include "module-cw-cycle-check.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-config.h"
#include "oscam-ecm.h"
#include "oscam-garbage.h"
#include "oscam-failban.h"
#include "oscam-net.h"
#include "oscam-time.h"
#include "oscam-lock.h"
#include "oscam-string.h"
#include "oscam-work.h"
#include "reader-common.h"

extern CS_MUTEX_LOCK ecmcache_lock;
extern struct ecm_request_t *ecmcwcache;
extern uint16_t len4caid[256];
extern uint32_t ecmcwcache_size;
extern int32_t exit_oscam;

extern struct ecm_request_t *ecm_pushed;
extern CS_MUTEX_LOCK ecm_pushed_lock;

static pthread_mutex_t cw_process_sleep_cond_mutex;
static pthread_cond_t cw_process_sleep_cond;
static int cw_process_wakeups;

static uint32_t auto_timeout(ECM_REQUEST *er, uint32_t timeout) {
	(void)er; // Prevent warning about unused er, when WITH_LB is disabled
#ifdef WITH_LB
	if (cfg.lb_auto_timeout)
		return lb_auto_timeout(er, timeout);
#endif
	return timeout;
}

#ifdef CS_CACHEEX
void cacheex_timeout(ECM_REQUEST *er){
	er->cacheex_wait_time_expired=1;
	if(er->rc >= E_UNHANDLED && er->stage < 2 && er->cacheex_wait_time){
		cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} cacheex timeout! ",(check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid);

		//check if "normal" readers selected
		if(  (!er->from_cacheex1_client && (er->reader_count+er->fallback_reader_count-er->cacheex_reader_count)<=0)  //not-cacheex-1 client and no normal readers avilable (or filtered by LB)
			 ||
			 (er->from_cacheex1_client && !er->reader_nocacheex_avail)  //cacheex1-client and no normal readers available for others clients
		){
			er->rc = E_NOTFOUND;
			er->selected_reader = NULL;
			if (er->reader_requested>0)
				er->rcEx = 0;  //not found by reader
			else
				er->rcEx = E2_GROUP;  //no matching reader

			cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} NO Readers... not_found! ",(check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid);
			send_dcw(er->client, er);
			return;

		}else{
			debug_ecm(D_TRACE, "request for %s %s", username(er->client), buf);
			request_cw_from_readers(er,0);
		}
	}
}
#endif

void fallback_timeout(ECM_REQUEST *er){
	if(er->rc >= E_UNHANDLED && er->stage < 4){
		cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} fallback timeout! (stage: %d)",(check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid, er->stage);
		debug_ecm(D_TRACE, "fallback for %s %s", username(er->client), buf);
		while(er->stage<4){ //if preferlocalcards=1 and no answer from locals, initial stage will be 2! We need to reach stage=4 to call fallback's.
			request_cw_from_readers(er,0);
		}
	}
}

void ecm_timeout(ECM_REQUEST *er){
	if(!er->readers_timeout_check){
		er->readers_timeout_check=1;

		if (check_client(er->client) && er->rc >= E_UNHANDLED) {
			cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} client timeout! ",(check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid);
			debug_ecm(D_TRACE, "timeout for %s %s", username(er->client), buf);
		}

#ifdef CS_CACHEEX
		bool send_timeout=false;
#endif

		struct s_ecm_answer *ea_list;
		for(ea_list = er->matching_rdr; ea_list; ea_list = ea_list->next) {
			if ((ea_list->status & (REQUEST_SENT|REQUEST_ANSWERED)) == REQUEST_SENT){ //Request sent, but no answer!
				write_ecm_answer(ea_list->reader, er, E_TIMEOUT, 0, NULL, NULL); //set timeout for readers not answered!
#ifdef CS_CACHEEX
				send_timeout=true;
#endif
			}
		}

#ifdef CS_CACHEEX
		if(er->from_cacheex1_client && !send_timeout && er->rc==E_UNHANDLED){//cacheex 1 clients waiting for INT cache by "normal" readers
			er->rc = E_NOTFOUND;
			er->selected_reader = NULL;
			if (er->reader_requested>0)
				er->rcEx = 0;  //not found by reader
			else
				er->rcEx = E2_GROUP;  //no matching reader

			cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} NO cw found in cache for cacheex-1 client... send not found! ",(check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid);
			send_dcw(er->client, er);
		}
#endif

	}
}

static void *cw_process(void) {
	set_thread_name(__func__);
	int32_t time_to_check_fbtimeout, time_to_check_ctimeout, next_check, ecmc_next, msec_wait = 3000;
	struct timeb t_now, tbc, ecmc_time;
	ECM_REQUEST *er = NULL;
	time_t ecm_maxcachetime;

#ifdef CS_CACHEEX
	int32_t time_to_check_cacheex_wait_time;
#endif

	pthread_mutex_init(&cw_process_sleep_cond_mutex, NULL);
	pthread_cond_init(&cw_process_sleep_cond, NULL);

#ifdef CS_ANTICASC
	int32_t ac_next;
	struct timeb ac_time;
	cs_ftime(&ac_time);
	add_ms_to_timeb(&ac_time, cfg.ac_stime*60*1000);
#endif

	cs_ftime(&ecmc_time);
	add_ms_to_timeb(&ecmc_time, 1000);

	while (!exit_oscam) {
		if (cw_process_wakeups == 0) { // No waiting wakeups, proceed to sleep
			sleepms_on_cond(&cw_process_sleep_cond, &cw_process_sleep_cond_mutex, msec_wait);
		}
		cw_process_wakeups = 0; // We've been woken up, reset the counter
		if (exit_oscam)
			break;

		next_check = 0;
#ifdef CS_ANTICASC
		ac_next = 0;
#endif
		ecmc_next = 0;
		msec_wait = 0;

		cs_ftime(&t_now);
		cs_readlock(&ecmcache_lock);
		for (er = ecmcwcache; er; er = er->next) {

			if(
				(er->from_cacheex || er->from_csp)				    //ignore ecms from cacheex/csp
				||
				er->readers_timeout_check  							//ignore already checked
				||
				!check_client(er->client)							//ignore ecm of killed clients
			)
			    continue;

			if(er->rc >= E_UNHANDLED){

#ifdef CS_CACHEEX
				//cacheex_wait_time
				if(er->stage<2 && er->cacheex_wait_time){
					tbc = er->tps;
					time_to_check_cacheex_wait_time=add_ms_to_timeb(&tbc,auto_timeout(er, er->cacheex_wait_time));
					if (comp_timeb(&t_now, &tbc) >= 0) {
						add_job(er->client, ACTION_CACHEEX_TIMEOUT, (void*)er, 0);
						time_to_check_cacheex_wait_time=0;
					}
					if (!next_check || (time_to_check_cacheex_wait_time > 0 && time_to_check_cacheex_wait_time < next_check))
						next_check = time_to_check_cacheex_wait_time;
				}
#endif
				if(er->stage<4){
					//fbtimeout
					tbc = er->tps;
					time_to_check_fbtimeout=add_ms_to_timeb(&tbc,auto_timeout(er, get_fallbacktimeout(er->caid)));
					if (comp_timeb(&t_now, &tbc) >= 0) {
						add_job(er->client, ACTION_FALLBACK_TIMEOUT, (void*)er, 0);
						time_to_check_fbtimeout=0;
					}
					if (!next_check || (time_to_check_fbtimeout > 0 && time_to_check_fbtimeout < next_check))
						next_check = time_to_check_fbtimeout;
				}
			}


			//clienttimeout
			if(!er->readers_timeout_check){ //ecm stays in cache at least ctimeout+2seconds!
				tbc = er->tps;
				time_to_check_ctimeout=add_ms_to_timeb(&tbc,auto_timeout(er, cfg.ctimeout));
				if (comp_timeb(&t_now, &tbc) >= 0) {
					add_job(er->client, ACTION_CLIENT_TIMEOUT, (void*)er, 0);
					time_to_check_ctimeout=0;
				}
				if (!next_check || (time_to_check_ctimeout > 0 && time_to_check_ctimeout < next_check))
					next_check = time_to_check_ctimeout;
			}
		}
		cs_readunlock(&ecmcache_lock);
#ifdef CS_ANTICASC
		if (cfg.ac_enabled && (ac_next = comp_timeb(&ac_time, &t_now)) <= 10) {
			ac_do_stat();
			cs_ftime(&ac_time);
			ac_next = add_ms_to_timeb(&ac_time, cfg.ac_stime*60*1000);
		}
#endif
		if ((ecmc_next = comp_timeb(&ecmc_time, &t_now)) <= 10) {
			ecm_maxcachetime = t_now.time-cfg.max_cache_time;
			uint32_t count = 0;
			struct ecm_request_t *ecm, *ecmt=NULL, *prv;

			cs_readlock(&ecmcache_lock);
			for (ecm = ecmcwcache, prv = NULL; ecm; prv = ecm, ecm = ecm->next, count++) {
				if (ecm->tps.time < ecm_maxcachetime) {
					cs_readunlock(&ecmcache_lock);
					cs_writelock(&ecmcache_lock);
					ecmt = ecm;
					if (prv)
						prv->next = NULL;
					else
						ecmcwcache = NULL;
					cs_writeunlock(&ecmcache_lock);
					break;
				}
			}
			if (!ecmt)
				cs_readunlock(&ecmcache_lock);
			ecmcwcache_size = count;

			while (ecmt) {
				ecm = ecmt->next;
				free_ecm(ecmt);
				ecmt = ecm;
			}

#ifdef CS_CACHEEX
			ecmt=NULL;
			cs_readlock(&ecm_pushed_lock);
			for (ecm = ecm_pushed, prv = NULL; ecm; prv = ecm, ecm = ecm->next) {
				if (ecm->tps.time < ecm_maxcachetime) {
					cs_readunlock(&ecm_pushed_lock);
					cs_writelock(&ecm_pushed_lock);
					ecmt = ecm;
					if (prv)
						prv->next = NULL;
					else
						ecm_pushed = NULL;
					cs_writeunlock(&ecm_pushed_lock);
					break;
				}
			}
			if (!ecmt)
				cs_readunlock(&ecm_pushed_lock);

			while (ecmt) {
				ecm = ecmt->next;
				free_ecm(ecmt);
				ecmt = ecm;
			}
#endif

			cs_ftime(&ecmc_time);
			ecmc_next = add_ms_to_timeb(&ecmc_time, 1000);
		}
		msec_wait = next_check;
#ifdef CS_ANTICASC
		if (!msec_wait || (ac_next > 0 && ac_next < msec_wait))
			msec_wait = ac_next;
#endif
		if (!msec_wait || (ecmc_next > 0 && ecmc_next < msec_wait))
			msec_wait = ecmc_next;

		if (!msec_wait)
			msec_wait = 3000;

		cleanupcwcycle();
		cleanup_hitcache();
	}

	return NULL;
}

void cw_process_thread_start(void) {
	start_thread((void *) &cw_process, "cw_process");
}

void cw_process_thread_wakeup(void) {
	cw_process_wakeups++; // Do not sleep...
	pthread_cond_signal(&cw_process_sleep_cond);
}


#ifdef CS_CACHEEX
bool cmp_ecm(ECM_REQUEST *er_new, ECM_REQUEST *er_cache)
{
	uint64_t grp = check_client(er_new->client)?er_new->client->grp:0;
	uint8_t ecmd5chk = 0;
	bool hasMatchAlias = false;
	ecmd5chk = checkECMD5(er_new);
	hasMatchAlias = cacheex_is_match_alias(er_new->client, er_new);

	if (er_cache==er_new) return false;

	if (!hasMatchAlias || !cacheex_match_alias(er_new->client, er_new, er_cache)) {
		//CWs from csp/cacheex have no ecms, csp ecmd5 is invalid, cacheex has ecmd5
		if (ecmd5chk && checkECMD5(er_cache)) {
			if (memcmp(er_cache->ecmd5, er_new->ecmd5, CS_ECMSTORESIZE))
				return false; // no match
		} else if (er_cache->csp_hash != er_new->csp_hash) //fallback for csp only
			return false; // no match
	}

	if (er_new->caid != er_cache->caid && er_cache->rc >= E_NOTFOUND && !chk_is_betatunnel_caid(er_new->caid))
		return false; //CW for the cached er_cache wasn't found but now the client asks on a different caid so give it another try

	//group check --> NOT check for rc!
	if(
		(grp
		&& er_cache->grp
		&& (grp & er_cache->grp))
		|| er_cache->from_csp || er_cache->csp_answered   //no group from csp cache
	){
		return true;
	}

	return false;
}
#endif

/**
 * get ecm from INT. cache
 **/
struct ecm_request_t *check_cwcache(ECM_REQUEST *er, struct s_client *cl)
{
#ifdef CS_CACHEEX
	// precalculate for better performance
	uint8_t ecmd5chk = checkECMD5(er);
	bool hasMatchAlias = cacheex_is_match_alias(cl, er);
#endif
	struct ecm_request_t *ecm;
	time_t timeout = time(NULL)-cfg.max_cache_time;
	uint64_t grp = cl && !cl->kill?cl->grp:0;

	cs_readlock(&ecmcache_lock);
	for (ecm = ecmcwcache; ecm; ecm = ecm->next) {
		if (ecm->tps.time <= timeout) {
			ecm = NULL;
			break;
		}

		if (ecm==er) continue;

	#ifdef CS_CACHEEX
		if (!hasMatchAlias || !cacheex_match_alias(cl, er, ecm)) {
			//CWs from csp/cacheex have no ecms, csp ecmd5 is invalid, cacheex has ecmd5
			if (ecmd5chk && checkECMD5(ecm)) {
				if (memcmp(ecm->ecmd5, er->ecmd5, CS_ECMSTORESIZE))
					continue;
			} else if (ecm->csp_hash != er->csp_hash) //fallback for csp only
				continue;
		}
	#else
		if (memcmp(ecm->ecmd5, er->ecmd5, CS_ECMSTORESIZE))
			continue;
	#endif

		if (er->caid != ecm->caid && ecm->rc >= E_NOTFOUND && !chk_is_betatunnel_caid(er->caid))
			continue; //CW for the cached ecm wasn't found but now the client asks on a different caid so give it another try

		//group and rc check
		if( (
				(grp  //client group
				&& ecm->grp  //ecm group --> only when readers/ex-clients answer (e_found) it
				&& (grp & ecm->grp))
			   #ifdef CS_CACHEEX
				|| ecm->from_csp || ecm->csp_answered   //no group from csp cache
			   #endif
			)
			&& ecm->rc<E_NOTFOUND
		){
			cs_readunlock(&ecmcache_lock);
			return ecm;
		}
	}
	cs_readunlock(&ecmcache_lock);
	return NULL; // nothing found so return null
}


#ifdef WITH_LB
/**
 * get same ecm hash with same readers
 **/
struct ecm_request_t *check_same_ecm(ECM_REQUEST *er)
{
	struct ecm_request_t *ecm;
	time_t timeout = time(NULL)-cfg.max_cache_time;

	cs_readlock(&ecmcache_lock);
	for (ecm = ecmcwcache; ecm; ecm = ecm->next) {
		if (ecm->tps.time <= timeout) {
			ecm = NULL;
			break;
		}

		if (ecm==er) continue;

		if (er->caid!=ecm->caid || memcmp(ecm->ecmd5, er->ecmd5, CS_ECMSTORESIZE))
			continue;

		if (!er->readers || !ecm->readers || er->readers!=ecm->readers)
			continue;

		struct s_ecm_answer *ea_ecm = ecm->matching_rdr;
		struct s_ecm_answer *ea_er = er->matching_rdr;
		uint8_t rdrs=er->readers;
		while(rdrs){
			if(ea_ecm->reader!=ea_er->reader)
				break;
			ea_ecm=ea_ecm->next;
			ea_er=ea_er->next;
			rdrs--;
		}

		if(!rdrs)
		{
			cs_readunlock(&ecmcache_lock);
			return ecm;
		}
	}
	cs_readunlock(&ecmcache_lock);
	return NULL; // nothing found so return null
}


void use_same_readers(ECM_REQUEST *er_new, ECM_REQUEST *er_cache){
	struct s_ecm_answer *ea_new = er_new->matching_rdr;
	struct s_ecm_answer *ea_cache = er_cache->matching_rdr;
	uint8_t rdrs=er_new->readers;
	while(rdrs){
		ea_new->status &= ~(READER_ACTIVE|READER_FALLBACK);
		if((ea_cache->status & READER_ACTIVE)){
			if(!(ea_cache->status & READER_FALLBACK)){
				ea_new->status |= READER_ACTIVE;
			}else{
				ea_new->status |= (READER_ACTIVE|READER_FALLBACK);
			}
		}

		ea_new=ea_new->next;
		ea_cache=ea_cache->next;
		rdrs--;
	}
}

#endif



void convert_to_beta(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto)
{
	static uint8_t headerN3[10] = {0xc7, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x87, 0x12};
	static uint8_t headerN2[10] = {0xc9, 0x00, 0x00, 0x00, 0x01, 0x10, 0x10, 0x00, 0x48, 0x12};

	er->ocaid = er->caid;
	er->caid = caidto;
	er->prid = 0;
	er->ecmlen = er->ecm[2] + 3;

	memmove(er->ecm + 13, er->ecm + 3, er->ecmlen - 3);

	if (er->ecmlen > 0x88) {
		memcpy(er->ecm + 3, headerN3, 10);
		if (er->ecm[0] == 0x81)
			er->ecm[12] += 1;
		er->ecm[1]=0x70;
	} else {
		memcpy(er->ecm + 3, headerN2, 10);
	}

	er->ecmlen += 10;
	er->ecm[2] = er->ecmlen - 3;
	er->btun = 1;

	cl->cwtun++;
	cl->account->cwtun++;
	first_client->cwtun++;

	cs_debug_mask(D_TRACE, "ECM converted ocaid from 0x%04X to BetaCrypt caid 0x%04X for service id 0x%04X",
		er->ocaid, caidto, er->srvid);
}

void convert_to_nagra(struct s_client *cl, ECM_REQUEST *er, uint16_t caidto)
{
	cs_debug_mask(D_TRACE, "convert_to_nagra");
	er->ocaid = er->caid;
	er->caid = caidto;
	er->prid = 0;
	er->ecmlen = er->ecm[2] + 3;

	//not sure
	if (er->ecmlen < 0x52)
		er->ecm[1] = 0x30;

	memmove(er->ecm + 3, er->ecm + 13, er->ecmlen - 3);

	er->ecmlen -= 10;
	er->ecm[2] = er->ecmlen - 3;
	er->btun = 1;

	cl->cwtun++;
	cl->account->cwtun++;
	first_client->cwtun++;

	cs_debug_mask(D_TRACE, "ECM converted ocaid from: 0x%04X to Nagra: 0x04%X for service id:0x04%X",
		er->ocaid, caidto, er->srvid);
}

void cs_betatunnel(ECM_REQUEST *er)
{
	int32_t n;
	struct s_client *cl = cur_client();
	uint32_t mask_all = 0xFFFF;

	TUNTAB *ttab;
	ttab = &cl->ttab;

	for (n = 0; n<ttab->n; n++) {
		if ((er->caid==ttab->bt_caidfrom[n]) && ((er->srvid==ttab->bt_srvid[n]) || (ttab->bt_srvid[n])==mask_all)) {
			if (chk_is_betatunnel_caid(er->caid) == 1 && er->ocaid == 0x0000) {
				convert_to_nagra(cl, er, ttab->bt_caidto[n]);
			} else if (er->ocaid == 0x0000) {
				convert_to_beta(cl, er, ttab->bt_caidto[n]);
			}
			return;
		}
	}
}

static void remove_ecm_from_reader(ECM_REQUEST *ecm)
{
	int32_t i;
	struct s_ecm_answer *ea = ecm->matching_rdr;
	while (ea) {
		if ((ea->status & REQUEST_SENT) && !(ea->status & REQUEST_ANSWERED)) {
			//we found a outstanding reader, clean it:
			struct s_reader *rdr = ea->reader;
			if (rdr) {
				struct s_client *cl = rdr->client;
				if (check_client(cl)) {
					ECM_REQUEST *ecmtask = cl->ecmtask;
					if (ecmtask) {
						for (i = 0; i < cfg.max_pending; ++i) {
							if (ecmtask[i].parent == ecm) {
								ecmtask[i].client = NULL;
								cacheex_set_csp_lastnode(&ecmtask[i]);
							}
						}
					}
				}
			}
		}
		ea = ea->next;
	}
}

void free_ecm(ECM_REQUEST *ecm)
{
	struct s_ecm_answer *ea, *nxt;
	cacheex_free_csp_lastnodes(ecm);
	//remove this ecm from reader queue to avoid segfault on very late answers (when ecm is already disposed)
	//first check for outstanding answers:
	remove_ecm_from_reader(ecm);
	//free matching_rdr list:
	ea = ecm->matching_rdr;
	ecm->matching_rdr = NULL;
	while (ea) {
		nxt = ea->next;
		cs_lock_destroy(&ea->ecmanswer_lock);
		add_garbage(ea);
		ea = nxt;
	}
	if (ecm->src_data)
		add_garbage(ecm->src_data);
	add_garbage(ecm);
}

ECM_REQUEST *get_ecmtask(void)
{
	ECM_REQUEST *er = NULL;
	struct s_client *cl = cur_client();
	if (!cl)
		return NULL;
	if (!cs_malloc(&er, sizeof(ECM_REQUEST)))
		return NULL;
	cs_ftime(&er->tps);

#ifdef CS_CACHEEX
	er->cacheex_wait.time = er->tps.time;
	er->cacheex_wait.millitm = er->tps.millitm;
	er->cacheex_wait_time = 0;
#endif
#ifdef MODULE_GBOX
    er->gbox_ecm_id = 0;
    er->gbox_hops = 0;
#endif
	er->rc     = E_UNHANDLED;
	er->client = cl;
	er->grp    = 0;  //no readers/cacheex-clients answers yet
	//cs_log("client %s ECMTASK %d module %s", username(cl), n, get_module(cl)->desc);
	return er;
}

void cleanup_ecmtasks(struct s_client *cl)
{
	if(cl && !cl->account->usr) return;  //not for anonymous users!

	ECM_REQUEST *ecm;

	//remove this clients ecm from queue. because of cache, just null the client:
	cs_readlock(&ecmcache_lock);
	for (ecm = ecmcwcache; ecm; ecm = ecm->next) {
		if (ecm->client == cl) {
			ecm->client = NULL;
			cacheex_set_cacheex_src(ecm, cl);
		}
	}
	cs_readunlock(&ecmcache_lock);

	//remove client from rdr ecm-queue:
	cs_readlock(&readerlist_lock);
	struct s_reader *rdr = first_active_reader;
	while (rdr) {
		if (check_client(rdr->client) && rdr->client->ecmtask) {
			int i;
			for (i = 0; i < cfg.max_pending; i++) {
				ecm = &rdr->client->ecmtask[i];
				if (ecm->client == cl) {
					ecm->client = NULL;
				}
			}
		}
		rdr = rdr->next;
	}
	cs_readunlock(&readerlist_lock);
}


static void add_cascade_data(struct s_client *client, ECM_REQUEST *er)
{
	if (!client->cascadeusers)
		client->cascadeusers = ll_create("cascade_data");
	LLIST *l = client->cascadeusers;
	LL_ITER it = ll_iter_create(l);
	time_t now = time(NULL);
	struct s_cascadeuser *cu;
	int8_t found = 0;
	while ((cu = ll_iter_next(&it))) {
		if (er->caid==cu->caid && er->prid==cu->prid && er->srvid==cu->srvid) { //found it
			if (cu->time < now)
				cu->cwrate = now-cu->time;
			cu->time = now;
			found = 1;
		}
		else if (cu->time+60 < now) //  old
			ll_iter_remove_data(&it);
	}
	if (!found) { //add it if not found
		if (!cs_malloc(&cu, sizeof(struct s_cascadeuser)))
			return;
		cu->caid = er->caid;
		cu->prid = er->prid;
		cu->srvid = er->srvid;
		cu->time = now;
		ll_append(l, cu);
	}
}

static int32_t is_double_check_caid(ECM_REQUEST *er)
{
	if (!cfg.double_check_caid.caid[0]) //no caids defined: Check all
		return 1;
	int32_t i;
	for (i = 0; i < CS_MAXCAIDTAB; i++) {
		uint16_t tcaid = cfg.double_check_caid.caid[i];
		if (!tcaid)
			break;
		if (tcaid == er->caid || (tcaid < 0x0100 && (er->caid >> 8) == tcaid)) {
			return 1;
		}
	}
	return 0;
}

struct s_ecm_answer * get_ecm_answer(struct s_reader * reader, ECM_REQUEST *er){
	if(!er || !reader) return NULL;

	struct s_ecm_answer *ea;

	for (ea = er->matching_rdr; ea; ea = ea->next){
		if(ea->reader == reader){
			return ea;
		}
	}
	return NULL;
}


void distribute_ea(struct s_ecm_answer *ea){

	struct s_ecm_answer *ea_temp;

	for (ea_temp = ea->pending; ea_temp; ea_temp = ea_temp->pending_next){
			cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [distribute_ea] send ea by reader %s answering for client %s", (check_client(ea_temp->er->client)?ea_temp->er->client->account->usr:"-"),ea_temp->er->caid, ea_temp->er->prid, ea_temp->er->srvid, ea_temp->reader->label, (check_client(ea->er->client)?ea->er->client->account->usr:"-"));
			write_ecm_answer(ea_temp->reader, ea_temp->er, ea->rc, ea->rcEx, ea->cw, NULL);
	}
}


int32_t send_dcw(struct s_client * client, ECM_REQUEST *er)
{
	if (!check_client(client) || client->typ != 'c')
		return 0;

	cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [send_dcw] rc %d from reader %s", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid, er->rc, er->selected_reader?er->selected_reader->label:"-");

	static const char stageTxt[]={'0','C','L','P','F','X'};
	static const char *stxt[]={"found", "cache1", "cache2", "cache3",
			"not found", "timeout", "sleeping",
			"fake", "invalid", "corrupt", "no card", "expdate", "disabled", "stopped"};
	static const char *stxtEx[16]={"", "group", "caid", "ident", "class", "chid", "queue", "peer", "sid", "", "", "", "", "", "", ""};
	static const char *stxtWh[16]={"", "user ", "reader ", "server ", "lserver ", "", "", "", "", "", "", "", "" ,"" ,"", ""};
	char sby[100]="", sreason[32]="", schaninfo[32]="";
	char erEx[32]="";
	char uname[38]="";
	char channame[32];
	struct timeb tpe;

	snprintf(uname,sizeof(uname)-1, "%s", username(client));

#ifdef WITH_DEBUG
	if (cs_dblevel & D_CLIENTECM) {
		char buf[ECM_FMT_LEN];
		char ecmd5[17*3];
		char cwstr[17*3];
		format_ecm(er, buf, ECM_FMT_LEN);
		cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
		cs_hexdump(0, er->cw, 16, cwstr, sizeof(cwstr));
#ifdef CS_CACHEEX
		char csphash[5*3];
		cs_hexdump(0, (void*)&er->csp_hash, 4, csphash, sizeof(csphash));
		cs_debug_mask(D_CLIENTECM, "Client %s csphash %s cw %s rc %d %s", username(client), csphash, cwstr, er->rc, buf);
#else
		cs_debug_mask(D_CLIENTECM, "Client %s cw %s rc %d %s", username(client), cwstr, er->rc, buf);
#endif
	}
#endif

	struct s_reader *er_reader = er->selected_reader; //responding reader
	struct s_ecm_answer *ea_orig = get_ecm_answer(er_reader,er);

	//check if ecm_answer from pending's
	if(ea_orig && er->rc==E_FOUND)
		if(ea_orig->is_pending)
			er->rc = E_CACHE2;

	//check if answer from cacheex-1 reader
	if(er->rc==E_FOUND && er_reader && cacheex_reader(er_reader)){ //so add hit to cacheex mode 1 readers
		er->rc = E_CACHEEX;
	}

	if (er->rc == E_TIMEOUT) {
		struct s_ecm_answer *ea_list;
		int32_t ofs = 0;
		for (ea_list = er->matching_rdr; ea_list; ea_list = ea_list->next) {
			if (ea_list->reader && ofs < (int32_t)sizeof(sby) && ( (ea_list->status & REQUEST_SENT) && (ea_list->rc==E_TIMEOUT || ea_list->rc>=E_99))) { //Request send, but no cw answered!
				ofs += snprintf(sby+ofs, sizeof(sby)-ofs-1, "%s%s", ofs?",":" by ", ea_list->reader->label);
			}
		}
		if (er->ocaid && ofs < (int32_t)sizeof(sby))
			ofs += snprintf(sby+ofs, sizeof(sby)-ofs-1, "(btun %04X)", er->ocaid);
	}else if (er_reader) {
		// add marker to reader if ECM_REQUEST was betatunneled
		if (er->ocaid)
			snprintf(sby, sizeof(sby)-1, " by %s(btun %04X)", er_reader->label, er->ocaid);
		else
			snprintf(sby, sizeof(sby)-1, " by %s", er_reader->label);
	}
#ifdef CS_CACHEEX
	else if(er->cacheex_src){  //only for cacheex mode-3 clients (no mode-1 or mode-2 because reader is set!) and csp - cache1 coming from cacheex have no reader set!
		if (er->ocaid)
			snprintf(sby, sizeof(sby)-1, " by %s(btun %04X)", (check_client(er->cacheex_src)? (er->cacheex_src->account && er->cacheex_src->account->usr[0]!='\0'?er->cacheex_src->account->usr:"csp") :"-"), er->ocaid);
		else
			snprintf(sby, sizeof(sby)-1, " by %s", (check_client(er->cacheex_src)? (er->cacheex_src->account && er->cacheex_src->account->usr[0]!='\0'?er->cacheex_src->account->usr:"csp") :"-"));
	}
#endif

	if (er->rc < E_NOTFOUND)
		er->rcEx = 0;

	if (er->rcEx)
		snprintf(erEx, sizeof(erEx)-1, "rejected %s%s", stxtWh[er->rcEx>>4], stxtEx[er->rcEx & 0xf]);

	get_servicename_or_null(client, er->srvid, er->caid, channame);
	if (!channame[0])
		schaninfo[0] = '\0';
	else
		snprintf(schaninfo, sizeof(schaninfo)-1, " - %s", channame);

	if (er->msglog[0])
		snprintf(sreason, sizeof(sreason)-1, " (%s)", er->msglog);

	cs_ftime(&tpe);

#ifdef CS_CACHEEX
	if(er->cacheex_wait_time && er->rc!=E_TIMEOUT){
		if (er->rc >= E_CACHEEX){
			uint32_t ntime = comp_timeb(&tpe,&er->tps);
			if (ntime >= er->cacheex_wait_time){
				snprintf(sreason, sizeof(sreason)-1, " (wait_time over)");
			}
		}
		else if (er->rc == E_FOUND){
			if(ea_orig) snprintf(sreason, sizeof(sreason)-1, " (real %d ms)", ea_orig->ecm_time);
		}
	}
#endif

	client->cwlastresptime = 1000 * (tpe.time-er->tps.time) + tpe.millitm-er->tps.millitm;

	time_t now = time(NULL);
	webif_client_add_lastresponsetime(client, client->cwlastresptime, now, er->rc); // add to ringbuffer

	if (er_reader) {
		struct s_client *er_cl = er_reader->client;
		if (check_client(er_cl)) {
			er_cl->cwlastresptime = client->cwlastresptime;
			webif_client_add_lastresponsetime(er_cl, client->cwlastresptime, now, er->rc);
			er_cl->last_srvidptr = client->last_srvidptr;
		}
	}

	webif_client_init_lastreader(client, er, er_reader, stxt);

	client->last = now;

	//cs_debug_mask(D_TRACE, "CHECK rc=%d er->cacheex_src=%s", er->rc, username(er->cacheex_src));
	switch(er->rc) {
	case E_FOUND: {
		client->cwfound++;
		client->account->cwfound++;
		first_client->cwfound++;
		break;
	}
	case E_CACHE1:
	case E_CACHE2:
	case E_CACHEEX: {
		client->cwcache++;
		client->account->cwcache++;
		first_client->cwcache++;
#ifdef CS_CACHEEX
		if (er->cacheex_src) {
			er->cacheex_src->cwcacheexhit++;
			if (er->cacheex_src->account)
				er->cacheex_src->account->cwcacheexhit++;
			first_client->cwcacheexhit++;
		}
#endif
		break;
	}
	case E_NOTFOUND:
	case E_CORRUPT:
	case E_NOCARD: {
		if (er->rcEx) {
			client->cwignored++;
			client->account->cwignored++;
			first_client->cwignored++;
		} else {
			client->cwnot++;
			client->account->cwnot++;
			first_client->cwnot++;
		}
		break;
	}
	case E_TIMEOUT: {
		client->cwtout++;
		client->account->cwtout++;
		first_client->cwtout++;
		break;
	}
	default: {
		client->cwignored++;
		client->account->cwignored++;
		first_client->cwignored++;
	} }


	ac_chk(client, er, 1);
	int32_t is_fake = 0;
	if (er->rc == E_FAKE) {
		is_fake = 1;
		er->rc = E_FOUND;
	}

	if (cfg.double_check &&  er->rc == E_FOUND && er->selected_reader && is_double_check_caid(er)) {
		if (er->checked == 0) {//First CW, save it and wait for next one
			er->checked = 1;
			er->origin_reader = er->selected_reader;
			memcpy(er->cw_checked, er->cw, sizeof(er->cw));
			cs_log("DOUBLE CHECK FIRST CW by %s idx %d cpti %d", er->origin_reader->label, er->idx, er->msgid);
		} else if (er->origin_reader != er->selected_reader) { //Second (or third and so on) cw. We have to compare
			if (memcmp(er->cw_checked, er->cw, sizeof(er->cw)) == 0) {
				er->checked++;
				cs_log("DOUBLE CHECKED! %d. CW by %s idx %d cpti %d", er->checked, er->selected_reader->label, er->idx, er->msgid);
			} else {
				cs_log("DOUBLE CHECKED NONMATCHING! %d. CW by %s idx %d cpti %d", er->checked, er->selected_reader->label, er->idx, er->msgid);
			}
		}
		if (er->checked < 2) { //less as two same cw? mark as pending!
			er->rc = E_UNHANDLED;
			goto ESC;
		}
	}

	get_module(client)->send_dcw(client, er);

	add_cascade_data(client, er);

	if (is_fake)
		er->rc = E_FAKE;

	if (!(er->rc == E_SLEEPING && client->cwlastresptime == 0)) {
		char buf[ECM_FMT_LEN];
		format_ecm(er, buf, ECM_FMT_LEN);
		if (er->reader_avail == 1 || er->stage==0) {
			cs_log("%s (%s): %s (%d ms)%s%s%s",
				uname, buf,
				er->rcEx?erEx:stxt[er->rc], client->cwlastresptime, sby, schaninfo, sreason);
		} else {
			cs_log("%s (%s): %s (%d ms)%s (%c/%d/%d/%d)%s%s",
				uname, buf,
				er->rcEx ? erEx : stxt[er->rc],
				client->cwlastresptime, sby,
				stageTxt[er->stage], er->reader_requested, (er->reader_count+er->fallback_reader_count), er->reader_avail,
				schaninfo, sreason);
		}
	}

	cs_ddump_mask (D_ATR, er->cw, 16, "cw:");
	led_status_cw_not_found(er);

ESC:

	return 0;
}

/*
 * write_ecm_request():
 */
static int32_t write_ecm_request(struct s_reader *rdr, ECM_REQUEST *er)
{
	add_job(rdr->client, ACTION_READER_ECM_REQUEST, (void*)er, 0);
	return 1;
}


/**
 * distributes answer to all cacheex1 clients
 **/
#ifdef CS_CACHEEX
static void distribute_ecm_cacheex1(ECM_REQUEST *er)
{
	if(er->from_cacheex1_client || er->rc>E_FOUND) return;

	time_t timeout = time(NULL)-cfg.max_cache_time;
	struct ecm_request_t *ecm;

	cs_readlock(&ecmcache_lock);
	for (ecm = ecmcwcache; ecm; ecm = ecm->next) {
		if (ecm->tps.time <= timeout)
			break;

		if(!ecm->from_cacheex1_client || !check_client(ecm->client)) continue;

		if( cmp_ecm(ecm, er) ){

			struct s_write_from_cache *wfc=NULL;
			if (!cs_malloc(&wfc, sizeof(struct s_write_from_cache)))
				return;
			wfc->er_new=ecm;
			wfc->er_cache=er;
			wfc->type=2;

			add_job(ecm->client, ACTION_ECM_ANSWER_CACHE, wfc, sizeof(struct s_write_from_cache));  //write_ecm_answer_fromcache
		}
	}
	cs_readunlock(&ecmcache_lock);
}
#endif

/**
 * sends the ecm request to the readers
 * ECM_REQUEST er : the ecm
 * er->stage: 0 = no reader asked yet
 *            2 = ask only local reader (skipped without preferlocalcards)
 *            3 = ask any non fallback reader
 *            4 = ask fallback reader
 **/
void request_cw_from_readers(ECM_REQUEST *er, uint8_t stop_stage)
{
	struct s_ecm_answer *ea;
	int8_t sent = 0;

	if (er->stage >= 4) return;

	while (1) {
		if(stop_stage && er->stage>=stop_stage) return;

		er->stage++;

#ifndef CS_CACHEEX
		if (er->stage == 1)
			er->stage++;
#endif
		if (er->stage == 2 && !cfg.preferlocalcards)
			er->stage++;

		for (ea = er->matching_rdr; ea; ea = ea->next) {
			switch(er->stage) {
	#ifdef CS_CACHEEX
				case 1: {
					// Cache-Exchange
					if ((ea->status & REQUEST_SENT) ||
							(ea->status & (READER_CACHEEX|READER_ACTIVE)) != (READER_CACHEEX|READER_ACTIVE))
						continue;
					break;
				}
	#endif
				case 2: {
					// only local reader
					if ((ea->status & REQUEST_SENT) ||
							(ea->status & (READER_ACTIVE|READER_FALLBACK|READER_LOCAL)) != (READER_ACTIVE|READER_LOCAL))
						continue;
					break;
				}
				case 3: {
					// any non fallback reader not asked yet
					if ((ea->status & REQUEST_SENT) ||
							(ea->status & (READER_ACTIVE|READER_FALLBACK)) != READER_ACTIVE)
						continue;
					break;
				}
				default: {
					// only fallbacks
					if ( (ea->status & REQUEST_SENT) ||
							(ea->status & (READER_ACTIVE|READER_FALLBACK)) != (READER_ACTIVE|READER_FALLBACK))
						continue;
					break;
				}
			}

			struct s_reader *rdr = ea->reader;
			char ecmd5[17*3];
			cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
			cs_debug_mask(D_TRACE | D_CSPCWC, "request_cw stage=%d to reader %s ecm hash=%s", er->stage, rdr?rdr->label:"", ecmd5);

			ea->status |= REQUEST_SENT;
			cs_ftime(&ea->time_request_sent);

			er->reader_requested++;

			write_ecm_request(ea->reader, er);

			//set sent=1 only if reader is active/connected. If not, switch to next stage!
			if (!sent && rdr) {
				struct s_client *rcl = rdr->client;
				if (check_client(rcl)) {
					if (rcl->typ=='r' && rdr->card_status==CARD_INSERTED)
						sent = 1;
					else if (rcl->typ=='p' && (rdr->card_status==CARD_INSERTED ||rdr->tcp_connected))
						sent = 1;
				}
			}

			cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [write_ecm_request] reader %s --> SENT %d", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid, rdr?ea->reader->label:"-", sent);
		}
		if (sent || er->stage >= 4)
			break;
	}
}


void chk_dcw(struct s_ecm_answer *ea)  //ea here is not the original one, but a copy!
{
	if (!ea || !ea->er)
		return;

	ECM_REQUEST *ert = ea->er;
	struct s_ecm_answer *ea_list;
	struct s_reader *eardr = ea->reader;
	if (!ert)
		return;

	//ecm request already answered!
	if (ert->rc < E_99) {
#ifdef CS_CACHEEX
		if (ea && ert->rc < E_NOTFOUND && ea->rc < E_NOTFOUND && memcmp(ea->cw, ert->cw, sizeof(ert->cw)) != 0) {
			char cw1[16*3+2], cw2[16*3+2];
			cs_hexdump(0, ea->cw, 16, cw1, sizeof(cw1));
			cs_hexdump(0, ert->cw, 16, cw2, sizeof(cw2));

			char ip1[20]="", ip2[20]="";
			if (ea->reader && check_client(ea->reader->client)) cs_strncpy(ip1, cs_inet_ntoa(ea->reader->client->ip), sizeof(ip1));
			if (ert->cacheex_src) cs_strncpy(ip2, cs_inet_ntoa(ert->cacheex_src->ip), sizeof(ip2));
			else if (ert->selected_reader && check_client(ert->selected_reader->client)) cs_strncpy(ip2, cs_inet_ntoa(ert->selected_reader->client->ip), sizeof(ip2));

			ECM_REQUEST *er = ert;
			debug_ecm(D_TRACE, "WARNING2: Different CWs %s from %s(%s)<>%s(%s): %s<>%s", buf,
				username(ea->reader ? ea->reader->client : ert->client), ip1,
				er->cacheex_src ? username(er->cacheex_src) : (ea->reader ? ea->reader->label : "unknown/csp"), ip2,
				cw1, cw2);
		}
#endif

		//answer too late, only cache update if not found
		if (ea && ert->rc >=E_NOTFOUND && ea->rc < ert->rc) {
			memcpy(ert->cw, ea->cw, sizeof(ea->cw));
			ert->rc = ea->rc;
			ert->rcEx = 0;
			ert->selected_reader = eardr;
		  #ifdef CS_CACHEEX
			if(eardr && cacheex_reader(eardr))
				ert->cacheex_src = eardr->client; //so adds hits to reader
		  #endif
		}

		//update group
		if (ea && ea->rc < E_NOTFOUND)
			ert->grp |= eardr->grp;
	}

	if (ert->rc < E_99)  return; // //ecm request already send to client!

	int32_t reader_left = 0, local_left = 0, reader_not_flb_left=0, has_not_fallback=0, has_local=0;
#ifdef CS_CACHEEX
	int8_t cacheex_left = 0;
	uint8_t has_cacheex = 0;
#endif

	ert->selected_reader = eardr;

	switch (ea->rc) {
	case E_FOUND:
			memcpy(ert->cw, ea->cw, 16);
			ert->rcEx = 0;
			ert->rc = ea->rc;
			ert->grp |= eardr->grp;
		  #ifdef CS_CACHEEX
			if(eardr && cacheex_reader(eardr)){
				ert->cacheex_src = eardr->client; //so adds hits to reader
			}
			if(!ea->is_pending) cacheex_cache_push(ert);
		  #endif
			break;
	case E_TIMEOUT:   // if timeout, no one reader answered in ctimeout, so send timeout to client!
			ert->rc = E_TIMEOUT;
			ert->rcEx = 0;
			break;
	case E_NOTFOUND: {

		#ifdef CS_CACHEEX
			/* if not wait_time expired and wait_time due to cacheex3 or ecm is cacheex-1 and other normal readers (for check INT cache), we have to wait before send rc to client!
			 * (Before cacheex_wait_time_expired, this answered reader is a cacheex mode 1 reader!)
			 */
			if( (!ert->cacheex_wait_time_expired && ert->cacheex_hitcache) || (ert->from_cacheex1_client && ert->reader_nocacheex_avail) )
				return;
		#endif

			ert->rcEx = ea->rcEx;
			cs_strncpy(ert->msglog, ea->msglog, sizeof(ert->msglog));

			for (ea_list = ert->matching_rdr; ea_list; ea_list = ea_list->next) {
				cs_readlock(&ea_list->ecmanswer_lock);

	#ifdef CS_CACHEEX
				if (((ea_list->status & (READER_CACHEEX|READER_FALLBACK|READER_ACTIVE))) == (READER_CACHEEX|READER_ACTIVE))
					has_cacheex = 1;
				if ( (!(ea_list->status & READER_FALLBACK)  &&  ((ea_list->status & (REQUEST_SENT|REQUEST_ANSWERED|READER_CACHEEX|READER_ACTIVE)) == (REQUEST_SENT|READER_CACHEEX|READER_ACTIVE))) || ea_list->rc<E_NOTFOUND)
					cacheex_left++;
	#endif
				if ( (!(ea_list->status & READER_FALLBACK)  &&  ((ea_list->status & (REQUEST_SENT|REQUEST_ANSWERED|READER_LOCAL|READER_ACTIVE)) == (REQUEST_SENT|READER_LOCAL|READER_ACTIVE))) || ea_list->rc<E_NOTFOUND)
					local_left++;

				if ( (!(ea_list->status & READER_FALLBACK)  &&  ((ea_list->status & (REQUEST_SENT|REQUEST_ANSWERED|READER_ACTIVE)) == (REQUEST_SENT|READER_ACTIVE))) || ea_list->rc<E_NOTFOUND)
					reader_not_flb_left++;

				if (((ea_list->status & (REQUEST_ANSWERED|READER_ACTIVE)) == (READER_ACTIVE)) || ea_list->rc<E_NOTFOUND)
					reader_left++;

				if (((ea_list->status & (READER_FALLBACK|READER_ACTIVE))) == (READER_ACTIVE))
					has_not_fallback=1;
				if (((ea_list->status & (READER_LOCAL|READER_FALLBACK|READER_ACTIVE))) == (READER_LOCAL|READER_ACTIVE))
					has_local=1;

				cs_readunlock(&ea_list->ecmanswer_lock);
			}

			switch(ert->stage) {
				#ifdef CS_CACHEEX
					case 1: { // Cache-Exchange
						if(has_cacheex && !cacheex_left) request_cw_from_readers(ert,0);
						break;
					}
				#endif
					case 2: { // only local reader (used only if cfg.preferlocalcards=1)
						if(has_local && !local_left) request_cw_from_readers(ert,0);
						break;
					}
					case 3: {
						// any fallback reader not asked yet
						if(has_not_fallback && !reader_not_flb_left) request_cw_from_readers(ert,0);
						break;
					}
			}

			if (!reader_left)  // no more matching reader
				ert->rc = E_NOTFOUND; //so we set the return code

			break;
	}
	default:
		cs_log("unexpected ecm answer rc=%d.", ea->rc);
		return;
		break;
	}

	if(ert->rc < E_99)
		send_dcw(ert->client, ert);

#ifdef CS_CACHEEX
	if(ert->rc == E_FOUND && !ert->from_cacheex1_client)
		distribute_ecm_cacheex1(ert);
#endif

}

uint32_t chk_provid(uint8_t *ecm, uint16_t caid)
{
	int32_t i, len, descriptor_length = 0;
	uint32_t provid = 0;

	switch(caid >> 8) {
	case 0x01:
		// seca
		provid = b2i(2, ecm+3);
		break;
	case 0x05:
		// viaccess
		i = (ecm[4] == 0xD2) ? ecm[5]+2 : 0;  // skip d2 nano
		if ((ecm[5+i] == 3) && ((ecm[4+i] == 0x90) || (ecm[4+i] == 0x40)))
			provid = (b2i(3, ecm+6+i) & 0xFFFFF0);

		i = (ecm[6] == 0xD2) ? ecm[7]+2 : 0;  // skip d2 nano long ecm
		if ((ecm[7+i] == 7) && ((ecm[6+i] == 0x90) || (ecm[6+i] == 0x40)))
			provid = (b2i(3, ecm+8+i) & 0xFFFFF0);

		break;
	case 0x0D:
		// cryptoworks
		len = (((ecm[1] & 0xf) << 8) | ecm[2])+3;
		for (i = 8; i < len; i += descriptor_length + 2) {
			descriptor_length = ecm[i+1];
			if (ecm[i] == 0x83) {
				provid = (uint32_t)ecm[i+2] & 0xFE;
				break;
			}
		}
		break;
#ifdef WITH_LB
	default:
		for (i = 0; i < CS_MAXCAIDTAB; i++) {
			uint16_t tcaid = cfg.lb_noproviderforcaid.caid[i];
			if (!tcaid) break;
			if (tcaid == caid) {
				provid = 0;
				break;
			}
			if (tcaid < 0x0100 && (caid >> 8) == tcaid) {
				provid = 0;
				break;
			}
		}
#endif
	}
	return provid;
}

void update_chid(ECM_REQUEST *er)
{
	er->chid = get_subid(er);
}


int32_t write_ecm_answer(struct s_reader * reader, ECM_REQUEST *er, int8_t rc, uint8_t rcEx, uint8_t *cw, char *msglog)
{
	if(!reader || !er || !er->tps.time) return 0;

	// drop too late answers, to avoid seg fault --> only answer until tps.time+((cfg.ctimeout+500)/1000+1) is accepted
	uint32_t timeout = time(NULL)-er->tps.time;
	if((timeout > ((cfg.ctimeout+500)/1000+1)) )
		return 0;

	int32_t i;
	uint8_t c;
	struct timeb now;
	cs_ftime(&now);

	if (er && er->parent) {
		// parent is only set on reader->client->ecmtask[], but we want original er
		ECM_REQUEST *er_reader_cp=er;
		er = er->parent; 		//Now er is "original" ecm, before it was the reader-copy
		er_reader_cp->rc = rc;
		er_reader_cp->idx = 0;

		timeout = time(NULL)-er->tps.time;
		if((timeout > ((cfg.ctimeout+500)/1000+1)) )
			return 0;
	}

	struct s_ecm_answer *ea=get_ecm_answer(reader,er);
	if(!ea) return 0;

	cs_writelock(&ea->ecmanswer_lock);

	if((ea->status & REQUEST_ANSWERED) ){
		cs_debug_mask(D_READER, "Reader %s already answer, skip this ecm answer!", reader? reader->label:"-");
		cs_writeunlock(&ea->ecmanswer_lock);
		return 0;
	}


	//SPECIAL CHECKs for rc
	if (rc < E_NOTFOUND && cw && chk_is_null_CW(cw)){  //if cw=0 by anticascading
		rc = E_NOTFOUND;
		cs_debug_mask(D_TRACE|D_LB, "WARNING: reader %s send fake cw, set rc=E_NOTFOUND!",reader?reader->label:"-");
	}

	if (reader && cw && rc < E_NOTFOUND) {
		if (reader->disablecrccws == 0) {
			for (i = 0; i < 16; i += 4) {
				c = ((cw[i]+cw[i+1]+cw[i+2]) & 0xff);
				if (cw[i+3]!=c) {
					if (reader->dropbadcws) {
						rc = E_NOTFOUND;
						rcEx = E2_WRONG_CHKSUM;
						break;
					} else {
						cs_debug_mask(D_TRACE, "notice: changed dcw checksum byte cw[%i] from %02x to %02x", i+3, cw[i+3],c);
						cw[i+3] = c;
					}
				}
			}
		} else {
			cs_debug_mask(D_TRACE, "notice: CW checksum check disabled");
		}
	}

#ifdef CW_CYCLE_CHECK
	if (!checkcwcycle(er, reader, cw, rc )) {
		rc = E_NOTFOUND;
		rcEx = E2_WRONG_CHKSUM;
	}
#endif
	//END -- SPECIAL CHECKs for rc


	ea->status |= REQUEST_ANSWERED;
	ea->rc=rc;
	ea->ecm_time=comp_timeb(&now,&ea->time_request_sent);
	if(ea->ecm_time<1) ea->ecm_time=1; //set ecm_time 1 if answer immediately
	ea->rcEx = rcEx;
	if(cw) memcpy(ea->cw, cw, 16);
	if (msglog) memcpy(ea->msglog, msglog, MSGLOGSIZE);

	cs_writeunlock(&ea->ecmanswer_lock);

	struct timeb tpe;
	cs_ftime(&tpe);
	int32_t ntime = comp_timeb(&tpe,&er->tps);
	if (ntime < 1) ntime = 1;
	cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [write_ecm_answer] reader %s rc %d, ecm time %d ms (%d ms)", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid, reader?reader->label:"-", rc, ea->ecm_time, ntime );

	//send ea for ecm request
	int32_t res = 0;
	struct s_client *cl = er->client;
	if (check_client(cl)){
	  res = 1;
	  add_job(er->client, ACTION_ECM_ANSWER_READER, ea, 0); //chk_dcw
	}

	//distribute ea for pendings
	if(ea->pending) //has pending ea
		distribute_ea(ea);


	if(!ea->is_pending){  //not for pending ea - only once for ea
		send_reader_stat(reader, er, ea, ea->rc);   //send stats for LB

		//reader checks
		char ecmd5[17*3];
		cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5));
		rdr_debug_mask(reader, D_TRACE, "ecm answer for ecm hash %s rc=%d", ecmd5, ea->rc);

		//Update reader stats:
		if (ea->rc == E_FOUND) {
			if (cfg.cwlogdir != NULL)
				logCWtoFile(er, ea->cw); /* CWL logging only if cwlogdir is set in config */

			reader->ecmsok++;
	   #ifdef CS_CACHEEX
			struct s_client *eacl = reader->client;
			if (cacheex_reader(reader) && check_client(eacl)) {
				eacl->cwcacheexgot++;
				cacheex_add_stats(eacl, ea->er->caid, ea->er->srvid, ea->er->prid, 1);
				first_client->cwcacheexgot++;
			}
       #endif
		} else if (ea->rc == E_NOTFOUND) {
			reader->ecmsnok++;
			if (reader->ecmnotfoundlimit && reader->ecmsnok >= reader->ecmnotfoundlimit) {
				rdr_log(reader,"ECM not found limit reached %u. Restarting the reader.",
						reader->ecmsnok);
				reader->ecmsnok = 0; // Reset the variable
				reader->ecmshealthnok = 0; // Reset the variable
				add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
			}
		}

		//Reader ECMs Health Try (by Pickser)
		if (reader->ecmsok != 0 || reader->ecmsnok != 0) {
			reader->ecmshealthok = ((double) reader->ecmsok / (reader->ecmsok + reader->ecmsnok)) * 100;
			reader->ecmshealthnok = ((double) reader->ecmsnok / (reader->ecmsok + reader->ecmsnok)) * 100;
		}

		if (rc == E_FOUND && reader->resetcycle > 0) {
			reader->resetcounter++;
			if (reader->resetcounter > reader->resetcycle) {
				reader->resetcounter = 0;
				rdr_log(reader, "Resetting reader, resetcyle of %d ecms reached", reader->resetcycle);
				reader->card_status = CARD_NEED_INIT;
				cardreader_reset(cl);
			}
		}
	}

	return res;
}

static void guess_cardsystem(ECM_REQUEST *er)
{
	uint16_t last_hope = 0;

	// viaccess - check by provid-search
	if ((er->prid = chk_provid(er->ecm, 0x500)))
		er->caid = 0x500;

	// nagra
	// is ecm[1] always 0x30 ?
	// is ecm[3] always 0x07 ?
	if ((er->ecm[6]==1) && (er->ecm[4]==er->ecm[2]-2))
		er->caid = 0x1801;

	// seca2 - very poor
	if ((er->ecm[8]==0x10) && ((er->ecm[9]&0xF1)==1))
		last_hope = 0x100;

	// is cryptoworks, but which caid ?
	if ((er->ecm[3]==0x81) && (er->ecm[4]==0xFF) &&
	    (!er->ecm[5]) && (!er->ecm[6]) && (er->ecm[7]==er->ecm[2]-5))
	{
		last_hope = 0xd00;
	}

	if (!er->caid && er->ecm[2] == 0x31 && er->ecm[0x0b] == 0x28)
		guess_irdeto(er);

	if (!er->caid) // guess by len ..
		er->caid = len4caid[er->ecm[2] + 3];

	if (!er->caid)
		er->caid = last_hope;
}

//chid calculation from module stat to here
//to improve the quickfix concerning ecm chid info and extend it to all client requests wereby the chid is known in module stat

uint32_t get_subid(ECM_REQUEST *er)
{
	if (!er->ecmlen)
		return 0;

	uint32_t id = 0;
	switch (er->caid>>8)
	{
		case 0x01: id = b2i(2, er->ecm+7); break; // seca
		case 0x05: id = b2i(2, er->ecm+8); break; // viaccess
		case 0x06: id = b2i(2, er->ecm+6); break; // irdeto
		case 0x09: id = b2i(2, er->ecm+11); break; // videoguard
		case 0x4A: // DRE-Crypt, Bulcrypt, Tongfang and others?
			if (!(er->caid == 0x4AEE)) // Bulcrypt excluded for now
				id = b2i(2, er->ecm+6);
			break;
	}
	return id;
}


static void set_readers_counter(ECM_REQUEST *er){
	struct s_ecm_answer *ea;

	er->reader_count = 0;
	er->fallback_reader_count = 0;
	for (ea = er->matching_rdr; ea; ea = ea->next) {
		if (ea->status & READER_ACTIVE) {
			if (!(ea->status & READER_FALLBACK))
				er->reader_count++;
			else
				er->fallback_reader_count++;
		}
	}
}


void write_ecm_answer_fromcache(struct s_write_from_cache *wfc){
	ECM_REQUEST *er=NULL;
	ECM_REQUEST *ecm=NULL;

	er=wfc->er_new;
	ecm=wfc->er_cache;

	int8_t rc_orig=er->rc;

	er->grp |= ecm->grp;  //update group
#ifdef CS_CACHEEX
	if(ecm->from_csp) er->csp_answered=1;  //update er as answered by csp (csp have no group)
#endif

	if(er->rc>=E_NOTFOUND){
			if(wfc->type==1)
				er->rc=E_CACHE1;
			else if(wfc->type==2)
				er->rc=E_CACHE2;
			else if(wfc->type==3)
				er->rc=E_CACHEEX;

			memcpy(er->cw, ecm->cw, 16);
			er->selected_reader = ecm->selected_reader;

		  #ifdef CS_CACHEEX
			er->cacheex_src = ecm->cacheex_src;

			int8_t cacheex = check_client(er->client) && er->client->account ? er->client->account->cacheex.mode : 0;
			if (cacheex==1 && check_client(er->client)) {
				cacheex_add_stats(er->client, er->caid, er->srvid, er->prid, 0);
				er->client->cwcacheexpush++;
				if (er->client->account)
					er->client->account->cwcacheexpush++;
				first_client->cwcacheexpush++;
			}

			if(wfc->type==3){ //cacheex answers
				struct s_client	*cl = ecm->cacheex_src;  //cacheex pushing client
				er->selected_reader = cl->reader;
			}
		  #endif

			if(rc_orig==E_UNHANDLED){
				if(wfc->type==1)
					cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [write_ecm_answer_fromcache] found ecm in INT. cache, rc %d!", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid, ecm->rc );
				else if(wfc->type==2)
					cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [write_ecm_answer_fromcache] distributed rc %d from client %s", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid, ecm->rc, check_client(ecm->client)?ecm->client->account->usr:"-");
				else if(wfc->type==3)
					cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [write_ecm_answer_fromcache] found cw from CACHEEX!", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid );

				send_dcw(er->client, er);
			}
	}
}


void get_cw(struct s_client * client, ECM_REQUEST *er)
{
	cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [get_cw] NEW REQUEST!", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid );

	int32_t i, j, m;
	time_t now = time((time_t*)0);
	uint32_t line = 0;

	er->client = client;
	er->rc = E_UNHANDLED; // set default rc status to unhandled
	if (now - client->lastecm > cfg.hideclient_to) client->lastswitch = 0;		// user was on freetv or didn't request for some time so we reset lastswitch to get correct stats/webif display
	client->lastecm = now;

	if (client == first_client || !client ->account || client->account == first_client->account) {
		//DVBApi+serial is allowed to request anonymous accounts:
		int16_t listenertype = get_module(client)->listenertype;
		if (listenertype != LIS_DVBAPI && listenertype != LIS_SERIAL) {
			er->rc = E_INVALID;
			er->rcEx = E2_GLOBAL;
			snprintf(er->msglog, sizeof(er->msglog), "invalid user account %s", username(client));
		}
	}

	if (er->ecmlen > MAX_ECM_SIZE) {
		er->rc = E_INVALID;
		er->rcEx = E2_GLOBAL;
		snprintf(er->msglog, sizeof(er->msglog), "ECM size %d > Max Ecm size %d, ignored! client %s", er->ecmlen, MAX_ECM_SIZE, username(client));
	}

	if (!client->grp) {
		er->rc = E_INVALID;
		er->rcEx = E2_GROUP;
		snprintf(er->msglog, sizeof(er->msglog), "invalid user group %s", username(client));
	}


	if (!er->caid)
		guess_cardsystem(er);

	/* Quickfix Area */

	// add chid for all client requests as in module stat
	update_chid(er);

	// quickfix for 0100:000065
	if (er->caid == 0x100 && er->prid == 0x65 && er->srvid == 0)
		er->srvid = 0x0642;

	// Quickfixes for Opticum/Globo HD9500
	// Quickfix for 0500:030300
	if (er->caid == 0x500 && er->prid == 0x030300)
		er->prid = 0x030600;

	// Quickfix for 0500:D20200
	if (er->caid == 0x500 && er->prid == 0xD20200)
		er->prid = 0x030600;

	//betacrypt ecm with nagra header
	if (chk_is_betatunnel_caid(er->caid) == 1 && (er->ecmlen == 0x89 || er->ecmlen == 0x4A) && er->ecm[3] == 0x07 && (er->ecm[4] == 0x84 || er->ecm[4] == 0x45))
	{
		if (er->caid == 0x1702) {
			er->caid = 0x1833;
		} else {
			check_lb_auto_betatunnel_mode(er);
		}
		cs_debug_mask(D_TRACE, "Quickfix remap beta->nagra: 0x%X, 0x%X, 0x%X, 0x%X", er->caid, er->ecmlen, er->ecm[3], er->ecm[4]);
	}

	//nagra ecm with betacrypt header 1801, 1833, 1834, 1835
	if (chk_is_betatunnel_caid(er->caid) == 2 && (er->ecmlen == 0x93 || er->ecmlen == 0x54) && er->ecm[13] == 0x07 && (er->ecm[14] == 0x84 || er->ecm[14] == 0x45))
	{
		if (er->caid == 0x1833) {
			er->caid = 0x1702;
		} else {
			er->caid = 0x1722;
		}
		cs_debug_mask(D_TRACE, "Quickfix remap nagra->beta: 0x%X, 0x%X, 0x%X, 0x%X", er->caid, er->ecmlen, er->ecm[13], er->ecm[44]);
	}

	//Ariva quickfix (invalid nagra provider)
	if (((er->caid & 0xFF00) == 0x1800) && er->prid > 0x00FFFF)
		er->prid = 0;

	//Check for invalid provider, extract provider out of ecm:
	uint32_t prid = chk_provid(er->ecm, er->caid);
	if (!er->prid) {
		er->prid = prid;
	} else {
		if (prid && prid != er->prid) {
			cs_debug_mask(D_TRACE, "provider fixed: %04X:%06X to %04X:%06X",er->caid, er->prid, er->caid, prid);
			er->prid = prid;
		}
	}

#ifdef MODULE_NEWCAMD
	// Set providerid for newcamd clients if none is given
	if (!er->prid && client->ncd_server) {
		int32_t pi = client->port_idx;
		if (pi >= 0 && cfg.ncd_ptab.nports && cfg.ncd_ptab.nports >= pi && cfg.ncd_ptab.ports[pi].ncd)
			er->prid = cfg.ncd_ptab.ports[pi].ncd->ncd_ftab.filts[0].prids[0];
	}
#endif

	// CAID not supported or found
	if (!er->caid) {
		er->rc = E_INVALID;
		er->rcEx = E2_CAID;
		snprintf( er->msglog, MSGLOGSIZE, "CAID not supported or found" );
	}

	// user expired
	if (client->expirationdate && client->expirationdate < client->lastecm)
		er->rc = E_EXPDATE;

	// out of timeframe
	if (client->allowedtimeframe[0] && client->allowedtimeframe[1]) {
		struct tm acttm;
		localtime_r(&now, &acttm);
		int32_t curtime = (acttm.tm_hour * 60) + acttm.tm_min;
		int32_t mintime = client->allowedtimeframe[0];
		int32_t maxtime = client->allowedtimeframe[1];
		if (!((mintime <= maxtime && curtime > mintime && curtime < maxtime) || (mintime > maxtime && (curtime > mintime || curtime < maxtime)))) {
			er->rc = E_EXPDATE;
		}
		cs_debug_mask(D_TRACE, "Check Timeframe - result: %d, start: %d, current: %d, end: %d\n",er->rc, mintime, curtime, maxtime);
	}

	// user disabled
	if (client->disabled != 0) {
		if (client->failban & BAN_DISABLED) {
			cs_add_violation(client, client->account->usr);
			cs_disconnect_client(client);
		}
		er->rc = E_DISABLED;
	}

	if (!chk_global_whitelist(er, &line)) {
		debug_ecm(D_TRACE, "whitelist filtered: %s (%s) line %d", username(client), buf, line);
		er->rc = E_INVALID;
	}

	// rc<100 -> ecm error
	if (er->rc >= E_UNHANDLED) {
		m = er->caid;
		i = er->srvid;

		if (i != client->last_srvid || !client->lastswitch) {
			if (cfg.usrfileflag)
				cs_statistics(client);
			client->lastswitch = now;
		}

		// user sleeping
		if (client->tosleep && (now - client->lastswitch > client->tosleep)) {
			if (client->failban & BAN_SLEEPING) {
				cs_add_violation(client, client->account->usr);
				cs_disconnect_client(client);
			}
			if (client->c35_sleepsend != 0) {
				er->rc = E_STOPPED; // send stop command CMD08 {00 xx}
			} else {
				er->rc = E_SLEEPING;
			}
		}

		client->last_srvid = i;
		client->last_caid = m;

		int32_t ecm_len = (((er->ecm[1] & 0x0F) << 8) | er->ecm[2]) + 3;

		for (j = 0; (j < 6) && (er->rc >= E_UNHANDLED); j++) {
			switch(j) {
			case 0:
				// fake (uniq)
				if (client->dup)
					er->rc = E_FAKE;
				break;
			case 1:
				// invalid (caid)
				if (!chk_bcaid(er, &client->ctab)) {
					er->rc = E_INVALID;
					er->rcEx = E2_CAID;
					snprintf( er->msglog, MSGLOGSIZE, "invalid caid 0x%04X", er->caid );
					}
				break;
			case 2:
				// invalid (srvid)
				// matching srvids (or 0000) specified in betatunnel will bypass this filter
				if (!chk_srvid(client, er)) {
					if (!chk_on_btun(SRVID_ZERO, client, er)) {
						er->rc = E_INVALID;
						snprintf( er->msglog, MSGLOGSIZE, "invalid SID" );
					}
				}
				break;
			case 3:
				// invalid (ufilters)
				if (!chk_ufilters(er))
					er->rc = E_INVALID;
				break;
			case 4:
				// invalid (sfilter)
				if (!chk_sfilter(er, &get_module(client)->ptab))
					er->rc = E_INVALID;
				break;
			case 5:
				// corrupt
				if ((i = er->ecmlen - ecm_len))  {
					if (i > 0) {
						cs_debug_mask(D_TRACE, "warning: ecm size adjusted from %d to %d", er->ecmlen, ecm_len);
						er->ecmlen = ecm_len;
					}
					else
						er->rc = E_CORRUPT;
				}
				break;
			}
		}
	}


	//not continue, send rc to client
	if (er->rc < E_UNHANDLED) {
		send_dcw(client, er);
		free_ecm(er);
		return;
	}


#ifdef CS_CACHEEX
	int8_t cacheex = client->account ? client->account->cacheex.mode : 0;
	er->from_cacheex1_client=0;
	if(cacheex==1) er->from_cacheex1_client=1;
#endif


	//Schlocke: above checks could change er->rc so
	/*BetaCrypt tunneling
	 *moved behind the check routines,
	 *because newcamd ECM will fail
	 *if ECM is converted before
	 */
	if (chk_is_betatunnel_caid(er->caid) && client->ttab.n) {
		cs_ddump_mask(D_TRACE, er->ecm, 13, "betatunnel? ecmlen=%d", er->ecmlen);
		cs_betatunnel(er);
	}

	// ignore ecm ...
	int32_t offset = 3;
	// ... and betacrypt header for cache md5 calculation
	if ((er->caid >> 8) == 0x17)
		offset = 13;
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	// store ECM in cache
	memcpy(er->ecmd5, MD5(er->ecm + offset, er->ecmlen - offset, md5tmp), CS_ECMSTORESIZE);
	cacheex_update_hash(er);
	ac_chk(client, er, 0);

	er->reader_avail = 0;
	er->readers = 0;
#ifdef CS_CACHEEX
	er->reader_nocacheex_avail=0;
#endif

	struct s_ecm_answer *ea, *prv = NULL;
	struct s_reader *rdr;

	cs_readlock(&readerlist_lock);
	cs_readlock(&clientlist_lock);

	for (rdr = first_active_reader; rdr; rdr = rdr->next) {
		uint8_t is_fallback=chk_is_fixed_fallback(rdr,er);

		int8_t match = matching_reader(er, rdr);
#ifdef WITH_LB
		//if this reader does not match, check betatunnel for it
		if (!match && cfg.lb_auto_betatunnel) {
			uint16_t caid = lb_get_betatunnel_caid_to(er->caid);
			if (caid) {
				uint16_t save_caid = er->caid;
				er->caid = caid;
				match = matching_reader(er, rdr); //matching
				er->caid = save_caid;
			}
		}
#endif
		if (match) {
			er->reader_avail++;

#ifdef CS_CACHEEX
			if(!rdr->cacheex.mode) er->reader_nocacheex_avail++;
			if(cacheex==1 && !cacheex_reader(rdr)) //ex1-cl only ask ex1-rdr
				continue;
#endif

			if (!cs_malloc(&ea, sizeof(struct s_ecm_answer)))
				goto OUT;

			er->readers++;

			ea->reader = rdr;
			ea->er=er;
			ea->rc=E_UNHANDLED;
			if (prv)
				prv->next = ea;
			else
				er->matching_rdr = ea;
			prv = ea;

			ea->status = READER_ACTIVE;
			if (!is_network_reader(rdr))
				ea->status |= READER_LOCAL;
			else if (cacheex_reader(rdr)){
				ea->status |= READER_CACHEEX;
				er->cacheex_reader_count++;
			}

			if (is_fallback)
				ea->status |= READER_FALLBACK;

			ea->pending=NULL;
			ea->is_pending=false;
			cs_lock_create(&ea->ecmanswer_lock, 5, "ecmanswer_lock");
		}
	}

OUT:
	cs_readunlock(&clientlist_lock);
	cs_readunlock(&readerlist_lock);


#ifdef WITH_LB
	//FILTER readers by loadbalancing
	stat_get_best_reader(er);
#endif

	//set reader_count and fallback_reader_count
	set_readers_counter(er);


#ifdef CS_CACHEEX
	//WAIT_TIME
	uint32_t wait_time_no_hitcache = get_cacheex_wait_time(er,NULL);   //NO check hitcache. Wait_time is dwtime, or, if absent, awtime.
	uint32_t wait_time_hitcache = get_cacheex_wait_time(er,client);  //check hitcache for calculating wait_time! If hitcache wait_time is biggest value between dwtime and awtime, else it's awtime.

	uint32_t cacheex_wait_time = 0;
	if(
		//If "normal" client and ex1-rdr>0, we cannot use hitcache for calculating wait_time because we cannot know if cw is available or not on ex1 server!
		(cacheex!=1 && er->cacheex_reader_count)
		||
		/* Cw for ex1-cl comes from: INT. cache by "normal" readers (normal clients that ask normal readers), ex1-rdr and ex3-clients.
		 * If readers, we have to wait cws generating by normal clients asking normal readers and answers by ex1-rdr (cannot use hitcache).
	  	 * If no readers, use hitcache for calculating wait_time.
		 */
		(cacheex==1 && er->reader_avail)
	)
		cacheex_wait_time = wait_time_no_hitcache;
	else
		cacheex_wait_time = wait_time_hitcache;


	cs_debug_mask(D_TRACE | D_CACHEEX, "[GET_CW] wait_time %d caid %04X prov %06X srvid %04X rc %d cacheex cl mode %d ex1rdr %d", cacheex_wait_time, er->caid, er->prid, er->srvid, er->rc, cacheex, er->cacheex_reader_count);
	cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [get_cw] wait_time %d - client cacheex mode %d, reader avail for ecm %d, hitcache %d", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid, cacheex_wait_time, cacheex==1?1:0, er->reader_avail, wait_time_hitcache?1:0);
	//END WAIT_TIME calculation

	if(!cacheex_wait_time && (er->reader_count + er->fallback_reader_count)==0)
#else
	if((er->reader_count + er->fallback_reader_count)==0)
#endif
	{
		er->readers_timeout_check=1;  //no readers asked to be checked at ctimeout
		er->rc = E_NOTFOUND;
		if (!er->rcEx)
			er->rcEx = E2_GROUP;
		snprintf(er->msglog, MSGLOGSIZE, "no matching reader");
		cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [get_cw] NO Readers and NO wait_time... not_found! ", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid);
		send_dcw(client, er);
		return;
	}


	//insert it in ecmcwcache!
	cs_writelock(&ecmcache_lock);
	er->next = ecmcwcache;
	ecmcwcache = er;
	ecmcwcache_size++;
	cs_writeunlock(&ecmcache_lock);


	//********  CHECK IF FOUND ECM IN CACHE
	struct ecm_request_t *ecm=NULL;
	ecm = check_cwcache(er, client);
	if (ecm) {  //found in cache
		er->readers_timeout_check=1;  //no readers asked to be checked at ctimeout

	  #ifdef CS_CACHEEX
		if (cfg.delay && cacheex!=1) //No delay on cacheexchange mode 1 client!
			cs_sleepms(cfg.delay);
   	  #else
			if (cfg.delay)
				cs_sleepms(cfg.delay);
	  #endif

		struct s_write_from_cache *wfc=NULL;
		if (!cs_malloc(&wfc, sizeof(struct s_write_from_cache)))
			return;
		wfc->er_new=er;
		wfc->er_cache=ecm;
		wfc->type=1;

		add_job(er->client, ACTION_ECM_ANSWER_CACHE, wfc, sizeof(struct s_write_from_cache));  //write_ecm_answer_fromcache
		return;
	}


#ifdef WITH_LB
	//cahe2 is handled by readers queue, so, if a same ecm hash with same readers, use these same readers to get cache2 from them! Not ask other readers!
	struct ecm_request_t *ecm_eq = NULL;
	ecm_eq = check_same_ecm(er);
	if(ecm_eq){
		//set all readers used by ecm_eq, so we get cache2 from them!
		use_same_readers(er, ecm_eq);
		cs_debug_mask(D_LB,"{client %s, caid %04X, prid %06X, srvid %04X} [get_cw] found same ecm hash with same readers from client %s, use them!", (check_client(er->client)?er->client->account->usr:"-"),er->caid, er->prid, er->srvid, (check_client(ecm_eq->client)?ecm_eq->client->account->usr:"-"));

		//set reader_count and fallback_reader_count
		set_readers_counter(er);
	}
#endif


	er->rcEx = 0;
#ifdef CS_CACHEEX
	er->cacheex_wait_time_expired=1;
	er->cacheex_hitcache=0;
	if (cacheex_wait_time) {   //wait time for cacheex
		add_ms_to_timeb(&er->cacheex_wait, cacheex_wait_time);
		er->cacheex_wait_time = cacheex_wait_time;
		er->cacheex_wait_time_expired=0;
		if(er->cacheex_reader_count>0){
			er->cacheex_hitcache = wait_time_hitcache?1:0;  //usefull only when cacheex mode 1 readers
			request_cw_from_readers(er,1); // setting stop_stage=1, we request only cacheex mode 1 readers. Others are requested at cacheex timeout!
		}
	} else
#endif
	request_cw_from_readers(er,0);


#ifdef WITH_DEBUG
	if (D_CLIENTECM & cs_dblevel) {
		char buf[ECM_FMT_LEN];
		format_ecm(er, buf, ECM_FMT_LEN);
		cs_ddump_mask(D_CLIENTECM, er->ecm, er->ecmlen, "Client %s ECM dump %s", username(client), buf);
	}
#endif

	cw_process_thread_wakeup();
}

int32_t ecmfmt(uint16_t caid, uint16_t onid, uint32_t prid, uint16_t chid, uint16_t pid, uint16_t srvid, uint16_t l, char *ecmd5hex, char *csphash, char *cw, char *result, size_t size, uint16_t origin_peer, uint8_t distance)
{
	if (!cfg.ecmfmt)
		return snprintf(result, size, "%04X&%06X/%04X/%04X/%02X:%s", caid, prid, chid, srvid, l, ecmd5hex);

	uint32_t s = 0, zero = 0, flen = 0, value = 0;
	char *c = cfg.ecmfmt, fmt[5] = "%04X";
	while (*c) {
		switch(*c) {
		case '0': zero = 1; value = 0; break;
		case 'c': flen = 4; value = caid; break;
		case 'o': flen = 4; value = onid; break;
		case 'p': flen = 6; value = prid; break;
		case 'i': flen = 4; value = chid; break;
		case 'd': flen = 4; value = pid; break;
		case 's': flen = 4; value = srvid; break;
		case 'l': flen = 2; value = l; break;
		case 'h': flen = CS_ECMSTORESIZE; break;
		case 'e': flen = 5; break;
		case 'w': flen = 17; break;
		case 'j': flen = 2; value = distance; break;
        case 'g': flen = 4; value = origin_peer; break;
		case '\\':
			c++;
			flen = 0;
			value = *c;
			break;
		default:  flen = 0; value = *c; break;
		}
		if (value)
			zero = 0;

		if (!zero) {
			//fmt[0] = '%';
			if (flen) { //Build %04X / %06X / %02X
				fmt[1] = '0';
				fmt[2] = flen+'0';
				fmt[3] = 'X';
				fmt[4] = 0;
			}
			else {
				fmt[1] = 'c';
				fmt[2] = 0;
			}
			if (flen == CS_ECMSTORESIZE) s += snprintf(result+s, size-s ,"%s", ecmd5hex);
			else if (flen == 5)          s += snprintf(result+s, size-s ,"%s", csphash);
			else if (flen == 17)         s += snprintf(result+s, size-s ,"%s", cw);
			else                         s += snprintf(result+s, size-s, fmt, value);
		}
		c++;
	}
	return s;
}

int32_t format_ecm(ECM_REQUEST *ecm, char *result, size_t size)
{
	char ecmd5hex[17 * 3];
	char csphash[5 * 3] = { 0 };
	char cwhex[17 * 3];
	cs_hexdump(0, ecm->ecmd5, 16, ecmd5hex, sizeof(ecmd5hex));
#ifdef CS_CACHEEX
	cs_hexdump(0, (void *)&ecm->csp_hash, 4, csphash, sizeof(csphash));
#endif
	cs_hexdump(0, ecm->cw, 16, cwhex, sizeof(cwhex));
#ifdef MODULE_GBOX
    if (ecm->gbox_hops)
       return ecmfmt(ecm->caid, ecm->onid, ecm->prid, ecm->chid, ecm->pid, ecm->srvid, ecm->ecmlen, ecmd5hex, csphash, cwhex, result, size, ecm->gbox_peer, ecm->gbox_hops);
    else
#endif
    return ecmfmt(ecm->caid, ecm->onid, ecm->prid, ecm->chid, ecm->pid, ecm->srvid, ecm->ecmlen, ecmd5hex, csphash, cwhex, result, size, 0, 0);
}

