#include "globals.h"
#include "module-cacheex.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-emm.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-work.h"
#include "reader-common.h"
#include "module-cccam-data.h"
#include "module-cccshare.h"
#include "oscam-time.h"

extern CS_MUTEX_LOCK system_lock;
extern int32_t thread_pipe[2];

struct job_data
{
	enum actions action;
	struct s_reader *rdr;
	struct s_client *cl;
	void *ptr;
	time_t time;
	uint16_t len;
};

static void free_job_data(struct job_data *data)
{
	if(!data)
		{ return; }
	if(data->len && data->ptr)
		{ free(data->ptr); }
	free(data);
}

void free_joblist(struct s_client *cl)
{
	pthread_mutex_trylock(&cl->thread_lock);
	LL_ITER it = ll_iter_create(cl->joblist);
	struct job_data *data;
	while((data = ll_iter_next(&it)))
	{
		free_job_data(data);
	}
	ll_destroy(cl->joblist);
	cl->joblist = NULL;
	cl->account = NULL;
	if(cl->work_job_data)  // Free job_data that was not freed by work_thread
		{ free_job_data(cl->work_job_data); }
	cl->work_job_data = NULL;
	pthread_mutex_unlock(&cl->thread_lock);
	pthread_mutex_destroy(&cl->thread_lock);
}

/*
 Work threads are named like this:
   w[r|c]XX-[rdr->label|client->username]

   w      - work thread prefix
   [r|c]  - depending whether the the action is related to reader or client
   XX     - two digit action code from enum actions
   label  - reader label or client username (see username() function)
*/
static void set_work_thread_name(struct job_data *data)
{
	char thread_name[16 + 1];
	snprintf(thread_name, sizeof(thread_name), "w%c%02d-%s",
			 data->action < ACTION_CLIENT_FIRST ? 'r' : 'c',
			 data->action,
			 username(data->cl)
			);
	set_thread_name(thread_name);
}

#define __free_job_data(client, job_data) \
    do { \
        client->work_job_data = NULL; \
        if (job_data && job_data != &tmp_data) { \
            free_job_data(job_data); \
        } \
        job_data = NULL; \
    } while(0)

void *work_thread(void *ptr)
{
	struct job_data *data = (struct job_data *)ptr;
	struct s_client *cl = data->cl;
	struct s_reader *reader = cl->reader;
	struct timeb start, end;  // start time poll, end time poll

	struct job_data tmp_data;
	struct pollfd pfd[1];

	pthread_setspecific(getclient, cl);
	cl->thread = pthread_self();
	cl->thread_active = 1;

	set_work_thread_name(data);

	struct s_module *module = get_module(cl);
	uint16_t bufsize = module->bufsize; //CCCam needs more than 1024bytes!
	if(!bufsize)
		{ bufsize = 1024; }

	uint8_t *mbuf;
	if(!cs_malloc(&mbuf, bufsize))
		{ return NULL; }
	cl->work_mbuf = mbuf; // Track locally allocated data, because some callback may call cs_exit/cs_disconect_client/pthread_exit and then mbuf would be leaked
	int32_t n = 0, rc = 0, i, idx, s;
	uint8_t dcw[16];
	time_t now;
	int8_t restart_reader = 0;
	while(cl->thread_active)
	{
		cs_ftime(&start); // register start time
		while(cl->thread_active)
		{
			if(!cl || cl->kill || !is_valid_client(cl))
			{
				pthread_mutex_lock(&cl->thread_lock);
				cl->thread_active = 0;
				pthread_mutex_unlock(&cl->thread_lock);
				cs_debug_mask(D_TRACE, "ending thread (kill)");
				__free_job_data(cl, data);
				cl->work_mbuf = NULL; // Prevent free_client from freeing mbuf (->work_mbuf)
				free_client(cl);
				if(restart_reader)
					{ restart_cardreader(reader, 0); }
				free(mbuf);
				pthread_exit(NULL);
				return NULL;
			}

			if(data && data->action != ACTION_READER_CHECK_HEALTH)
				{ cs_debug_mask(D_TRACE, "data from add_job action=%d client %c %s", data->action, cl->typ, username(cl)); }

			if(!data)
			{
				if(!cl->kill && cl->typ != 'r')
					{ client_check_status(cl); } // do not call for physical readers as this might cause an endless job loop
				pthread_mutex_lock(&cl->thread_lock);
				if(cl->joblist && ll_count(cl->joblist) > 0)
				{
					LL_ITER itr = ll_iter_create(cl->joblist);
					data = ll_iter_next_remove(&itr);
					if(data)
						{ set_work_thread_name(data); }
					//cs_debug_mask(D_TRACE, "start next job from list action=%d", data->action);
				}
				pthread_mutex_unlock(&cl->thread_lock);
			}

			if(!data)
			{
				/* for serial client cl->pfd is file descriptor for serial port not socket
				   for example: pfd=open("/dev/ttyUSB0"); */
				if(!cl->pfd || module->listenertype == LIS_SERIAL)
					{ break; }
				pfd[0].fd = cl->pfd;
				pfd[0].events = POLLIN | POLLPRI;

				pthread_mutex_lock(&cl->thread_lock);
				cl->thread_active = 2;
				pthread_mutex_unlock(&cl->thread_lock);
				rc = poll(pfd, 1, 3000);
				pthread_mutex_lock(&cl->thread_lock);
				cl->thread_active = 1;
				pthread_mutex_unlock(&cl->thread_lock);
				if(rc > 0)
				{
					cs_ftime(&end); // register end time
					cs_debug_mask(D_TRACE, "[OSCAM-WORK] new event %d occurred on fd %d after %ld ms inactivity", pfd[0].revents,
								  pfd[0].fd, 1000 * (end.time - start.time) + end.millitm - start.millitm);
					data = &tmp_data;
					data->ptr = NULL;
					cs_ftime(&start); // register start time for new poll next run

					if(reader)
						{ data->action = ACTION_READER_REMOTE; }
					else
					{
						if(cl->is_udp)
						{
							data->action = ACTION_CLIENT_UDP;
							data->ptr = mbuf;
							data->len = bufsize;
						}
						else
							{ data->action = ACTION_CLIENT_TCP; }
						if(pfd[0].revents & (POLLHUP | POLLNVAL | POLLERR))
							{ cl->kill = 1; }
					}
				}
			}

			if(!data)
				{ continue; }

			if(!reader && data->action < ACTION_CLIENT_FIRST)
			{
				__free_job_data(cl, data);
				break;
			}

			if(!data->action)
				{ break; }

			now = time(NULL);
			time_t diff = (time_t)(cfg.ctimeout / 1000) + 1;
			if(data != &tmp_data && data->time < now - diff)
			{
				cs_debug_mask(D_TRACE, "dropping client data for %s time %ds", username(cl), (int32_t)(now - data->time));
				__free_job_data(cl, data);
				continue;
			}

			if(data != &tmp_data)
				{ cl->work_job_data = data; } // Track the current job_data
			switch(data->action)
			{
			case ACTION_READER_IDLE:
				reader_do_idle(reader);
				break;
			case ACTION_READER_REMOTE:
				s = check_fd_for_data(cl->pfd);
				if(s == 0)  // no data, another thread already read from fd?
					{ break; }
				if(s < 0)
				{
					if(reader->ph.type == MOD_CONN_TCP)
						{ network_tcp_connection_close(reader, "disconnect"); }
					break;
				}
				rc = reader->ph.recv(cl, mbuf, bufsize);
				if(rc < 0)
				{
					if(reader->ph.type == MOD_CONN_TCP)
						{ network_tcp_connection_close(reader, "disconnect on receive"); }
					break;
				}
				cl->last = now;
				idx = reader->ph.c_recv_chk(cl, dcw, &rc, mbuf, rc);
				if(idx < 0) { break; }  // no dcw received
				if(!idx) { idx = cl->last_idx; }
				reader->last_g = now; // for reconnect timeout
				for(i = 0, n = 0; i < cfg.max_pending && n == 0; i++)
				{
					if(cl->ecmtask[i].idx == idx)
					{
						cl->pending--;
						casc_check_dcw(reader, i, rc, dcw);
						n++;
					}
				}
				break;
			case ACTION_READER_RESET:
				cardreader_do_reset(reader);
				break;
			case ACTION_READER_ECM_REQUEST:
				reader_get_ecm(reader, data->ptr);
				break;
			case ACTION_READER_EMM:
				reader_do_emm(reader, data->ptr);
				break;
			case ACTION_READER_CARDINFO:
				reader_do_card_info(reader);
				break;
			case ACTION_READER_INIT:
				if(!cl->init_done)
					{ reader_init(reader); }
				break;
			case ACTION_READER_RESTART:
				cl->kill = 1;
				restart_reader = 1;
				break;
			case ACTION_READER_RESET_FAST:
				reader->card_status = CARD_NEED_INIT;
				cardreader_do_reset(reader);
				break;
			case ACTION_READER_CHECK_HEALTH:
				cardreader_do_checkhealth(reader);
				break;
			case ACTION_READER_CAPMT_NOTIFY:
				if(reader->ph.c_capmt) { reader->ph.c_capmt(cl, data->ptr); }
				break;
			case ACTION_CLIENT_UDP:
				n = module->recv(cl, data->ptr, data->len);
				if(n < 0) { break; }
				module->s_handler(cl, data->ptr, n);
				break;
			case ACTION_CLIENT_TCP:
				s = check_fd_for_data(cl->pfd);
				if(s == 0)  // no data, another thread already read from fd?
					{ break; }
				if(s < 0)    // system error or fd wants to be closed
				{
					cl->kill = 1; // kill client on next run
					continue;
				}
				n = module->recv(cl, mbuf, bufsize);
				if(n < 0)
				{
					cl->kill = 1; // kill client on next run
					continue;
				}
				module->s_handler(cl, mbuf, n);
				break;
			case ACTION_CACHEEX_TIMEOUT:
#ifdef CS_CACHEEX
				cacheex_timeout(data->ptr);
#endif
				break;
			case ACTION_FALLBACK_TIMEOUT:
				fallback_timeout(data->ptr);
				break;
			case ACTION_CLIENT_TIMEOUT:
				ecm_timeout(data->ptr);
				break;
			case ACTION_ECM_ANSWER_READER:
				chk_dcw(data->ptr);
				break;
			case ACTION_ECM_ANSWER_CACHE:
				write_ecm_answer_fromcache(data->ptr);
				break;
			case ACTION_CLIENT_INIT:
				if(module->s_init)
					{ module->s_init(cl); }
				cl->is_udp = module->type == MOD_CONN_UDP;
				cl->init_done = 1;
				break;
			case ACTION_CLIENT_IDLE:
				if(module->s_idle)
					{ module->s_idle(cl); }
				else
				{
					cs_log("user %s reached %d sec idle limit.", username(cl), cfg.cmaxidle);
					cl->kill = 1;
				}
				break;
			case ACTION_CACHE_PUSH_OUT:
			{
#ifdef CS_CACHEEX
				ECM_REQUEST *er = data->ptr;
				int32_t res = 0, stats = -1;
				// cc-nodeid-list-check
				if(reader)
				{
					if(reader->ph.c_cache_push_chk && !reader->ph.c_cache_push_chk(cl, er))
						{ break; }
					res = reader->ph.c_cache_push(cl, er);
					stats = cacheex_add_stats(cl, er->caid, er->srvid, er->prid, 0);
				}
				else
				{
					if(module->c_cache_push_chk && !module->c_cache_push_chk(cl, er))
						{ break; }
					res = module->c_cache_push(cl, er);
				}
				debug_ecm(D_CACHEEX, "pushed ECM %s to %s res %d stats %d", buf, username(cl), res, stats);
				cl->cwcacheexpush++;
				if(cl->account)
					{ cl->account->cwcacheexpush++; }
				first_client->cwcacheexpush++;
#endif
				break;
			}
			case ACTION_CLIENT_KILL:
				cl->kill = 1;
				break;
			case ACTION_CLIENT_SEND_MSG:
			{
#ifdef MODULE_CCCAM
				struct s_clientmsg *clientmsg = (struct s_clientmsg *)data->ptr;
				cc_cmd_send(cl, clientmsg->msg, clientmsg->len, clientmsg->cmd);
#endif
				break;
			}
			} // switch

			__free_job_data(cl, data);
		}

		if(thread_pipe[1] && (mbuf[0] != 0x00))
		{
			cs_ddump_mask(D_TRACE, mbuf, 1, "[OSCAM-WORK] Write to pipe:");
			if(write(thread_pipe[1], mbuf, 1) == -1)    // wakeup client check
			{
				cs_debug_mask(D_TRACE, "[OSCAM-WORK] Writing to pipe failed (errno=%d %s)", errno, strerror(errno));
			}
		}

		// Check for some race condition where while we ended, another thread added a job
		pthread_mutex_lock(&cl->thread_lock);
		if(cl->joblist && ll_count(cl->joblist) > 0)
		{
			pthread_mutex_unlock(&cl->thread_lock);
			continue;
		}
		else
		{
			cl->thread_active = 0;
			pthread_mutex_unlock(&cl->thread_lock);
			break;
		}
	}
	cl->thread_active = 0;
	cl->work_mbuf = NULL; // Prevent free_client from freeing mbuf (->work_mbuf)
	free(mbuf);
	pthread_exit(NULL);
	return NULL;
}

/**
 * adds a job to the job queue
 * if ptr should be free() after use, set len to the size
 * else set size to 0
**/
int32_t add_job(struct s_client *cl, enum actions action, void *ptr, int32_t len)
{
	if(!cl || cl->kill)
	{
		if(!cl)
			{ cs_log("WARNING: add_job failed. Client killed!"); } // Ignore jobs for killed clients
		if(len && ptr)
			{ free(ptr); }
		return 0;
	}

#ifdef CS_CACHEEX
	// Avoid full running queues:
	if(action == ACTION_CACHE_PUSH_OUT && ll_count(cl->joblist) > 2000)
	{
		cs_debug_mask(D_TRACE, "WARNING: job queue %s %s has more than 2000 jobs! count=%d, dropped!",
					  cl->typ == 'c' ? "client" : "reader",
					  username(cl), ll_count(cl->joblist));
		if(len && ptr)
			{ free(ptr); }
		// Thread down???
		pthread_mutex_lock(&cl->thread_lock);
		if(cl->thread_active)
		{
			// Just test for invalid thread id:
			if(pthread_detach(cl->thread) == ESRCH)
			{
				cl->thread_active = 0;
				cs_debug_mask(D_TRACE, "WARNING: %s %s thread died!",
							  cl->typ == 'c' ? "client" : "reader", username(cl));
			}
		}
		pthread_mutex_unlock(&cl->thread_lock);
		return 0;
	}
#endif

	struct job_data *data;
	if(!cs_malloc(&data, sizeof(struct job_data)))
	{
		if(len && ptr)
			{ free(ptr); }
		return 0;
	}

	data->action = action;
	data->ptr    = ptr;
	data->cl     = cl;
	data->len    = len;
	data->time   = time(NULL);

	pthread_mutex_lock(&cl->thread_lock);
	if(cl->thread_active)
	{
		if(!cl->joblist)
			{ cl->joblist = ll_create("joblist"); }
		ll_append(cl->joblist, data);
		if(cl->thread_active == 2)
			{ pthread_kill(cl->thread, OSCAM_SIGNAL_WAKEUP); }
		pthread_mutex_unlock(&cl->thread_lock);
		cs_debug_mask(D_TRACE, "add %s job action %d queue length %d %s",
					  action > ACTION_CLIENT_FIRST ? "client" : "reader", action,
					  ll_count(cl->joblist), username(cl));
		return 1;
	}

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	/* pcsc doesn't like this either; segfaults on x86, x86_64 */
	struct s_reader *rdr = cl->reader;
	if(cl->typ != 'r' || !rdr || rdr->typ != R_PCSC)
		{ pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE); }

	if(action != ACTION_READER_CHECK_HEALTH)
	{
		cs_debug_mask(D_TRACE, "start %s thread action %d",
					  action > ACTION_CLIENT_FIRST ? "client" : "reader", action);
	}

	int32_t ret = pthread_create(&cl->thread, &attr, work_thread, (void *)data);
	if(ret)
	{
		cs_log("ERROR: can't create thread for %s (errno=%d %s)",
			   action > ACTION_CLIENT_FIRST ? "client" : "reader", ret, strerror(ret));
		free_job_data(data);
	}
	else
	{
		pthread_detach(cl->thread);
	}
	pthread_attr_destroy(&attr);

	cl->thread_active = 1;
	pthread_mutex_unlock(&cl->thread_lock);
	return 1;
}
