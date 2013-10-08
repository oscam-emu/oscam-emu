#include "globals.h"
#ifdef MODULE_MONITOR
#include "cscrypt/md5.h"
#include "module-monitor.h"
#include "oscam-aes.h"
#include "oscam-client.h"
#include "oscam-config.h"
#include "oscam-conf-chk.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-work.h"

extern char *entitlement_type[];
extern char *loghist;
extern char *loghistptr;

struct monitor_data
{
	bool            auth;
	uint8_t         ucrc[4];
	struct aes_keys aes_keys;
	int32_t         seq;
	int32_t         counter;
	char            btxt[256];
};

static int8_t monitor_check_ip(void)
{
	int32_t ok = 0;
	struct s_client *cur_cl = cur_client();
	struct monitor_data *module_data = cur_cl->module_data;

	if(module_data->auth) { return 0; }
	ok = check_ip(cfg.mon_allowed, cur_cl->ip);
	if(!ok)
	{
		cs_auth_client(cur_cl, (struct s_auth *)0, "invalid ip");
		return -1;
	}
	return 0;
}

static int8_t monitor_auth_client(char *usr, char *pwd)
{
	struct s_auth *account;
	struct s_client *cur_cl = cur_client();
	struct monitor_data *module_data = cur_cl->module_data;

	if(module_data->auth) { return 0; }
	if((!usr) || (!pwd))
	{
		cs_auth_client(cur_cl, (struct s_auth *)0, NULL);
		return -1;
	}
	for(account = cfg.account; account; account = account->next)
	{
		if(account->monlvl && streq(usr, account->usr) && streq(pwd, account->pwd))
		{
			module_data->auth = 1;
			break;
		}
	}
	if(!module_data->auth)
	{
		cs_auth_client(cur_cl, (struct s_auth *)0, "invalid account");
		return -1;
	}
	if(cs_auth_client(cur_cl, account, NULL))
		{ return -1; }
	return 0;
}

static int32_t secmon_auth_client(uchar *ucrc)
{
	uint32_t crc;
	struct s_auth *account;
	struct s_client *cur_cl = cur_client();
	struct monitor_data *module_data = cur_cl->module_data;
	unsigned char md5tmp[MD5_DIGEST_LENGTH];

	if(module_data->auth)
	{
		int32_t s = memcmp(module_data->ucrc, ucrc, 4);
		if(s)
			{ cs_log("wrong user-crc or garbage !?"); }
		return !s;
	}
	cur_cl->crypted = 1;
	crc = (ucrc[0] << 24) | (ucrc[1] << 16) | (ucrc[2] << 8) | ucrc[3];
	for(account = cfg.account; (account) && (!module_data->auth); account = account->next)
		if((account->monlvl) &&
				(crc == crc32(0L, MD5((unsigned char *)account->usr, strlen(account->usr), md5tmp), MD5_DIGEST_LENGTH)))
		{
			memcpy(module_data->ucrc, ucrc, 4);
			aes_set_key(&module_data->aes_keys, (char *)MD5((unsigned char *)ESTR(account->pwd), strlen(ESTR(account->pwd)), md5tmp));
			if(cs_auth_client(cur_cl, account, NULL))
				{ return -1; }
			module_data->auth = 1;
		}
	if(!module_data->auth)
	{
		cs_auth_client(cur_cl, (struct s_auth *)0, "invalid user");
		return -1;
	}
	return module_data->auth;
}

int32_t monitor_send_idx(struct s_client *cl, char *txt)
{
	struct monitor_data *module_data = cl->module_data;
	int32_t l;
	unsigned char buf[256 + 32];
	if(!cl->udp_fd)
		{ return -1; }
	struct timespec req_ts;
	req_ts.tv_sec = 0;
	req_ts.tv_nsec = 500000;
	nanosleep(&req_ts, NULL); //avoid lost udp-pakkets
	if(!cl->crypted)
		{ return sendto(cl->udp_fd, txt, strlen(txt), 0, (struct sockaddr *)&cl->udp_sa, cl->udp_sa_len); }
	buf[0] = '&';
	buf[9] = l = strlen(txt);
	l = boundary(4, l + 5) + 5;
	memcpy(buf + 1, module_data->ucrc, 4);
	cs_strncpy((char *)buf + 10, txt, sizeof(buf) - 10);
	uchar tmp[10];
	memcpy(buf + 5, i2b_buf(4, crc32(0L, buf + 10, l - 10), tmp), 4);
	aes_encrypt_idx(&module_data->aes_keys, buf + 5, l - 5);
	return sendto(cl->udp_fd, buf, l, 0, (struct sockaddr *)&cl->udp_sa, cl->udp_sa_len);
}

#define monitor_send(t) monitor_send_idx(cur_client(), t)

static int32_t monitor_recv(struct s_client *client, uchar *buf, int32_t UNUSED(buflen))
{
	int32_t n = recv_from_udpipe(buf);
	if(!n)
		{ return buf[0] = 0; }
	if(!client->module_data && !cs_malloc(&client->module_data, sizeof(struct monitor_data)))
		{ return 0; }
	if(buf[0] == '&')
	{
		int32_t bsize;
		if(n < 21)  // 5+16 is minimum
		{
			cs_log("packet too small!");
			return buf[0] = 0;
		}
		int32_t res = secmon_auth_client(buf + 1);
		if(res == -1)
		{
			cs_disconnect_client(client);
			return 0;
		}
		if(!res)
		{
			return buf[0] = 0;
		}
		struct monitor_data *module_data = client->module_data;
		aes_decrypt(&module_data->aes_keys, buf + 5, 16);
		bsize = boundary(4, buf[9] + 5) + 5;
		if(n < bsize)
		{
			cs_log("packet-size mismatch !");
			return buf[0] = 0;
		}
		aes_decrypt(&module_data->aes_keys, buf + 21, n - 21);
		uchar tmp[10];
		if(memcmp(buf + 5, i2b_buf(4, crc32(0L, buf + 10, n - 10), tmp), 4))
		{
			cs_log("CRC error ! wrong password ?");
			return buf[0] = 0;
		}
		n = buf[9];
		memmove(buf, buf + 10, n);
	}
	else
	{
		if(monitor_check_ip() == -1)
		{
			cs_disconnect_client(client);
			return 0;
		}
	}
	buf[n] = '\0';
	n = strlen(trim((char *)buf));
	if(n) { client->last = time((time_t *) 0); }
	return n;
}

static void monitor_send_info(char *txt, int32_t last)
{
	struct s_client *cur_cl = cur_client();
	struct monitor_data *module_data = cur_cl->module_data;
	char buf[8];
	if(txt)
	{
		if(!module_data->btxt[0])
		{
			module_data->counter = 0;
			txt[2] = 'B';
		}
		else
			{ module_data->counter++; }
		snprintf(buf, sizeof(buf), "%03d", module_data->counter);
		memcpy(txt + 4, buf, 3);
		txt[3] = '0' + module_data->seq;
	}
	else if(!last)
		{ return; }

	if(!last)
	{
		if(module_data->btxt[0]) { monitor_send(module_data->btxt); }
		cs_strncpy(module_data->btxt, txt, sizeof(module_data->btxt));
		return;
	}

	if(txt && module_data->btxt[0])
	{
		monitor_send(module_data->btxt);
		txt[2] = 'E';
		cs_strncpy(module_data->btxt, txt, sizeof(module_data->btxt));
	}
	else
	{
		if(txt)
			{ cs_strncpy(module_data->btxt, txt, sizeof(module_data->btxt)); }
		module_data->btxt[2] = (module_data->btxt[2] == 'B') ? 'S' : 'E';
	}

	if(module_data->btxt[0])
	{
		monitor_send(module_data->btxt);
		module_data->seq = (module_data->seq + 1) % 10;
	}
	module_data->btxt[0] = 0;
}

static char *monitor_client_info(char id, struct s_client *cl, char *sbuf)
{
	char channame[32];
	sbuf[0] = '\0';

	if(cl)
	{
		char ldate[16], ltime[16], *usr;
		int32_t lsec, isec, con, cau, lrt = - 1;
		time_t now;
		struct tm lt;
		now = time((time_t *)0);

		if((cfg.hideclient_to <= 0) ||
				(now - cl->lastecm < cfg.hideclient_to) ||
				(now - cl->lastemm < cfg.hideclient_to) ||
				(cl->typ != 'c'))
		{
			lsec = now - cl->login;
			isec = now - cl->last;
			usr = username(cl);
			if(cl->dup)
				{ con = 2; }
			else if((cl->tosleep) && (now - cl->lastswitch > cl->tosleep))
				{ con = 1; }
			else
				{ con = 0; }

			// no AU reader == 0 / AU ok == 1 / Last EMM > aulow == -1
			if(cl->typ == 'c' || cl->typ == 'p' || cl->typ == 'r')
			{

				if((cl->typ == 'c' && ll_count(cl->aureader_list) == 0) ||
						((cl->typ == 'p' || cl->typ == 'r') && cl->reader->audisabled))
					{ cau = 0; }

				else if((now - cl->lastemm) / 60 > cfg.aulow)
					{ cau = (-1); }

				else
					{ cau = 1; }

			}
			else
			{
				cau = 0;
			}

			if(cl->typ == 'r')
			{
				int32_t i;
				struct s_reader *rdr;
				for(i = 0, rdr = first_active_reader; rdr ; rdr = rdr->next, i++)
					if(cl->reader == rdr)
						{ lrt = i; }

				if(lrt >= 0)
					{ lrt = 10 + cl->reader->card_status; }
			}
			else
				{ lrt = cl->cwlastresptime; }
			localtime_r(&cl->login, &lt);
			snprintf(ldate, sizeof(ldate), "%02d.%02d.%02d", lt.tm_mday, lt.tm_mon + 1, lt.tm_year % 100);
			int32_t cnr = get_threadnum(cl);
			snprintf(ltime, sizeof(ldate), "%02d:%02d:%02d", lt.tm_hour, lt.tm_min, lt.tm_sec);
			snprintf(sbuf, 256, "[%c--CCC]%8X|%c|%d|%s|%d|%d|%s|%d|%s|%s|%s|%d|%04X:%04X|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d\n",
					 id, cl->tid, cl->typ, cnr, usr, cau, cl->crypted,
					 cs_inet_ntoa(cl->ip), cl->port, client_get_proto(cl),
					 ldate, ltime, lsec, cl->last_caid, cl->last_srvid,
					 get_servicename_or_null(cl, cl->last_srvid, cl->last_caid, channame), isec, con,
					 cl->cwfound, cl->cwnot, cl->cwcache, cl->cwignored,
					 cl->cwtout, cl->emmok, cl->emmnok, lrt);
		}
	}
	return sbuf;
}

static void monitor_process_info(void)
{
	time_t now = time((time_t *)0);
	char sbuf[256];

	struct s_client *cl, *cur_cl = cur_client();

	for(cl = first_client; cl ; cl = cl->next)
	{
		if((cfg.hideclient_to <= 0) ||
				(now - cl->lastecm < cfg.hideclient_to) ||
				(now - cl->lastemm < cfg.hideclient_to) ||
				(cl->typ != 'c'))
		{
			if((cur_cl->monlvl < 2) && (cl->typ != 's'))
			{
				if((cur_cl->account && cl->account && strcmp(cur_cl->account->usr, cl->account->usr)) ||
						((cl->typ != 'c') && (cl->typ != 'm')))
					{ continue; }
			}
			monitor_send_info(monitor_client_info('I', cl, sbuf), 0);
		}
	}
	monitor_send_info(NULL, 1);
}

static void monitor_send_details(char *txt, uint32_t tid)
{
	char buf[256];
	snprintf(buf, 255, "[D-----]%8X|%s\n", tid, txt);
	monitor_send_info(buf, 0);
}

static void monitor_send_details_version(void)
{
	char buf[256];
	snprintf(buf, sizeof(buf), "[V-0000]version=%s, build=%s, system=%s\n", CS_VERSION, CS_SVN_VERSION, CS_TARGET);
	monitor_send_info(buf, 1);
}

static void monitor_send_keepalive_ack(void)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "[K-0000]keepalive_ack\n");
	monitor_send_info(buf, 1);
}

static void monitor_process_details_master(char *buf, uint32_t pid)
{
	snprintf(buf, 256, "Version=%sr%s", CS_VERSION, CS_SVN_VERSION);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "System=%s", CS_TARGET);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "DebugLevel=%d", cs_dblevel);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "MaxClients=UNLIMITED");
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "ClientMaxIdle=%d sec", cfg.cmaxidle);
	monitor_send_details(buf, pid);
	if(cfg.max_log_size)
		{ snprintf(buf + 200, 56, "%d Kb", cfg.max_log_size); }
	else
		{ cs_strncpy(buf + 200, "unlimited", 56); }
	snprintf(buf, 256, "MaxLogsize=%s", buf + 200);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "ClientTimeout=%u ms", cfg.ctimeout);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "CacheDelay=%d ms", cfg.delay);
	monitor_send_details(buf, pid);
	if(cfg.cwlogdir)
	{
		snprintf(buf, 256, "CwlogDir=%s", cfg.cwlogdir);
		monitor_send_details(buf, pid);
	}
	if(cfg.preferlocalcards)
	{
		snprintf(buf, 256, "PreferlocalCards=%d", cfg.preferlocalcards);
		monitor_send_details(buf, pid);
	}
	if(cfg.waitforcards)
	{
		snprintf(buf, 256, "WaitforCards=%d", cfg.waitforcards);
		monitor_send_details(buf, pid);
	}
	snprintf(buf, 256, "LogFile=%s", cfg.logfile);
	monitor_send_details(buf, pid);
	if(cfg.mailfile)
	{
		snprintf(buf, 256, "MailFile=%s", cfg.mailfile);
		monitor_send_details(buf, pid);
	}
	if(cfg.usrfile)
	{
		snprintf(buf, 256, "UsrFile=%s", cfg.usrfile);
		monitor_send_details(buf, pid);
	}
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "Sleep=%d", cfg.tosleep);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "Monitorport=%d", cfg.mon_port);
	monitor_send_details(buf, pid);
	snprintf(buf, 256, "Nice=%d", cfg.nice);
	monitor_send_details(buf, pid);
#ifdef WEBIF
	snprintf(buf, 256, "Restartmode=%d", cs_get_restartmode());
	monitor_send_details(buf, pid);
#else
	snprintf(buf, 256, "Restartmode=%s", "no");
	monitor_send_details(buf, pid);
#endif

	//  monitor_send_details(buf, pid);
}


static void monitor_process_details_reader(struct s_client *cl)
{
	char tbuffer1[64], tbuffer2[64], buf[256] = { 0 }, tmpbuf[256] = { 0 }, valid_to[32] = { 0 };
	struct s_reader *rdr = cl->reader;
	if(!rdr)
	{
		monitor_send_details("Reader do not exist or it is not started.", cl->tid);
		return;
	}

	if(rdr->card_valid_to)
	{
		struct tm vto_t;
		localtime_r(&rdr->card_valid_to, &vto_t);
		strftime(valid_to, sizeof(valid_to) - 1, "%Y-%m-%d", &vto_t);
	}
	else
	{
		strncpy(valid_to, "n/a", 3);
	}

	snprintf(tmpbuf, sizeof(tmpbuf) - 1, "Cardsystem: %s Reader: %s ValidTo: %s HexSerial: %s ATR: %s",
			 rdr->csystem.desc,
			 rdr->label,
			 valid_to,
			 cs_hexdump(1, rdr->hexserial, 8, tbuffer2, sizeof(tbuffer2)),
			 rdr->card_atr_length
			 ? cs_hexdump(1, rdr->card_atr, rdr->card_atr_length, buf, sizeof(buf))
			 : ""
			);
	monitor_send_details(tmpbuf, cl->tid);

	if(!rdr->ll_entitlements)
	{
		monitor_send_details("No entitlements for the reader.", cl->tid);
		return;
	}

	S_ENTITLEMENT *item;
	LL_ITER itr = ll_iter_create(rdr->ll_entitlements);
	time_t now = (time(NULL) / 86400) * 86400;

	while((item = ll_iter_next(&itr)))
	{
		struct tm start_t, end_t;

		localtime_r(&item->start, &start_t);
		localtime_r(&item->end  , &end_t);

		strftime(tbuffer1, sizeof(tbuffer1) - 1, "%Y-%m-%d %H:%M %z", &start_t);
		strftime(tbuffer2, sizeof(tbuffer2) - 1, "%Y-%m-%d %H:%M %z", &end_t);

		char *entresname = get_tiername(item->id & 0xFFFF, item->caid, buf);
		if(!entresname[0])
			{ entresname = get_provider(item->caid, item->provid, buf, sizeof(buf)); }

		snprintf(tmpbuf, sizeof(tmpbuf) - 1, "%s Type: %s CAID: %04X Provid: %06X ID: %08X%08X Class: %08X StartDate: %s ExpireDate: %s Name: %s",
				 item->end > now ? "active " : "expired",
				 entitlement_type[item->type],
				 item->caid,
				 item->provid,
				 (uint32_t)(item->id >> 32),
				 (uint32_t)(item->id),
				 item->class,
				 tbuffer1,
				 tbuffer2,
				 entresname
				);
		monitor_send_details(tmpbuf, cl->tid);
	}
}


static void monitor_process_details(char *arg)
{
	uint32_t tid = 0; //using threadid 8 positions hex see oscam-log.c //FIXME untested but pid isnt working anyway with threading
	struct s_client *cl = NULL, *cl1;
	char sbuf[256];

	if(!arg)
		{ cl = first_client; } // no arg - show master
	else
	{
		if(sscanf(arg, "%X", &tid) == 1)
		{
			for(cl1 = first_client; cl1 ; cl1 = cl1->next)
				if(cl1->tid == tid)
				{
					cl = cl1;
					break;
				}
		}
	}

	if(!cl)
		{ monitor_send_details("Invalid TID", tid); }
	else
	{
		//monitor_send_info(monitor_client_info('D', idx), 0); //FIXME
		switch(cl->typ)
		{
		case 's':
			monitor_process_details_master(sbuf, cl->tid);
			break;
		case 'c':
		case 'm':
			monitor_send_details(monitor_client_info(1, cl, sbuf), cl->tid);
			break;
		case 'r':
			monitor_process_details_reader(cl);//with client->typ='r' client->ridx is always filled and valid, so no need checking
			break;
		case 'p':
			monitor_send_details(monitor_client_info(1, cl, sbuf), cl->tid);
			break;
		}
	}
	monitor_send_info(NULL, 1);
}

static void monitor_send_login(void)
{
	char buf[64];
	struct s_client *cur_cl = cur_client();
	struct monitor_data *module_data = cur_cl->module_data;
	if(module_data->auth && cur_cl->account)
		{ snprintf(buf, sizeof(buf), "[A-0000]1|%s logged in\n", cur_cl->account->usr); }
	else
		{ cs_strncpy(buf, "[A-0000]0|not logged in\n", sizeof(buf)); }
	monitor_send_info(buf, 1);
}

static void monitor_login(char *usr)
{
	char *pwd = NULL;
	int8_t res = 0;
	if((usr) && (pwd = strchr(usr, ' ')))
		{ * pwd++ = 0; }
	if(pwd)
		{ res = monitor_auth_client(trim(usr), trim(pwd)); }
	else
		{ res = monitor_auth_client(NULL, NULL); }

	if(res == -1)
	{
		cs_disconnect_client(cur_client());
		return;
	}
	monitor_send_login();
}

static void monitor_logsend(char *flag)
{
	if(!flag) { return; }  //no arg

	struct s_client *cur_cl = cur_client();
	if(strcmp(flag, "on"))
	{
		if(strcmp(flag, "onwohist"))
		{
			cur_cl->log = 0;
			return;
		}
	}

	if(cur_cl->log)     // already on
		{ return; }

	int32_t i, d = 0;
	if(!strcmp(flag, "on") && cfg.loghistorysize)
	{
		char *t_loghistptr = loghistptr, *ptr1 = NULL;
		if(loghistptr >= loghist + (cfg.loghistorysize) - 1)
			{ t_loghistptr = loghist; }
		int32_t l1 = strlen(t_loghistptr + 1) + 2;
		char *lastpos = loghist + (cfg.loghistorysize) - 1;

		for(ptr1 = t_loghistptr + l1, i = 0; i < 200; i++, ptr1 = ptr1 + l1)
		{
			l1 = strlen(ptr1) + 1;
			if(!d && ((ptr1 >= lastpos) || (l1 < 2)))
			{
				ptr1 = loghist;
				l1 = strlen(ptr1) + 1;
				d++;
			}

			if(d && ((ptr1 >= t_loghistptr) || (l1 < 2)))
				{ break; }

			char p_usr[32], p_txt[512];
			size_t pos1 = strcspn(ptr1, "\t") + 1;

			cs_strncpy(p_usr, ptr1 , pos1 > sizeof(p_usr) ? sizeof(p_usr) : pos1);

			if((p_usr[0]) && ((cur_cl->monlvl > 1) || (cur_cl->account && !strcmp(p_usr, cur_cl->account->usr))))
			{
				snprintf(p_txt, sizeof(p_txt), "[LOG%03d]%s", cur_cl->logcounter, ptr1 + pos1);
				cur_cl->logcounter = (cur_cl->logcounter + 1) % 1000;
				monitor_send(p_txt);
			}
		}
	}

	cur_cl->log = 1;
}

static void monitor_set_debuglevel(char *flag)
{
	if(flag)
	{
		cs_dblevel = atoi(flag);
#ifndef WITH_DEBUG
		cs_log("*** Warning: Debug Support not compiled in ***");
#else
		cs_log("%s debug_level=%d", "all", cs_dblevel);
#endif
	}
}

static void monitor_get_account(void)
{
	struct s_auth *account;
	char buf[256];
	int32_t count = 0;

	for(account = cfg.account; (account); account = account->next)
	{
		count++;
		snprintf(buf, sizeof(buf), "[U-----]%s\n", account->usr);
		monitor_send_info(buf, 0);
	}
	snprintf(buf, sizeof(buf), "[U-----] %i User registered\n", count);
	monitor_send_info(buf, 1);
	return;
}

static void monitor_set_account(char *args)
{
	struct s_auth *account;
	char delimiter[] = " =";
	char *ptr, *saveptr1 = NULL;
	int32_t argidx, i, found;
	char *argarray[3];
	static const char *token[] = {"au", "sleep", "uniq", "monlevel", "group", "services", "betatunnel", "ident", "caid", "chid", "class", "hostname", "expdate", "keepalive", "disabled"};
	int32_t tokencnt = sizeof(token) / sizeof(char *);
	char buf[256], tmp[64];

	argidx = 0;
	found = 0;

	snprintf(tmp, sizeof(tmp), "%s", args);
	snprintf(buf, sizeof(buf), "[S-0000]setuser: %s check\n", tmp);
	monitor_send_info(buf, 0);

	ptr = strtok_r(args, delimiter, &saveptr1);

	// resolve arguments
	while(ptr != NULL)
	{
		argarray[argidx] = trim(ptr);
		ptr = strtok_r(NULL, delimiter, &saveptr1);
		argidx++;
	}

	if(argidx != 3)
	{
		snprintf(buf, sizeof(buf), "[S-0000]setuser: %s failed - wrong number of parameters (%d)\n", tmp,  argidx);
		monitor_send_info(buf, 0);
		snprintf(buf, sizeof(buf), "[S-0000]setuser: %s end\n", tmp);
		monitor_send_info(buf, 1);
		return;
	}

	//search account
	for(account = cfg.account; (account) ; account = account->next)
	{
		if(!strcmp(argarray[0], account->usr))
		{
			found = 1;
			break;
		}
	}

	if(found != 1)
	{
		snprintf(buf, sizeof(buf), "[S-0000]setuser: %s failed - user %s not found\n", tmp , argarray[0]);
		monitor_send_info(buf, 0);
		snprintf(buf, sizeof(buf), "[S-0000]setuser: %s end\n", tmp);
		monitor_send_info(buf, 1);
		return;
	}

	found = -1;
	for(i = 0; i < tokencnt; i++)
	{
		if(!strcmp(argarray[1], token[i]))
		{
			// preparing the parameters before re-load
			switch(i)
			{

			case    6:
				clear_tuntab(&account->ttab);
				break;     //betatunnel

			case    8:
				clear_caidtab(&account->ctab);
				break;    //Caid
			}
			found = i;
		}
	}

	if(found < 0)
	{
		snprintf(buf, sizeof(buf), "[S-0000]setuser: parameter %s not exist. possible values:\n", argarray[1]);
		monitor_send_info(buf, 0);
		for(i = 0; i < tokencnt; i++)
		{
			snprintf(buf, sizeof(buf), "[S-0000]%s\n", token[i]);
			monitor_send_info(buf, 0);
		}
		snprintf(buf, sizeof(buf), "[S-0000]setuser: %s end\n", tmp);
		monitor_send_info(buf, 1);
		return;
	}
	else
	{
		chk_account(token[found], argarray[2], account);
	}

	if(write_userdb() == 0)
		{ cs_reinit_clients(cfg.account); }

	snprintf(buf, sizeof(buf), "[S-0000]setuser: %s done - param %s set to %s\n", tmp, argarray[1], argarray[2]);
	monitor_send_info(buf, 1);
}

static void monitor_set_server(char *args)
{
	char delimiter[] = "=";
	char *ptr, *saveptr1;
	int32_t argidx, i;
	char *argarray[3];
	static const char *token[] = {"clienttimeout", "fallbacktimeout", "clientmaxidle", "cachedelay", "bindwait", "netprio", "sleep", "unlockparental", "serialreadertimeout", "maxlogsize", "showecmdw", "waitforcards", "preferlocalcards"};
	char buf[256];

	argidx = 0;
	ptr = strtok_r(args, delimiter, &saveptr1);

	// resolve arguments
	while(ptr != NULL)
	{
		argarray[argidx] = trim(ptr);
		ptr = strtok_r(NULL, delimiter, &saveptr1);
		argidx++;
	}

	if(argidx != 2)
	{
		snprintf(buf, sizeof(buf), "[S-0000]setserver failed - wrong number of parameters (%d)\n", argidx);
		monitor_send_info(buf, 1);
		return;
	}

	trim(argarray[0]);
	trim(argarray[1]);
	strtolower(argarray[0]);

	for(i = 0; i < 13; i++)
		if(!strcmp(argarray[0], token[i])) { break; }

	if(i < 13)
	{
		config_set("global", token[i], argarray[1]);
		snprintf(buf, sizeof(buf), "[S-0000]setserver done - param %s set to %s\n", argarray[0], argarray[1]);
		monitor_send_info(buf, 1);
	}
	else
	{
		snprintf(buf, sizeof(buf), "[S-0000]setserver failed - parameter %s not exist\n", argarray[0]);
		monitor_send_info(buf, 1);
		return;
	}

	/*Hide by blueven. Introduce new fallbacktimeout_percaid.
	 *
	 * if (cfg.ftimeout>=cfg.ctimeout) {
	    cfg.ftimeout = cfg.ctimeout - 100;
	    snprintf(buf, sizeof(buf), "[S-0000]setserver WARNING: fallbacktimeout adjusted to %u ms\n", cfg.ftimeout);
	    monitor_send_info(buf, 1);
	}*/
	//kill(first_client->pid, SIGUSR1);
}

#ifdef WEBIF
static void monitor_restart_server(void)
{
	cs_restart_oscam();
}
#endif

static void monitor_list_commands(const char *args[], int32_t cmdcnt)
{
	int32_t i;
	for(i = 0; i < cmdcnt; i++)
	{
		char buf[64];
		snprintf(buf, sizeof(buf), "[S-0000]commands: %s\n", args[i]);
		if(i < cmdcnt - 1)
			{ monitor_send_info(buf, 0); }
		else
			{ monitor_send_info(buf, 1); }
	}
}

static int32_t monitor_process_request(char *req)
{
	int32_t i, rc;
	static const char *cmd[] = {"login",
								"exit",
								"log",
								"status",
								"shutdown",
								"reload",
								"details",
								"version",
								"debug",
								"getuser",
								"setuser",
								"setserver",
								"commands",
								"keepalive",
								"reread"
#ifdef WEBIF
								, "restart"
#endif
							   };

	int32_t cmdcnt = sizeof(cmd) / sizeof(char *); // Calculate the amount of items in array
	char *arg;
	struct s_client *cur_cl = cur_client();
	struct monitor_data *module_data = cur_cl->module_data;

	if((arg = strchr(req, ' ')))
	{
		*arg++ = 0;
		trim(arg);
	}
	//trim(req);

	if(!module_data->auth && strcmp(req, cmd[0]) != 0)
		{ monitor_login(NULL); }

	for(rc = 1, i = 0; i < cmdcnt; i++)
		if(!strcmp(req, cmd[i]))
		{
			switch(i)
			{
			case  0:
				monitor_login(arg);
				break;  // login
			case  1:
				cs_disconnect_client(cur_cl);
				break;    // exit
			case  2:
				monitor_logsend(arg);
				break;    // log
			case  3:
				monitor_process_info();
				break;  // status
			case  4:
				if(cur_cl->monlvl > 3) { cs_exit_oscam(); }
				break; // shutdown
			case  5:
				if(cur_cl->monlvl > 2) { cs_accounts_chk(); }
				break;   // reload
			case  6:
				monitor_process_details(arg);
				break;    // details
			case  7:
				monitor_send_details_version();
				break;  // version
			case  8:
				if(cur_cl->monlvl > 3) { monitor_set_debuglevel(arg); }
				break; // debuglevel
			case  9:
				if(cur_cl->monlvl > 3) { monitor_get_account(); }
				break;   // getuser
			case 10:
				if(cur_cl->monlvl > 3) { monitor_set_account(arg); }
				break;    // setuser
			case 11:
				if(cur_cl->monlvl > 3) { monitor_set_server(arg); }
				break; // setserver
			case 12:
				if(cur_cl->monlvl > 3) { monitor_list_commands(cmd, cmdcnt); }
				break;  // list commands
			case 13:
				if(cur_cl->monlvl > 3) { monitor_send_keepalive_ack(); }
				break;    // keepalive
			case 14:
			{
				char buf[64];    // reread
				snprintf(buf, sizeof(buf), "[S-0000]reread\n");
				monitor_send_info(buf, 1);
				cs_card_info();
				break;
			}
#ifdef WEBIF
			case 15:
				if(cur_cl->monlvl > 3) { monitor_restart_server(); }
				break;    // keepalive
#endif
			default:
				continue;
			}
			break;
		}
	return rc;
}

static void *monitor_server(struct s_client *client, uchar *mbuf, int32_t UNUSED(n))
{
	client->typ = 'm';
	monitor_process_request((char *)mbuf);

	return NULL;
}

static void monitor_cleanup(struct s_client *client)
{
	NULLFREE(client->module_data);
}

void module_monitor(struct s_module *ph)
{
	ph->ptab.nports = 1;
	ph->ptab.ports[0].s_port = cfg.mon_port;
	ph->desc = "monitor";
	ph->type = MOD_CONN_UDP;
	IP_ASSIGN(ph->s_ip, cfg.mon_srvip);
	ph->s_handler = monitor_server;
	ph->recv = monitor_recv;
	ph->cleanup = monitor_cleanup;
	//  ph->send_dcw=NULL;
}
#endif
