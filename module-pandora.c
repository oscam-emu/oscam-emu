#include "globals.h"

#ifdef MODULE_PANDORA

#include "cscrypt/md5.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-net.h"
#include "oscam-string.h"

#define CWS_NETMSGSIZE 320
#define START_TIME 150000
#define MAX_TIME 500000

static void simple_crypt(uchar *buf, int len, uchar *key, int key_len)
{
	int i, x;
	for(i = 0, x = 0; i < len; i++)
	{
		buf[i] ^= key[x++];
		if(x >= key_len)
			{ x = 0; }
	}
}

static void pandora_process_request(struct s_client *cl, uchar *buf, int32_t l)
{
	int ecmlen;
	ECM_REQUEST *er;
	uchar md5tmp[MD5_DIGEST_LENGTH];

	if(!(er = get_ecmtask()))
		{ return; }
	er->caid = b2i(2, buf + 1);
	er->srvid = b2i(2, buf + 3);
	er->prid = b2i(4, buf + 5);
	//er->ecmcrc32 = crc32(0L, buf+10, CS_ECMSTORESIZE);
	er->chid = b2i(2, buf + 10 + CS_ECMSTORESIZE);

	if(l > 12 + CS_ECMSTORESIZE + 16)
	{
		ecmlen = b2i(2, buf + 12 + CS_ECMSTORESIZE);
		if((ecmlen > 320) || cl->pand_ignore_ecm)
			{ er->ecmlen = 0; }
		else
		{
			if(!memcmp(buf + 10,
					   MD5(buf + 14 + CS_ECMSTORESIZE, ecmlen, md5tmp),
					   CS_ECMSTORESIZE))
			{
				er->ecmlen = ecmlen;
				memcpy(er->ecm, buf + 14 + CS_ECMSTORESIZE, ecmlen);
				//set_ecmhash(cl, er);
			}
			else
				{ er->ecmlen = 0; }
		}
	}
	else
		{ er->ecmlen = 0; }

	if(!er->ecmlen)
		{ usleep(cl->pand_autodelay); }
	get_cw(cl, er);
}

static int pandora_recv(struct s_client *cl, uchar *buf, int32_t l)
{
	int ret;

	if(!cl->udp_fd)
		{ return (-9); }
	if(cl->typ != 'c')
		{ ret = recv_from_udpipe(buf); }
	else
	{
		ret = recvfrom(cl->udp_fd, buf, l, 0, (struct sockaddr *)&cl->udp_sa, &cl->udp_sa_len);
	}
	if(ret < 1)
		{ return (-1); }

	simple_crypt(buf, ret, cl->pand_md5_key, 16);
	cl->last = time((time_t *) 0);

	if(cl->typ != 'c')
		{ pandora_process_request(cl, buf, ret); }
	return (ret);
}

static void pandora_send_dcw(struct s_client *cl, ECM_REQUEST *er)
{
	uchar msgbuf[CWS_NETMSGSIZE], len;
	if(cfg.pand_skip_send_dw)
		{ return; }
	if(er->rc < 4)
	{
		msgbuf[0] = 2; //DW_FOUND
		memcpy(&msgbuf[1], er->cw, 16);
		len = 1 + 16;
		cl->pand_autodelay = START_TIME;
	}
	else
	{
		msgbuf[0] = 0xFF; //DW_NOT_FOUND
		len = 1;
		if(cl->pand_autodelay < MAX_TIME)
			{ cl->pand_autodelay += 100000; }
	}
	simple_crypt(msgbuf, len, cl->pand_md5_key, 16);
	sendto(cl->udp_fd, msgbuf, len, 0, (struct sockaddr *) &cl->udp_sa, cl->udp_sa_len);
}

int pandora_auth_client(struct s_client *cl, IN_ADDR_T ip)
{
	int ok;
	struct s_auth *account;

#ifdef IPV6SUPPORT
	// FIXME: Add IPv6 support
	(void)ip; // Prevent warning about unused var "ip"
#else
	if(!cl->pand_ignore_ecm && cfg.pand_allowed)
	{
		struct s_ip *p_ip;
		for(ok = 0, p_ip = cfg.pand_allowed; (p_ip) && (!ok); p_ip
				= p_ip->next)
			{ ok = ((ip >= p_ip->ip[0]) && (ip <= p_ip->ip[1])); }

		if(!ok)
		{
			cs_auth_client(cl, (struct s_auth *) 0, "IP not allowed");
			return 0;
		}
	}
#endif

	for(ok = 0, account = cfg.account; cfg.pand_usr && account && !ok; account = account->next)
	{
		ok = streq(cfg.pand_usr, account->usr);
		if(ok && cs_auth_client(cl, account, NULL))
			{ cs_disconnect_client(cl); }
	}
	if(!ok)
		{ cs_auth_client(cl, (struct s_auth *)(-1), NULL); }
	return ok;
}

static void *pandora_server(struct s_client *cl, uchar *UNUSED(mbuf),
							int32_t UNUSED(len))
{
	uchar md5tmp[MD5_DIGEST_LENGTH];
	if(!cl->init_done)
	{
		if(cfg.pand_pass)
		{
			cl->pand_autodelay = 150000;
			memcpy(cl->pand_md5_key,
				   MD5((uchar *)cfg.pand_pass, strlen(cfg.pand_pass), md5tmp), 16);
			cl->pand_ignore_ecm = (cfg.pand_ecm) ? 0 : 1;
			cl->crypted = 1;
			pandora_auth_client(cl, cl->ip);
			cl->init_done = 1;
		}
		else
		{
			cs_log("Password for Pandora share MUST be set !!!");
		}
	}
	return NULL;
}

/************************************************************************************************************************
 *       client functions
 *************************************************************************************************************************/
int pandora_client_init(struct s_client *cl)
{
	static struct sockaddr_in loc_sa;
	int16_t p_proto;
	char ptxt[16];
	struct s_reader *rdr = cl->reader;
	uchar md5tmp[MD5_DIGEST_LENGTH];

	cl->pfd = 0;
	if(rdr->r_port <= 0)
	{
		cs_log("invalid port %d for server %s", rdr->r_port, rdr->device);
		return (1);
	}
	p_proto = IPPROTO_UDP;

	set_null_ip(&cl->ip);
	memset((char *) &loc_sa, 0, sizeof(loc_sa));
	loc_sa.sin_family = AF_INET;

	if(IP_ISSET(cfg.srvip))
		{ IP_ASSIGN(SIN_GET_ADDR(loc_sa), cfg.srvip); }
	else
		{ loc_sa.sin_addr.s_addr = INADDR_ANY; }
	loc_sa.sin_port = htons(rdr->l_port);

	if((cl->udp_fd = socket(PF_INET, SOCK_DGRAM, p_proto)) < 0)
	{
		cs_log("Socket creation failed (errno=%d)", errno);
		return 1;
	}

	int32_t opt = 1;
	setsockopt(cl->udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

#ifdef SO_REUSEPORT
	setsockopt(cl->udp_fd, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(opt));
#endif

	set_socket_priority(cl->udp_fd, cfg.netprio);

	if(rdr->l_port > 0)
	{
		if(bind(cl->udp_fd, (struct sockaddr *) &loc_sa, sizeof(loc_sa)) < 0)
		{
			cs_log("bind failed (errno=%d)", errno);
			close(cl->udp_fd);
			return (1);
		}
		snprintf(ptxt, sizeof(ptxt), ", port=%d", rdr->l_port);
	}
	else
		{ ptxt[0] = '\0'; }

	memcpy(cl->pand_md5_key, MD5((uchar *)rdr->r_pwd, strlen(rdr->r_pwd), md5tmp), 16);
	cl->crypted = 1;

	//cl->grp = 0xFFFFFFFF;
	//rdr->caid[0] = rdr->ctab.caid[0];

	cl->pand_send_ecm = rdr->pand_send_ecm;
	memset((char *) &cl->udp_sa, 0, sizeof(cl->udp_sa));
#ifdef IPV6SUPPORT
	((struct sockaddr_in *)(&cl->udp_sa))->sin_family = AF_INET;
	((struct sockaddr_in *)(&cl->udp_sa))->sin_port = htons((u_short) rdr->r_port);
#else
	cl->udp_sa.sin_family = AF_INET;
	cl->udp_sa.sin_port = htons((u_short) rdr->r_port);
#endif

	cs_log("proxy %s:%d pandora %s (%s)", rdr->device, rdr->r_port, rdr->pand_send_ecm ? "with ECM support" : "", ptxt);

	cl->pfd = cl->udp_fd;
	//fcntl(cl->udp_fd, F_SETFL, fcntl(cl->udp_fd, F_GETFL, 0) | O_NONBLOCK); //!!!!!
	return (0);
}

static int pandora_send_ecm(struct s_client *cl, ECM_REQUEST *er, uchar *UNUSED(buf))
{
	uchar md5tmp[MD5_DIGEST_LENGTH];
	uchar msgbuf[CWS_NETMSGSIZE];
	int ret, len;
	uchar adel;
	adel = (cfg.ctimeout > 7) ? 7 : cfg.ctimeout;

	msgbuf[0] = 1;
	msgbuf[1] = er->caid >> 8;
	msgbuf[2] = er->caid & 0xFF;
	msgbuf[3] = er->srvid >> 8;
	msgbuf[4] = er->srvid & 0xFF;
	msgbuf[5] = er->prid >> 24;
	msgbuf[6] = er->prid >> 16;
	msgbuf[7] = er->prid >> 8;
	msgbuf[8] = er->prid & 0xFF;
	msgbuf[9] = adel;
	memcpy(&msgbuf[10], MD5(er->ecm, er->ecmlen, md5tmp), CS_ECMSTORESIZE);
	msgbuf[10 + CS_ECMSTORESIZE] = er->chid >> 8;
	msgbuf[11 + CS_ECMSTORESIZE] = er->chid & 0xFF;
	len = 12 + CS_ECMSTORESIZE;
	if(cl->pand_send_ecm)
	{
		msgbuf[12 + CS_ECMSTORESIZE] = er->ecmlen >> 8;
		msgbuf[13 + CS_ECMSTORESIZE] = er->ecmlen & 0xFF;
		memcpy(&msgbuf[14 + CS_ECMSTORESIZE], er->ecm, er->ecmlen);
		len += er->ecmlen + 2;
	}
	simple_crypt(msgbuf, len, cl->pand_md5_key, 16);
	ret = sendto(cl->pfd, msgbuf, len, 0, (struct sockaddr *) &cl->udp_sa, cl->udp_sa_len);
	return ((ret < len) ? (-1) : 0);
}

static int pandora_recv_chk(struct s_client *UNUSED(cl), uchar *dcw, int *rc,
							uchar *buf, int UNUSED(n))
{
	if(buf[0] != 0x2)
		{ return (-1); }
	*rc = 1;
	memcpy(dcw, buf + 1, 16);
	return (0);
}

void module_pandora(struct s_module *ph)
{
	ph->ptab.nports = 1;
	ph->ptab.ports[0].s_port = cfg.pand_port;
	ph->num = R_PANDORA;

	ph->desc = "pandora";
	ph->type = MOD_CONN_UDP;
	ph->large_ecm_support = 1;
	//ph->watchdog = 1;
	IP_ASSIGN(ph->s_ip, cfg.pand_srvip);
	ph->s_handler = pandora_server;
	ph->recv = pandora_recv;
	ph->send_dcw = pandora_send_dcw;

	ph->c_init = pandora_client_init;
	ph->c_recv_chk = pandora_recv_chk;
	ph->c_send_ecm = pandora_send_ecm;
}

#endif
