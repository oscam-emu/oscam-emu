#include "globals.h"
#ifdef MODULE_RADEGAST
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-reader.h"

static int32_t radegast_connect(void);

static int32_t radegast_send(struct s_client *client, uchar *buf)
{
	int32_t l = buf[1] + 2;
	return (send(client->pfd, buf, l, 0));
}

static int32_t radegast_recv(struct s_client *client, uchar *buf, int32_t l)
{
	int32_t n;
	if(!client->pfd) { return (-1); }
	if(client->typ == 'c')     // server code
	{
		if((n = recv(client->pfd, buf, l, 0)) > 0)
			{ client->last = time((time_t *) 0); }
	}
	else      // client code
	{
		if((n = recv(client->pfd, buf, l, 0)) > 0)
		{
			cs_ddump_mask(D_CLIENT, buf, n, "radegast: received %d bytes from %s", n, remote_txt());
			client->last = time((time_t *) 0);
			if((buf[0] == 0x02) && (buf[1] == 0x12) && (buf[2] == 0x05) && (buf[3] == 0x10)) { return (n); }  // dcw received
			else if((buf[0] == 0x02) && (buf[1] == 0x02) && (buf[2] == 0x04) && (buf[3] == 0x00)) { return (n); }  // dcw no found
			else if((buf[0] == 0x81) && (buf[1] == 0x00)) { return (n); }  // cmd unknown
			else { n = -1; }// no cmd radegast disconnect
		}
	}
	return (n);
}

static int32_t radegast_recv_chk(struct s_client *client, uchar *dcw, int32_t *rc, uchar *buf, int32_t UNUSED(n))
{
	if((buf[0] == 2) && (buf[1] == 0x12))
	{
		char tmp_dbg[33];
		memcpy(dcw, buf + 4, 16);
		cs_debug_mask(D_CLIENT, "radegast: recv chk - %s", cs_hexdump(0, dcw, 16, tmp_dbg, sizeof(tmp_dbg)));
		*rc = 1;
		return (client->reader->msg_idx);
	}

	return (-1);
}

static void radegast_auth_client(IN_ADDR_T ip)
{
	int32_t ok;
	struct s_auth *account;
	struct s_client *cl = cur_client();

	ok = check_ip(cfg.rad_allowed, ip);

	if(!ok)
	{
		cs_log("radegast: IP not allowed");
		cs_auth_client(cl, (struct s_auth *)0, NULL);
		cs_disconnect_client(cl);
	}

	for(ok = 0, account = cfg.account; cfg.rad_usr && account && !ok; account = account->next)
	{
		ok = streq(cfg.rad_usr, account->usr);
		if(ok && cs_auth_client(cl, account, NULL))
			{ cs_disconnect_client(cl); }
	}

	if(!ok)
		{ cs_auth_client(cl, ok ? account : (struct s_auth *)(-1), "radegast"); }
}

static void radegast_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
	uchar mbuf[1024];
	mbuf[0] = 0x02;   // DCW
	if(er->rc < E_NOTFOUND)
	{
		mbuf[1] = 0x12; // len (overall)
		mbuf[2] = 0x05; // ACCESS
		mbuf[3] = 0x10; // len
		memcpy(mbuf + 4, er->cw, 16);
	}
	else
	{
		mbuf[1] = 0x02; // len (overall)
		mbuf[2] = 0x04; // NO ACCESS
		mbuf[3] = 0x00; // len
	}
	radegast_send(client, mbuf);
}

static void radegast_process_ecm(uchar *buf, int32_t l)
{
	int32_t i, n, sl;
	ECM_REQUEST *er;
	struct s_client *cl = cur_client();

	if(!(er = get_ecmtask()))
		{ return; }
	for(i = 0; i < l; i += (sl + 2))
	{
		sl = buf[i + 1];
		switch(buf[i])
		{
		case  2:      // CAID (upper byte only, oldstyle)
			er->caid = buf[i + 2] << 8;
			break;
		case 10:      // CAID
			er->caid = b2i(2, buf + i + 2);
			break;
		case  3:      // ECM DATA
			//er->ecmlen = sl;
			er->ecmlen = (((buf[i + 1 + 2] & 0x0F) << 8) | buf[i + 2 + 2]) + 3;
			memcpy(er->ecm, buf + i + 2, er->ecmlen);
			break;
		case  6:      // PROVID (ASCII)
			n = (sl > 6) ? 3 : (sl >> 1);
			er->prid = cs_atoi((char *) buf + i + 2 + sl - (n << 1), n, 0);
			break;
		case  7:      // KEYNR (ASCII), not needed
			break;
		case  8:      // ECM PROCESS PID ?? don't know, not needed
			break;
		}
	}
	if(l != i)
		{ cs_log("WARNING: ECM-request corrupt"); }
	else
		{ get_cw(cl, er); }
}

static void radegast_process_unknown(uchar *buf)
{
	uchar answer[2] = {0x81, 0x00};
	radegast_send(cur_client(), answer);
	cs_log("unknown request %02X, len=%d", buf[0], buf[1]);
}

static void *radegast_server(struct s_client *client, uchar *mbuf, int32_t n)
{
	if(n < 3)
		{ return NULL; }

	if(!client->init_done)
	{
		radegast_auth_client(cur_client()->ip);
		client->init_done = 1;
	}

	switch(mbuf[0])
	{
	case 1:
		radegast_process_ecm(mbuf + 2, mbuf[1]);
		break;
	default:
		radegast_process_unknown(mbuf);
	}

	return NULL;
}

static int32_t radegast_send_ecm(struct s_client *client, ECM_REQUEST *er, uchar *UNUSED(buf))
{
	int32_t n;
	uchar provid_buf[8];
	uchar header[22] = "\x02\x01\x00\x06\x08\x30\x30\x30\x30\x30\x30\x30\x30\x07\x04\x30\x30\x30\x38\x08\x01\x02";
	uchar *ecmbuf;

	if(!radegast_connect())
		{ return (-1); }

	if(!cs_malloc(&ecmbuf, er->ecmlen + 30))
		{ return -1; }

	ecmbuf[0] = 1;
	ecmbuf[1] = (er->ecmlen + 30 - 2) & 0xff;
	memcpy(ecmbuf + 2, header, sizeof(header));
	for(n = 0; n < 4; n++)
	{
		snprintf((char *)provid_buf + (n * 2), sizeof(provid_buf) - (n * 2), "%02X", ((uchar *)(&er->prid))[4 - 1 - n]);
	}
	ecmbuf[7] = provid_buf[0];
	ecmbuf[8] = provid_buf[1];
	ecmbuf[9] = provid_buf[2];
	ecmbuf[10] = provid_buf[3];
	ecmbuf[11] = provid_buf[4];
	ecmbuf[12] = provid_buf[5];
	ecmbuf[13] = provid_buf[6];
	ecmbuf[14] = provid_buf[7];
	ecmbuf[2 + sizeof(header)] = 0xa;
	ecmbuf[3 + sizeof(header)] = 2;
	ecmbuf[4 + sizeof(header)] = er->caid >> 8;
	ecmbuf[5 + sizeof(header)] = er->caid & 0xff;
	ecmbuf[6 + sizeof(header)] = 3;
	ecmbuf[7 + sizeof(header)] = er->ecmlen & 0xff;
	memcpy(ecmbuf + 8 + sizeof(header), er->ecm, er->ecmlen);
	ecmbuf[4] = er->caid >> 8;

	client->reader->msg_idx = er->idx;
	n = send(client->pfd, ecmbuf, er->ecmlen + 30, 0);

	cs_debug_mask(D_TRACE, "radegast: sending ecm");
	cs_ddump_mask(D_CLIENT, ecmbuf, er->ecmlen + 30, "ecm:");
	free(ecmbuf);
	return ((n < 1) ? (-1) : 0);
}

int32_t radegast_cli_init(struct s_client *cl)
{
	int32_t handle;

	handle = network_tcp_connection_open(cl->reader);
	if(handle < 0) { return -1; }

	cs_log("radegast: proxy %s:%d (fd=%d)",
		   cl->reader->device, cl->reader->r_port, cl->udp_fd);

	cl->reader->tcp_connected = 2;
	cl->reader->card_status = CARD_INSERTED;
	cl->reader->last_g = cl->reader->last_s = time((time_t *)0);

	cs_debug_mask(D_CLIENT, "radegast: last_s=%ld, last_g=%ld", cl->reader->last_s, cl->reader->last_g);

	cl->pfd = cl->udp_fd;

	return (0);
}

static void radegast_server_init(struct s_client *cl)
{
	if(!cl->init_done)
	{
		if(IP_ISSET(cl->ip))
			{ cs_log("radegast: new connection from %s", cs_inet_ntoa(cl->ip)); }
		radegast_auth_client(cur_client()->ip);
		cl->init_done = 1;
	}
	return;
}

static int32_t radegast_connect(void)
{
	struct s_client *cl = cur_client();

	if(cl->reader->tcp_connected < 2 && radegast_cli_init(cl) < 0)
		{ return 0; }

	if(!cl->udp_fd)
		{ return 0; }

	return 1;
}

void radegast_idle(void)
{
	struct s_client *client = cur_client();
	struct s_reader *rdr = client->reader;
	time_t now = time(NULL);
	if(!rdr) { return; }

	if(rdr->tcp_ito > 0)
	{
		int32_t time_diff;
		time_diff = abs(now - rdr->last_s);
		if(time_diff > (rdr->tcp_ito))
		{
			network_tcp_connection_close(rdr, "inactivity");
			return;
		}
	}
	else if(rdr->tcp_ito == -1)
	{
		radegast_connect();
		return;
	}
}

void module_radegast(struct s_module *ph)
{
	ph->ptab.nports = 1;
	ph->ptab.ports[0].s_port = cfg.rad_port;

	ph->desc = "radegast";
	ph->type = MOD_CONN_TCP;
	ph->large_ecm_support = 1;
	ph->listenertype = LIS_RADEGAST;
	IP_ASSIGN(ph->s_ip, cfg.rad_srvip);
	ph->s_handler = radegast_server;
	ph->s_init = radegast_server_init;
	ph->c_idle = radegast_idle;
	ph->recv = radegast_recv;
	ph->send_dcw = radegast_send_dcw;
	ph->c_init = radegast_cli_init;
	ph->c_recv_chk = radegast_recv_chk;
	ph->c_send_ecm = radegast_send_ecm;
	ph->num = R_RADEGAST;
}
#endif
