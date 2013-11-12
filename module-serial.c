#include "globals.h"
#ifdef MODULE_SERIAL
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-reader.h"

#define HSIC_CRC 0xA5
#define SSSP_MAX_PID 8

#define P_HSIC      1   // Humax Sharing Interface Client
#define P_SSSP      2   // Simple Serial Sharing Protocol
#define P_BOMBA     3   // This is not really a Protocol
#define P_DSR95     4   // DSR9500 with SID
#define P_GS        5   // GS7001
#define P_ALPHA     6   // AlphaStar Receivers
#define P_DSR95_OLD 7   // DSR9500 without SID
#define P_GBOX      8   // Arion with gbox
#define P_MAX       P_GBOX
#define P_AUTO      0xFF

#define P_DSR_AUTO    0
#define P_DSR_GNUSMAS 1
#define P_DSR_OPEN    2
#define P_DSR_PIONEER 3
#define P_DSR_WITHSID 4
#define P_DSR_UNKNOWN 5

#define IS_ECM  0   // incoming data is ECM
#define IS_DCW  1   // incoming data is DCW
#define IS_PMT  2   // incoming data is PMT
#define IS_LGO  3   // incoming data is client logon
#define IS_ECHO 4   // incoming data is DCW echo from Samsung
#define IS_CAT  5   // incoming data is CAT
#define IS_BAD  0xFF    // incoming data is unknown

static const char *const proto_txt[] = {"unknown", "hsic", "sssp", "bomba", "dsr9500", "gs",
										"alpha", "dsr9500old", "gbox"
									   };
static const char *const dsrproto_txt[] = {"unknown", "samsung", "openbox", "pioneer",
		"extended", "unknown"
										  };
static const char *const incomplete = "incomplete request (%d bytes)";

typedef struct s_gbox
{
	int32_t cat_len;
	int32_t pmt_len;
	int32_t ecm_len;
} GBOX_LENS;

typedef struct s_sssp
{
	uint16_t caid;
	uint16_t pid;
	uint32_t  prid;
} SSSP_TAB;

//added to support multiple instances with thread
struct s_serial_client
{
	int32_t connected;
	struct timeb tps;
	struct timeb tpe;
	char oscam_ser_usr[32];
	char oscam_ser_device[64];
	int32_t oscam_ser_port;
	speed_t oscam_ser_baud;
	int32_t oscam_ser_delay;
	int32_t oscam_ser_timeout;
	int32_t oscam_ser_proto;
	int32_t serial_errors;
	int32_t dsr9500type;
	int32_t samsung_0a;   // number of 0A in ALL dcw sent into samsung
	int32_t samsung_dcw;  // number of dcw sent into samsung before echo or ecm is received

	GBOX_LENS gbox_lens;
	SSSP_TAB sssp_tab[SSSP_MAX_PID];
	uint16_t sssp_srvid;
	int32_t sssp_num;
	int32_t sssp_fix;
};

static pthread_mutex_t mutex;
static pthread_cond_t cond;
static int32_t bcopy_end = -1;
static struct s_module *serial_ph = NULL;

struct s_thread_param
{
	uint8_t module_idx;
	struct s_serial_client serialdata;
};

static int32_t chk_ser_srvid_match(uint16_t caid, uint16_t sid, uint32_t provid, SIDTAB *sidtab)
{
	int32_t i, rc = 0;

	if(!sidtab->num_caid)
		{ rc |= 1; }
	else
		for(i = 0; (i < sidtab->num_caid) && (!(rc & 1)); i++)
			if(caid == sidtab->caid[i]) { rc |= 1; }

	if(!sidtab->num_provid)
		{ rc |= 2; }
	else
		for(i = 0; (i < sidtab->num_provid) && (!(rc & 2)); i++)
			if(provid == sidtab->provid[i]) { rc |= 2; }

	if(!sidtab->num_srvid)
		{ rc |= 4; }
	else
		for(i = 0; (i < sidtab->num_srvid) && (!(rc & 4)); i++)
			if(sid == sidtab->srvid[i]) { rc |= 4; }

	return (rc == 7);
}

static int32_t chk_ser_srvid(struct s_client *cl, uint16_t caid, uint16_t sid, uint32_t provid)
{
	int32_t nr, rc = 0;
	SIDTAB *sidtab;

	if(!cl->sidtabs.ok)
	{
		if(!cl->sidtabs.no) { return (1); }
		rc = 1;
	}
	for(nr = 0, sidtab = cfg.sidtab; sidtab; sidtab = sidtab->next, nr++)
		if(sidtab->num_caid | sidtab->num_provid | sidtab->num_srvid)
		{
			if((cl->sidtabs.no & ((SIDTABBITS)1 << nr)) &&
					(chk_ser_srvid_match(caid, sid, provid, sidtab)))
				{ return (0); }
			if((cl->sidtabs.ok & ((SIDTABBITS)1 << nr)) &&
					(chk_ser_srvid_match(caid, sid, provid, sidtab)))
				{ rc = 1; }
		}
	return (rc);
}

static void oscam_wait_ser_fork(void)
{
	pthread_mutex_lock(&mutex);
	do
	{
		if(bcopy_end)
		{
			bcopy_end = 0;
			break;
		}
		else
			{ pthread_cond_wait(&cond, &mutex); }
	}
	while(1);
	pthread_mutex_unlock(&mutex);
}

static int32_t oscam_ser_alpha_convert(uchar *buf, int32_t l)
{
	int32_t i;
	if(buf[0] == 0x7E)    // normalize
	{
		l -= 2;
		memmove(buf, buf + 1, l); // remove BOT/EOT
		for(i = 0; i < l; i++)
			if(buf[i] == 0x20)
			{
				memmove(buf + i, buf + i + 1, --l);
				buf[i] ^= 0x20;
			}
	}
	else              // to alphastar
	{
		memmove(buf + 1, buf, l++); // insert BOT
		buf[0] = 0x7E;
		for(i = 1; i < l; i++)
			if((buf[i] == 0x20) || (buf[i] == 0x7E) || (buf[i] == 0x7F))
			{
				buf[i] ^= 0x20;
				memmove(buf + i + 1, buf + i, l++);
				buf[i++] = 0x20;
			}
		buf[l++] = 0x7F;    // insert EOT
	}
	return (l);
}

static void oscam_ser_disconnect(void);

static int32_t oscam_ser_parse_url(char *url, struct s_serial_client *serialdata, char *pcltype)
{
	char *service, *usr, *dev, *baud = NULL, *dummy, *para;
	char cltype;

	cltype = pcltype ? (*pcltype) : cur_client()->typ;

	serialdata->oscam_ser_proto = P_AUTO;
	if((dummy = strstr(url, "://")))
	{
		int32_t i;
		service = url;
		url = dummy + 3;
		*dummy = 0;
		for(i = 1; i <= P_MAX; i++)
			if(!strcmp(service, proto_txt[i]))
				{ serialdata->oscam_ser_proto = i; }
	}
	if(!(cltype == 'c') && (serialdata->oscam_ser_proto == P_AUTO)) { return (0); }
	switch(serialdata->oscam_ser_proto)   // set the defaults
	{
	case P_GS:
		serialdata->oscam_ser_timeout = 500;
		serialdata->oscam_ser_baud = B19200;
		break;
	default:
		serialdata->oscam_ser_timeout = 50;
#ifdef B115200
		serialdata->oscam_ser_baud = B115200;
#else
		serialdata->oscam_ser_baud = B9600;
#endif
	}

	switch(serialdata->oscam_ser_proto)
	{
	case P_DSR95:
		serialdata->dsr9500type = (cltype == 'c') ? P_DSR_AUTO : P_DSR_WITHSID;
		break;
	case P_DSR95_OLD:
		serialdata->dsr9500type = P_DSR_AUTO;
		serialdata->oscam_ser_proto = P_DSR95;
	}

	usr = url;
	if((dev = strchr(usr, '@')))
	{
		*dev++ = '\0';
		if((dummy = strchr(usr, ':')))    // fake pwd
			{ *dummy++ = '\0'; }
		if((cltype == 'c') && (!usr[0])) { return (0); }
	}
	else
	{
		if(cltype == 'c') { return (0); }   // user needed in server-mode
		dev = usr;
	}
	if((baud = strchr(dev, ':')))      // port = baud
		{ *baud++ = '\0'; }
	dummy = baud ? baud : dev;
	if((para = strchr(dummy, '?')))
	{
		char *ptr1, *ptr2, *saveptr1 = NULL;
		*para++ = '\0';
		for(ptr1 = strtok_r(para, "&", &saveptr1); ptr1; ptr1 = strtok_r(NULL, "&", &saveptr1))
		{
			if(!(ptr2 = strchr(ptr1, '='))) { continue; }
			*ptr2++ = '\0';
			strtolower(ptr1);
			if(!strcmp("delay"  , ptr1)) { serialdata->oscam_ser_delay  = atoi(ptr2); }
			if(!strcmp("timeout", ptr1)) { serialdata->oscam_ser_timeout = atoi(ptr2); }
		}
	}
	if(baud)
	{
		trim(baud);
#ifdef B115200
		if(!strcmp(baud, "115200"))
			{ serialdata->oscam_ser_baud = B115200; }
		else
#endif
#ifdef B57600
			if(!strcmp(baud, "57600"))
				{ serialdata->oscam_ser_baud = B57600; }
			else
#endif
				if(!strcmp(baud, "38400"))
					{ serialdata->oscam_ser_baud = B38400; }
				else if(!strcmp(baud, "19200"))
					{ serialdata->oscam_ser_baud = B19200; }
				else if(!strcmp(baud, "9600"))
					{ serialdata->oscam_ser_baud = B9600; }
	}
	if((para = strchr(dev, ',')))      // device = ip/hostname and port
	{
		*para++ = '\0';
		serialdata->oscam_ser_port = atoi(para);
	}
	else
		{ serialdata->oscam_ser_port = 0; }
	cs_strncpy(serialdata->oscam_ser_usr, usr, sizeof(serialdata->oscam_ser_usr));
	cs_strncpy(serialdata->oscam_ser_device, dev, sizeof(serialdata->oscam_ser_device));
	return (serialdata->oscam_ser_baud);
}

static void oscam_ser_set_baud(struct termios *tio, speed_t baud)
{
	cfsetospeed(tio, baud);
	cfsetispeed(tio, baud);
}

static int32_t oscam_ser_set_serial_device(int32_t fd, speed_t baud)
{
	struct termios tio;

	memset(&tio, 0, sizeof(tio));
	//  tio.c_cflag = (CS8 | CREAD | HUPCL | CLOCAL);
	tio.c_cflag = (CS8 | CREAD | CLOCAL);
	tio.c_iflag = IGNPAR;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;
	//#if !defined(__CYGWIN__)
	oscam_ser_set_baud(&tio, B1200);
	tcsetattr(fd, TCSANOW, &tio);
	cs_sleepms(500);
	//#endif
	oscam_ser_set_baud(&tio, baud);
	return (tcsetattr(fd, TCSANOW, &tio));
}

static int32_t oscam_ser_poll(int32_t event, struct s_client *client)
{
	int32_t msec;
	struct pollfd pfds;
	struct timeb tpc;
	cs_ftime(&tpc);
	msec = 1000 * (client->serialdata->tpe.time - tpc.time) + client->serialdata->tpe.millitm - tpc.millitm;
	if(msec < 0)
		{ return (0); }
	pfds.fd = cur_client()->pfd;
	pfds.events = event;
	pfds.revents = 0;
	if(poll(&pfds, 1, msec) != 1)
		{ return (0); }
	else
		{ return (((pfds.revents)&event) == event); }
}

static int32_t oscam_ser_write(struct s_client *client, const uchar *const buf, int32_t n)
{
	int32_t i;
	for(i = 0; (i < n) && (oscam_ser_poll(POLLOUT, client)); i++)
	{
		if(client->serialdata->oscam_ser_delay)
			{ cs_sleepms(client->serialdata->oscam_ser_delay); }
		if(write(client->pfd, buf + i, 1) < 1)
			{ break; }
	}
	return (i);
}

static int32_t oscam_ser_send(struct s_client *client, const uchar *const buf, int32_t l)
{
	int32_t n;
	struct s_serial_client *serialdata = client->serialdata ;
	if(!client->pfd) { return (0); }
	cs_ftime(&serialdata->tps);
	serialdata->tpe = client->serialdata->tps;
	serialdata->tpe.millitm += serialdata->oscam_ser_timeout + (l * (serialdata->oscam_ser_delay + 1));
	serialdata->tpe.time += (serialdata->tpe.millitm / 1000);
	serialdata->tpe.millitm %= 1000;
	n = oscam_ser_write(client, buf, l);
	cs_ftime(&serialdata->tpe);
	cs_ddump_mask(D_CLIENT, buf, l, "send %d of %d bytes to %s in %ld msec", n, l, remote_txt(),
				  1000 * (serialdata->tpe.time - serialdata->tps.time) + serialdata->tpe.millitm - serialdata->tps.millitm);
	if(n != l)
		{ cs_log("transmit error. send %d of %d bytes only !", n, l); }
	return (n);
}

static int32_t oscam_ser_selrec(uchar *buf, int32_t n, int32_t l, int32_t *c)
{
	int32_t i;
	if(*c + n > l)
		{ n = l - *c; }
	if(n <= 0) { return (0); }
	for(i = 0; (i < n) && (oscam_ser_poll(POLLIN, cur_client())); i++)
		if(read(cur_client()->pfd, buf + *c, 1) < 1)
			{ return (0); }
		else
			{ (*c)++; }
	return (i == n);
}

static int32_t oscam_ser_recv(struct s_client *client, uchar *xbuf, int32_t l)
{
	int32_t s, p, n, r;
	uchar job = IS_BAD;
	static uchar lb;
	static int32_t have_lb = 0;
	uchar *buf = xbuf + 1;
	struct s_serial_client *serialdata = client->serialdata;

	if(!client->pfd) { return (-1); }
	cs_ftime(&serialdata->tps);
	serialdata->tpe = serialdata->tps;
	serialdata->tpe.millitm += serialdata->oscam_ser_timeout;
	serialdata->tpe.time += (serialdata->tpe.millitm / 1000);
	serialdata->tpe.millitm %= 1000;
	buf[0] = lb;
	for(s = p = r = 0, n = have_lb; (s < 4) && (p >= 0); s++)
	{
		switch(s)
		{
		case 0:       // STAGE 0: skip known garbage from DSR9500
			if(oscam_ser_selrec(buf, 2 - n, l, &n))
			{
				if((buf[0] == 0x0A) && (buf[1] == 0x0D))
					{ p = (-4); }
				if((buf[0] == 0x0D) && (buf[1] == 0x0A))
					{ p = (-4); }
			}
			else
				{ p = (-3); }
			have_lb = 0;
			break;
		case 1:       // STAGE 1: identify protocol
			p = (-3);
			if(oscam_ser_selrec(buf, 1, l, &n))  // now we have 3 bytes in buf
			{
				if((buf[0] == 0x04) && (buf[1] == 0x00) && (buf[2] == 0x02))    //skip unsupported Advanced Serial Sharing Protocol HF 8900
				{
					oscam_ser_selrec(buf, 2, l, &n); // get rest 2 bytes to buffor
					p = (-4);
					have_lb = 0;
					break;
				}
				else
				{

					p = (-2);
					if(client->typ == 'c')       // HERE IS SERVER
					{
						job = IS_ECM;   // assume ECM
						switch(buf[0])
						{
						case 0x00:
							if((buf[1] == 0x01) && (buf[2] == 0x00))
							{
								p = P_GS;
								job = IS_LGO;
								serialdata->tpe.time++;
							}
							break;
						case 0x01:
							if((buf[1] & 0xf0) == 0xb0) { p = P_GBOX; }
							else
							{
								p = P_SSSP;
								job = IS_PMT;
							}
							break;  // pmt-request
						case 0x02:
							p = P_HSIC;
							break;
						case 0x03:
							switch(serialdata->oscam_ser_proto)
							{
							case P_SSSP  :
							case P_GS    :
							case P_DSR95 :
								p = serialdata->oscam_ser_proto;
								break;
							case P_AUTO  :
								p = (buf[1] < 0x30) ? P_SSSP : P_DSR95;
								break;    // auto for GS is useless !!
							}
							break;
						case 0x04:
							p = P_DSR95;
							job = IS_ECHO;
							serialdata->dsr9500type = P_DSR_GNUSMAS;
							break;
						case 0x7E:
							p = P_ALPHA;
							if(buf[1] != 0x80) { job = IS_BAD; }
							break;
						case 0x80:
						case 0x81:
							p = P_BOMBA;
							break;
						}
					}

					else                // HERE IS CLIENT
					{
						job = IS_DCW;   // assume DCW
						switch(serialdata->oscam_ser_proto)
						{
						case P_HSIC :
							if((buf[0] == 4) && (buf[1] == 4)) { p = P_HSIC; }
							break;
						case P_BOMBA:
							p = P_BOMBA;
							break;
						case P_DSR95:
							if(buf[0] == 4) { p = P_DSR95; }
							break;
						case P_ALPHA:
							if(buf[0] == 0x88) { p = P_ALPHA; }
							break;
						}
					}
					if((serialdata->oscam_ser_proto != p) && (serialdata->oscam_ser_proto != P_AUTO))
						{ p = (-2); }
				}
			}
			break;
		case 2:       // STAGE 2: examine length
			if(client->typ == 'c') switch(p)
				{
				case P_SSSP  :
					r = (buf[1] << 8) | buf[2];
					break;
				case P_BOMBA :
					r = buf[2];
					break;
				case P_HSIC  :
					if(oscam_ser_selrec(buf, 12, l, &n)) { r = buf[14]; }
					else { p = (-1); }
					break;
				case P_DSR95 :
					if(job == IS_ECHO)
					{
						r = 17 * serialdata->samsung_dcw - 3 + serialdata->samsung_0a;
						serialdata->samsung_dcw = serialdata->samsung_0a = 0;
					}
					else
					{
						if(oscam_ser_selrec(buf, 16, l, &n))
						{
							uchar b;
							if(cs_atob(&b, (char *)buf + 17, 1) < 0)
								{ p = (-2); }
							else
							{
								r = (b << 1);
								r += (serialdata->dsr9500type == P_DSR_WITHSID) ? 4 : 0;
							}
						}
						else { p = (-1); }
					}
					break;
				case P_GS    :
					if(job == IS_LGO)
						{ r = 5; }
					else
					{
						if(oscam_ser_selrec(buf, 1, l, &n))
							{ r = (buf[3] << 8) | buf[2]; }
						else { p = (-1); }
					}
					break;
				case P_ALPHA :
					r = -0x7F; // char specifying EOT
					break;
				case P_GBOX  :
					r = ((buf[1] & 0xf) << 8) | buf[2];
					serialdata->gbox_lens.cat_len = r;
					break;
				default      :
					serialdata->dsr9500type = P_DSR_AUTO;
				}
			else switch(p)
				{
				case P_HSIC   :
					r = (buf[2] == 0x3A) ? 20 : 0;
					break; // 3A=DCW / FC=ECM was wrong
				case P_BOMBA  :
					r = 13;
					break;
				case P_DSR95  :
					r = 14;
					break;
				case P_ALPHA  :
					r = (buf[1] << 8) | buf[2];
					break; // should be 16 always
				}
			break;
		case 3:       // STAGE 3: get the rest ...
			if(r > 0)   // read r additional bytes
			{
				int32_t all = n + r;
				if(!oscam_ser_selrec(buf, r, l, &n))
				{
					cs_debug_mask(D_CLIENT, "not all data received, waiting another 50 ms");
					serialdata->tpe.millitm += 50;
					if(!oscam_ser_selrec(buf, all - n, l, &n))
						{ p = (-1); }
				}
				// auto detect DSR9500 protocol
				if(client->typ == 'c' && p == P_DSR95 && serialdata->dsr9500type == P_DSR_AUTO)
				{
					serialdata->tpe.millitm += 20;
					if(oscam_ser_selrec(buf, 2, l, &n))
					{
						if(cs_atoi((char *)buf + n - 2, 1, 1) == 0xFFFFFFFF)
						{
							switch((buf[n - 2] << 8) | buf[n - 1])
							{
							case 0x0A0D :
								serialdata->dsr9500type = P_DSR_OPEN;
								break;
							case 0x0D0A :
								serialdata->dsr9500type = P_DSR_PIONEER;
								break;
							default     :
								serialdata->dsr9500type = P_DSR_UNKNOWN;
								break;
							}
						}
						else
						{
							if(oscam_ser_selrec(buf, 2, l, &n))
								if(cs_atoi((char *)buf + n - 2, 1, 1) == 0xFFFFFFFF)
									{ serialdata->dsr9500type = P_DSR_UNKNOWN; }
								else
									{ serialdata->dsr9500type = P_DSR_WITHSID; }
							else
							{
								serialdata->dsr9500type = P_DSR_UNKNOWN;
								p = (-1);
							}
						}
					}
					else
						{ serialdata->dsr9500type = P_DSR_GNUSMAS; }
					if(p)
						cs_log("detected dsr9500-%s type receiver",
							   dsrproto_txt[serialdata->dsr9500type]);
				}
				// gbox
				if(client->typ == 'c' && p == P_GBOX)
				{
					int32_t j;
					for(j = 0; (j < 3) && (p > 0); j++)
						switch(j)
						{
						case 0: // PMT head
							if(!oscam_ser_selrec(buf, 3, l, &n))
								{ p = (-1); }
							else if(!(buf[n - 3] == 0x02 && (buf[n - 2] & 0xf0) == 0xb0))
								{ p = (-2); }
							break;
						case 1: // PMT + ECM header
							serialdata->gbox_lens.pmt_len = ((buf[n - 2] & 0xf) << 8) | buf[n - 1];
							if(!oscam_ser_selrec(buf, serialdata->gbox_lens.pmt_len + 3, l, &n))
								{ p = (-1); }
							break;
						case 2: // ECM + ECM PID
							serialdata->gbox_lens.ecm_len = ((buf[n - 2] & 0xf) << 8) | buf[n - 1];
							if(!oscam_ser_selrec(buf, serialdata->gbox_lens.ecm_len + 4, l, &n))
								{ p = (-1); }
						}
				} // gbox
			}
			else if(r < 0)  // read until specified char (-r)
			{
				while((buf[n - 1] != (-r)) && (p > 0))
					if(!oscam_ser_selrec(buf, 1, l, &n))
						{ p = (-1); }
			}
			break;
		}
	}
	if(p == (-2) || p == (-1))
	{
		oscam_ser_selrec(buf, l - n, l, &n); // flush buffer
		serialdata->serial_errors++;
	}
	cs_ftime(&serialdata->tpe);
	cs_ddump_mask(D_CLIENT, buf, n, "received %d bytes from %s in %ld msec", n, remote_txt(),
				  1000 * (serialdata->tpe.time - serialdata->tps.time) + serialdata->tpe.millitm - serialdata->tps.millitm);
	client->last = serialdata->tpe.time;
	switch(p)
	{
	case(-1):
		if(client->typ == 'c' && (n > 2) && (buf[0] == 2) && (buf[1] == 2) && (buf[2] == 2))
		{
			oscam_ser_disconnect();
			cs_log("humax powered on");    // this is nice ;)
		}
		else
		{
			if(client->typ == 'c' && buf[0] == 0x1 && buf[1] == 0x08 && buf[2] == 0x20 && buf[3] == 0x08)
			{
				oscam_ser_disconnect();
				cs_log("ferguson powered on");  // this is nice to ;)
			}
			else
				{ cs_log(incomplete, n); }
		}
		break;
	case(-2):
		cs_debug_mask(D_CLIENT, "unknown request or garbage");
		break;
	}
	xbuf[0] = (uchar)((job << 4) | p);
	return ((p < 0) ? 0 : n + 1);
}

/*
 *  server functions
 */

static void oscam_ser_disconnect_client(void)
{
	uchar mbuf[1024];
	struct s_serial_client *serialdata = cur_client()->serialdata;
	switch(serialdata->connected ? serialdata->connected : serialdata->oscam_ser_proto)
	{
	case P_GS:
		mbuf[0] = 0x01;
		mbuf[1] = 0x00;
		mbuf[2] = 0x00;
		mbuf[3] = 0x00;
		oscam_ser_send(cur_client(), mbuf, 4);
		break;
	}
	serialdata->dsr9500type = P_DSR_AUTO;
	serialdata->serial_errors = 0;
}

static void oscam_ser_init_client(void)
{
	uchar mbuf[4];
	switch(cur_client()->serialdata->oscam_ser_proto)     // sure, does not work in auto-mode
	{
	case P_GS:
		oscam_ser_disconnect_client(); // send disconnect first
		cs_sleepms(300);              // wait a little bit
		mbuf[0] = 0x00;
		mbuf[1] = 0x00;
		mbuf[2] = 0x00;
		mbuf[3] = 0x00;
		oscam_ser_send(cur_client(), mbuf, 4);    // send connect
		break;
	}
}

static void oscam_ser_disconnect(void)
{
	oscam_ser_disconnect_client();
	if(cur_client()->serialdata->connected)
		{ cs_log("%s disconnected (%s)", username(cur_client()), proto_txt[cur_client()->serialdata->connected]); }
	cur_client()->serialdata->connected = 0;
}

static void oscam_ser_auth_client(int32_t proto)
{
	int32_t ok = 0;
	struct s_serial_client *serialdata = cur_client()->serialdata;
	// After reload base account ptrs may be placed in other address,
	// and we may can't find it in this process.
	// Simply save valid account.
	struct s_auth *account = 0;

	if(serialdata->connected == proto)
		{ return; }
	if(serialdata->connected)
		{ oscam_ser_disconnect(); }
	serialdata->connected = proto;

	for(ok = 0, account = cfg.account; (account) && (!ok); account = account->next)
		if((ok = !strcmp(serialdata->oscam_ser_usr, account->usr)))
			{ break; }
	cs_auth_client(cur_client(), ok ? account : (struct s_auth *)(-1), proto_txt[serialdata->connected]);
}

static void oscam_ser_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
	uchar mbuf[23];
	int32_t i;
	uchar crc;
	struct s_serial_client *serialdata = cur_client()->serialdata;
	if(er->rc < E_NOTFOUND)       // found
		switch(serialdata->connected)
		{
		case P_HSIC:
			for(i = 0, crc = HSIC_CRC; i < 16; i++)
				{ crc ^= er->cw[i]; }
			memset(mbuf   , 0x04  ,  2);
			memset(mbuf + 2 , 0x3a  ,  2);
			memcpy(mbuf + 4 , er->cw, 16);
			memcpy(mbuf + 20, &crc  ,  1);
			memset(mbuf + 21, 0x1b  ,  2);
			oscam_ser_send(client, mbuf, 23);
			break;
		case P_SSSP:
			mbuf[0] = 0xF2;
			mbuf[1] = 0;
			mbuf[2] = 16;
			memcpy(mbuf + 3, er->cw, 16);
			oscam_ser_send(client, mbuf, 19);
			if(!serialdata->sssp_fix)
			{
				mbuf[0] = 0xF1;
				mbuf[1] = 0;
				mbuf[2] = 2;
				i2b_buf(2, er->pid, mbuf + 3);
				oscam_ser_send(client, mbuf, 5);
				serialdata->sssp_fix = 1;
			}
			break;
		case P_GBOX:
		case P_BOMBA:
			oscam_ser_send(client, er->cw, 16);
			break;
		case P_DSR95:
			mbuf[0] = 4;
			memcpy(mbuf + 1, er->cw, 16);
			oscam_ser_send(client, mbuf, 17);
			if(serialdata->dsr9500type == P_DSR_GNUSMAS)
			{
				serialdata->samsung_0a = 0;
				for(i = 1; i < 17; i++)
					if(mbuf[i] == 0x0A)
						{ serialdata->samsung_0a++; }
				serialdata->samsung_dcw++;
			}
			break;
		case P_GS:
			mbuf[0] = 0x03;
			mbuf[1] = 0x08;
			mbuf[2] = 0x10;
			mbuf[3] = 0x00;
			memcpy(mbuf + 4, er->cw, 16);
			oscam_ser_send(client, mbuf, 20);
			break;
		case P_ALPHA:
			mbuf[0] = 0x88;
			mbuf[1] = 0x00;
			mbuf[2] = 0x10;
			memcpy(mbuf + 3, er->cw, 16);
			oscam_ser_send(client, mbuf, 19);
			break;
		}
	else          // not found
		switch(serialdata->connected)
		{
		case P_GS:
			mbuf[0] = 0x03;
			mbuf[1] = 0x09;
			mbuf[2] = 0x00;
			mbuf[3] = 0x00;
			oscam_ser_send(client, mbuf, 4);
			break;
		}
	serialdata->serial_errors = 0; // clear error counter
}

static void oscam_ser_process_pmt(uchar *buf, int32_t l)
{
	int32_t i;
	uchar sbuf[32];
	struct s_serial_client *serialdata = cur_client()->serialdata;
	switch(serialdata->connected)
	{
	case P_SSSP:
		serialdata->sssp_fix = 0;
		memset(serialdata->sssp_tab, 0, sizeof(serialdata->sssp_tab));
		serialdata->sssp_srvid = b2i(2, buf + 3);
		serialdata->sssp_num = 0;


		for(i = 9; (i < l) && (serialdata->sssp_num < SSSP_MAX_PID); i += 7)
		{
			if(chk_ser_srvid(cur_client(), b2i(2, buf + i), b2i(2, buf + 3), b2i(3, buf + i + 4)))  // check support for pid (caid, sid and provid in oscam.services)
			{
				memcpy(sbuf + 3 + (serialdata->sssp_num << 1), buf + i + 2, 2);
				serialdata->sssp_tab[serialdata->sssp_num].caid = b2i(2, buf + i);
				serialdata->sssp_tab[serialdata->sssp_num].pid = b2i(2, buf + i + 2);
				serialdata->sssp_tab[serialdata->sssp_num].prid = b2i(3, buf + i + 4);
				serialdata->sssp_num++;
			}
		}
		sbuf[0] = 0xF1;
		sbuf[1] = 0;
		sbuf[2] = (serialdata->sssp_num << 1);
		oscam_ser_send(cur_client(), sbuf, sbuf[2] + 3);
		break;
	}
}

static void oscam_ser_client_logon(uchar *buf, int32_t l)
{
	uchar gs_logon[] = {0, 1, 0, 0, 2, 1, 0, 0};
	switch(cur_client()->serialdata->connected)
	{
	case P_GS:
		if((l >= 8) && (!memcmp(buf, gs_logon, 8)))
		{
			buf[0] = 0x02;
			buf[1] = 0x04;
			buf[2] = 0x00;
			buf[3] = 0x00;
			oscam_ser_send(cur_client(), buf, 4);
		}
		break;
	}
}

static int32_t oscam_ser_check_ecm(ECM_REQUEST *er, uchar *buf, int32_t l)
{
	int32_t i;
	struct s_serial_client *serialdata = cur_client()->serialdata;

	if(l < 16)
	{
		cs_log(incomplete, l);
		return (1);
	}

	switch(serialdata->connected)
	{
	case P_HSIC:
		er->ecmlen = l - 12;
		er->caid = b2i(2, buf + 1);
		er->prid = b2i(3, buf + 3);
		er->pid  = b2i(2, buf + 6);
		er->srvid = b2i(2, buf + 10);
		memcpy(er->ecm, buf + 12, er->ecmlen);
		break;
	case P_SSSP:
		er->pid = b2i(2, buf + 3);
		for(i = 0; (i < 8) && (serialdata->sssp_tab[i].pid != er->pid); i++) { ; }
		if(i >= serialdata->sssp_num)
		{
			cs_debug_mask(D_CLIENT, "illegal request, unknown pid=%04X", er->pid);
			return (2);
		}
		er->ecmlen = l - 5;
		er->srvid = serialdata->sssp_srvid;
		er->caid = serialdata->sssp_tab[i].caid;
		er->prid = serialdata->sssp_tab[i].prid;
		memcpy(er->ecm, buf + 5, er->ecmlen);
		break;
	case P_BOMBA:
		er->ecmlen = l;
		memcpy(er->ecm, buf, er->ecmlen);
		break;
	case P_DSR95:
		buf[l] = '\0'; // prepare for trim
		trim((char *)buf + 13); // strip spc, nl, cr ...
		er->ecmlen = strlen((char *)buf + 13) >> 1;
		er->prid = cs_atoi((char *)buf + 3, 3, 0); // ignore errors
		er->caid = cs_atoi((char *)buf + 9, 2, 0); // ignore errors
		if(cs_atob(er->ecm, (char *)buf + 13, er->ecmlen) < 0)
		{
			cs_log("illegal characters in ecm-request");
			return (1);
		}
		if(serialdata->dsr9500type == P_DSR_WITHSID)
		{
			er->ecmlen -= 2;
			er->srvid = cs_atoi((char *)buf + 13 + (er->ecmlen << 1), 2, 0);
		}
		break;
	case P_GS:
		er->ecmlen = ((buf[3] << 8) | buf[2]) - 6;
		er->srvid = (buf[5] << 8) | buf[4];  // sid
		er->caid  = (buf[7] << 8) | buf[6];
		er->prid  = 0;
		if(er->ecmlen > 256) { er->ecmlen = 256; }
		memcpy(er->ecm, buf + 10, er->ecmlen);
		break;
	case P_ALPHA:
		l = oscam_ser_alpha_convert(buf, l);
		er->ecmlen = b2i(2, buf + 1) - 2;
		er->caid  = b2i(2, buf + 3);
		if((er->ecmlen != l - 5) || (er->ecmlen > 257))
		{
			cs_log(incomplete, l);
			return (1);
		}
		memcpy(er->ecm, buf + 5, er->ecmlen);
		break;
	case P_GBOX:
		er->srvid = b2i(2, buf + serialdata->gbox_lens.cat_len + 3 + 3);
		er->ecmlen = serialdata->gbox_lens.ecm_len + 3;
		memcpy(er->ecm, buf + serialdata->gbox_lens.cat_len + 3 + serialdata->gbox_lens.pmt_len + 3, er->ecmlen);
		break;
	}
	return (0);
}

static void oscam_ser_process_ecm(uchar *buf, int32_t l)
{
	ECM_REQUEST *er;

	if(!(er = get_ecmtask()))
		{ return; }

	switch(oscam_ser_check_ecm(er, buf, l))
	{
	case 2:
		er->rc = E_CORRUPT;
		return; // error without log
	case 1:
		er->rc = E_CORRUPT;           // error with log
	}
	get_cw(cur_client(), er);
}


static void oscam_ser_server(void)
{
	int32_t n;
	uchar mbuf[1024];

	int32_t *pserial_errors = &cur_client()->serialdata->serial_errors;

	cur_client()->serialdata->connected = 0;
	oscam_ser_init_client();

	while((n = process_input(mbuf, sizeof(mbuf), INT_MAX)) > 0)
	{
		if((*pserial_errors) > 3)
		{
			cs_log("too many errors, reiniting...");
			break;
		}
		oscam_ser_auth_client(mbuf[0] & 0xF);
		switch(mbuf[0] >> 4)
		{
		case IS_ECM:
			oscam_ser_process_ecm(mbuf + 1, n - 1);
			break;
		case IS_PMT:
			oscam_ser_process_pmt(mbuf + 1, n - 1);
			break;
		case IS_LGO:
			oscam_ser_client_logon(mbuf + 1, n - 1);
			break;
		}
	}
	if(cur_client()->serialdata->oscam_ser_port > 0)
		{ network_tcp_connection_close(cur_client()->reader, "error reading from socket"); }
	oscam_ser_disconnect();
}

static int32_t init_oscam_ser_device(struct s_client *cl)
{
	char *device = cl->serialdata->oscam_ser_device;
	speed_t baud = cl->serialdata->oscam_ser_baud;
	int32_t port = cl->serialdata->oscam_ser_port;
	int32_t fd;

	// network connection to a TCP-exposed serial port
	if(port > 0)
	{
		cs_strncpy(cl->reader->device, device, sizeof(cl->reader->device));
		cl->reader->r_port = cl->port = port;
		fd = network_tcp_connection_open(cl->reader);
		if(fd < 0)
			{ return 0; }
		else
			{ return fd; }
	}
	else  // standard serial port connection
	{
		fd = open(device, O_RDWR | O_NOCTTY | O_SYNC | O_NONBLOCK);
		if(fd > 0)
		{
			fcntl(fd, F_SETFL, 0);
			if(oscam_ser_set_serial_device(fd, baud) < 0) { cs_log("ERROR ioctl"); }
			if(tcflush(fd, TCIOFLUSH) < 0) { cs_log("ERROR flush"); }
		}
		else
		{
			fd = 0;
			cs_log("ERROR opening %s (errno=%d %s)", device, errno, strerror(errno));
		}
		return (fd);
	}
}

static void oscam_copy_serialdata(struct s_serial_client *dest, struct s_serial_client *src)
{
	if(dest &&  src)
	{
		dest->connected = src->connected;
		memcpy(&dest->tps, &src->tps, sizeof(dest->tps));
		memcpy(&dest->tpe, &src->tpe, sizeof(dest->tpe));
		memcpy(&dest->oscam_ser_usr, &src->oscam_ser_usr, sizeof(dest->oscam_ser_usr));
		memcpy(&dest->oscam_ser_device, &src->oscam_ser_device, sizeof(dest->oscam_ser_device));
		dest->oscam_ser_port = src->oscam_ser_port;
		dest->oscam_ser_baud = src->oscam_ser_baud;
		dest->oscam_ser_delay = src->oscam_ser_delay;
		dest->oscam_ser_timeout = src->oscam_ser_timeout;
		dest->oscam_ser_proto = src->oscam_ser_proto;
		dest->serial_errors = src->serial_errors;
		dest->dsr9500type = src->dsr9500type;
		dest->samsung_0a = src->samsung_0a;   // number of 0A in ALL dcw sent into samsung
		dest->samsung_dcw = src->samsung_dcw;  // number of dcw sent into samsung before echo or ecm is received

		dest->gbox_lens = src->gbox_lens;
		memcpy(&dest->sssp_tab, &src->sssp_tab, sizeof(dest->sssp_tab));
		dest->sssp_srvid = src->sssp_srvid;
		dest->sssp_num = src->sssp_num;
		dest->sssp_fix = src->sssp_fix;
	}
}

static void oscam_init_serialdata(struct s_serial_client *dest)
{
	if(dest)
	{
		memset(dest, 0, sizeof(struct s_serial_client));
		dest->oscam_ser_timeout = 50;
		dest->dsr9500type = P_DSR_AUTO;
	}
}

static void *oscam_ser_fork(void *pthreadparam)
{
	struct s_thread_param *pparam = (struct s_thread_param *) pthreadparam;
	struct s_client *cl = create_client(get_null_ip());
	pthread_setspecific(getclient, cl);
	cl->thread = pthread_self();
	cl->typ = 'c';
	cl->module_idx = pparam->module_idx;
	cl->account = first_client->account;

	if(!cl->serialdata && !cs_malloc(&cl->serialdata, sizeof(struct s_serial_client)))
		{ return NULL; }

	set_thread_name(__func__);
	oscam_init_serialdata(cl->serialdata);
	oscam_copy_serialdata(cl->serialdata, &pparam->serialdata);
	if(cl->serialdata->oscam_ser_port > 0)
	{
		// reader struct for serial network connection
		struct s_reader *newrdr;
		if(!cs_malloc(&newrdr, sizeof(struct s_reader)))
			{ return NULL; }
		memset(newrdr, 0, sizeof(struct s_reader));
		newrdr->client = cl;
		newrdr->ph = *serial_ph;
		cl->reader = newrdr;
		cs_strncpy(cl->reader->label, "network-socket", sizeof(cl->reader->label));
	}
	cs_log("serial: initialized (%s@%s)", cl->serialdata->oscam_ser_proto > P_MAX ?
		   "auto" : proto_txt[cl->serialdata->oscam_ser_proto], cl->serialdata->oscam_ser_device);

	pthread_mutex_lock(&mutex);
	bcopy_end = 1;
	pthread_mutex_unlock(&mutex);
	pthread_cond_signal(&cond);

	while(1)
	{
		cl->login = time((time_t *)0);
		cl->pfd = init_oscam_ser_device(cl);
		if(cl->pfd)
			{ oscam_ser_server(); }
		else
			{ cs_sleepms(60000); }    // retry in 1 min. (USB-Device ?)
		if(cl->pfd) { close(cl->pfd); }
	}
	NULLFREE(cl->serialdata);
	NULLFREE(cl->reader);
	return NULL;
}

void *init_oscam_ser(struct s_client *UNUSED(cl), uchar *UNUSED(mbuf), int32_t module_idx)
{
	char sdevice[512];
	int32_t ret;
	struct s_thread_param param;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	oscam_init_serialdata(&param.serialdata);
	if(cfg.ser_device)
		{ cs_strncpy(sdevice, cfg.ser_device, sizeof(sdevice)); }
	else
		{ memset(sdevice, 0, sizeof(sdevice)); }
	param.module_idx = module_idx;
	char *p;
	pthread_t temp;
	char cltype = 'c'; //now auto should work
	if(bcopy_end == -1)  //mutex should be initialized only once
	{
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&cond, NULL);
		bcopy_end = 0;
	}
	while((p = strrchr(sdevice, ';')))
	{
		*p = 0;
		if(!(p + 1) || (!(p + 1)[0])) { return NULL; }
		if(!oscam_ser_parse_url(p + 1, &param.serialdata, &cltype)) { return NULL; }
		ret = pthread_create(&temp, &attr, oscam_ser_fork, (void *) &param);
		if(ret)
		{
			cs_log("ERROR: can't create serial reader thread (errno=%d %s)", ret, strerror(ret));
			pthread_attr_destroy(&attr);
			return NULL;
		}
		else
		{
			oscam_wait_ser_fork();
			pthread_detach(temp);
		}
	}

	if(!sdevice[0]) { return NULL; }
	if(!oscam_ser_parse_url(sdevice, &param.serialdata, &cltype)) { return NULL; }
	ret = pthread_create(&temp, &attr, oscam_ser_fork, (void *) &param);
	if(ret)
	{
		cs_log("ERROR: can't create serial reader thread (errno=%d %s)", ret, strerror(ret));
		pthread_attr_destroy(&attr);
		return NULL;
	}
	else
	{
		oscam_wait_ser_fork();
		pthread_detach(temp);
	}
	pthread_attr_destroy(&attr);
	return NULL;
}

/*
 *  client functions
 */

static int32_t oscam_ser_client_init(struct s_client *client)
{
	if(!client->serialdata && !cs_malloc(&client->serialdata, sizeof(struct s_serial_client)))
		{ return 1; }

	oscam_init_serialdata(client->serialdata);

	if((!client->reader->device[0])) { cs_disconnect_client(client); }
	if(!oscam_ser_parse_url(client->reader->device, client->serialdata, NULL)) { cs_disconnect_client(client); }
	client->pfd = init_oscam_ser_device(client);
	return ((client->pfd > 0) ? 0 : 1);
}

static int32_t oscam_ser_send_ecm(struct s_client *client, ECM_REQUEST *er, uchar *buf)
{
	char *tmp;
	switch(client->serialdata->oscam_ser_proto)
	{
	case P_HSIC:
		memset(buf, 0, 12);
		buf[0] = 2;
		i2b_buf(2, er->caid, buf + 1);
		i2b_buf(3, er->prid, buf + 3);
		i2b_buf(2, er->pid, buf + 6);
		i2b_buf(2, er->srvid, buf + 10);
		memcpy(buf + 12, er->ecm, er->ecmlen);
		oscam_ser_send(client, buf, 12 + er->ecmlen);
		break;
	case P_BOMBA:
		oscam_ser_send(client, er->ecm, er->ecmlen);
		break;
	case P_DSR95:
		if(cs_malloc(&tmp, er->ecmlen * 2 + 1))
		{
			if(client->serialdata->dsr9500type == P_DSR_WITHSID)
			{
				snprintf((char *)buf, 512, "%c%08X%04X%s%04X\n\r",
						 3, er->prid, er->caid, cs_hexdump(0, er->ecm, er->ecmlen, tmp, er->ecmlen * 2 + 1), er->srvid);
				oscam_ser_send(client, buf, (er->ecmlen << 1) + 19); // 1 + 8 + 4 + l*2 + 4 + 2
			}
			else
			{
				snprintf((char *)buf, 512, "%c%08X%04X%s\n\r",
						 3, er->prid, er->caid, cs_hexdump(0, er->ecm, er->ecmlen, tmp, er->ecmlen * 2 + 1));
				oscam_ser_send(client, buf, (er->ecmlen << 1) + 15); // 1 + 8 + 4 + l*2 + 2
			}
			free(tmp);
		}
		break;
	case P_ALPHA:
		buf[0] = 0x80;
		i2b_buf(2, 2 + er->ecmlen, buf + 1);
		i2b_buf(2, er->caid, buf + 3);
		memcpy(buf + 5, er->ecm, er->ecmlen);
		oscam_ser_send(client, buf, oscam_ser_alpha_convert(buf, 5 + er->ecmlen));
		break;
	}
	return (0);
}

static void oscam_ser_process_dcw(uchar *dcw, int32_t *rc, uchar *buf, int32_t l, struct s_client *client)
{
	switch(client->serialdata->oscam_ser_proto)
	{
	case P_HSIC:
		if((l >= 23) && (buf[2] == 0x3A) && (buf[3] == 0x3A))
		{
			int32_t i;
			uchar crc;
			for(i = 4, crc = HSIC_CRC; i < 20; i++)
				{ crc ^= buf[i]; }
			if(crc == buf[20])
			{
				memcpy(dcw, buf + 4, 16);
				*rc = 1;
			}
		}
		break;
	case P_BOMBA:
		if(l >= 16)
		{
			memcpy(dcw, buf, 16);
			*rc = 1;
		}
		break;
	case P_DSR95:
		if((l >= 17) && (buf[0] == 4))
		{
			memcpy(dcw, buf + 1, 16);
			*rc = 1;
		}
		break;
	case P_ALPHA:
		if((l >= 19) && (buf[0] == 0x88))
		{
			memcpy(dcw, buf + 3, 16);
			*rc = 1;
		}
		break;
	}
}

static int32_t oscam_ser_recv_chk(struct s_client *client, uchar *dcw, int32_t *rc, uchar *buf, int32_t n)
{
	*rc = (-1);
	switch(buf[0] >> 4)
	{
	case IS_DCW:
		oscam_ser_process_dcw(dcw, rc, buf + 1, n - 1, client);
		break;
	}
	return ((*rc < 0) ? (-1) : 0); // idx not supported in serial module
}

/*
 *  protocol structure
 */

void module_serial(struct s_module *ph)
{
	ph->desc = "serial";
	ph->type = MOD_CONN_SERIAL;
	ph->large_ecm_support = 1;
	ph->listenertype = LIS_SERIAL;
	ph->s_handler = init_oscam_ser;
	ph->recv = oscam_ser_recv;
	ph->send_dcw = oscam_ser_send_dcw;
	ph->c_init = oscam_ser_client_init;
	ph->c_recv_chk = oscam_ser_recv_chk;
	ph->c_send_ecm = oscam_ser_send_ecm;
	ph->num = R_SERIAL;
	serial_ph = ph;
}
#endif
