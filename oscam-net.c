#include "globals.h"
#include "oscam-client.h"
#include "oscam-failban.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-work.h"

extern CS_MUTEX_LOCK gethostbyname_lock;
extern int32_t exit_oscam;

#ifndef IPV6SUPPORT
static int32_t inet_byteorder = 0;

static in_addr_t cs_inet_order(in_addr_t n)
{
	if(!inet_byteorder)
		{ inet_byteorder = (inet_addr("1.2.3.4") + 1 == inet_addr("1.2.3.5")) ? 1 : 2; }
	switch(inet_byteorder)
	{
	case 1:
		break;
	case 2:
		n = ((n & 0xff000000) >> 24) |
			((n & 0x00ff0000) >>  8) |
			((n & 0x0000ff00) <<  8) |
			((n & 0x000000ff) << 24);
		break;
	}
	return n;
}
#endif

char *cs_inet_ntoa(IN_ADDR_T addr)
{
#ifdef IPV6SUPPORT
	static char buff[INET6_ADDRSTRLEN];
	if(IN6_IS_ADDR_V4MAPPED(&addr) || IN6_IS_ADDR_V4COMPAT(&addr))
	{
		snprintf(buff, sizeof(buff), "%d.%d.%d.%d",
				 addr.s6_addr[12], addr.s6_addr[13], addr.s6_addr[14], addr.s6_addr[15]);
	}
	else
	{
		inet_ntop(AF_INET6, &(addr.s6_addr), buff, INET6_ADDRSTRLEN);
	}
	return buff;
#else
	struct in_addr in;
	in.s_addr = addr;
	return (char *)inet_ntoa(in);
#endif
}

void cs_inet_addr(char *txt, IN_ADDR_T *out)
{
#ifdef IPV6SUPPORT
	char buff[INET6_ADDRSTRLEN];
	//trying as IPv6 address
	if(inet_pton(AF_INET6, txt, out->s6_addr) == 0)
	{
		//now trying as mapped IPv4
		snprintf(buff, sizeof(buff), "::ffff:%s", txt);
		inet_pton(AF_INET6, buff, out->s6_addr);
	}
#else
	*out = inet_addr(txt);
#endif
}

void cs_resolve(const char *hostname, IN_ADDR_T *ip, struct SOCKADDR *sock, socklen_t *sa_len)
{
#ifdef IPV6SUPPORT
	cs_getIPv6fromHost(hostname, ip, sock, sa_len);
#else
	*ip = cs_getIPfromHost(hostname);
	if(sa_len)
		{ *sa_len = sizeof(*sock); }
#endif
}

#ifdef IPV6SUPPORT
int32_t cs_in6addr_equal(struct in6_addr *a1, struct in6_addr *a2)
{
	return memcmp(a1, a2, 16) == 0;
}

int32_t cs_in6addr_lt(struct in6_addr *a, struct in6_addr *b)
{
	int i;
	for(i = 0; i < 4; i++)
	{
		if((i == 2) && ((IN6_IS_ADDR_V4COMPAT(a) && IN6_IS_ADDR_V4MAPPED(b)) ||
						(IN6_IS_ADDR_V4COMPAT(b) && IN6_IS_ADDR_V4MAPPED(a))))
			{ continue; }   //skip comparing this part

		if(a->s6_addr32[i] != b->s6_addr32[i])
			{ return ntohl(a->s6_addr32[i]) < ntohl(b->s6_addr32[i]); }
	}

	return 0;
}

int32_t cs_in6addr_isnull(struct in6_addr *addr)
{
	int i;
	for(i = 0; i < 16; i++)
		if(addr->s6_addr[i])
			{ return 0; }
	return 1;
}

void cs_in6addr_copy(struct in6_addr *dst, struct in6_addr *src)
{
	memcpy(dst, src, 16);
}

void cs_in6addr_ipv4map(struct in6_addr *dst, in_addr_t src)
{
	memset(dst->s6_addr, 0, 16);
	dst->s6_addr[10] = 0xff;
	dst->s6_addr[11] = 0xff;
	memcpy(dst->s6_addr + 12, &src, 4);
}
#endif

IN_ADDR_T get_null_ip(void)
{
	IN_ADDR_T ip;
#ifdef IPV6SUPPORT
	cs_inet_addr("::", &ip);
#else
	ip = 0;
#endif
	return ip;
}

void set_null_ip(IN_ADDR_T *ip)
{
#ifdef IPV6SUPPORT
	cs_inet_addr("::", ip);
#else
	*ip = 0;
#endif
}

void set_localhost_ip(IN_ADDR_T *ip)
{
#ifdef IPV6SUPPORT
	cs_inet_addr("::1", ip);
#else
	cs_inet_addr("127.0.0.1", ip);
#endif
}

int32_t check_ip(struct s_ip *ip, IN_ADDR_T n)
{
	struct s_ip *p_ip;
	int32_t ok = 0;
#ifdef IPV6SUPPORT
	for(p_ip = ip; (p_ip) && (!ok); p_ip = p_ip->next)
	{
		ok  = cs_in6addr_lt(&n, &p_ip->ip[0]);
		ok |= cs_in6addr_lt(&p_ip->ip[1], &n);
		ok = !ok;
	}
#else
	for(p_ip = ip; (p_ip) && (!ok); p_ip = p_ip->next)
		{ ok = ((cs_inet_order(n) >= cs_inet_order(p_ip->ip[0])) && (cs_inet_order(n) <= cs_inet_order(p_ip->ip[1]))); }
#endif
	return ok;
}

/* Returns the ip from the given hostname. If gethostbyname is configured in the config file, a lock
   will be held until the ip has been resolved. */
uint32_t cs_getIPfromHost(const char *hostname)
{
	uint32_t result = 0;
	//Resolve with gethostbyname:
	if(cfg.resolve_gethostbyname)
	{
		cs_writelock(&gethostbyname_lock);
		struct hostent *rht = gethostbyname(hostname);
		if(!rht)
			{ cs_log("can't resolve %s", hostname); }
		else
			{ result = ((struct in_addr *)rht->h_addr)->s_addr; }
		cs_writeunlock(&gethostbyname_lock);
	}
	else     //Resolve with getaddrinfo:
	{
		struct addrinfo hints, *res = NULL;
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_INET;
		hints.ai_protocol = IPPROTO_TCP;

		int32_t err = getaddrinfo(hostname, NULL, &hints, &res);
		if(err != 0 || !res || !res->ai_addr)
		{
			cs_log("can't resolve %s, error: %s", hostname, err ? gai_strerror(err) : "unknown");
		}
		else
		{
			result = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
		}
		if(res) { freeaddrinfo(res); }
	}
	return result;
}

#ifdef IPV6SUPPORT
void cs_getIPv6fromHost(const char *hostname, struct in6_addr *addr, struct sockaddr_storage *sa, socklen_t *sa_len)
{
	uint32_t ipv4addr = 0;
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	int32_t err = getaddrinfo(hostname, NULL, &hints, &res);
	if(err != 0 || !res || !res->ai_addr)
	{
		cs_log("can't resolve %s, error: %s", hostname, err ? gai_strerror(err) : "unknown");
	}
	else
	{
		ipv4addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
		if(res->ai_family == AF_INET)
			{ cs_in6addr_ipv4map(addr, ipv4addr); }
		else
			{ IP_ASSIGN(*addr, SIN_GET_ADDR(*res->ai_addr)); }
		if(sa)
			{ memcpy(sa, res->ai_addr, res->ai_addrlen); }
		if(sa_len)
			{ *sa_len = res->ai_addrlen; }
	}
	if(res)
		{ freeaddrinfo(res); }
}
#endif

int set_socket_priority(int fd, int priority)
{
#ifdef SO_PRIORITY
	return priority ? setsockopt(fd, SOL_SOCKET, SO_PRIORITY, (void *)&priority, sizeof(int *)) : -1;
#else
	(void)fd;
	(void)priority;
	return -1;
#endif
}

void setTCPTimeouts(int32_t sock)
{
	int32_t flag = 1;
	// this is not only for a real keepalive but also to detect closed connections so it should not be configurable
	if(setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) && errno != EBADF)
	{
		cs_log("Setting SO_KEEPALIVE failed, errno=%d, %s", errno, strerror(errno));
	}
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT) && defined(TCP_KEEPINTVL)
	flag = 10;
	if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &flag, sizeof(flag)) && errno != EBADF)  //send first keepalive packet after 10 seconds of last package received (keepalive packets included)
	{
		cs_log("Setting TCP_KEEPIDLE failed, errno=%d, %s", errno, strerror(errno));
	}
	flag = 3;
	if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &flag, sizeof(flag)) && errno != EBADF)       //send up to 3 keepalive packets out (in interval TCP_KEEPINTVL), then disconnect if no response
	{
		cs_log("Setting TCP_KEEPCNT failed, errno=%d, %s", errno, strerror(errno));
	}
	flag = 1;
	if(setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &flag, sizeof(flag)) && errno != EBADF)
	{
		;       //send a keepalive packet out every second (until answer has been received or TCP_KEEPCNT has been reached)
		cs_log("Setting TCP_KEEPINTVL failed, errno=%d, %s", errno, strerror(errno));
	}
#endif
	struct timeval tv;
	tv.tv_sec = 60;
	tv.tv_usec = 0;
	if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) && errno != EBADF)
	{
		;
		cs_log("Setting SO_SNDTIMEO failed, errno=%d, %s", errno, strerror(errno));
	}
	tv.tv_sec = 600;
	tv.tv_usec = 0;
	if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) && errno != EBADF)
	{
		;
		cs_log("Setting SO_RCVTIMEO failed, errno=%d, %s", errno, strerror(errno));
	}
#if defined(TCP_USER_TIMEOUT)
	int timeout = 60000;  // RFC 5482 user timeout in milliseconds
	setsockopt(sock, SOL_TCP, TCP_USER_TIMEOUT, (char *) &timeout, sizeof(timeout));
#endif
}

int8_t check_fd_for_data(int32_t fd)
{
	int32_t rc;
	struct pollfd pfd[1];

	pfd[0].fd = fd;
	pfd[0].events = (POLLIN | POLLPRI);
	rc = poll(pfd, 1, 0);

	if(rc == -1)
		{ cs_log("check_fd_for_data(fd=%d) failed: (errno=%d %s)", fd, errno, strerror(errno)); }

	if(rc == -1 || rc == 0)
		{ return rc; }

	if(pfd[0].revents & (POLLHUP | POLLNVAL | POLLERR))
		{ return -2; }

	return 1;
}

int32_t recv_from_udpipe(uint8_t *buf)
{
	uint16_t n;
	if(buf[0] != 'U')
	{
		cs_log("INTERNAL PIPE-ERROR");
		cs_exit(1);
	}
	memcpy(&n, buf + 1, 2);
	memmove(buf, buf + 3, n);
	return n;
}

int32_t process_input(uint8_t *buf, int32_t buflen, int32_t timeout)
{
	int32_t rc, i, pfdcount, polltime;
	struct pollfd pfd[2];
	struct s_client *cl = cur_client();

	time_t starttime = time(NULL);
	while(1)
	{
		pfdcount = 0;
		if(cl->pfd)
		{
			pfd[pfdcount].fd = cl->pfd;
			pfd[pfdcount++].events = POLLIN | POLLPRI;
		}

		polltime  = timeout - (time(NULL) - starttime);
		if(polltime < 0)
		{
			polltime = 0;
		}

		int32_t p_rc = poll(pfd, pfdcount, polltime);

		if(p_rc < 0)
		{
			if(errno == EINTR)
				{ continue; }
			else
				{ return 0; }
		}

		if(p_rc == 0 && (starttime + timeout) < time(NULL))  // client maxidle reached
		{
			rc = -9;
			break;
		}

		for(i = 0; i < pfdcount && p_rc > 0; i++)
		{
			if(pfd[i].revents & POLLHUP)   // POLLHUP is only valid in revents so it doesn't need to be set above in events
			{
				return 0;
			}
			if(!(pfd[i].revents & (POLLIN | POLLPRI)))
				{ continue; }

			if(pfd[i].fd == cl->pfd)
				{ return get_module(cl)->recv(cl, buf, buflen); }
		}
	}
	return rc;
}

static struct s_client *find_client_by_ip(IN_ADDR_T ip, in_port_t port)
{
	struct s_client *cl;
	for(cl = first_client; cl; cl = cl->next)
	{
		if(!cl->kill &&
				IP_EQUAL(cl->ip, ip) && cl->port == port &&
				(cl->typ == 'c' || cl->typ == 'm'))
		{
			return cl;
		}
	}
	return NULL;
}

int32_t accept_connection(struct s_module *module, int8_t module_idx, int8_t port_idx)
{
	struct SOCKADDR cad;
	int32_t scad = sizeof(cad), n;
	struct s_client *cl;
	struct s_port *port = &module->ptab.ports[port_idx];

	if(module->type == MOD_CONN_UDP)
	{
		uchar *buf;
		if(!cs_malloc(&buf, 1024))
			{ return -1; }
		if((n = recvfrom(port->fd, buf + 3, 1024 - 3, 0, (struct sockaddr *)&cad, (socklen_t *)&scad)) > 0)
		{
			uint16_t rl;
			cl = find_client_by_ip(SIN_GET_ADDR(cad), ntohs(SIN_GET_PORT(cad)));
			rl = n;
			buf[0] = 'U';
			memcpy(buf + 1, &rl, 2);

			if(cs_check_violation(SIN_GET_ADDR(cad), port->s_port))
			{
				free(buf);
				return 0;
			}

			cs_debug_mask(D_TRACE, "got %d bytes on port %d from ip %s:%d client %s",
						  n, port->s_port,
						  cs_inet_ntoa(SIN_GET_ADDR(cad)), SIN_GET_PORT(cad),
						  username(cl));

			if(!cl)
			{
				cl = create_client(SIN_GET_ADDR(cad));
				if(!cl) { return 0; }

				cl->module_idx = module_idx;
				cl->port_idx = port_idx;
				cl->udp_fd = port->fd;
				cl->udp_sa = cad;
				cl->udp_sa_len = sizeof(cl->udp_sa);

				cl->port = ntohs(SIN_GET_PORT(cad));
				cl->typ = 'c';

				add_job(cl, ACTION_CLIENT_INIT, NULL, 0);
			}
			add_job(cl, ACTION_CLIENT_UDP, buf, n + 3);
		}
		else
			{ free(buf); }
	}
	else     //TCP
	{
		int32_t pfd3;
		if((pfd3 = accept(port->fd, (struct sockaddr *)&cad, (socklen_t *)&scad)) > 0)
		{

			if(cs_check_violation(SIN_GET_ADDR(cad), port->s_port))
			{
				close(pfd3);
				return 0;
			}

			cl = create_client(SIN_GET_ADDR(cad));
			if(cl == NULL)
			{
				close(pfd3);
				return 0;
			}

			int32_t flag = 1;
			setsockopt(pfd3, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
			setTCPTimeouts(pfd3);

			cl->module_idx = module_idx;
			cl->udp_fd = pfd3;
			cl->port_idx = port_idx;

			cl->pfd = pfd3;
			cl->port = ntohs(SIN_GET_PORT(cad));
			cl->typ = 'c';

			add_job(cl, ACTION_CLIENT_INIT, NULL, 0);
		}
	}
	return 0;
}

int32_t start_listener(struct s_module *module, struct s_port *port)
{
	int32_t ov = 1, timeout, is_udp, i;
	char ptxt[2][32];
	struct SOCKADDR sad; // structure to hold server's address
	socklen_t sad_len;

	ptxt[0][0] = ptxt[1][0] = '\0';
	if(!port->s_port)
	{
		cs_debug_mask(D_TRACE, "%s: disabled", module->desc);
		return 0;
	}
	is_udp = (module->type == MOD_CONN_UDP);

	memset(&sad, 0 , sizeof(sad));
#ifdef IPV6SUPPORT
	SIN_GET_FAMILY(sad) = AF_INET6;
	SIN_GET_ADDR(sad) = in6addr_any;
	sad_len = sizeof(struct sockaddr_in6);
#else
	sad.sin_family = AF_INET;
	sad_len = sizeof(struct sockaddr);
	if(!module->s_ip)
		{ module->s_ip = cfg.srvip; }
	if(module->s_ip)
	{
		sad.sin_addr.s_addr = module->s_ip;
		snprintf(ptxt[0], sizeof(ptxt[0]), ", ip=%s", inet_ntoa(sad.sin_addr));
	}
	else
	{
		sad.sin_addr.s_addr = INADDR_ANY;
	}
#endif
	timeout = cfg.bindwait;
	port->fd = 0;

	if(port->s_port > 0)    // test for illegal value
	{
		SIN_GET_PORT(sad) = htons((uint16_t)port->s_port);
	}
	else
	{
		cs_log("%s: Bad port %d", module->desc, port->s_port);
		return 0;
	}

	int s_domain = PF_INET;
#ifdef IPV6SUPPORT
	s_domain = PF_INET6;
#endif
	int s_type  = (is_udp ? SOCK_DGRAM : SOCK_STREAM);
	int s_proto = (is_udp ? IPPROTO_UDP : IPPROTO_TCP);

	if((port->fd = socket(s_domain, s_type, s_proto)) < 0)
	{
		cs_log("%s: Cannot create socket (errno=%d: %s)", module->desc, errno, strerror(errno));
#ifdef IPV6SUPPORT
		cs_log("%s: Trying fallback to IPv4", module->desc);
		s_domain = PF_INET;
		if((port->fd = socket(s_domain, s_type, s_proto)) < 0)
		{
			cs_log("%s: Cannot create socket (errno=%d: %s)", module->desc, errno, strerror(errno));
			return 0;
		}
#else
		return 0;
#endif
	}

#ifdef IPV6SUPPORT
	// azbox toolchain do not have this define
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 26
#endif
	// set the server socket option to listen on IPv4 and IPv6 simultaneously
	int val = 0;
	if(setsockopt(port->fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&val, sizeof(val)) < 0)
	{
		cs_log("%s: setsockopt(IPV6_V6ONLY) failed (errno=%d: %s)", module->desc, errno, strerror(errno));
	}
#endif

	ov = 1;
	if(setsockopt(port->fd, SOL_SOCKET, SO_REUSEADDR, (void *)&ov, sizeof(ov)) < 0)
	{
		cs_log("%s: setsockopt failed (errno=%d: %s)", module->desc, errno, strerror(errno));
		close(port->fd);
		port->fd = 0;
		return 0;
	}

#ifdef SO_REUSEPORT
	setsockopt(port->fd, SOL_SOCKET, SO_REUSEPORT, (void *)&ov, sizeof(ov));
#endif

	if(set_socket_priority(port->fd, cfg.netprio) > -1)
		{ snprintf(ptxt[1], sizeof(ptxt[1]), ", prio=%d", cfg.netprio); }

	if(!is_udp)
	{
		int32_t keep_alive = 1;
		setsockopt(port->fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keep_alive, sizeof(keep_alive));
	}

	while(timeout-- && !exit_oscam)
	{
		if(bind(port->fd, (struct sockaddr *)&sad, sad_len) < 0)
		{
			if(timeout)
			{
				cs_log("%s: Bind request failed (%s), waiting another %d seconds",
					   module->desc, strerror(errno), timeout);
				cs_sleepms(1000);
			}
			else
			{
				cs_log("%s: Bind request failed (%s), giving up", module->desc, strerror(errno));
				close(port->fd);
				port->fd = 0;
				return 0;
			}
		}
		else
		{
			timeout = 0;
		}
	}

	if(!is_udp)
	{
		if(listen(port->fd, CS_QLEN) < 0)
		{
			cs_log("%s: Cannot start listen mode (errno=%d: %s)", module->desc, errno, strerror(errno));
			close(port->fd);
			port->fd = 0;
			return 0;
		}
	}

	cs_log("%s: initialized (fd=%d, port=%d%s%s)",
		   module->desc, port->fd,
		   port->s_port,
		   ptxt[0], ptxt[1]);

	for(i = 0; port->ncd && i < port->ncd->ncd_ftab.nfilts; i++)
	{
		int32_t j, pos = 0;
		char buf[30 + (8 * port->ncd->ncd_ftab.filts[i].nprids)];
		pos += snprintf(buf, sizeof(buf), "-> CAID: %04X PROVID: ", port->ncd->ncd_ftab.filts[i].caid);

		for(j = 0; j < port->ncd->ncd_ftab.filts[i].nprids; j++)
			{ pos += snprintf(buf + pos, sizeof(buf) - pos, "%06X, ", port->ncd->ncd_ftab.filts[i].prids[j]); }

		if(pos > 2 && j > 0)
			{ buf[pos - 2] = '\0'; }

		cs_log("%s", buf);
	}

	return port->fd;
}
