#ifndef OSCAM_NET_H_
#define OSCAM_NET_H_

#ifdef IPV6SUPPORT
#define GET_IP() *(struct in6_addr *)pthread_getspecific(getip)
#define IP_ISSET(a) !cs_in6addr_isnull(&a)
#define IP_EQUAL(a, b) cs_in6addr_equal(&a, &b)
#define IP_ASSIGN(a, b) cs_in6addr_copy(&a, &b)
#define SIN_GET_ADDR(a) ((struct sockaddr_in6 *)&a)->sin6_addr
#define SIN_GET_PORT(a) ((struct sockaddr_in6 *)&a)->sin6_port
#define SIN_GET_FAMILY(a) ((struct sockaddr_in6 *)&a)->sin6_family
extern int32_t cs_in6addr_equal(struct in6_addr *a1, struct in6_addr *a2);
extern int32_t cs_in6addr_isnull(struct in6_addr *addr);
extern int32_t cs_in6addr_lt(struct in6_addr *a, struct in6_addr *b);
extern void cs_in6addr_copy(struct in6_addr *dst, struct in6_addr *src);
extern void cs_in6addr_ipv4map(struct in6_addr *dst, in_addr_t src);
extern void cs_getIPv6fromHost(const char *hostname, struct in6_addr *addr, struct sockaddr_storage *sa, socklen_t *sa_len);
#else
#define GET_IP() *(in_addr_t *)pthread_getspecific(getip)
#define IP_ISSET(a) (a)
#define IP_EQUAL(a, b) (a == b)
#define IP_ASSIGN(a, b) (a = b)
#define SIN_GET_ADDR(a) (a.sin_addr.s_addr)
#define SIN_GET_PORT(a) (a.sin_port)
#define SIN_GET_FAMILY(a) (a.sin_family)
#endif

char *cs_inet_ntoa(IN_ADDR_T addr);
void cs_inet_addr(char *txt, IN_ADDR_T *out);
void cs_resolve(const char *hostname, IN_ADDR_T *ip, struct SOCKADDR *sock, socklen_t *sa_len);
IN_ADDR_T get_null_ip(void);
void set_null_ip(IN_ADDR_T *ip);
void set_localhost_ip(IN_ADDR_T *ip);
int32_t check_ip(struct s_ip *ip, IN_ADDR_T n);
uint32_t cs_getIPfromHost(const char *hostname);
int set_socket_priority(int fd, int priority);
void setTCPTimeouts(int32_t sock);
int8_t check_fd_for_data(int32_t fd);
int32_t recv_from_udpipe(uchar *);
int32_t process_input(uint8_t *buf, int32_t buflen, int32_t timeout);
int32_t accept_connection(struct s_module *module, int8_t module_idx, int8_t port_idx);
int32_t start_listener(struct s_module *module, struct s_port *port);

#endif
