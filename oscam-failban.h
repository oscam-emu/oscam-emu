#ifndef OSCAM_FAILBAN_H_
#define OSCAM_FAILBAN_H_

extern int32_t cs_check_violation(IN_ADDR_T ip, int32_t port);
int32_t cs_add_violation_by_ip(IN_ADDR_T ip, int32_t port, char *info);
extern void cs_add_violation(struct s_client *cl, char *info);

#endif
