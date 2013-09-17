#ifndef MODULE_MONITOR_H_
#define MODULE_MONITOR_H_

#ifdef MODULE_MONITOR
int32_t monitor_send_idx(struct s_client *cl, char *txt);
#else
int32_t monitor_send_idx(struct s_client *UNUSED(cl), char *UNUSED(txt)) { return 0; }
#endif

#endif
