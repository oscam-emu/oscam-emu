#ifndef OSCAM_LOG_H_
#define OSCAM_LOG_H_

int32_t cs_init_log(void);
void cs_reopen_log(void);
int32_t cs_open_logfiles(void);
void cs_disable_log(int8_t disabled);

void cs_reinit_loghist(uint32_t size);

void cs_log_int(uint16_t mask, int8_t lock, const uchar *buf, int32_t n, const char *fmt, ...) __attribute__((format(printf, 5, 6)));

#define cs_log(...)          cs_log_int(0, 1, NULL, 0, ##__VA_ARGS__)
#define cs_log_nolock(...)   cs_log_int(0, 0, NULL, 0, ##__VA_ARGS__)
#define cs_dump(buf, n, ...) cs_log_int(0, 1, buf,  n, ##__VA_ARGS__)

#define cs_debug_mask(mask, ...)         do { if (config_enabled(WITH_DEBUG) && ((mask) & cs_dblevel)) cs_log_int(mask, 1, NULL, 0, ##__VA_ARGS__); } while(0)
#define cs_debug_mask_nolock(mask, ...)  do { if (config_enabled(WITH_DEBUG) && ((mask) & cs_dblevel)) cs_log_int(mask, 0, NULL, 0, ##__VA_ARGS__); } while(0)
#define cs_ddump_mask(mask, buf, n, ...) do { if (config_enabled(WITH_DEBUG) && ((mask) & cs_dblevel)) cs_log_int(mask, 1, buf , n, ##__VA_ARGS__); } while(0)

void logCWtoFile(ECM_REQUEST *er, uchar *cw);

int32_t cs_init_statistics(void);
void cs_statistics(struct s_client *client);

void log_free(void);

#endif
