#ifndef OSCAM_TIME_H_
#define OSCAM_TIME_H_

int32_t comp_timeb(struct timeb *tpa, struct timeb *tpb);
time_t cs_timegm(struct tm *tm);
struct tm *cs_gmtime_r(const time_t *timep, struct tm *r);
char *cs_ctime_r(const time_t *timep, char *buf);
void cs_ftime(struct timeb *tp);
void cs_sleepms(uint32_t msec);
void cs_sleepus(uint32_t usec);
void add_ms_to_timespec(struct timespec *timeout, int32_t msec);
int32_t add_ms_to_timeb(struct timeb *tb, int32_t ms);
void sleepms_on_cond(pthread_cond_t *cond, pthread_mutex_t *mutex, uint32_t msec);

#endif
