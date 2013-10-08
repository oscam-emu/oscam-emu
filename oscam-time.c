#include "globals.h"
#include "oscam-time.h"

int32_t comp_timeb(struct timeb *tpa, struct timeb *tpb)
{
	return ((tpa->time - tpb->time) * 1000) + (tpa->millitm - tpb->millitm);
}

/* Checks if year is a leap year. If so, 1 is returned, else 0. */
static int8_t is_leap(unsigned int y)
{
	return (y % 4) == 0 && ((y % 100) != 0 || (y % 400) == 0);
}

/* Drop-in replacement for timegm function as some plattforms strip the function from their libc.. */
time_t cs_timegm(struct tm *tm)
{
	time_t result = 0;
	int32_t i;
	if(tm->tm_mon > 12 || tm->tm_mon < 0 || tm->tm_mday > 31 || tm->tm_min > 60 || tm->tm_sec > 60 || tm->tm_hour > 24)
		{ return 0; }
	for(i = 70; i < tm->tm_year; ++i)
	{
		result += is_leap(i + 1900) ? 366 : 365;
	}
	for(i = 0; i < tm->tm_mon; ++i)
	{
		if(i == 0 || i == 2 || i == 4 || i == 6 || i == 7 || i == 9 || i == 11) { result += 31; }
		else if(i == 3 || i == 5 || i == 8 || i == 10) { result += 30; }
		else if(is_leap(tm->tm_year + 1900)) { result += 29; }
		else { result += 28; }
	}
	result += tm->tm_mday - 1;
	result *= 24;
	result += tm->tm_hour;
	result *= 60;
	result += tm->tm_min;
	result *= 60;
	result += tm->tm_sec;
	return result;
}

/* Drop-in replacement for gmtime_r as some plattforms strip the function from their libc. */
struct tm *cs_gmtime_r(const time_t *timep, struct tm *r)
{
	static const int16_t daysPerMonth[13] = { 0,
											31,
											31 + 28,
											31 + 28 + 31,
											31 + 28 + 31 + 30,
											31 + 28 + 31 + 30 + 31,
											31 + 28 + 31 + 30 + 31 + 30,
											31 + 28 + 31 + 30 + 31 + 30 + 31,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30,
											31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31
											};
	time_t i;
	time_t work = * timep % 86400;
	r->tm_sec = work % 60;
	work /= 60;
	r->tm_min = work % 60;
	r->tm_hour = work / 60;
	work = * timep / 86400;
	r->tm_wday = (4 + work) % 7;
	for(i = 1970; ; ++i)
	{
		time_t k = is_leap(i) ? 366 : 365;
		if(work >= k)
			{ work -= k; }
		else
			{ break; }
	}
	r->tm_year = i - 1900;
	r->tm_yday = work;
	r->tm_mday = 1;
	if(is_leap(i) && work > 58)
	{
		if(work == 59)
			{ r->tm_mday = 2; } /* 29.2. */
		work -= 1;
	}
	for(i = 11; i && daysPerMonth[i] > work; --i)
		{ ; }
	r->tm_mon   = i;
	r->tm_mday += work - daysPerMonth[i];
	return r;
}

/* Drop-in replacement for ctime_r as some plattforms strip the function from their libc. */
char *cs_ctime_r(const time_t *timep, char *buf)
{
	struct tm t;
	localtime_r(timep, &t);
	strftime(buf, 26, "%c\n", &t);
	return buf;
}

void cs_ftime(struct timeb *tp)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	tp->time    = tv.tv_sec;
	tp->millitm = tv.tv_usec / 1000;
}

void cs_sleepms(uint32_t msec)
{
	//does not interfere with signals like sleep and usleep do
	struct timespec req_ts;
	req_ts.tv_sec = msec / 1000;
	req_ts.tv_nsec = (msec % 1000) * 1000000L;
	int32_t olderrno = errno; // Some OS (especially MacOSX) seem to set errno to ETIMEDOUT when sleeping
	nanosleep(&req_ts, NULL);
	errno = olderrno;
}

void cs_sleepus(uint32_t usec)
{
	//does not interfere with signals like sleep and usleep do
	struct timespec req_ts;
	req_ts.tv_sec = usec / 1000000;
	req_ts.tv_nsec = (usec % 1000000) * 1000L;
	int32_t olderrno = errno;       // Some OS (especially MacOSX) seem to set errno to ETIMEDOUT when sleeping
	nanosleep(&req_ts, NULL);
	errno = olderrno;
}

void add_ms_to_timespec(struct timespec *timeout, int32_t msec)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	int32_t nano_secs = ((now.tv_usec * 1000) + ((msec % 1000) * 1000 * 1000));
	timeout->tv_sec = now.tv_sec + (msec / 1000) + (nano_secs / 1000000000);
	timeout->tv_nsec = nano_secs % 1000000000;
}

int32_t add_ms_to_timeb(struct timeb *tb, int32_t ms)
{
	struct timeb tb_now;
	tb->time += ms / 1000;
	tb->millitm += ms % 1000;
	if(tb->millitm >= 1000)
	{
		tb->millitm -= 1000;
		tb->time++;
	}
	cs_ftime(&tb_now);
	return comp_timeb(tb, &tb_now);
}

void sleepms_on_cond(pthread_cond_t *cond, pthread_mutex_t *mutex, uint32_t msec)
{
	struct timespec ts;
	add_ms_to_timespec(&ts, msec);
	pthread_mutex_lock(mutex);
	pthread_cond_timedwait(cond, mutex, &ts); // sleep on sleep_cond
	pthread_mutex_unlock(mutex);
}
