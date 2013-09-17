#include "globals.h"
#include "oscam-lock.h"
#include "oscam-time.h"

extern char *LOG_LIST;

/**
 * creates a lock
 **/
void cs_lock_create(CS_MUTEX_LOCK *l, int16_t timeout, const char *name)
{
	memset(l, 0, sizeof(CS_MUTEX_LOCK));
	l->timeout = timeout;
	l->name = name;
	pthread_mutex_init(&l->lock, NULL);
	pthread_cond_init(&l->writecond, NULL);
	pthread_cond_init(&l->readcond, NULL);
#ifdef WITH_MUTEXDEBUG
	cs_debug_mask_nolock(D_TRACE, "lock %s created", name);
#endif
}

void cs_lock_destroy(CS_MUTEX_LOCK *l)
{
	if (!l || !l->name || l->flag) return;

	cs_rwlock_int(l, WRITELOCK);
#ifdef WITH_DEBUG
	const char *old_name = l->name;
#endif
	l->name = NULL; //No new locks!
	cs_rwunlock_int(l, WRITELOCK);
	
	//Do not destroy when having pending locks!
	int32_t n = (l->timeout/10)+2;
	while ((--n>0) && (l->writelock || l->readlock)) cs_sleepms(10);

	cs_rwlock_int(l, WRITELOCK);
	l->flag++; //No new unlocks!
	cs_rwunlock_int(l, WRITELOCK);
	
#ifdef WITH_DEBUG
	if (!n && old_name != LOG_LIST)
		cs_log_nolock("WARNING lock %s destroy timed out.", old_name);
#endif

	pthread_mutex_destroy(&l->lock);
	pthread_cond_destroy(&l->writecond);
	pthread_cond_destroy(&l->readcond);
#ifdef WITH_MUTEXDEBUG
	cs_debug_mask_nolock(D_TRACE, "lock %s destroyed", l->name);
#endif
}

void cs_rwlock_int(CS_MUTEX_LOCK *l, int8_t type) {
	struct timespec ts;
	int8_t ret = 0;

	if (!l || !l->name || l->flag)
		return;

	ts.tv_sec = time(NULL) + l->timeout;
	ts.tv_nsec = 0;

	pthread_mutex_lock(&l->lock);

	if (type == WRITELOCK) {
		l->writelock++;
		// if read- or writelock is busy, wait for unlock
		if (l->writelock > 1 || l->readlock > 0)
			ret = pthread_cond_timedwait(&l->writecond, &l->lock, &ts);
	} else {
		l->readlock++;
		// if writelock is busy, wait for unlock
		if (l->writelock > 0)
			ret = pthread_cond_timedwait(&l->readcond, &l->lock, &ts);
	}

	if (ret > 0) {
		// lock wasn't returned within time, assume locking thread to
		// be stuck or finished, so enforce lock.
		l->writelock = (type==WRITELOCK) ? 1 : 0;
		l->readlock = (type==WRITELOCK) ? 0 : 1;
#ifdef WITH_DEBUG
		if (l->name != LOG_LIST)
			cs_log_nolock("WARNING lock %s (%s) timed out.", l->name, (type==WRITELOCK)?"WRITELOCK":"READLOCK");
#endif
	}

	pthread_mutex_unlock(&l->lock);
#ifdef WITH_MUTEXDEBUG
	//cs_debug_mask_nolock(D_TRACE, "lock %s locked", l->name);
#endif
	return;
}

void cs_rwunlock_int(CS_MUTEX_LOCK *l, int8_t type) {

	if (!l || l->flag) return;

	pthread_mutex_lock(&l->lock);

	if (type == WRITELOCK)
		l->writelock--;
	else
		l->readlock--;

	if (l->writelock < 0) l->writelock = 0;
	if (l->readlock < 0) l->readlock = 0;

	// waiting writelocks always have priority. If one is waiting, signal it
	if (l->writelock)
		pthread_cond_signal(&l->writecond);
	// Otherwise signal a waiting readlock (if any)
	else if (l->readlock && type != READLOCK)
		pthread_cond_broadcast(&l->readcond);

	pthread_mutex_unlock(&l->lock);

#ifdef WITH_MUTEXDEBUG
#ifdef WITH_DEBUG
	if (l->name != LOG_LIST)  {
		const char *typetxt[] = { "", "write", "read" };
		cs_debug_mask_nolock(D_TRACE, "%slock %s: released", typetxt[type], l->name);
	}
#endif
#endif
}

int8_t cs_try_rwlock_int(CS_MUTEX_LOCK *l, int8_t type) {
	if (!l || !l->name || l->flag)
		return 0;

	int8_t status = 0;

	pthread_mutex_lock(&l->lock);

	if (type==WRITELOCK) {
		if (l->writelock || l->readlock)
			status = 1;
		else
			l->writelock++;
	}
	else {
		if (l->writelock)
			status = 1;
		else
			l->readlock++;
	}

	pthread_mutex_unlock(&l->lock);

#ifdef WITH_MUTEXDEBUG
#ifdef WITH_DEBUG
	if (l->name != LOG_LIST) {
		const char *typetxt[] = { "", "write", "read" };
		cs_debug_mask_nolock(D_TRACE, "try_%slock %s: status=%d", typetxt[type], l->name, status);
	}
#endif
#endif
	return status;
}
