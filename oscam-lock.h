#ifndef OSCAM_LOCK_H_
#define OSCAM_LOCK_H_

// Lock types
#define WRITELOCK 1
#define READLOCK 2

void cs_lock_create(CS_MUTEX_LOCK *l, int16_t timeout, const char *name);
void cs_lock_destroy(CS_MUTEX_LOCK *l);
void cs_rwlock_int(CS_MUTEX_LOCK *l, int8_t type);
void cs_rwunlock_int(CS_MUTEX_LOCK *l, int8_t type);
int8_t cs_try_rwlock_int(CS_MUTEX_LOCK *l, int8_t type);

#define cs_writelock(l)	cs_rwlock_int(l, WRITELOCK)
#define cs_readlock(l)	cs_rwlock_int(l, READLOCK)
#define cs_writeunlock(l)	cs_rwunlock_int(l, WRITELOCK)
#define cs_readunlock(l)	cs_rwunlock_int(l, READLOCK)
#define cs_try_writelock(l)	cs_try_rwlock_int(l, WRITELOCK)
#define cs_try_readlock(l)	cs_try_rwlock_int(l, READLOCK)

#endif
