#include "globals.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-string.h"
#include "oscam-time.h"

#define HASH_BUCKETS 16

struct cs_garbage
{
    time_t time;
    void *data;
#ifdef WITH_DEBUG
    char *file;
    uint16_t line;
#endif
    struct cs_garbage *next;
};

static struct cs_garbage *garbage_first[HASH_BUCKETS];
static struct cs_garbage *garbage_last[HASH_BUCKETS];
static CS_MUTEX_LOCK garbage_lock[HASH_BUCKETS];
static pthread_t garbage_thread;
static int32_t garbage_collector_active;
static int32_t garbage_debug;

#ifdef WITH_DEBUG
void add_garbage_debug(void *data, char *file, uint16_t line)
{
#else
void add_garbage(void *data)
{
#endif
    if (!data)
        return;

    if (!garbage_collector_active || garbage_debug == 1)
    {
        cs_sleepms(1);
        free(data);
        return;
    }

    int32_t bucket = (uintptr_t)data / 16 % HASH_BUCKETS;
    struct cs_garbage *garbage;
    if (!cs_malloc(&garbage, sizeof(struct cs_garbage)))
    {
        cs_sleepms(1);
        free(data);
        return;
    }
    garbage->time = time(NULL);
    garbage->data = data;
#ifdef WITH_DEBUG
    garbage->file = file;
    garbage->line = line;
#endif
    cs_writelock(&garbage_lock[bucket]);

#ifdef WITH_DEBUG
    if (garbage_debug == 2)
    {
        struct cs_garbage *garbagecheck = garbage_first[bucket];
        while (garbagecheck)
        {
            if (garbagecheck->data == data)
            {
                cs_log("Found a try to add garbage twice. Not adding the element to garbage list...");
                cs_log("Current garbage addition: %s, line %d.", file, line);
                cs_log("Original garbage addition: %s, line %d.", garbagecheck->file, garbagecheck->line);
                cs_writeunlock(&garbage_lock[bucket]);
                free(garbage);
                return;
            }
            garbagecheck = garbagecheck->next;
        }
    }
#endif

    if (garbage_last[bucket]) garbage_last[bucket]->next = garbage;
    else garbage_first[bucket] = garbage;
    garbage_last[bucket] = garbage;
    cs_writeunlock(&garbage_lock[bucket]);
}

static pthread_cond_t sleep_cond;
static pthread_mutex_t sleep_cond_mutex;

static void garbage_collector(void)
{
    int8_t i;
    struct cs_garbage *garbage, *next, *prev, *first;
    set_thread_name(__func__);
    while (garbage_collector_active)
    {

        for (i = 0; i < HASH_BUCKETS; ++i)
        {
            cs_writelock(&garbage_lock[i]);
            first = garbage_first[i];
            time_t deltime = time((time_t)0) - (2 * cfg.ctimeout / 1000 + 1); //clienttimeout +1 second
            for (garbage = first, prev = NULL; garbage; prev = garbage, garbage = garbage->next)
            {
                if (deltime < garbage->time)    // all following elements are too new
                {
                    if (prev)
                    {
                        garbage_first[i] = garbage;
                        prev->next = NULL;
                    }
                    break;
                }
            }
            if (!garbage && garbage_first[i])       // end of list reached and everything is to be cleaned
            {
                garbage = first;
                garbage_first[i] = NULL;
                garbage_last[i] = NULL;
            }
            else if (prev) garbage = first;         // set back to beginning to cleanup all
            else garbage = NULL;        // garbage not old enough yet => nothing to clean

            while (garbage)
            {
                next = garbage->next;
                if (garbage->data) free(garbage->data);
                free(garbage);
                garbage = next;
            }
            cs_writeunlock(&garbage_lock[i]);
        }

        sleepms_on_cond(&sleep_cond, &sleep_cond_mutex, 1000);
    }
    pthread_exit(NULL);
}

void start_garbage_collector(int32_t debug)
{

    garbage_debug = debug;
    int8_t i;
    for (i = 0; i < HASH_BUCKETS; ++i)
    {
        cs_lock_create(&garbage_lock[i], 5, "garbage_lock");

        garbage_first[i] = NULL;
    }
    pthread_mutex_init(&sleep_cond_mutex, NULL);
    pthread_cond_init(&sleep_cond, NULL);

    pthread_attr_t attr;
    pthread_attr_init(&attr);

    garbage_collector_active = 1;

    pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
    int32_t ret = pthread_create(&garbage_thread, &attr, (void *)&garbage_collector, NULL);
    if (ret)
    {
        cs_log("ERROR: can't create garbagecollector thread (errno=%d %s)", ret, strerror(ret));
        pthread_attr_destroy(&attr);
        cs_exit(1);
    }
    pthread_attr_destroy(&attr);
}

void stop_garbage_collector(void)
{
    if (garbage_collector_active)
    {
        int8_t i;

        garbage_collector_active = 0;
        pthread_cond_signal(&sleep_cond);
        pthread_join(garbage_thread, NULL);
        for (i = 0; i < HASH_BUCKETS; ++i)
            cs_writelock(&garbage_lock[i]);

        for (i = 0; i < HASH_BUCKETS; ++i)
        {
            while (garbage_first[i])
            {
                struct cs_garbage *next = garbage_first[i]->next;
                free(garbage_first[i]->data);
                free(garbage_first[i]);
                garbage_first[i] = next;
            }
        }
    }
}
