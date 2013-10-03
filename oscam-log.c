#include "globals.h"
#include <syslog.h>
#include "module-monitor.h"
#include "oscam-client.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-log.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"

// Do not allow log_list to grow bigger than that many entries
#define MAX_LOG_LIST_BACKLOG 10000

extern char *syslog_ident;
extern int32_t exit_oscam;

char *LOG_LIST = "log_list";

static FILE *fp;
static FILE *fps;
static int8_t logStarted;
static LLIST *log_list;
static bool log_running;
static int log_list_queued;
static pthread_t log_thread;
static pthread_cond_t log_thread_sleep_cond;
static pthread_mutex_t log_thread_sleep_cond_mutex;

struct s_log
{
    char *txt;
    int8_t header_len;
    int8_t direct_log;
    int8_t cl_typ;
    char *cl_usr;
    char *cl_text;
};

#if defined(WEBIF) || defined(MODULE_MONITOR)
static CS_MUTEX_LOCK loghistory_lock;
char *loghist = NULL;     // ptr of log-history
char *loghistptr = NULL;
#endif

#define LOG_BUF_SIZE 512

static void switch_log(char *file, FILE **f, int32_t (*pfinit)(void))
{
    if (cfg.max_log_size && file)   //only 1 thread needs to switch the log; even if anticasc, statistics and normal log are running
        //at the same time, it is ok to have the other logs switching 1 entry later
    {
        if (*f != NULL && ftell(*f) >= cfg.max_log_size * 1024)
        {
            int32_t rc;
            char prev_log[strlen(file) + 6];
            snprintf(prev_log, sizeof(prev_log), "%s-prev", file);
            fprintf(*f, "switch log file\n");
            fflush(*f);
            fclose(*f);
            *f = (FILE *)0;
            rc = rename(file, prev_log);
            if ( rc != 0 )
            {
                fprintf(stderr, "rename(%s, %s) failed (errno=%d %s)\n", file, prev_log, errno, strerror(errno));
            }
            else if ( pfinit())
            {
                fprintf(stderr, "Initialisation of log file failed, continuing without logging thread %8lX. Log will be output to stdout!", (unsigned long)pthread_self());
                cfg.logtostdout = 1;
            }
        }
    }
}

void cs_reopen_log(void)
{
    if (cfg.logfile)
    {
        if (fp)
        {
            fprintf(fp, "flush and re-open log file\n");
            fflush(fp);
            fclose(fp);
            fp = NULL;
        }
        if (cs_open_logfiles())
        {
            fprintf(stderr, "Initialisation of log file failed, continuing without logging thread %8luX. Log will be output to stdout!", (unsigned long)pthread_self());
            cfg.logtostdout = 1;
        }
    }
    if (cfg.usrfile)
    {
        if (fps)
        {
            fprintf(fps, "flush and re-open user log file\n");
            fflush(fps);
            fclose(fps);
            fps = NULL;
        }
        if (cs_init_statistics())
        {
            fprintf(stderr, "Initialisation of user log file failed, continuing without logging thread %8luX.", (unsigned long)pthread_self());
        }
    }
}

static void cs_write_log(char *txt, int8_t do_flush)
{
    // filter out entries with leading 's' and forward to statistics
    if (txt[0] == 's')
    {
        if (fps)
        {
            switch_log(cfg.usrfile, &fps, cs_init_statistics);
            if (fps)
            {
                fputs(txt + 1, fps); // remove the leading 's' and write to file
                if (do_flush) fflush(fps);
            }
        }
    }
    else
    {
        if (!cfg.disablelog)
        {
            if (fp)
            {
                switch_log(cfg.logfile, &fp, cs_open_logfiles);     // only call the switch code if lock = 1 is specified as otherwise we are calling it internally
                if (fp)
                {
                    fputs(txt, fp);
                    if (do_flush) fflush(fp);
                }
            }
            if (cfg.logtostdout)
            {
                fputs(txt + 11, stdout);
                if (do_flush) fflush(stdout);
            }
        }
    }
}

static void log_list_flush(void)
{
    pthread_cond_signal(&log_thread_sleep_cond);
    int32_t i = 0;
    while (ll_count(log_list) > 0 && i < 200)
    {
        cs_sleepms(5);
        ++i;
    }
}

static void log_list_add(struct s_log *log)
{
    int32_t count = ll_count(log_list);
    log_list_queued++;
    if (count < MAX_LOG_LIST_BACKLOG)
    {
        ll_append(log_list, log);
    }
    else     // We have too much backlog
    {
        free(log->txt);
        free(log);
        cs_write_log("-------------> Too much data in log_list, dropping log message.\n", 1);
    }
    pthread_cond_signal(&log_thread_sleep_cond);
}

static void cs_write_log_int(char *txt)
{
    if (exit_oscam == 1)
    {
        cs_write_log(txt, 1);
    }
    else
    {
        char *newtxt = cs_strdup(txt);
        if (!newtxt)
            return;
        struct s_log *log;
        if (!cs_malloc(&log, sizeof(struct s_log)))
        {
            free(newtxt);
            return;
        }
        log->txt = newtxt;
        log->header_len = 0;
        log->direct_log = 1;
        log_list_add(log);
    }
}

int32_t cs_open_logfiles(void)
{
    char *starttext;
    if (logStarted) starttext = "log switched";
    else starttext = "started";
    if (!fp && cfg.logfile)     //log to file
    {
        if ((fp = fopen(cfg.logfile, "a+")) <= (FILE *)0)
        {
            fp = (FILE *)0;
            fprintf(stderr, "couldn't open logfile: %s (errno %d %s)\n", cfg.logfile, errno, strerror(errno));
        }
        else
        {
            setvbuf(fp, NULL, _IOFBF, 8 * 1024);
            time_t t;
            char line[80];
            memset(line, '-', sizeof(line));
            line[(sizeof(line) / sizeof(char)) - 1] = '\0';
            time(&t);
            if (!cfg.disablelog)
            {
                char buf[28];
                cs_ctime_r(&t, buf);
                fprintf(fp, "\n%s\n>> OSCam <<  cardserver %s at %s%s\n", line, starttext, buf, line);
            }
        }
    }
    // according to syslog docu: calling closelog is not necessary and calling openlog multiple times is safe
    // We use openlog to set the default syslog settings so that it's possible to allow switching syslog on and off
    openlog(syslog_ident, LOG_NDELAY | LOG_PID, LOG_DAEMON);

    cs_log_nolock(">> OSCam <<  cardserver %s, version " CS_VERSION ", build r" CS_SVN_VERSION " (" CS_TARGET ")", starttext);
    return (fp <= (FILE *)0);
}

#if defined(WEBIF) || defined(MODULE_MONITOR)
/*
 This function allows to reinit the in-memory loghistory with a new size.
*/
void cs_reinit_loghist(uint32_t size)
{
    char *tmp = NULL, *tmp2;
    if (size != cfg.loghistorysize)
    {
        if (size == 0 || cs_malloc(&tmp, size))
        {
            cs_writelock(&loghistory_lock);
            tmp2 = loghist;
            // On shrinking, the log is not copied and the order is reversed
            if (size < cfg.loghistorysize)
            {
                cfg.loghistorysize = size;
                cs_sleepms(20); // Monitor or webif may be currently outputting the loghistory but don't use locking so we sleep a bit...
                loghistptr = tmp;
                loghist = tmp;
            }
            else
            {
                if (loghist)
                {
                    memcpy(tmp, loghist, cfg.loghistorysize);
                    loghistptr = tmp + (loghistptr - loghist);
                }
                else loghistptr = tmp;
                loghist = tmp;
                cs_sleepms(20); // Monitor or webif may be currently outputting the loghistory but don't use locking so we sleep a bit...
                cfg.loghistorysize = size;
            }
            cs_writeunlock(&loghistory_lock);
            if (tmp2 != NULL) add_garbage(tmp2);
        }
    }
}
#endif

static time_t log_ts;

static int32_t get_log_header(int32_t m, char *txt)
{
    struct s_client *cl = cur_client();
    struct tm lt;
    int32_t pos;

    time(&log_ts);
    localtime_r(&log_ts, &lt);

    pos = snprintf(txt, LOG_BUF_SIZE,  "[LOG000]%4d/%02d/%02d %02d:%02d:%02d ", lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec);

    switch (m)
    {
    case 1: // Add thread id and reader type
        return pos + snprintf(txt + pos, LOG_BUF_SIZE - pos, "%8X %c ", cl ? cl->tid : 0, cl ? cl->typ : ' ');
    case 0: // Add thread id
        return pos + snprintf(txt + pos, LOG_BUF_SIZE - pos, "%8X%-3.3s ", cl ? cl->tid : 0, "");
    default: // Add empty thread id
        return pos + snprintf(txt + pos, LOG_BUF_SIZE - pos, "%8X%-3.3s ", 0, "");
    }
}

static void write_to_log(char *txt, struct s_log *log, int8_t do_flush)
{
    (void)log; // Prevent warning when WEBIF, MODULE_MONITOR and CS_ANTICASC are disabled

#ifdef CS_ANTICASC
    extern FILE *ac_log;
    if (!strncmp(txt + log->header_len, "acasc:", 6) && ac_log)
    {
        strcat(txt, "\n");
        fputs(txt + 8, ac_log);
        fflush(ac_log);
    }
    else
#endif
    {
        if (cfg.logtosyslog)
            syslog(LOG_INFO, "%s", txt + 29);
        strcat(txt, "\n");
    }
    cs_write_log(txt + 8, do_flush);

#if defined(WEBIF) || defined(MODULE_MONITOR)
    if (loghist && !exit_oscam)
    {
        char *usrtxt = log->cl_text;
        char *target_ptr = NULL;
        int32_t target_len = strlen(usrtxt) + (strlen(txt) - 8) + 1;

        cs_writelock(&loghistory_lock);
        char *lastpos = loghist + (cfg.loghistorysize) - 1;
        if (loghist + target_len + 1 >= lastpos)
        {
            strncpy(txt + 39, "Log entry too long!", strlen(txt) - 39); // we can assume that the min loghistorysize is always 1024 so we don't need to check if this new string fits into it!
            target_len = strlen(usrtxt) + (strlen(txt) - 8) + 1;
        }
        if (!loghistptr)
            loghistptr = loghist;

        if (loghistptr + target_len + 1 > lastpos)
        {
            *loghistptr = '\0';
            loghistptr = loghist + target_len + 1;
            *loghistptr = '\0';
            target_ptr = loghist;
        }
        else
        {
            target_ptr = loghistptr;
            loghistptr = loghistptr + target_len + 1;
            *loghistptr = '\0';
        }
        cs_writeunlock(&loghistory_lock);

        snprintf(target_ptr, target_len + 1, "%s\t%s", usrtxt, txt + 8);
    }
#endif

#if defined(MODULE_MONITOR)
    char sbuf[16];
    struct s_client *cl;
    for (cl = first_client; cl ; cl = cl->next)
    {
        if ((cl->typ == 'm') && (cl->monlvl > 0) && cl->log) //this variable is only initialized for cl->typ = 'm'
        {
            if (cl->monlvl < 2)
            {
                if (log->cl_typ != 'c' && log->cl_typ != 'm')
                    continue;
                if (log->cl_usr && cl->account && strcmp(log->cl_usr, cl->account->usr))
                    continue;
            }
            snprintf(sbuf, sizeof(sbuf), "%03d", cl->logcounter);
            cl->logcounter = (cl->logcounter + 1) % 1000;
            memcpy(txt + 4, sbuf, 3);
            monitor_send_idx(cl, txt);
        }
    }
#endif
}

static void write_to_log_int(char *txt, int8_t header_len)
{
#if !defined(WEBIF) && !defined(MODULE_MONITOR)
    if (cfg.disablelog) return;
#endif
    char *newtxt = cs_strdup(txt);
    if (!newtxt)
        return;
    struct s_log *log;
    if (!cs_malloc(&log, sizeof(struct s_log)))
    {
        free(newtxt);
        return;
    }
    log->txt = newtxt;
    log->header_len = header_len;
    log->direct_log = 0;
    struct s_client *cl = cur_client();
    log->cl_usr = "";
    if (!cl)
    {
        log->cl_text = "undef";
        log->cl_typ = ' ';
    }
    else
    {
        switch (cl->typ)
        {
        case 'c':
        case 'm':
            if (cl->account)
            {
                log->cl_text = cl->account->usr;
                log->cl_usr = cl->account->usr;
            }
            else log->cl_text = "";
            break;
        case 'p':
        case 'r':
            log->cl_text = cl->reader ? cl->reader->label : "";
            break;
        default:
            log->cl_text = "server";
            break;
        }
        log->cl_typ = cl->typ;
    }

    if (exit_oscam == 1 || cfg.disablelog) //Exit or log disabled. if disabled, just display on webif/monitor
    {
        char buf[LOG_BUF_SIZE];
        cs_strncpy(buf, log->txt, LOG_BUF_SIZE);
        write_to_log(buf, log, 1);
        free(log->txt);
        free(log);
    }
    else
        log_list_add(log);
}

static pthread_mutex_t log_mutex;
static char log_txt[LOG_BUF_SIZE];
static char dupl[LOG_BUF_SIZE / 4];
static char last_log_txt[LOG_BUF_SIZE];
static time_t last_log_ts;
static unsigned int last_log_duplicates;

void cs_log_int(uint16_t mask, int8_t lock __attribute__((unused)), const uchar *buf, int32_t n, const char *fmt, ...)
{
    if ((mask & cs_dblevel) || !mask )
    {
        va_list params;

        int32_t dupl_header_len, repeated_line, i, len = 0;
        pthread_mutex_lock(&log_mutex);
        if (fmt)
        {
            va_start(params, fmt);
            len = get_log_header(1, log_txt);
            vsnprintf(log_txt + len, sizeof(log_txt) - len, fmt, params);
            va_end(params);
            if (cfg.logduplicatelines)
            {
                memcpy(last_log_txt, log_txt + len, LOG_BUF_SIZE);
                write_to_log_int(log_txt, len);
            }
            else
            {
                repeated_line = strcmp(last_log_txt, log_txt + len) == 0;
                if (last_log_duplicates > 0)
                {
                    if (!last_log_ts) // Must be initialized once
                        last_log_ts = log_ts;
                    // Report duplicated lines when the new log line is different
                    // than the old or 60 seconds have passed.
                    if (!repeated_line || log_ts - last_log_ts >= 60)
                    {
                        dupl_header_len = get_log_header(2, dupl);
                        snprintf(dupl + dupl_header_len - 1, sizeof(dupl) - dupl_header_len, "--- Skipped %u duplicated log lines ---", last_log_duplicates);
                        write_to_log_int(dupl, 0);
                        last_log_duplicates = 0;
                        last_log_ts = log_ts;
                    }
                }
                if (!repeated_line)
                {
                    memcpy(last_log_txt, log_txt + len, LOG_BUF_SIZE);
                    write_to_log_int(log_txt, len);
                }
                else
                {
                    last_log_duplicates++;
                }
            }
        }
        if (buf)
        {
            for (i = 0; i < n; i += 16)
            {
                len = get_log_header(0, log_txt);
                cs_hexdump(1, buf + i, (n - i > 16) ? 16 : n - i, log_txt + len, sizeof(log_txt) - len);
                write_to_log_int(log_txt, len);
            }
        }
        pthread_mutex_unlock(&log_mutex);
    }
}

static void cs_close_log(void)
{
    log_list_flush();
    if (fp)
    {
        fclose(fp);
        fp = (FILE *)0;
    }
}

/*
 * This function writes the current CW from ECM struct to a cwl file.
 * The filename is re-calculated and file re-opened every time.
 * This will consume a bit cpu time, but nothing has to be stored between
 * each call. If not file exists, a header is prepended
 */
void logCWtoFile(ECM_REQUEST *er, uchar *cw)
{
    FILE *pfCWL;
    char srvname[128];
    /* %s / %s   _I  %04X  _  %s  .cwl  */
    char buf[256 + sizeof(srvname)];
    char date[9];
    unsigned char  i, parity, writeheader = 0;
    time_t t;
    struct tm timeinfo;

    /*
    * search service name for that id and change characters
    * causing problems in file name
    */

    get_servicename(cur_client(), er->srvid, er->caid, srvname);

    for (i = 0; srvname[i]; i++)
        if (srvname[i] == ' ') srvname[i] = '_';

    /* calc log file name */
    time(&t);
    localtime_r(&t, &timeinfo);
    strftime(date, sizeof(date), "%Y%m%d", &timeinfo);
    snprintf(buf, sizeof(buf), "%s/%s_I%04X_%s.cwl", cfg.cwlogdir, date, er->srvid, srvname);

    /* open failed, assuming file does not exist, yet */
    if ((pfCWL = fopen(buf, "r")) == NULL)
    {
        writeheader = 1;
    }
    else
    {
        /* we need to close the file if it was opened correctly */
        fclose(pfCWL);
    }

    if ((pfCWL = fopen(buf, "a+")) == NULL)
    {
        /* maybe this fails because the subdir does not exist. Is there a common function to create it?
            for the moment do not print32_t to log on every ecm
            cs_log(""error opening cw logfile for writing: %s (errno=%d %s)", buf, errno, strerror(errno)); */
        return;
    }
    if (writeheader)
    {
        /* no global macro for cardserver name :( */
        fprintf(pfCWL, "# OSCam cardserver v%s - http://www.streamboard.tv/oscam/\n", CS_VERSION);
        fprintf(pfCWL, "# control word log file for use with tsdec offline decrypter\n");
        strftime(buf, sizeof(buf), "DATE %Y-%m-%d, TIME %H:%M:%S, TZ %Z\n", &timeinfo);
        fprintf(pfCWL, "# %s", buf);
        fprintf(pfCWL, "# CAID 0x%04X, SID 0x%04X, SERVICE \"%s\"\n", er->caid, er->srvid, srvname);
    }

    parity = er->ecm[0] & 1;
    fprintf(pfCWL, "%d ", parity);
    for (i = parity * 8; i < 8 + parity * 8; i++)
        fprintf(pfCWL, "%02X ", cw[i]);
    /* better use incoming time er->tps rather than current time? */
    strftime(buf, sizeof(buf), "%H:%M:%S\n", &timeinfo);
    fprintf(pfCWL, "# %s", buf);
    fflush(pfCWL);
    fclose(pfCWL);
}

int32_t cs_init_statistics(void)
{
    if ((!fps) && (cfg.usrfile != NULL))
    {
        if ((fps = fopen(cfg.usrfile, "a+")) <= (FILE *)0)
        {
            fps = (FILE *)0;
            cs_log("couldn't open statistics file: %s", cfg.usrfile);
        }
    }
    return (fps <= (FILE *)0);
}

void cs_statistics(struct s_client *client)
{
    if (!cfg.disableuserfile)
    {
        time_t t;
        struct tm lt;
        char buf[LOG_BUF_SIZE];

        float cwps;

        time(&t);
        localtime_r(&t, &lt);
        if (client->cwfound + client->cwnot > 0)
        {
            cwps = client->last - client->login;
            cwps /= client->cwfound + client->cwnot;
        }
        else
            cwps = 0;

        char channame[32];
        get_servicename(client, client->last_srvid, client->last_caid, channame);

        int32_t lsec;
        if ((client->last_caid == 0xFFFF) && (client->last_srvid == 0xFFFF))
            lsec = client->last - client->login; //client leave calc total duration
        else
            lsec = client->last - client->lastswitch;

        int32_t secs = 0, fullmins = 0, mins = 0, fullhours = 0;

        if ((lsec > 0) && (lsec < 1000000))
        {
            secs = lsec % 60;
            if (lsec > 60)
            {
                fullmins = lsec / 60;
                mins = fullmins % 60;
                if (fullmins > 60)
                {
                    fullhours = fullmins / 60;
                }
            }
        }

        /* statistics entry start with 's' to filter it out on other end of pipe
         * so we can use the same Pipe as Log
         */
        snprintf(buf, sizeof(buf), "s%02d.%02d.%02d %02d:%02d:%02d %3.1f %s %s %d %d %d %d %d %d %d %ld %ld %02d:%02d:%02d %s %04X:%04X %s\n",
                 lt.tm_mday, lt.tm_mon + 1, lt.tm_year % 100,
                 lt.tm_hour, lt.tm_min, lt.tm_sec, cwps,
                 client->account->usr,
                 cs_inet_ntoa(client->ip),
                 client->port,
                 client->cwfound,
                 client->cwcache,
                 client->cwnot,
                 client->cwignored,
                 client->cwtout,
                 client->cwtun,
                 client->login,
                 client->last,
                 fullhours, mins, secs,
                 get_module(client)->desc,
                 client->last_caid,
                 client->last_srvid,
                 channame);

        cs_write_log_int(buf);
    }
}

void log_list_thread(void)
{
    char buf[LOG_BUF_SIZE];
    log_running = 1;
    set_thread_name(__func__);
    do
    {
        log_list_queued = 0;
        LL_ITER it = ll_iter_create(log_list);
        struct s_log *log;
        while ((log = ll_iter_next_remove(&it)))
        {
            int8_t do_flush = ll_count(log_list) == 0; //flush on writing last element

            cs_strncpy(buf, log->txt, LOG_BUF_SIZE);
            if (log->direct_log)
                cs_write_log(buf, do_flush);
            else
                write_to_log(buf, log, do_flush);
            free(log->txt);
            free(log);
        }
        if (!log_list_queued) // The list is empty, sleep until new data comes in and we are woken up
            sleepms_on_cond(&log_thread_sleep_cond, &log_thread_sleep_cond_mutex, 60 * 1000);
    }
    while (log_running);
    ll_destroy(log_list);
    log_list = NULL;
}

int32_t cs_init_log(void)
{
    if (logStarted == 0)
    {
        pthread_mutex_init(&log_mutex, NULL);

        pthread_mutex_init(&log_thread_sleep_cond_mutex, NULL);
        pthread_cond_init(&log_thread_sleep_cond, NULL);

#if defined(WEBIF) || defined(MODULE_MONITOR)
        cs_lock_create(&loghistory_lock, 5, "loghistory_lock");
#endif

        log_list = ll_create(LOG_LIST);
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
        int32_t ret = pthread_create(&log_thread, &attr, (void *)&log_list_thread, NULL);
        if (ret)
        {
            fprintf(stderr, "ERROR: Can't create logging thread (errno=%d %s)", ret, strerror(ret));
            pthread_attr_destroy(&attr);
            cs_exit(1);
        }
        pthread_attr_destroy(&attr);
    }
    int32_t rc = 0;
    if (!cfg.disablelog) rc = cs_open_logfiles();
    logStarted = 1;
    return rc;
}

void cs_disable_log(int8_t disabled)
{
    if (cfg.disablelog != disabled)
    {
        if (disabled && logStarted)
        {
            cs_log("Stopping log...");
            log_list_flush();
        }
        cfg.disablelog = disabled;
        if (disabled)
        {
            if (logStarted)
            {
                cs_sleepms(20);
                cs_close_log();
            }
        }
        else
        {
            cs_open_logfiles();
        }
    }
}

void log_free(void)
{
    cs_close_log();
    log_running = 0;
    pthread_cond_signal(&log_thread_sleep_cond);
    pthread_join(log_thread, NULL);
#if defined(WEBIF) || defined(MODULE_MONITOR)
    free(loghist);
    loghist = loghistptr = NULL;
#endif
}
