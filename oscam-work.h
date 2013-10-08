#ifndef OSCAM_WORK_H_
#define OSCAM_WORK_H_

enum actions
{
	// Reader action
	ACTION_READER_IDLE         = 1,     // wr01
	ACTION_READER_REMOTE       = 2,     // wr02
	ACTION_READER_RESET        = 4,     // wr04
	ACTION_READER_ECM_REQUEST  = 5,     // wr05
	ACTION_READER_EMM          = 6,     // wr06
	ACTION_READER_CARDINFO     = 7,     // wr07
	ACTION_READER_INIT         = 8,     // wr08
	ACTION_READER_RESTART      = 9,     // wr09
	ACTION_READER_RESET_FAST   = 10,    // wr10
	ACTION_READER_CHECK_HEALTH = 11,    // wr11
	ACTION_READER_CAPMT_NOTIFY = 12,    // wr12
	// Client actions
	ACTION_CLIENT_UDP          = 22,    // wc22
	ACTION_CLIENT_TCP          = 23,    // wc23
	ACTION_CLIENT_KILL         = 24,    // wc24
	ACTION_CLIENT_INIT         = 25,    // wc25
	ACTION_CLIENT_IDLE         = 26,    // wc26
	ACTION_CACHE_PUSH_OUT      = 27,    // wc27
	ACTION_CLIENT_SEND_MSG     = 28,    // wc28
	ACTION_CACHEEX_TIMEOUT     = 29,    // wc29
	ACTION_FALLBACK_TIMEOUT    = 30,    // wc30
	ACTION_CLIENT_TIMEOUT      = 31,    // wc31
	ACTION_ECM_ANSWER_READER   = 32,    // wc32
	ACTION_ECM_ANSWER_CACHE    = 33     // wc33
};

#define ACTION_CLIENT_FIRST 20 // This just marks where client actions start

int32_t add_job(struct s_client *cl, enum actions action, void *ptr, int32_t len);
void free_joblist(struct s_client *cl);

#endif
