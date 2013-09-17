#ifndef MODULE_CW_CYCLE_CHECK_H_
#define MODULE_CW_CYCLE_CHECK_H_

#ifdef CW_CYCLE_CHECK

struct s_cwc_md5 {
	uchar			md5[CS_ECMSTORESIZE];
	int32_t			csp_hash;
	uchar			cw[16];
};

struct s_cw_cycle_check {
	uchar			cw[16];
	time_t			time;
	time_t			locktime; // lock in learning
	uint16_t		caid;
	uint16_t		sid;
	uint16_t		chid;
	uint32_t		provid;
	int16_t			ecmlen;
	int8_t			stage;
	int32_t			cycletime;
	int32_t			dyncycletime;
	int8_t			nextcyclecw;
	int8_t			badrepeat;
	bool			cw_stageswitch;
	struct s_cwc_md5	ecm_md5[15]; // max 15 old ecm md5 /csp-hashs
	int8_t			cwc_hist_entry;
	uint8_t			old;
	struct s_cw_cycle_check *prev;
	struct s_cw_cycle_check *next;
};

void cleanupcwcycle(void);
uint8_t checkcwcycle(ECM_REQUEST *er, struct s_reader *reader, uchar *cw, int8_t rc);
uint8_t cwcycle_check_act(uint16_t caid);
#else
static inline uint8_t cwcycle_check_act(uint16_t UNUSED(caid)) { return 0; };
static inline void cleanupcwcycle(void) { };
#endif

#endif
