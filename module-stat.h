#ifndef MODULE_STAT_H_
#define MODULE_STAT_H_

void save_stat_to_file(int32_t thread);
int32_t clean_stat_by_rc(struct s_reader *rdr, int8_t rc, int8_t inverse);
int32_t clean_all_stats_by_rc(int8_t rc, int8_t inverse);
int32_t clean_stat_by_id(struct s_reader *rdr, uint16_t caid, uint32_t prid, uint16_t srvid, uint16_t chid, uint16_t ecmlen);
void clear_reader_stat(struct s_reader *rdr);
void clear_all_stat(void);
READER_STAT **get_sorted_stat_copy(struct s_reader *rdr, int32_t reverse, int32_t *size);
void update_ecmlen_from_stat(struct s_reader *rdr);
int32_t lb_valid_btun(ECM_REQUEST *er, uint16_t caidto);
uint32_t lb_auto_timeout(ECM_REQUEST *er, uint32_t ctimeout);
uint16_t lb_get_betatunnel_caid_to(uint16_t caid);

#ifdef WITH_LB
void init_stat(void);
void stat_finish(void);
void load_stat_from_file(void);
void send_reader_stat(struct s_reader *rdr, ECM_REQUEST *er, struct s_ecm_answer *ea, int8_t rc);
void stat_get_best_reader(ECM_REQUEST *er);
void lb_mark_last_reader(ECM_REQUEST *er);
void check_lb_auto_betatunnel_mode(ECM_REQUEST *er);
#else
static inline void init_stat(void) { }
static inline void stat_finish(void) { }
static inline void load_stat_from_file(void) { }
static inline void send_reader_stat(struct s_reader *UNUSED(rdr), ECM_REQUEST *UNUSED(er), struct s_ecm_answer *UNUSED(ea), int8_t UNUSED(rc)) { }
static inline void stat_get_best_reader(ECM_REQUEST *UNUSED(er)) { }
static inline void lb_mark_last_reader(ECM_REQUEST *UNUSED(er)) { }
static inline void check_lb_auto_betatunnel_mode(ECM_REQUEST *UNUSED(er)) { }
#endif

#endif
