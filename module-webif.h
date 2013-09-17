#ifndef MODULE_WEBIF_H_
#define MODULE_WEBIF_H_

#ifdef WEBIF
void webif_init(void);
void webif_close(void);
void webif_client_reset_lastresponsetime(struct s_client *cl);
void webif_client_add_lastresponsetime(struct s_client *cl, int32_t ltime, time_t timestamp, int32_t rc);
void webif_client_init_lastreader(struct s_client *cl, ECM_REQUEST *er, struct s_reader *er_reader, const char *stxt[]);
#else
static inline void webif_init(void) { }
static inline void webif_close(void) { }
static inline void webif_client_reset_lastresponsetime(struct s_client *UNUSED(cl)) { }
static inline void webif_client_add_lastresponsetime(struct s_client *UNUSED(cl), int32_t UNUSED(ltime), time_t UNUSED(timestamp), int32_t UNUSED(rc)) { }
static inline void webif_client_init_lastreader(struct s_client *UNUSED(cl), ECM_REQUEST *UNUSED(er), struct s_reader *UNUSED(er_reader), const char *UNUSED(stxt[])) { }
#endif

#endif
