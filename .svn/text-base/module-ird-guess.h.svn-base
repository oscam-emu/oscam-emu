#ifndef MODULE_IRD_GUESS_H
#define MODULE_IRD_GUESS_H

#ifdef IRDETO_GUESSING
int32_t init_irdeto_guess_tab(void);
void guess_irdeto(ECM_REQUEST *er);
void free_irdeto_guess_tab(void);
#else
static inline int32_t init_irdeto_guess_tab(void) { return 0; }
static inline void guess_irdeto(ECM_REQUEST *UNUSED(er)) { }
static inline void free_irdeto_guess_tab(void) { }
#endif

#endif
