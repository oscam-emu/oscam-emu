#ifndef MODULE_CCCAM_H_
#define MODULE_CCCAM_H_

// In this file put functions that are called outside of module-cccam.c and module-cccshare.c

void cc_update_nodeid(void);

void cc_UA_cccam2oscam(uint8_t *in, uint8_t *out, uint16_t caid);

int32_t cc_UA_valid(uint8_t *ua);

void refresh_shares(void);
LLIST **get_and_lock_sharelist(void);
void unlock_sharelist(void);

struct cc_card **get_sorted_card_copy(LLIST *cards, int32_t reverse, int32_t *size);

void cccam_init_share(void);

#if defined(MODULE_CCCSHARE)
void cccam_done_share(void);
#else
static inline void cccam_done_share(void) { }
#endif

#if defined(MODULE_CCCAM)
bool cccam_forward_origin_card(ECM_REQUEST *er);
bool cccam_snprintf_cards_stat(struct s_client *cl, char *emmtext, size_t emmtext_sz);
bool cccam_client_extended_mode(struct s_client *cl);
#else
static inline bool cccam_forward_origin_card(ECM_REQUEST *UNUSED(er)) { return false; }
static inline bool cccam_snprintf_cards_stat(struct s_client *UNUSED(cl), char *UNUSED(emmtext), size_t UNUSED(emmtext_sz)) { return false; }
static inline bool cccam_client_extended_mode(struct s_client *UNUSED(cl)) { return false; }
#endif

#endif
