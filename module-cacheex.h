#ifndef MODULE_CACHEEX_H_
#define MODULE_CACHEEX_H_

static inline uint64_t cacheex_node_id(void *var)
{
    uint64_t *x = var;
    return *x;
}

extern uint8_t cacheex_peer_id[8];

extern int32_t cacheex_add_stats(struct s_client *cl, uint16_t caid, uint16_t srvid, uint32_t prid, uint8_t direction);
extern int8_t cacheex_maxhop(struct s_client *cl);
void cacheex_cache_push(ECM_REQUEST *er);
extern inline int8_t cacheex_match_alias(struct s_client *cl, ECM_REQUEST *er, ECM_REQUEST *ecm);
extern void cacheex_add_to_cache(struct s_client *cl, ECM_REQUEST *er);
extern void cacheex_add_to_cache_from_csp(struct s_client *cl, ECM_REQUEST *er);
#ifdef CS_CACHEEX
extern void cacheex_init(void);
extern void cacheex_clear_account_stats(struct s_auth *account);
extern void cacheex_clear_client_stats(struct s_client *client);
extern void cacheex_load_config_file(void);
extern void cacheex_update_hash(ECM_REQUEST *er);
static inline bool cacheex_reader(struct s_reader *rdr)
{
    return rdr->cacheex.mode == 1;
};
extern bool cacheex_is_match_alias(struct s_client *cl, ECM_REQUEST *er);
static inline void cacheex_set_csp_lastnode(ECM_REQUEST *er)
{
    er->csp_lastnodes = NULL;
}
static inline void cacheex_free_csp_lastnodes(ECM_REQUEST *er)
{
    LLIST *l = er->csp_lastnodes;
    er->csp_lastnodes = NULL;
    ll_destroy_data(l);
}
static inline void cacheex_set_cacheex_src(ECM_REQUEST *ecm, struct s_client *cl)
{
    if (ecm->cacheex_src == cl)
        ecm->cacheex_src = NULL;
}
static inline void cacheex_init_cacheex_src(ECM_REQUEST *ecm, ECM_REQUEST *er)
{
    if (!ecm->cacheex_src)
        ecm->cacheex_src = er->cacheex_src;
}
/**
 * Check for NULL ecmd5
 **/
static inline uint8_t checkECMD5(ECM_REQUEST *er)
{
    int8_t i;
    for (i = 0; i < CS_ECMSTORESIZE; i++)
        if (er->ecmd5[i]) return 1;
    return 0;
}
void add_hitcache(struct s_client *cl, ECM_REQUEST *er);
struct csp_ce_hit_t *check_hitcache(ECM_REQUEST *er, struct s_client *cl, uint8_t lock);
void cleanup_hitcache(void);
uint32_t get_cacheex_wait_time(ECM_REQUEST *er, struct s_client *cl);
int32_t chk_csp_ctab(ECM_REQUEST *er, CECSPVALUETAB *tab);
uint8_t check_cacheex_filter(struct s_client *cl, ECM_REQUEST *er);
#else
static inline void cacheex_init(void) { };
static inline void cacheex_clear_account_stats(struct s_auth *UNUSED(account)) { };
static inline void cacheex_clear_client_stats(struct s_client *UNUSED(client)) { };
static inline void cacheex_load_config_file(void) { };
static inline void cacheex_update_hash(ECM_REQUEST *UNUSED(er)) { };
static inline bool cacheex_reader(struct s_reader *UNUSED(rdr))
{
    return false;
};
static inline bool cacheex_is_match_alias(struct s_client *UNUSED(cl), ECM_REQUEST *UNUSED(er))
{
    return false;
}
static inline void cacheex_set_csp_lastnode(ECM_REQUEST *UNUSED(er)) { }
static inline void cacheex_free_csp_lastnodes(ECM_REQUEST *UNUSED(er)) { }
static inline void cacheex_set_cacheex_src(ECM_REQUEST *UNUSED(ecm), struct s_client *UNUSED(cl)) { }
static inline void cacheex_init_cacheex_src(ECM_REQUEST *UNUSED(ecm), ECM_REQUEST *UNUSED(er)) { }
static inline void cleanup_hitcache(void) { }
#endif

#endif
