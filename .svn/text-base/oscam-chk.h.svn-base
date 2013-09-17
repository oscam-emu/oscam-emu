#ifndef OSCAM_CHK_H_
#define OSCAM_CHK_H_

// betatunnel check (chk_on_btun)
#define SRVID_ZERO	0 // srvid + 0000 (used for service-filter bypass)
#define SRVID_MASK	1 // srvid + FFFF

uint32_t get_fallbacktimeout(uint16_t caid);
int32_t ecm_ratelimit_check(struct s_reader * reader, ECM_REQUEST *er, int32_t reader_mode);
int32_t matching_reader(ECM_REQUEST *er, struct s_reader *rdr);

uint8_t chk_is_fixed_fallback(struct s_reader *rdr, ECM_REQUEST *er);
uint8_t chk_has_fixed_fallback(ECM_REQUEST *er);
int32_t chk_srvid_match(ECM_REQUEST *er, SIDTAB *sidtab);
int32_t chk_srvid(struct s_client *cl, ECM_REQUEST *er);
int32_t has_srvid(struct s_client *cl, ECM_REQUEST *er);
int32_t has_lb_srvid(struct s_client *cl, ECM_REQUEST *er);
int32_t chk_srvid_match_by_caid_prov(uint16_t caid, uint32_t provid, SIDTAB *sidtab);
int32_t chk_srvid_by_caid_prov(struct s_client *cl, uint16_t caid, uint32_t provid);
int32_t chk_srvid_by_caid_prov_rdr(struct s_reader *rdr, uint16_t caid, uint32_t provid);
int32_t chk_is_betatunnel_caid(uint16_t caid);
uint16_t chk_on_btun(uint8_t chk_sx, struct s_client *cl, ECM_REQUEST *er);
int32_t chk_sfilter(ECM_REQUEST *er, PTAB *ptab);
int32_t chk_ufilters(ECM_REQUEST *er);
int32_t chk_rsfilter(struct s_reader * reader, ECM_REQUEST *er);
int32_t chk_rfilter2(uint16_t rcaid, uint32_t rprid, struct s_reader *rdr);
int32_t chk_ctab(uint16_t caid, CAIDTAB *ctab);
int32_t chk_ctab_ex(uint16_t caid, CAIDTAB *ctab);
int32_t chk_caid(uint16_t caid, CAIDTAB *ctab);
int32_t chk_caid_rdr(struct s_reader *rdr,uint16_t caid);
int32_t chk_bcaid(ECM_REQUEST *er, CAIDTAB *ctab);
int32_t chk_is_null_CW(uchar cw[]);
bool check_client(struct s_client *cl);

#endif
