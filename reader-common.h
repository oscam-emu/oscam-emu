#ifndef READER_COMMON_H_
#define READER_COMMON_H_

//Warning: OK = 0 and ERROR = 1 in csctapi !!!
#define SKIPPED 2
#define OK      1
#define ERROR   0

#include "csctapi/atr.h"
#include "oscam-string.h"
#include "oscam-reader.h"

int32_t reader_cmd2icc(struct s_reader *reader, const uchar *buf, const int32_t l, uchar *response, uint16_t *response_length);
int32_t card_write(struct s_reader *reader, const uchar *, const uchar *, uchar *, uint16_t *);

#define write_cmd(cmd, data) \
    { \
        if (card_write(reader, cmd, data, cta_res, &cta_lr)) return ERROR; \
    }

#define get_atr \
    unsigned char atr[ATR_MAX_SIZE]; \
    uint32_t atr_size; \
    memset(atr, 0, sizeof(atr)); \
    ATR_GetRaw(newatr, atr, &atr_size);

#define get_hist \
    unsigned char hist[ATR_MAX_HISTORICAL]; \
    uint32_t hist_size = 0; \
    ATR_GetHistoricalBytes(newatr, hist, &hist_size);

#define def_resp \
    unsigned char cta_res[CTA_RES_LEN]; \
    memset(cta_res, 0, CTA_RES_LEN); \
    uint16_t cta_lr;

#ifdef WITH_CARDREADER
void cardreader_init_locks(void);
bool cardreader_init(struct s_reader *reader);
void cardreader_close(struct s_reader *reader);
void cardreader_do_reset(struct s_reader *reader);
void cardreader_reset(struct s_client *cl);
int32_t cardreader_do_checkhealth(struct s_reader *reader);
void cardreader_checkhealth(struct s_client *cl, struct s_reader *rdr);
int32_t cardreader_do_emm(struct s_reader *reader, EMM_PACKET *ep);
void cardreader_process_ecm(struct s_reader *reader, struct s_client *cl, ECM_REQUEST *er);
void cardreader_get_card_info(struct s_reader *reader);
int32_t check_sct_len(const unsigned char *data, int32_t off);
#else
static inline void cardreader_init_locks(void) { }
static inline bool cardreader_init(struct s_reader *UNUSED(reader))
{
    return true;
}
static inline void cardreader_close(struct s_reader *UNUSED(reader)) { }
static inline void cardreader_do_reset(struct s_reader *UNUSED(reader))
{
    return;
}
static inline void cardreader_reset(struct s_client *UNUSED(cl)) { }
static inline int32_t cardreader_do_checkhealth(struct s_reader *UNUSED(reader))
{
    return false;
}
static inline void cardreader_checkhealth(struct s_client *UNUSED(cl), struct s_reader *UNUSED(rdr)) { }
static inline int32_t cardreader_do_emm(struct s_reader *UNUSED(reader), EMM_PACKET *UNUSED(ep))
{
    return 0;
}
static inline void cardreader_process_ecm(struct s_reader *UNUSED(reader), struct s_client *UNUSED(cl), ECM_REQUEST *UNUSED(er)) { }
static inline void cardreader_get_card_info(struct s_reader *UNUSED(reader)) { }
#endif

#endif
