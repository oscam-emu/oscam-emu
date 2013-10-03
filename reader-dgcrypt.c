#include "globals.h"
#ifdef READER_DGCRYPT
#include "reader-common.h"

#define DEBUG 0

static const uint8_t dgcrypt_atr[8] = { 0x3B, 0xE9, 0x00, 0x00, 0x81, 0x31, 0xC3, 0x45 };
static const uint8_t cmd_CWKEY[5]   = { 0x81, 0xD0, 0x00, 0x01, 0x08 };
//static const uint8_t cmd_CAID[5]    = { 0x81, 0xC0, 0x00, 0x01, 0x0A };
static const uint8_t cmd_SERIAL[5]  = { 0x81, 0xD1, 0x00, 0x01, 0x10 };
static const uint8_t cmd_LABEL[5]   = { 0x81, 0xD2, 0x00, 0x01, 0x10 };
static const uint8_t cmd_SUBSYS[5]  = { 0x81, 0xDD, 0x00, 0x10, 0x04 };
static const uint8_t cmd_ECM[3]     = { 0x80, 0xEA, 0x80 };

struct dgcrypt_data
{
    uint8_t         session_key[16];
};

static int32_t dgcrypt_cmd(struct s_reader *rdr, const uint8_t *buf, const int32_t buflen, uint8_t *response, uint16_t *response_length, uint16_t min_response_len)
{
    rdr->ifsc = 195;
    rdr->ns   = 1;
    if (DEBUG)
    {
        char tmp[512];
        rdr_log(rdr, "SEND -> %s(%d)", cs_hexdump(1, buf, buflen, tmp, sizeof(tmp)), buflen);
    }
    int32_t ret = reader_cmd2icc(rdr, buf, buflen, response, response_length);
    if (DEBUG)
    {
        char tmp[512];
        rdr_log(rdr, "RECV <- %s(%d) ret=%d", cs_hexdump(1, response, *response_length, tmp, sizeof(tmp)), *response_length, ret);
    }
    // reader_cmd2icc retuns ERROR=1, OK=0 - the opposite of OK and ERROR defines in reader-common.h
    if (ret)
    {
        rdr_log(rdr, "ERROR: reader_cmd2icc() ret=%d", ret);
        return ERROR;
    }
    if (*response_length < 2 || *response_length < min_response_len)
    {
        rdr_log(rdr, "ERROR: response_length=%d < min_response_length=%d", *response_length, min_response_len);
        return ERROR; // Response is two short
    }
    if (response[*response_length - 2] != 0x90 || response[*response_length - 1] != 0x00)
    {
        rdr_log(rdr, "ERROR: response[-2] != 0x90 its 0x%02X", response[*response_length - 2]);
        rdr_log(rdr, "ERROR: response[-1] != 0x00 its 0x%02X", response[*response_length - 1]);
        return ERROR; // The reader responded with "command not OK"
    }
    return OK;
}

static int32_t dgcrypt_card_init(struct s_reader *rdr, ATR *newatr)
{
    def_resp

    get_atr
    if (atr_size < sizeof(dgcrypt_atr))
        return ERROR;

    // Full ATR: 3B E9 00 00 81 31 C3 45 99 63 74 69 19 99 12 56 10 EC
    if (memcmp(atr, dgcrypt_atr, sizeof(dgcrypt_atr)) != 0)
        return ERROR;

    if (!cs_malloc(&rdr->csystem_data, sizeof(struct dgcrypt_data)))
        return ERROR;
    struct dgcrypt_data *csystem_data = rdr->csystem_data;

    rdr_log(rdr, "[dgcrypt-reader] card detected.");

    memset(rdr->sa, 0, sizeof(rdr->sa));
    memset(rdr->prid, 0, sizeof(rdr->prid));
    memset(rdr->hexserial, 0, sizeof(rdr->hexserial));

    rdr->nprov = 1;
    rdr->caid  = 0x4ABF;

    // Get session key
    //   Send: 81 D0 00 01 08
    //   Recv: 32 86 17 D5 2C 66 61 14 90 00
    if (!dgcrypt_cmd(rdr, cmd_CWKEY, sizeof(cmd_CWKEY), cta_res, &cta_lr, 8))
        return ERROR;
    memcpy(csystem_data->session_key + 0, cta_res, 8);
    memcpy(csystem_data->session_key + 8, cta_res, 8);

    // Get CAID
    //   Send: 81 C0 00 01 0A
    //   Recv: 4A BF 90 00
    //  if (!dgcrypt_cmd(rdr, cmd_CAID, sizeof(cmd_CAID), cta_res, &cta_lr, 2))
    //      return ERROR;
    //  rdr->caid = (cta_res[0] << 8) | cta_res[1];

    // Get serial number
    //   Send: 81 D1 00 01 10
    //   Recv: 00 0D DB 08 71 0D D5 0C 30 30 30 30 30 30 30 30 90 00
    if (!dgcrypt_cmd(rdr, cmd_SERIAL, sizeof(cmd_SERIAL), cta_res, &cta_lr, 8))
        return ERROR;
    memcpy(rdr->hexserial, cta_res + 1, 7);

    // Get LABEL
    //   Send: 81 D2 00 01 10
    //   Recv: 50 61 79 5F 54 56 5F 43 61 72 64 00 00 00 00 00 90 00
    //    Txt: P  a  y  _  T  V  _  C  a  r  d
    if (!dgcrypt_cmd(rdr, cmd_LABEL, sizeof(cmd_LABEL), cta_res, &cta_lr, 16))
        return ERROR;
    char label[17];
    memset(label, 0, sizeof(label));
    memcpy(label, cta_res, 16);

    // Get subsystem - !FIXME! We are not using the answer of this command!
    //   Send: 81 DD 00 10 04
    //   Recv: 00 55 00 55 90 00
    if (!dgcrypt_cmd(rdr, cmd_LABEL, sizeof(cmd_LABEL), cta_res, &cta_lr, 4))
        return ERROR;

    rdr_log_sensitive(rdr, "CAID: 0x%04X, Serial: {%"PRIu64"} HexSerial: {%02X %02X %02X %02X %02X %02X %02X} Label: {%s}",
                      rdr->caid,
                      b2ll(7, rdr->hexserial),
                      rdr->hexserial[0], rdr->hexserial[1], rdr->hexserial[2],
                      rdr->hexserial[3], rdr->hexserial[4], rdr->hexserial[5], rdr->hexserial[6],
                      label);

    return OK;
}

static int32_t dgcrypt_do_ecm(struct s_reader *rdr, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
    def_resp
    uint8_t cmd_buffer[256];
    struct dgcrypt_data *csystem_data = rdr->csystem_data;

    memcpy(cmd_buffer, er->ecm, er->ecm[2] + 3);
    // Replace The first 3 bytes of the ECM with the command
    memcpy(cmd_buffer, cmd_ECM, sizeof(cmd_ECM));

    // Write ECM
    //   Send: 80 EA 80 00 55 00 00 3F 90 03 00 00 18 5D 82 4E 01 C4 2D 60 12 ED 34 37 ED 72 .. .. ..
    //   Recv: 72 25 8D A1 0D 0D D2 44 EE ED 51 2F 3B 5D 19 63 E6 90 00
    if (!dgcrypt_cmd(rdr, cmd_buffer, er->ecm[2] + 3, cta_res, &cta_lr, 17))
        return ERROR;
    if (cta_res[0] != 0x72) // CW response MUST start with 0x72
        return ERROR;

    int i;
    for (i = 0; i < 16; i++)
    {
        ea->cw[i] = cta_res[1 + i] ^ csystem_data->session_key[i];
    }
    return OK;
}

void reader_dgcrypt(struct s_cardsystem *ph)
{
    // DGCrypt system does not send EMMs
    ph->card_init = dgcrypt_card_init;
    ph->do_ecm    = dgcrypt_do_ecm;
    ph->caids[0]  = 0x4ABF;
    ph->desc      = "dgcrypt";
}
#endif
