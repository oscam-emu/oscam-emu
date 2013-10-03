#include "globals.h"
#ifdef READER_NAGRA
#include "cscrypt/bn.h"
#include "cscrypt/idea.h"
#include "oscam-time.h"
#include "reader-common.h"

struct nagra_data
{
    IDEA_KEY_SCHEDULE ksSession;
    int8_t          is_pure_nagra;
    int8_t          is_tiger;
    int8_t          is_n3_na;
    int8_t          has_dt08;
    int8_t          swapCW;
    uint8_t         ExpiryDate[2];
    uint8_t         ActivationDate[2];
    uint8_t         plainDT08RSA[64];
    uint8_t         IdeaCamKey[16];
    uint8_t         sessi[16];
    uint8_t         signature[8];
    uint8_t         cam_state[3];
};

// Card Status checks
#define HAS_CW()      ((csystem_data->cam_state[2]&6)==6)
#define RENEW_SESSIONKEY() ((csystem_data->cam_state[0]&128)==128 || (csystem_data->cam_state[0]&64)==64 || (csystem_data->cam_state[0]&32)==32 || (csystem_data->cam_state[2]&8)==8)
#define SENDDATETIME() (csystem_data->cam_state[0]&8)
// Datatypes
#define DT01        0x01
#define IRDINFO     0x00
#define TIERS       0x05
#define DT06        0x06
#define CAMDATA     0x08

#define SYSTEM_NAGRA 0x1800
#define SYSTEM_MASK 0xFF00


static time_t tier_date(uint32_t date, char *buf, int32_t l)
{
    time_t ut = 870393600L + date * (24 * 3600);
    if (buf)
    {
        struct tm t;
        cs_gmtime_r(&ut, &t);
        snprintf(buf, l, "%04d/%02d/%02d", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
    }
    return ut;
}

static char *nagra_datetime(struct s_reader *rdr, uint8_t *ndays, int32_t offset, char *result, time_t *t)
{
    struct nagra_data *csystem_data = rdr->csystem_data;
    struct tm tms;
    memset(&tms, 0, sizeof(tms));
    int32_t days = (ndays[0] << 8 | ndays[1]) + offset;
    int32_t sec = 0;
    if (!csystem_data->is_tiger)
        sec = (ndays[2] << 8 | ndays[3]);
    if (days > 0x41B4 && sizeof(time_t) < 8) // to overcome 32-bit systems limitations
        days = 0x41A2;                   // 01-01-2038
    tms.tm_year = 92;
    tms.tm_mday = days + 1;
    tms.tm_sec = sec;
    time_t ut = mktime(&tms);
    if (t)
        *t = ut;
    if (csystem_data->is_tiger)
        snprintf(result, 11, "%02d/%02d/%04d", tms.tm_mday, tms.tm_mon + 1, tms.tm_year + 1900);
    else
        snprintf(result, 17, "%04d/%02d/%02d %02d:%02d", tms.tm_year + 1900, tms.tm_mon + 1, tms.tm_mday, tms.tm_hour, tms.tm_min);
    return result;
}

static int32_t do_cmd(struct s_reader *reader, unsigned char cmd, int32_t ilen, unsigned char res, int32_t rlen, const unsigned char *data, unsigned char *cta_res, uint16_t *p_cta_lr)
{
    /*
    here we build the command related to the protocol T1 for ROM142 or T14 for ROM181
    the only different that i know is the command length byte msg[4], this msg[4]+=1 by a ROM181 smartcard (_nighti_)
    one example for the cmd$C0
    T14 protocol:       01 A0 CA 00 00 03 C0 00 06 91
    T1  protocol: 21 00 08 A0 CA 00 00 02 C0 00 06 87
    */
    int32_t msglen = ilen + 6;
    unsigned char msg[msglen];
    static const char nagra_head[] = {0xA0, 0xCA, 0x00, 0x00};
    struct nagra_data *csystem_data = reader->csystem_data;

    memset(msg, 0, msglen);
    memcpy(msg, nagra_head, 4);
    msg[4] = ilen;
    msg[5] = cmd;
    int32_t dlen = ilen - 2;
    msg[6] = dlen;
    if (data && dlen > 0) memcpy(msg + 7, data, dlen);
    msg[dlen + 7] = rlen;
    if (dlen < 0)
    {
        rdr_debug_mask(reader, D_READER, "invalid data length encountered");
        return ERROR;
    }
    if (csystem_data->is_pure_nagra == 1)
    {
        msg[4] += 1;
    }
    if (!reader_cmd2icc(reader, msg, msglen, cta_res, p_cta_lr))
    {
        cs_sleepms(5);
        if (cta_res[0] != res)
        {
            rdr_debug_mask(reader, D_READER, "result not expected (%02x != %02x)", cta_res[0], res);
            return ERROR;
        }
        if ((*p_cta_lr - 2) != rlen)
        {
            rdr_debug_mask(reader, D_READER, "result length expected (%d != %d)", (*p_cta_lr - 2), rlen);
            return ERROR;
        }
        return *p_cta_lr;
    }
    return ERROR;
}

static void ReverseMem(unsigned char *vIn, int32_t len)
{
    unsigned char temp;
    int32_t i;
    for (i = 0; i < (len / 2); i++)
    {
        temp = vIn[i];
        vIn[i] = vIn[len - i - 1];
        vIn[len - i - 1] = temp;
    }
}

static void Signature(unsigned char *sig, const unsigned char *vkey, const unsigned char *msg, int32_t len)
{
    IDEA_KEY_SCHEDULE ks;
    unsigned char v[8];
    unsigned char b200[16];
    unsigned char b0f0[8];
    memcpy(b200, vkey, sizeof(b200));
    int32_t i;
    int32_t j;
    for (i = 0; i < len; i += 8)
    {
        idea_set_encrypt_key(b200, &ks);
        memset(v, 0, sizeof(v));
        idea_cbc_encrypt(msg + i, b0f0, 8, &ks, v, IDEA_DECRYPT);
        for (j = 7; j >= 0; j--) b0f0[j] ^= msg[i + j];
        memcpy(b200 + 0, b0f0, 8);
        memcpy(b200 + 8, b0f0, 8);
    }
    memcpy(sig, b0f0, 8);
    return;
}

static int32_t CamStateRequest(struct s_reader *reader)
{
    def_resp;
    struct nagra_data *csystem_data = reader->csystem_data;
    char tmp_dbg[10];
    if (do_cmd(reader, 0xC0, 0x02, 0xB0, 0x06, NULL, cta_res, &cta_lr))
    {
        memcpy(csystem_data->cam_state, cta_res + 3, 3);
        rdr_debug_mask(reader, D_READER, "Camstate: %s", cs_hexdump(1, csystem_data->cam_state, 3, tmp_dbg, sizeof(tmp_dbg)));
    }
    else
    {
        rdr_debug_mask(reader, D_READER, "CamStateRequest failed");
        return ERROR;
    }
    return OK;
}

static void DateTimeCMD(struct s_reader *reader)
{
    def_resp;
    if (!do_cmd(reader, 0xC8, 0x02, 0xB8, 0x06, NULL, cta_res, &cta_lr))
    {
        rdr_debug_mask(reader, D_READER, "DateTimeCMD failed!");
    }

}

static int32_t NegotiateSessionKey_Tiger(struct s_reader *reader)
{
    def_resp;
    unsigned char vFixed[] = {0, 1, 2, 3, 0x11};
    unsigned char parte_fija[120];
    unsigned char parte_variable[88];
    unsigned char d1_rsa_modulo[88];
    unsigned char d2_data[88];
    unsigned char sign1[8];
    unsigned char sk[16];
    unsigned char tmp[104];
    unsigned char idea_sig[16];
    unsigned char rnd[88];
    char tmp2[17];
    struct nagra_data *csystem_data = reader->csystem_data;

    if (!do_cmd(reader, 0xd1, 0x02, 0x51, 0xd2, NULL, cta_res, &cta_lr))
    {
        rdr_debug_mask(reader, D_READER, "CMD$D1 failed");
        return ERROR;
    }

    BN_CTX *ctx = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
    BN_CTX_start(ctx);
#endif
    BIGNUM *bnN = BN_CTX_get(ctx);
    BIGNUM *bnE = BN_CTX_get(ctx);
    BIGNUM *bnCT = BN_CTX_get(ctx);
    BIGNUM *bnPT = BN_CTX_get(ctx);
    BN_bin2bn(reader->rsa_mod, 120, bnN);
    BN_bin2bn(vFixed + 4, 1, bnE);
    BN_bin2bn(&cta_res[90], 120, bnCT);
    BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
    memset(parte_fija, 0, 120);
    BN_bn2bin(bnPT, parte_fija + (120 - BN_num_bytes(bnPT)));
    BN_CTX_end(ctx);
    BN_CTX_free (ctx);

    rdr_debug_mask(reader, D_READER, "---------- SIG CHECK ---------------------");
    memset(tmp, 0, 104);
    memcpy(tmp + 4, parte_fija + 11, 100);
    memset(idea_sig, 0x37, 16);
    Signature(sign1, idea_sig, tmp, 104);
    rdr_debug_mask(reader, D_READER, "sign1: %s", cs_hexdump(0, sign1, 8, tmp2, sizeof(tmp2)));
    rdr_debug_mask(reader, D_READER, "sign2: %s", cs_hexdump(0, parte_fija + 111, 8, tmp2, sizeof(tmp2)));
    if (!memcmp (parte_fija + 111, sign1, 8) == 0)
    {
        rdr_debug_mask(reader, D_READER, "signature check nok");
        rdr_debug_mask(reader, D_READER, "------------------------------------------");
        return ERROR;
    }
    rdr_debug_mask(reader, D_READER, "signature check ok");
    rdr_debug_mask(reader, D_READER, "------------------------------------------");

    memcpy(reader->hexserial + 2, parte_fija + 15, 4);
    memcpy(reader->sa[0], parte_fija + 15, 2);

    memcpy(reader->irdId, parte_fija + 19, 4);
    memcpy(d1_rsa_modulo, parte_fija + 23, 88);

    ReverseMem(cta_res + 2, 88);
    BN_CTX *ctx1 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
    BN_CTX_start(ctx1);
#endif
    BIGNUM *bnN1 = BN_CTX_get(ctx1);
    BIGNUM *bnE1 = BN_CTX_get(ctx1);
    BIGNUM *bnCT1 = BN_CTX_get(ctx1);
    BIGNUM *bnPT1 = BN_CTX_get(ctx1);
    BN_bin2bn(d1_rsa_modulo, 88, bnN1);
    BN_bin2bn(vFixed + 4, 1, bnE1);
    BN_bin2bn(cta_res + 2, 88, bnCT1);
    BN_mod_exp(bnPT1, bnCT1, bnE1, bnN1, ctx1);
    memset(parte_variable, 0, 88);
    BN_bn2bin(bnPT1, parte_variable + (88 - BN_num_bytes(bnPT1)));
    BN_CTX_end(ctx1);
    BN_CTX_free (ctx1);

    csystem_data->ActivationDate[0] = parte_variable[65];
    csystem_data->ActivationDate[1] = parte_variable[66];
    csystem_data->ExpiryDate[0] = parte_variable[69];
    csystem_data->ExpiryDate[1] = parte_variable[70];

    reader->prid[0][0] = 0x00;
    reader->prid[0][1] = 0x00;
    reader->prid[0][2] = parte_variable[73];
    reader->prid[0][3] = parte_variable[74];
    reader->caid = (SYSTEM_NAGRA | parte_variable[76]);
    memcpy(sk, &parte_variable[79], 8);
    memcpy(sk + 8, &parte_variable[79], 8);
    rdr_log_sensitive(reader, "type: NAGRA, caid: %04X, IRD ID: {%s}", reader->caid, cs_hexdump(1, reader->irdId, 4, tmp2, sizeof(tmp2)));
    rdr_log(reader, "ProviderID: %s", cs_hexdump(1, reader->prid[0], 4, tmp2, sizeof(tmp2)));

    memset(rnd, 0, 88);
    memcpy(rnd, sk, 16);
    ReverseMem(rnd, 88);


    BN_CTX *ctx3 = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
    BN_CTX_start(ctx3);
#endif
    BIGNUM *bnN3 = BN_CTX_get(ctx3);
    BIGNUM *bnE3 = BN_CTX_get(ctx3);
    BIGNUM *bnCT3 = BN_CTX_get(ctx3);
    BIGNUM *bnPT3 = BN_CTX_get(ctx3);
    BN_bin2bn(d1_rsa_modulo, 88, bnN3);
    BN_bin2bn(vFixed + 4, 1, bnE3);
    BN_bin2bn(rnd, 88, bnCT3);
    BN_mod_exp(bnPT3, bnCT3, bnE3, bnN3, ctx3);
    memset(d2_data, 0, 88);
    BN_bn2bin(bnPT3, d2_data + (88 - BN_num_bytes(bnPT3)));
    BN_CTX_end(ctx3);
    BN_CTX_free (ctx3);
    ReverseMem(d2_data, 88);

    if (!do_cmd(reader, 0xd2, 0x5a, 0x52, 0x03, d2_data, cta_res, &cta_lr))
    {
        rdr_debug_mask(reader, D_READER, "CMD$D2 failed");
        return ERROR;
    }
    if (cta_res[2] == 0x00)
    {
        memcpy(csystem_data->sessi, sk, 16);
        IDEA_KEY_SCHEDULE ks;
        idea_set_encrypt_key(csystem_data->sessi, &ks);
        idea_set_decrypt_key(&ks, &csystem_data->ksSession);
        rdr_debug_mask(reader, D_READER, "Tiger session key negotiated");
        return OK;
    }
    rdr_log(reader, "Negotiate sessionkey was not successfull! Please check tivusat rsa key");
    return ERROR;

}

static int32_t NegotiateSessionKey(struct s_reader *reader)
{
    def_resp;
    unsigned char negot[64];
    unsigned char cmd2b[] = {0x21, 0x40, 0x4D, 0xA0, 0xCA, 0x00, 0x00, 0x47, 0x27, 0x45,
                             0x1C, 0x54, 0xd1, 0x26, 0xe7, 0xe2, 0x40, 0x20,
                             0xd1, 0x66, 0xf4, 0x18, 0x97, 0x9d, 0x5f, 0x16,
                             0x8f, 0x7f, 0x7a, 0x55, 0x15, 0x82, 0x31, 0x14,
                             0x06, 0x57, 0x1a, 0x3f, 0xf0, 0x75, 0x62, 0x41,
                             0xc2, 0x84, 0xda, 0x4c, 0x2e, 0x84, 0xe9, 0x29,
                             0x13, 0x81, 0xee, 0xd6, 0xa9, 0xf5, 0xe9, 0xdb,
                             0xaf, 0x22, 0x51, 0x3d, 0x44, 0xb3, 0x20, 0x83,
                             0xde, 0xcb, 0x5f, 0x35, 0x2b, 0xb0, 0xce, 0x70,
                             0x01, 0x02, 0x03, 0x04, //IRD nr
                             0x00
                            };//keynr
    unsigned char tmp[64];
    unsigned char idea1[16];
    unsigned char idea2[16];
    unsigned char sign1[8];
    unsigned char sign2[8];
    struct nagra_data *csystem_data = reader->csystem_data;

    if (csystem_data->is_tiger)
    {
        if (!NegotiateSessionKey_Tiger(reader))
        {
            rdr_debug_mask(reader, D_READER, "NegotiateSessionKey_Tiger failed");
            return ERROR;
        }
        return OK;
    }

    if (!csystem_data->has_dt08) // if we have no valid dt08 calc then we use rsa from config and hexserial for calc of sessionkey
    {
        rdr_debug_mask(reader, D_READER, "No valid DT08 calc using rsa from config and serial from card");
        memcpy(csystem_data->plainDT08RSA, reader->rsa_mod, 64);
        memcpy(csystem_data->signature, reader->boxkey, sizeof(reader->boxkey));
    }

    if ((csystem_data->is_n3_na) && (!do_cmd(reader, 0x29, 0x02, 0xA9, 0x04, NULL, cta_res, &cta_lr)))
    {
        rdr_debug_mask(reader, D_READER, "Nagra3: CMD$29 failed");
        return ERROR;
    }

    memcpy(tmp, reader->irdId, 4);
    tmp[4] = 0; //keynr 0

    if (!csystem_data->is_n3_na)
    {
        if (!do_cmd(reader, 0x2a, 0x02, 0xaa, 0x42, NULL, cta_res, &cta_lr))
        {
            rdr_debug_mask(reader, D_READER, "CMD$2A failed");
            return ERROR;
        }
    }
    else if (!do_cmd(reader, 0x26, 0x07, 0xa6, 0x42, tmp, cta_res, &cta_lr))
    {
        rdr_debug_mask(reader, D_READER, "CMD$26 failed");
        return ERROR;
    }

    // RSA decrypt of cmd$2a data, result is stored in "negot"
    ReverseMem(cta_res + 2, 64);
    unsigned char vFixed[] = {0, 1, 2, 3};
    BN_CTX *ctx = BN_CTX_new();
#ifdef WITH_LIBCRYPTO
    BN_CTX_start(ctx);
#endif
    BIGNUM *bnN = BN_CTX_get(ctx);
    BIGNUM *bnE = BN_CTX_get(ctx);
    BIGNUM *bnCT = BN_CTX_get(ctx);
    BIGNUM *bnPT = BN_CTX_get(ctx);
    BN_bin2bn(csystem_data->plainDT08RSA, 64, bnN);
    BN_bin2bn(vFixed + 3, 1, bnE);
    BN_bin2bn(cta_res + 2, 64, bnCT);
    BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
    memset(negot, 0, 64);
    BN_bn2bin(bnPT, negot + (64 - BN_num_bytes(bnPT)));

    memcpy(tmp, negot, 64);
    ReverseMem(tmp, 64);

    // build sessionkey
    // first halve is IDEA Hashed in chuncs of 8 bytes using the Signature1 from dt08 calc, CamID-Inv.CamID(16 bytes key) the results are the First 8 bytes of the Session key
    memcpy(idea1, csystem_data->signature, 8);
    memcpy(idea1 + 8, reader->hexserial + 2, 4);
    idea1[12] = ~reader->hexserial[2]; idea1[13] = ~reader->hexserial[3]; idea1[14] = ~reader->hexserial[4]; idea1[15] = ~reader->hexserial[5];

    Signature(sign1, idea1, tmp, 32);
    memcpy(idea2, sign1, 8); memcpy(idea2 + 8, sign1, 8);
    Signature(sign2, idea2, tmp, 32);
    memcpy(csystem_data->sessi, sign1, 8); memcpy(csystem_data->sessi + 8, sign2, 8);

    // prepare cmd$2b data
    BN_bin2bn(negot, 64, bnCT);
    BN_mod_exp(bnPT, bnCT, bnE, bnN, ctx);
    memset(cmd2b + 10, 0, 64);
    BN_bn2bin(bnPT, cmd2b + 10 + (64 - BN_num_bytes(bnPT)));
    BN_CTX_end(ctx);
    BN_CTX_free (ctx);
    ReverseMem(cmd2b + 10, 64);

    IDEA_KEY_SCHEDULE ks;
    idea_set_encrypt_key(csystem_data->sessi, &ks);
    idea_set_decrypt_key(&ks, &csystem_data->ksSession);

    memcpy(cmd2b + 74, reader->irdId, 4);
    cmd2b[78] = 0; //keynr

    if (!csystem_data->is_n3_na)
    {
        if (!do_cmd(reader, 0x2b, 0x42, 0xab, 0x02, cmd2b + 10, cta_res, &cta_lr))
        {
            rdr_debug_mask(reader, D_READER, "CMD$2B failed");
            return ERROR;
        }
    }
    else if (!do_cmd(reader, 0x27, 0x47, 0xa7, 0x02, cmd2b + 10, cta_res, &cta_lr))
    {
        rdr_debug_mask(reader, D_READER, "CMD$27 failed");
        return ERROR;
    }

    rdr_debug_mask(reader, D_READER, "session key negotiated");

    DateTimeCMD(reader);

    if (!CamStateRequest(reader))
    {
        rdr_debug_mask(reader, D_READER, "CamStateRequest failed");
        return ERROR;
    }
    if RENEW_SESSIONKEY()
    {
        rdr_log(reader, "Negotiate sessionkey was not successfull! Please check rsa key and boxkey");
        return ERROR;
    }

    return OK;
}

static void decryptDT08(struct s_reader *reader, unsigned char *cta_res)
{
    unsigned char vFixed[] = {0, 1, 2, 3};
    unsigned char v[72];
    unsigned char buf[72];
    unsigned char sign2[8];
    unsigned char static_dt08[73];
    unsigned char camid[4];
    char tmp_dbg[13];
    int32_t i, n;
    BN_CTX *ctx;
    BIGNUM *bn_mod, *bn_exp, *bn_data, *bn_res;
    struct nagra_data *csystem_data = reader->csystem_data;

    memcpy(static_dt08, &cta_res[12], 73);
    // decrypt RSA Part of dt08
    bn_mod = BN_new ();
    bn_exp = BN_new ();
    bn_data = BN_new ();
    bn_res = BN_new ();
    ctx = BN_CTX_new();
    if (ctx == NULL)
    {
        rdr_debug_mask(reader, D_READER, "RSA Error in dt08 decrypt");
    }
    ReverseMem(static_dt08 + 1, 64);
    BN_bin2bn (reader->rsa_mod, 64, bn_mod); // rsa modulus
    BN_bin2bn (vFixed + 3, 1, bn_exp); // exponent
    BN_bin2bn (static_dt08 + 1, 64, bn_data);
    BN_mod_exp (bn_res, bn_data, bn_exp, bn_mod, ctx);
    memset (static_dt08 + 1, 0, 64);
    n = BN_bn2bin (bn_res, static_dt08 + 1);
    BN_CTX_free (ctx);
    ReverseMem(static_dt08 + 1, n);

    // RSA data can never be bigger than the modulo
    static_dt08[64] |= static_dt08[0] & 0x80;

    // IdeaCamKey
    memcpy (&csystem_data->IdeaCamKey[0], reader->boxkey, sizeof(reader->boxkey));
    memcpy (&csystem_data->IdeaCamKey[8], reader->irdId, 4);
    for (i = 0; i < 4; i++)
        csystem_data->IdeaCamKey[12 + i] = ~reader->irdId[i];

    // now IDEA decrypt
    IDEA_KEY_SCHEDULE ks;
    idea_set_encrypt_key(csystem_data->IdeaCamKey, &ks);
    idea_set_decrypt_key(&ks, &csystem_data->ksSession);
    memcpy (&buf[0], static_dt08 + 1, 64);
    memcpy (&buf[64], static_dt08 + 65, 8);
    memset(v, 0, sizeof(v));
    memset(static_dt08, 0, sizeof(static_dt08));
    idea_cbc_encrypt(buf, static_dt08, 72, &csystem_data->ksSession, v, IDEA_DECRYPT);

    if (csystem_data->swapCW == 1)
    {
        memset(camid, 0xff, 4);
    }
    else
    {
        memcpy(camid, reader->hexserial + 2, 4);
    }
    rdr_debug_mask(reader, D_READER, "using camid %s for dt08 calc", cs_hexdump(1, camid, 4, tmp_dbg, sizeof(tmp_dbg)));

    // Calculate csystem_data->signature
    memcpy (csystem_data->signature, static_dt08, 8);
    memset (static_dt08 + 0, 0, 4);
    memcpy (static_dt08 + 4, camid, 4);
    Signature(sign2, csystem_data->IdeaCamKey, static_dt08, 72);

    if (memcmp (csystem_data->signature, sign2, 8) == 0)
    {
        csystem_data->has_dt08 = 1;
        memcpy (csystem_data->plainDT08RSA, static_dt08 + 8, 64);
        rdr_debug_mask(reader, D_READER, "DT08 signature check ok");
    }
    else
    {
        csystem_data->has_dt08 = 0;
        rdr_debug_mask(reader, D_READER, "DT08 signature check nok");
    }

    BN_free( bn_mod );
    BN_free( bn_exp );
    BN_free( bn_data );
    BN_free( bn_res );
}

static void addProvider(struct s_reader *reader, unsigned char *cta_res)
{
    int32_t i;
    int32_t toadd = 1;
    for (i = 0; i < reader->nprov; i++)
    {
        if ((cta_res[7] == reader->prid[i][2]) && (cta_res[8] == reader->prid[i][3]))
        {
            toadd = 0;
        }
    }
    if (toadd)
    {
        reader->prid[reader->nprov][0] = 0;
        reader->prid[reader->nprov][1] = 0;
        reader->prid[reader->nprov][2] = cta_res[7];
        reader->prid[reader->nprov][3] = cta_res[8];
        memcpy(reader->sa[reader->nprov], reader->sa[0], 4);
        reader->nprov += 1;
    }
}

static int32_t ParseDataType(struct s_reader *reader, unsigned char dt, unsigned char *cta_res, uint16_t cta_lr)
{
    struct nagra_data *csystem_data = reader->csystem_data;
    char ds[20], de[16];
    uint16_t chid;
    switch (dt)
    {
    case IRDINFO:
    {
        reader->prid[0][0] = 0;
        reader->prid[0][1] = 0;
        reader->prid[0][2] = cta_res[7];
        reader->prid[0][3] = cta_res[8];
        if ( ((cta_res[7] == 0x34) && (cta_res[8] == 0x11)) || ((cta_res[7] == 0x04) && (cta_res[8] == 0x01))) //provider 3411, 0401 needs cw swap
        {
            rdr_debug_mask(reader, D_READER, "detect provider with swap cw!");
            csystem_data->swapCW = 1;
        }

        reader->prid[1][0] = 0x00;
        reader->prid[1][1] = 0x00;
        reader->prid[1][2] = 0x00;
        reader->prid[1][3] = 0x00;
        memcpy(reader->sa[1], reader->sa[0], 4);
        reader->nprov += 1;

        reader->caid = (SYSTEM_NAGRA | cta_res[11]);
        memcpy(reader->irdId, cta_res + 14, 4);
        if (reader->csystem.active)         // do not output on init but only afterwards in card_info
        {
            rdr_log_sensitive(reader, "IRD ID: {%s}", cs_hexdump(1, reader->irdId, 4, ds, sizeof(ds)));
            nagra_datetime(reader, cta_res + 24, 0, ds, &reader->card_valid_to);
            rdr_log(reader, "active to: %s", ds);
        }
        return OK;
    }
    case TIERS:
        if ((cta_lr > 33) && (chid = b2i(2, cta_res + 11)))
        {
            int32_t id = (cta_res[7] * 256) | cta_res[8];

            // todo: add entitlements to list
            cs_add_entitlement(reader,
                               reader->caid,
                               id,
                               chid,
                               0,
                               tier_date(b2i(2, cta_res + 20) - 0x7f7, ds, 15),
                               tier_date(b2i(2, cta_res + 13) - 0x7f7, de, 15),
                               4);


            // tier_date(b2i(2, cta_res+20)-0x7f7, ds, 15);
            // tier_date(b2i(2, cta_res+13)-0x7f7, de, 15);
            rdr_log(reader, "|%04X|%04X    |%s  |%s  |", id, chid, ds, de);
            addProvider(reader, cta_res);
        }
    case 0x08:
    case 0x88: if (cta_res[11] == 0x49) decryptDT08(reader, cta_res);
    default:
        return OK;
    }
    return ERROR;
}

static int32_t GetDataType(struct s_reader *reader, unsigned char dt, int32_t len)
{
    def_resp;
    int32_t result = OK;
    while (result == OK)
    {
        if (!do_cmd(reader, 0x22, 0x03, 0xA2, len, &dt, cta_res, &cta_lr))
        {
            rdr_debug_mask(reader, D_READER, "failed to get datatype %02X", dt);
            result = ERROR;
            break;
        }

        if (((cta_res[2] == 0) && (dt != 0x08)) || ((cta_res[2] == 0) && (dt != 0x88)))
        {
            result = OK;
            break;
        }

        if (!ParseDataType(reader, dt & 0x0F, cta_res, cta_lr))
        {
            result = ERROR;
            break;
        }

        if (((cta_res[11] == 0x49) && (dt != 0x08)) || ((cta_res[11] == 0x49) && (dt != 0x88)))
        {
            result = OK;
            break;
        }
        dt |= 0x80; // get next item
    }
    return result;
}

static int32_t nagra2_card_init(struct s_reader *reader, ATR *newatr)
{
    get_atr;
    def_resp;
    memset(reader->rom, 0, 15);

    int8_t is_pure_nagra = 0;
    int8_t is_tiger = 0;
    int8_t is_n3_na = 0;
    memset(reader->irdId, 0xff, 4);
    memset(reader->hexserial, 0, 8);

    cs_clear_entitlement(reader); // reset the entitlements

    if (memcmp(atr + 11, "DNASP240", 8) == 0 || memcmp(atr + 11, "DNASP241", 8) == 0)
    {
        rdr_log(reader, "detect nagra 3 NA card");
        memcpy(reader->rom, atr + 11, 15);
        is_n3_na = 1;
    }
    else if (memcmp(atr + 11, "DNASP", 5) == 0)
    {
        rdr_log(reader, "detect native nagra card");
        memcpy(reader->rom, atr + 11, 15);
    }
    else if (memcmp(atr + 11, "TIGER", 5) == 0 || (memcmp(atr + 11, "NCMED", 5) == 0))
    {
        rdr_log(reader, "detect nagra tiger card");
        memcpy(reader->rom, atr + 11, 15);
        is_tiger = 1;
    }
    else if ((!memcmp(atr + 4, "IRDETO", 6)) && ((atr[14] == 0x03) && (atr[15] == 0x84) && (atr[16] == 0x55)))
    {
        rdr_log(reader, "detect irdeto tunneled nagra card");
        if (check_filled(reader->rsa_mod, 64) == 0)
        {
            rdr_log(reader, "no rsa key configured -> using irdeto mode");
            return ERROR;
        }
        if (reader->force_irdeto)
        {
            rdr_log(reader, "rsa key configured but irdeto mode forced -> using irdeto mode");
            return ERROR;
        }
        rdr_log(reader, "rsa key configured -> using nagra mode");
        is_pure_nagra = 1;
        if (!cs_malloc(&reader->csystem_data, sizeof(struct nagra_data)))
            return ERROR;
        struct nagra_data *csystem_data = reader->csystem_data;
        csystem_data->is_pure_nagra = is_pure_nagra;
        if (!do_cmd(reader, 0x10, 0x02, 0x90, 0x11, 0, cta_res, &cta_lr))
        {
            rdr_debug_mask(reader, D_READER, "get rom version failed");
            return ERROR;
        }
        memcpy(reader->rom, cta_res + 2, 15);
    }
    else return ERROR;

    // Private data may be already allocated, see above (the irdeto check).
    if (!reader->csystem_data)
    {
        if (!cs_malloc(&reader->csystem_data, sizeof(struct nagra_data)))
            return ERROR;
    }
    struct nagra_data *csystem_data = reader->csystem_data;
    csystem_data->is_pure_nagra = is_pure_nagra;
    csystem_data->is_tiger      = is_tiger;
    csystem_data->is_n3_na      = is_n3_na;

    reader->nprov = 1;

    if (!csystem_data->is_tiger)
    {
        CamStateRequest(reader);
        if (!do_cmd(reader, 0x12, 0x02, 0x92, 0x06, 0, cta_res, &cta_lr))
        {
            rdr_debug_mask(reader, D_READER, "get serial failed");
            return ERROR;
        }
        memcpy(reader->hexserial + 2, cta_res + 2, 4);
        memcpy(reader->sa[0], cta_res + 2, 2);

        if (!GetDataType(reader, DT01, 0x0E)) return ERROR;
        rdr_debug_mask(reader, D_READER, "DT01 DONE");
        CamStateRequest(reader);
        if (!GetDataType(reader, IRDINFO, 0x39)) return ERROR;
        rdr_debug_mask(reader, D_READER, "IRDINFO DONE");
        CamStateRequest(reader);
        if (!GetDataType(reader, CAMDATA, 0x55)) return ERROR;
        rdr_debug_mask(reader, D_READER, "CAMDATA Done");
        if (!GetDataType(reader, 0x04, 0x44)) return ERROR;
        rdr_debug_mask(reader, D_READER, "DT04 DONE");
        CamStateRequest(reader);
        if (!GetDataType(reader, DT06, 0x16)) return ERROR;
        rdr_debug_mask(reader, D_READER, "DT06 DONE");
        CamStateRequest(reader);
    }
    if (!NegotiateSessionKey(reader))
    {
        rdr_debug_mask(reader, D_READER, "NegotiateSessionKey failed");
        return ERROR;
    }
    return OK;
}

typedef struct
{
    char date1[11];
    char date2[11];
    uint8_t type;
    uint16_t value;
    uint16_t price;
} ncmed_rec;

static time_t tiger_date2time(const char *date)
{
    struct tm timeinfo;
    int32_t y, m, d;

    sscanf(date, "%02d/%02d/%04d", &d, &m, &y);
    memset(&timeinfo, 0, sizeof(struct tm));
    timeinfo.tm_year = y - 1900;
    timeinfo.tm_mon = m - 1;
    timeinfo.tm_mday = d;

    return mktime(&timeinfo);
}

static int32_t reccmp(const void *r1, const void *r2)
{
    int32_t v1, v2, y, m, d;
    sscanf(((ncmed_rec *)r1)->date1, "%02d/%02d/%04d", &d, &m, &y);
    v1 = y * 372 + 1 + m * 31 + d;
    sscanf(((ncmed_rec *)r2)->date1, "%02d/%02d/%04d", &d, &m, &y);
    v2 = y * 372 + 1 + m * 31 + d;
    return (v1 == v2) ? 0 : (v1 < v2) ? -1 : 1;
}

static int32_t reccmp2(const void *r1, const void *r2)
{
    char rec1[13], rec2[13];
    snprintf(rec1, sizeof(rec1), "%04X", ((ncmed_rec *)r1)->value);
    memcpy(rec1 + 4, ((ncmed_rec *)r1)->date2 + 6, 4);
    memcpy(rec1 + 8, ((ncmed_rec *)r1)->date2 + 3, 2);
    memcpy(rec1 + 10, ((ncmed_rec *)r1)->date2, 2);
    snprintf(rec2, sizeof(rec2), "%04X", ((ncmed_rec *)r2)->value);
    memcpy(rec2 + 4, ((ncmed_rec *)r2)->date2 + 6, 4);
    memcpy(rec2 + 8, ((ncmed_rec *)r2)->date2 + 3, 2);
    memcpy(rec2 + 10, ((ncmed_rec *)r2)->date2, 2);
    rec1[12] = rec2[12] = 0;
    return strcmp(rec2, rec1);
}

static int32_t nagra2_card_info(struct s_reader *reader)
{
    int32_t i;
    char currdate[11], tmp[64];
    struct nagra_data *csystem_data = reader->csystem_data;
    rdr_log(reader, "ROM:    %c %c %c %c %c %c %c %c", reader->rom[0], reader->rom[1], reader->rom[2], reader->rom[3], reader->rom[4], reader->rom[5], reader->rom[6], reader->rom[7]);
    rdr_log(reader, "REV:    %c %c %c %c %c %c", reader->rom[9], reader->rom[10], reader->rom[11], reader->rom[12], reader->rom[13], reader->rom[14]);
    rdr_log_sensitive(reader, "SER:    {%s}", cs_hexdump(1, reader->hexserial + 2, 4, tmp, sizeof(tmp)));
    rdr_log(reader, "CAID:   %04X", reader->caid);
    rdr_log(reader, "Prv.ID: %s(sysid)", cs_hexdump(1, reader->prid[0], 4, tmp, sizeof(tmp)));
    for (i = 1; i < reader->nprov; i++)
    {
        rdr_log(reader, "Prv.ID: %s", cs_hexdump(1, reader->prid[i], 4, tmp, sizeof(tmp)));
    }
    cs_clear_entitlement(reader); //reset the entitlements
    if (csystem_data->is_tiger)
    {
        rdr_log(reader, "Activation Date : %s", nagra_datetime(reader, csystem_data->ActivationDate, 0, currdate, 0));
        rdr_log(reader, "Expiry Date : %s", nagra_datetime(reader, csystem_data->ExpiryDate, 0, currdate, &reader->card_valid_to));
    }
    if (reader->nagra_read && csystem_data->is_tiger && memcmp(reader->rom, "NCMED", 5) == 0)
    {
        ncmed_rec records[255];
        int32_t num_records = 0;
        uint8_t tier_cmd1[] = { 0x00, 0x00 };
        uint8_t tier_cmd2[] = { 0x01, 0x00 };
        def_resp;
        int32_t j;
        do_cmd(reader, 0xD0, 0x04, 0x50, 0x0A, tier_cmd1, cta_res, &cta_lr);
        if (cta_lr == 0x0C)
        {
            int32_t prepaid = 0;
            int32_t credit = 0;
            int32_t balance = 0;

            uint16_t credit_in = cta_res[8] << 8 | cta_res[9];
            uint16_t credit_out = cta_res[5] << 8 | cta_res[6];
            balance = (credit_in - credit_out) / 100;

            for (i = 0; i < 13; ++i)
            {
                tier_cmd2[1] = i;
                do_cmd(reader, 0xD0, 0x04, 0x50, 0xAA, tier_cmd2, cta_res, &cta_lr);
                if (cta_lr == 0xAC)
                {
                    //cs_dump(cta_res, cta_lr, "NCMED Card Record #%d", i+1);
                    for (j = 2; j < cta_res[1] - 14; ++j)
                    {
                        if (cta_res[j] == 0x80 && cta_res[j + 6] != 0x00)
                        {
                            int32_t val_offs = 0;
                            nagra_datetime(reader, &cta_res[j + 6], 0, records[num_records].date2, 0);

                            switch (cta_res[j + 1])
                            {
                            case 0x00:
                            case 0x01:
                            case 0x20:
                            case 0x21:
                            case 0x29:
                                nagra_datetime(reader, &cta_res[j + 8], 0, records[num_records].date1, 0);
                                val_offs = 1;
                                break;

                            case 0x80:
                                nagra_datetime(reader, &cta_res[j + 6], 0, records[num_records].date1, 0);
                                val_offs = 1;
                                break;

                            default:
                                rdr_log(reader, "Unknown record : %s", cs_hexdump(1, &cta_res[j], 17, tmp, sizeof(tmp)));
                            }
                            if (val_offs > 0)
                            {
                                records[num_records].type = cta_res[j + 1];
                                records[num_records].value = cta_res[j + 4] << 8 | cta_res[j + 5];
                                records[num_records++].price = cta_res[j + 11] << 8 | cta_res[j + 12];
                            }
                            j += 16;
                        }
                    }
                }
            }
            if (reader->nagra_read == 1)
                qsort(records, num_records, sizeof(ncmed_rec), reccmp);
            else
                qsort(records, num_records, sizeof(ncmed_rec), reccmp2);

            int32_t  euro = 0;
            char tiername[83];
            time_t rawtime;
            struct tm timeinfo;
            time ( &rawtime );
            localtime_r(&rawtime, &timeinfo);
            snprintf(currdate, sizeof(currdate), "%02d/%02d/%04d", timeinfo.tm_mday, timeinfo.tm_mon + 1, timeinfo.tm_year + 1900);

            for (i = 0; i < num_records; ++i)
            {
                switch (records[i].type)
                {
                case 0x00:
                case 0x01:
                    if (reccmp(records[i].date2, currdate) >= 0)
                    {
                        if (reader->nagra_read == 2)
                            rdr_log(reader, "Tier : %04X, expiry date: %s %s",
                                    records[i].value, records[i].date2, get_tiername(records[i].value, reader->caid, tiername));
                        else if (reader->nagra_read == 1)
                        {
                            euro = (records[i].price / 100);
                            rdr_log(reader, "Activation     : ( %04X ) from %s to %s  (%3d euro) %s",
                                    records[i].value, records[i].date1, records[i].date2, euro, get_tiername(records[i].value, reader->caid, tiername));
                        }
                        cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[0]), records[i].value, 0, tiger_date2time(records[i].date1), tiger_date2time(records[i].date2), 4);
                    }
                    break;

                case 0x20:
                case 0x21:
                    if (reccmp(records[i].date2, currdate) >= 0)
                    {
                        if (reader->nagra_read == 2)
                        {
                            rdr_log(reader, "Tier : %04X, expiry date: %s %s",
                                    records[i].value, records[i].date2, get_tiername(records[i].value, reader->caid, tiername));
                        }
                        cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[0]), records[i].value, 0, tiger_date2time(records[i].date1), tiger_date2time(records[i].date2), 4);
                    }
                    break;
                }
                if (reader->nagra_read == 2)
                {
                    while (i < num_records - 1 && records[i].value == records[i + 1].value)
                        ++i;
                }
            }

            for (i = 0; i < num_records; ++i)
            {
                switch (records[i].type)
                {
                case 0x80:
                    if (reader->nagra_read == 1)
                    {
                        euro = (records[i].price / 100) - prepaid;
                        credit += euro;
                        prepaid += euro;
                        if (euro)
                            rdr_log(reader, "Recharge       :               %s                (%3d euro)",
                                    records[i].date2, euro);
                    }
                    break;

                case 0x20:
                case 0x21:
                    if (reader->nagra_read == 1)
                    {
                        euro = records[i].price / 100;
                        credit -= euro;
                        rdr_log(reader, "Subscription   : ( %04X ) from %s to %s  (%3d euro) %s",
                                records[i].value, records[i].date1, records[i].date2, euro, get_tiername(records[i].value, reader->caid, tiername));
                    }
                    break;

                case 0x29:
                    euro = records[i].price / 100;
                    if (reader->nagra_read == 1) credit -= euro;
                    rdr_log(reader, "Event purchase : ( %04X ) from %s to %s  (%3d euro)",
                            records[i].value, records[i].date1, records[i].date2, euro);
                    break;
                }
            }
            if (reader->nagra_read == 1)
                rdr_log(reader, "Credit         :                                          %3d euro", credit);
            else
                rdr_log(reader, "Credit : %3d euro", balance);
        }
    }
    else
    {
        def_resp;
        char tmp_dbg[13];
        CamStateRequest(reader);
        if (!do_cmd(reader, 0x12, 0x02, 0x92, 0x06, 0, cta_res, &cta_lr))
        {
            rdr_debug_mask(reader, D_READER, "get serial failed");
            return ERROR;
        }
        memcpy(reader->hexserial + 2, cta_res + 2, 4);
        rdr_debug_mask_sensitive(reader, D_READER, "SER:  {%s}", cs_hexdump(1, reader->hexserial + 2, 4, tmp_dbg, sizeof(tmp_dbg)));
        memcpy(reader->sa[0], cta_res + 2, 2);
        reader->nprov = 1;
        if (!GetDataType(reader, IRDINFO, 0x39)) return ERROR;
        rdr_debug_mask(reader, D_READER, "IRDINFO DONE");
        CamStateRequest(reader);

        if (!memcmp(reader->rom + 5, "181", 3) == 0) //dt05 is not supported by rom181
        {
            rdr_log(reader, "-----------------------------------------");
            rdr_log(reader, "|id  |tier    |valid from  |valid to    |");
            rdr_log(reader, "+----+--------+------------+------------+");
            if (!GetDataType(reader, TIERS, 0x57)) return ERROR;
            rdr_log(reader, "-----------------------------------------");
            CamStateRequest(reader);
        }
    }
    rdr_log(reader, "ready for requests");
    return OK;
}

void nagra2_post_process(struct s_reader *reader)
{
    struct nagra_data *csystem_data = reader->csystem_data;
    if (!csystem_data->is_tiger)
    {
        CamStateRequest(reader);
        if RENEW_SESSIONKEY() NegotiateSessionKey(reader);
        if SENDDATETIME() DateTimeCMD(reader);
    }
}

static int32_t nagra2_do_ecm(struct s_reader *reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
    def_resp;
    struct nagra_data *csystem_data = reader->csystem_data;
    if (!csystem_data->is_tiger)
    {
        int32_t retry = 0;
        if (csystem_data->is_n3_na)
        {
            unsigned char ecm_pkt[256 + 16];
            memset(ecm_pkt, 0, sizeof(ecm_pkt));
            memcpy(ecm_pkt, er->ecm + 3 + 2, er->ecm[4]);

            while (!do_cmd(reader, er->ecm[3] + 1, er->ecm[4] + 5 + 2, 0x88, 0x04, ecm_pkt, cta_res, &cta_lr))
            {
                if (retry == 0)
                    rdr_debug_mask(reader, D_READER, "nagra2_do_ecm (N3_NA) failed, retry");
                else
                {
                    rdr_debug_mask(reader, D_READER, "nagra2_do_ecm (N3_NA) failed, retry failed!");
                    return ERROR;
                }
                retry++;
                cs_sleepms(10);
            }
        }
        else
        {
            if (reader->ecmcommand < 5 )  // cache ecm commands until ecmcommand cache is full
            {
                reader->ecmcommandcache[reader->ecmcommand] = er->ecm[3];
                reader->ecmcommand++;
                if (reader->ecmcommand == 5)  // cache is full, comparing!
                {
                    int32_t t = 0;
                    int32_t matchfound = 0;
                    reader->ecmcommand++; // No more caching of ecm commands, next ecms will be compared!
                    while (t < 5)
                    {
                        if (reader->ecmcommandcache[t] == er->ecm[3]) matchfound++;
                        t++;
                    }
                    if (matchfound != 5)
                    {
                        reader->ecmcommand = 0; // reset ecm filter, start a new auto filter attempt
                        rdr_debug_mask(reader, D_READER, "Auto ecm command filter caid %04X failed!", reader->caid);
                    }
                    else
                    {
                        reader->ecmcommandcache[0] = er->ecm[3]; // Passed the filter, store the normal ecm command for this reader!
                        rdr_debug_mask(reader, D_READER, "Auto ecm command filter caid %04X set to command %02X", reader->caid, er->ecm[3]);
                    }
                }
            }
            else if (reader->ecmcommandcache[0] != er->ecm[3])
            {
                rdr_debug_mask(reader, D_READER, "Warning: received an abnominal ecm command %02X for caid: %04X, ignoring!", er->ecm[3], reader->caid);
                memset(ea, 0, sizeof(struct s_ecm_answer)); // give it back 00000000 to not disturb the loadbalancer for valid ecm requests on this channel.
                return OK;
            }

            while (!do_cmd(reader, er->ecm[3], er->ecm[4] + 2, 0x87, 0x02, er->ecm + 3 + 2, cta_res, &cta_lr))
            {
                if (retry == 0)
                    rdr_debug_mask(reader, D_READER, "nagra2_do_ecm failed, retry");
                else
                {
                    rdr_debug_mask(reader, D_READER, "nagra2_do_ecm failed, retry failed!");
                    return ERROR;
                }
                retry++;
                cs_sleepms(10);
            }
        }
        cs_sleepms(10);

        retry = 0;
        while (!CamStateRequest(reader) && retry < 3)
        {
            rdr_debug_mask(reader, D_READER, "CamStateRequest failed, try: %d", retry);
            retry++;
            cs_sleepms(10);
        }
        if (HAS_CW() && (do_cmd(reader, 0x1C, 0x02, 0x9C, 0x36, NULL, cta_res, &cta_lr)))
        {
            unsigned char v[8];
            memset(v, 0, sizeof(v));
            idea_cbc_encrypt(&cta_res[30], ea->cw, 8, &csystem_data->ksSession, v, IDEA_DECRYPT);
            memset(v, 0, sizeof(v));
            idea_cbc_encrypt(&cta_res[4], ea->cw + 8, 8, &csystem_data->ksSession, v, IDEA_DECRYPT);
            if (csystem_data->swapCW == 1)
            {
                rdr_debug_mask(reader, D_READER, "swap cws");
                unsigned char tt[8];
                memcpy(&tt[0], &ea->cw[0], 8);
                memcpy(&ea->cw[0], &ea->cw[8], 8);
                memcpy(&ea->cw[8], &tt[0], 8);
            }
            return OK;
        }
    }
    else
    {
        //check ECM prov id
        if (memcmp(&reader->prid[0][2], er->ecm + 5, 2))
            return ERROR;

        //                  ecm_data: 80 30 89 D3 87 54 11 10 DA A6 0F 4B 92 05 34 00 ...
        //serial_data: A0 CA 00 00 8C D3 8A 00 00 00 00 00 10 DA A6 0F .
        unsigned char ecm_trim[150];
        memset(ecm_trim, 0, 150);
        memcpy(&ecm_trim[5], er->ecm + 3 + 2 + 2, er->ecm[4] + 2);
        if (do_cmd(reader, er->ecm[3], er->ecm[4] + 5, 0x53, 0x16, ecm_trim, cta_res, &cta_lr))
        {
            if (cta_res[2] == 0x01)
            {

                unsigned char v[8];
                memset(v, 0, sizeof(v));
                idea_cbc_encrypt(&cta_res[14], ea->cw, 8, &csystem_data->ksSession, v, IDEA_DECRYPT);
                memset(v, 0, sizeof(v));
                idea_cbc_encrypt(&cta_res[6], ea->cw + 8, 8, &csystem_data->ksSession, v, IDEA_DECRYPT);
                return OK;
            }
            rdr_debug_mask(reader, D_READER, "can't decode ecm");
            return ERROR;
        }
    }
    return ERROR;
}

int32_t nagra2_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr)  //returns 1 if shared emm matches SA, unique emm matches serial, or global or unknown
{
    switch (ep->emm[0])
    {
    case 0x83:
        memset(ep->hexserial, 0, 8);
        ep->hexserial[0] = ep->emm[5];
        ep->hexserial[1] = ep->emm[4];
        ep->hexserial[2] = ep->emm[3];
        if (ep->emm[7] == 0x10)
        {
            ep->type = SHARED;
            return (!memcmp (rdr->hexserial + 2, ep->hexserial, 3));
        }
        else
        {
            ep->hexserial[3] = ep->emm[6];
            ep->type = UNIQUE;
            return (!memcmp (rdr->hexserial + 2, ep->hexserial, 4));
        }
    case 0x82:
        ep->type = GLOBAL;
        return 1;
    default:
        ep->type = UNKNOWN;
        return 1;
    }
}

static int32_t nagra2_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count)
{
    if (*emm_filters == NULL)
    {
        const unsigned int max_filter_count = 3;
        if (!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
            return ERROR;

        struct s_csystem_emm_filter *filters = *emm_filters;
        *filter_count = 0;

        int32_t idx = 0;

        filters[idx].type = EMM_GLOBAL;
        filters[idx].enabled   = 1;
        filters[idx].filter[0] = 0x82;
        filters[idx].mask[0]   = 0xFF;
        idx++;

        filters[idx].type = EMM_SHARED;
        filters[idx].enabled   = 1;
        filters[idx].filter[0] = 0x83;
        filters[idx].filter[1] = rdr->hexserial[4];
        filters[idx].filter[2] = rdr->hexserial[3];
        filters[idx].filter[3] = rdr->hexserial[2];
        filters[idx].filter[4] = 0x00;
        filters[idx].filter[5] = 0x10;
        memset(&filters[idx].mask[0], 0xFF, 6);
        idx++;

        filters[idx].type = EMM_UNIQUE;
        filters[idx].enabled   = 1;
        filters[idx].filter[0] = 0x83;
        filters[idx].filter[1] = rdr->hexserial[4];
        filters[idx].filter[2] = rdr->hexserial[3];
        filters[idx].filter[3] = rdr->hexserial[2];
        filters[idx].filter[4] = rdr->hexserial[5];
        filters[idx].filter[5] = 0x00;
        memset(&filters[idx].mask[0], 0xFF, 6);
        idx++;

        *filter_count = idx;
    }

    return OK;
}

static int32_t nagra2_do_emm(struct s_reader *reader, EMM_PACKET *ep)
{
    def_resp;
    struct nagra_data *csystem_data = reader->csystem_data;
    if (!csystem_data->is_tiger)
    {
        if (!do_cmd(reader, ep->emm[8], ep->emm[9] + 2, 0x84, 0x02, ep->emm + 8 + 2, cta_res, &cta_lr))
        {
            rdr_debug_mask(reader, D_READER, "nagra2_do_emm failed");
            return ERROR;
        }
        // for slow t14 nagra cards, we must do additional timeout
        if (csystem_data->is_pure_nagra == 1)
        {
            cs_sleepms(300);
        }
        cs_sleepms(250);
        nagra2_post_process(reader);
    }
    else
    {
        //check EMM prov id
        if (memcmp(&reader->prid[0][2], ep->emm + 10, 2))
            return ERROR;

        //   emm_data: 82 70 8E 00 00 00 00 00 D3 87 8D 11 C0 F4 B1 27 2C 3D 25 94 ...
        //serial_data: A0 CA 00 00 8C D3 8A 01 00 00 00 00 C0 F4 B1 27 2C 3D 25 94 ...
        unsigned char emm_trim[150] = { 0x01, 0x00, 0x00, 0x00, 0x00 };
        memcpy(&emm_trim[5], ep->emm + 3 + 5 + 2 + 2, ep->emm[9] + 2);
        if (!do_cmd(reader, ep->emm[8], ep->emm[9] + 5, 0x53, 0x16, emm_trim, cta_res, &cta_lr))
        {
            rdr_debug_mask(reader, D_READER, "nagra2_do_emm failed");
            return ERROR;
        }
        cs_sleepms(300);
    }
    return OK;
}

void reader_nagra(struct s_cardsystem *ph)
{
    ph->do_emm = nagra2_do_emm;
    ph->do_ecm = nagra2_do_ecm;
    ph->post_process = nagra2_post_process;
    ph->card_info = nagra2_card_info;
    ph->card_init = nagra2_card_init;
    ph->get_emm_type = nagra2_get_emm_type;
    ph->get_emm_filter = nagra2_get_emm_filter;
    ph->caids[0] = 0x18;
    ph->desc = "nagra";
}
#endif
