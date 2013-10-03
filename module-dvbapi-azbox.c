#include "globals.h"

#if defined(HAVE_DVBAPI) && defined(WITH_AZBOX)

#include "extapi/openxcas/openxcas_api.h"
#include "extapi/openxcas/openxcas_message.h"

#define DVBAPI_LOG_PREFIX 1
#include "module-dvbapi.h"
#include "module-dvbapi-azbox.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"

#define LOG_PREFIX "openxcas: "
#define LOG_PREFIX_MSG "openxcasmsg: "

// These variables are declared in module-dvbapi.c
extern void *dvbapi_client;
extern DEMUXTYPE demux[MAX_DEMUX];

// These are used in module-dvbapi.c
int32_t openxcas_provid;
uint16_t openxcas_sid, openxcas_caid, openxcas_ecm_pid;

static unsigned char openxcas_cw[16];
static int32_t openxcas_seq, openxcas_filter_idx, openxcas_stream_id, openxcas_cipher_idx, openxcas_busy = 0;
static uint16_t openxcas_video_pid, openxcas_audio_pid, openxcas_data_pid;

void azbox_openxcas_ecm_callback(int32_t stream_id, uint32_t UNUSED(seq), int32_t cipher_index, uint32_t UNUSED(caid), unsigned char *ecm_data, int32_t l, uint16_t pid)
{
    cs_debug_mask(D_DVBAPI, LOG_PREFIX "ecm callback received");

    openxcas_stream_id = stream_id;
    //openxcas_seq = seq;
    //openxcas_caid = caid;
    openxcas_ecm_pid = pid;
    openxcas_busy = 1;

    ECM_REQUEST *er;
    if (!(er = get_ecmtask()))
        return;

    er->srvid = openxcas_sid;
    er->caid  = openxcas_caid;
    er->pid   = openxcas_ecm_pid;
    er->prid  = openxcas_provid;

    er->ecmlen = l;
    memcpy(er->ecm, ecm_data, er->ecmlen);

    request_cw(dvbapi_client, er, 0, 0);

    //openxcas_stop_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);
    //openxcas_remove_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);

    openxcas_cipher_idx = cipher_index;

    struct timeb tp;
    cs_ftime(&tp);
    tp.time += 500;
}


void azbox_openxcas_ex_callback(int32_t stream_id, uint32_t seq, int32_t idx, uint32_t pid, unsigned char *ecm_data, int32_t l)
{
    cs_debug_mask(D_DVBAPI, LOG_PREFIX "ex callback received");

    openxcas_stream_id = stream_id;
    openxcas_ecm_pid = pid;
    openxcas_cipher_idx = idx; // is this really cipher_idx?

    ECM_REQUEST *er;
    if (!(er = get_ecmtask()))
        return;

    er->srvid = openxcas_sid;
    er->caid  = openxcas_caid;
    er->pid   = openxcas_ecm_pid;
    er->prid  = openxcas_provid;

    er->ecmlen = l;
    memcpy(er->ecm, ecm_data, er->ecmlen);

    request_cw(dvbapi_client, er, 0, 0);

    if (openxcas_stop_filter_ex(stream_id, seq, openxcas_filter_idx) < 0)
        cs_log(LOG_PREFIX "unable to stop ex filter");
    else
        cs_debug_mask(D_DVBAPI, LOG_PREFIX "ex filter stopped");



    unsigned char mask[12];
    unsigned char comp[12];
    memset(&mask, 0x00, sizeof(mask));
    memset(&comp, 0x00, sizeof(comp));

    mask[0] = 0xff;
    comp[0] = ecm_data[0] ^ 1;

    if ((openxcas_filter_idx = openxcas_start_filter_ex(stream_id, seq, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ex_callback)) < 0)
        cs_log(LOG_PREFIX "unable to start ex filter");
    else
        cs_debug_mask(D_DVBAPI, LOG_PREFIX "ex filter started, pid = %x", openxcas_ecm_pid);
}

void *azbox_main_thread(void *cli)
{
    struct s_client *client = (struct s_client *) cli;
    client->thread = pthread_self();
    pthread_setspecific(getclient, cli);
    dvbapi_client = cli;

    struct s_auth *account;
    int32_t ok = 0;
    for (account = cfg.account; account; account = account->next)
    {
        if ((ok = streq(cfg.dvbapi_usr, account->usr)))
            break;
    }
    cs_auth_client(client, ok ? account : (struct s_auth *)(-1), "dvbapi");

    dvbapi_read_priority();

    openxcas_msg_t msg;
    int32_t ret;
    while ((ret = openxcas_get_message(&msg, 0)) >= 0)
    {
        cs_sleepms(10);

        if (ret)
        {
            openxcas_stream_id = msg.stream_id;
            openxcas_seq = msg.sequence;

            switch (msg.cmd)
            {
            case OPENXCAS_SELECT_CHANNEL:
                cs_debug_mask(D_DVBAPI, LOG_PREFIX_MSG "OPENXCAS_SELECT_CHANNEL");

                // parse channel info
                struct stOpenXCASChannel chan;
                memcpy(&chan, msg.buf, msg.buf_len);

                cs_log(LOG_PREFIX "channel change: sid = %x, vpid = %x. apid = %x", chan.service_id, chan.v_pid, chan.a_pid);

                openxcas_video_pid = chan.v_pid;
                openxcas_audio_pid = chan.a_pid;
                openxcas_data_pid = chan.d_pid;
                break;
            case OPENXCAS_START_PMT_ECM:
                cs_debug_mask(D_DVBAPI, LOG_PREFIX_MSG "OPENXCAS_START_PMT_ECM");

                // parse pmt
                uchar *dest;
                if (!cs_malloc(&dest, msg.buf_len + 7 - 12 - 4))
                    break;

                memcpy(dest, "\x00\xFF\xFF\x00\x00\x13\x00", 7);

                dest[1] = msg.buf[3];
                dest[2] = msg.buf[4];
                dest[5] = msg.buf[11] + 1;

                memcpy(dest + 7, msg.buf + 12, msg.buf_len - 12 - 4);

                dvbapi_parse_capmt(dest, 7 + msg.buf_len - 12 - 4, -1, NULL);
                free(dest);

                unsigned char mask[12];
                unsigned char comp[12];
                memset(&mask, 0x00, sizeof(mask));
                memset(&comp, 0x00, sizeof(comp));

                mask[0] = 0xfe;
                comp[0] = 0x80;

                if ((ret = openxcas_add_filter(msg.stream_id, OPENXCAS_FILTER_ECM, 0, 0xffff, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ecm_callback)) < 0)
                    cs_log(LOG_PREFIX "unable to add ecm filter");
                else
                    cs_debug_mask(D_DVBAPI, LOG_PREFIX "ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, 0);

                if (openxcas_start_filter(msg.stream_id, msg.sequence, OPENXCAS_FILTER_ECM) < 0)
                    cs_log(LOG_PREFIX "unable to start ecm filter");
                else
                    cs_debug_mask(D_DVBAPI, LOG_PREFIX "ecm filter started");

                if (!openxcas_create_cipher_ex(msg.stream_id, openxcas_seq, 0, openxcas_ecm_pid, openxcas_video_pid, 0xffff, openxcas_audio_pid, 0xffff, 0xffff, 0xffff))
                    cs_log(LOG_PREFIX "failed to create cipher ex");
                else
                    cs_debug_mask(D_DVBAPI, LOG_PREFIX "cipher created");
                break;
            case OPENXCAS_STOP_PMT_ECM:
                cs_debug_mask(D_DVBAPI, LOG_PREFIX_MSG "OPENXCAS_STOP_PMT_ECM");
                openxcas_stop_filter(msg.stream_id, OPENXCAS_FILTER_ECM);
                openxcas_remove_filter(msg.stream_id, OPENXCAS_FILTER_ECM);
                openxcas_stop_filter_ex(msg.stream_id, msg.sequence, openxcas_filter_idx);
                openxcas_destory_cipher_ex(msg.stream_id, msg.sequence);
                memset(&demux, 0, sizeof(demux));
                break;
            case OPENXCAS_ECM_CALLBACK:
                cs_debug_mask(D_DVBAPI, LOG_PREFIX_MSG "OPENXCAS_ECM_CALLBACK");
                struct stOpenXCAS_Data data;
                memcpy(&data, msg.buf, msg.buf_len);
                if (!openxcas_busy)
                    openxcas_filter_callback(msg.stream_id, msg.sequence, OPENXCAS_FILTER_ECM, &data);
                break;
            case OPENXCAS_PID_FILTER_CALLBACK:
                cs_debug_mask(D_DVBAPI, LOG_PREFIX_MSG "OPENXCAS_PID_FILTER_CALLBACK");
                openxcas_filter_callback_ex(msg.stream_id, msg.sequence, (struct stOpenXCAS_Data *)msg.buf);
                break;
            case OPENXCAS_QUIT:
                cs_debug_mask(D_DVBAPI, LOG_PREFIX_MSG "OPENXCAS_QUIT");
                openxcas_close();
                cs_log(LOG_PREFIX "exited");
                return NULL;
                break;
            case OPENXCAS_UKNOWN_MSG:
            default:
                cs_debug_mask(D_DVBAPI, LOG_PREFIX_MSG "OPENXCAS_UKNOWN_MSG (%d)", msg.cmd);
                //cs_ddump_mask(D_DVBAPI, &msg, sizeof(msg), "msg dump:");
                break;
            }
        }
    }
    cs_log(LOG_PREFIX "invalid message");
    return NULL;
}

void azbox_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
    cs_debug_mask(D_DVBAPI, LOG_PREFIX "send_dcw");

    FILE *ecmtxt;
    if ((ecmtxt = fopen(ECMINFO_FILE, "w")))
    {
        char tmp[25];
        if (er->rc <= E_CACHEEX)
        {
            fprintf(ecmtxt, "caid: 0x%04X\npid: 0x%04X\nprov: 0x%06X\n", er->caid, er->pid, (uint) er->prid);
            fprintf(ecmtxt, "reader: %s\n", er->selected_reader->label);
            if (is_cascading_reader(er->selected_reader))
                fprintf(ecmtxt, "from: %s\n", er->selected_reader->device);
            else
                fprintf(ecmtxt, "from: local\n");
            fprintf(ecmtxt, "protocol: %s\n", reader_get_type_desc(er->selected_reader, 1));
            fprintf(ecmtxt, "hops: %d\n", er->selected_reader->currenthops);
            fprintf(ecmtxt, "ecm time: %.3f\n", (float) client->cwlastresptime / 1000);
            fprintf(ecmtxt, "cw0: %s\n", cs_hexdump(1, demux[0].lastcw[0], 8, tmp, sizeof(tmp)));
            fprintf(ecmtxt, "cw1: %s\n", cs_hexdump(1, demux[0].lastcw[1], 8, tmp, sizeof(tmp)));
            fclose(ecmtxt);
            ecmtxt = NULL;
        }
        else
        {
            fprintf(ecmtxt, "ECM information not found\n");
            fclose(ecmtxt);
        }
    }

    openxcas_busy = 0;

    int32_t i;
    for (i = 0; i < MAX_DEMUX; i++)
    {
        if (er->rc >= E_NOTFOUND)
        {
            cs_debug_mask(D_DVBAPI, "cw not found");

            if (demux[i].pidindex == -1)
                dvbapi_try_next_caid(i, 0);

            openxcas_stop_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);
            openxcas_remove_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM);

            unsigned char mask[12];
            unsigned char comp[12];
            memset(&mask, 0x00, sizeof(mask));
            memset(&comp, 0x00, sizeof(comp));

            mask[0] = 0xfe;
            comp[0] = 0x80;

            if (openxcas_add_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM, 0, 0xffff, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ecm_callback) < 0)
            {
                cs_log(LOG_PREFIX "unable to add ecm filter (0)");
                if (openxcas_add_filter(openxcas_stream_id, OPENXCAS_FILTER_ECM, openxcas_caid, 0xffff, openxcas_ecm_pid, mask, comp, (void *)azbox_openxcas_ecm_callback) < 0)
                    cs_log(LOG_PREFIX "unable to add ecm filter (%04x)", openxcas_caid);
                else
                    cs_debug_mask(D_DVBAPI, LOG_PREFIX "ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, openxcas_caid);
            }
            else
                cs_debug_mask(D_DVBAPI, LOG_PREFIX "ecm filter added, pid = %x, caid = %x", openxcas_ecm_pid, 0);

            if (openxcas_start_filter(openxcas_stream_id, openxcas_seq, OPENXCAS_FILTER_ECM) < 0)
                cs_log(LOG_PREFIX "unable to start ecm filter");
            else
                cs_debug_mask(D_DVBAPI, LOG_PREFIX "ecm filter started");

            return;
        }
    }

    unsigned char nullcw[8];
    memset(nullcw, 0, 8);

    int32_t n;
    for (n = 0; n < 2; n++)
    {
        if (memcmp(er->cw + (n * 8), demux[0].lastcw[n], 8) && memcmp(er->cw + (n * 8), nullcw, 8))
        {
            memcpy(demux[0].lastcw[n], er->cw + (n * 8), 8);
            memcpy(openxcas_cw + (n * 8), er->cw + (n * 8), 8);
        }
    }

    if (openxcas_set_key(openxcas_stream_id, openxcas_seq, 0, openxcas_cipher_idx, openxcas_cw, openxcas_cw + 8) != 1)
        cs_log(LOG_PREFIX "set cw failed");
    else
        cs_ddump_mask(D_DVBAPI, openxcas_cw, 16, LOG_PREFIX "write cws to descrambler");
}

#ifdef WITH_CARDREADER
#define __openxcas_open openxcas_open_with_smartcard
#else
#define __openxcas_open openxcas_open
#endif

void azbox_init(void)
{
    openxcas_debug_message_onoff(1);  // debug
    if (__openxcas_open("oscamCAS") < 0)
        cs_log(LOG_PREFIX "could not init");
}

void azbox_close(void)
{
    if (openxcas_close() < 0)
        cs_log(LOG_PREFIX "could not close");
}

#endif
