#ifndef __OPENXCAS_API_H__
#define __OPENXCAS_API_H__

#include "openxcas_message.h"
#include "openxcas_smartcard.h"

/*
 * Be careful! This API is not safe in multi-process
 *
 */

enum eOPENXCAS_FILTER_TYPE {
  OPENXCAS_FILTER_UNKNOWN = 0,
  OPENXCAS_FILTER_ECM,
  OPENXCAS_FILTER_EMM,
};

#ifdef __cplusplus
extern "C" {
#endif

/* This function will be used for checking compatibility with API
 * After printing information, it is terminated automatically
 * Be careful! Module name & version info should set exactly
 */
void openxcas_show_info_and_exit(char * module_name, char * version_info);

/* RETURN VALUE: status
 * -1 : error
 *  0 : success
 */
int openxcas_open(char * module_name);

/* RETURN VALUE: status
 * -1 : error
 *  0 : success
 */
int openxcas_open_with_smartcard(char * module_name);

/* RETURN VALUE: status
 * -1 : error
 *  0 : success
 */
int openxcas_close(void);

/*
 * This function should be called after opening openxcas
 */
void openxcas_debug_message_onoff(int bVerbose);

/* RETURN VALUE: device fd
 * -1 : error
 *  >0 : success
 */
int openxcas_get_smartcard_device(unsigned int idx);

/* RETURN VALUE: status
 * -1 : error
 *  0 : success
 */
int openxcas_release_smartcard_device(unsigned int idx);


/* RETURN VALUE: status
 *  path of working directory
 *
 */
char * openxcas_get_working_directory(void);

/* RETURN VALUE: status
 * -1 : error
 *  0 : timeout
 *  1 : success
 */
int openxcas_get_message(openxcas_msg_t * message, int wait_time);

/* RETURN VALUE: status
 * -1 : error
 *  0 : timeout
 *  1 : success
 */
int openxcas_put_message(int streamd_id, unsigned int sequence,
    int msg_type, unsigned char *msg_buf, unsigned int msg_size);

/*
 * DVB-CSA Key API
 *
 */

/* RETURN VALUE: status
 * -1 : error
 *  0 : timeout
 *  1 : success
 */
int openxcas_set_key(int stream_id, unsigned int sequence,
    unsigned short ca_system_id, unsigned short cipher_index,
    unsigned char * even, unsigned char * odd);

/* RETURN VALUE: status
 * -1 : error
 *  0 : timeout
 *  1 : success
 *
 * Be careful!
 * If you call this function,
 * all filter information is reset(same to call openxcas_remove_filter)
 */
int openxcas_key_not_found(int stream_id, unsigned int sequence);


/* for ADAPTOR */

/*
 * Filter API
 * Use for ECM & EMM
 *
 */

/* RETURN VALUE: filter_index
 * -1   : error
 * >= 0 : success
 */
int openxcas_add_filter(int stream_id,
    int type, unsigned short ca_system_id,
    unsigned short target_pid, unsigned short pid,
    unsigned char * mask, unsigned char * comp,
    ecmemm_callback callback_func);

/* RETURN VALUE: status
 * -1 : error
 *  0 : timeout
 *  1 : success
 */
int openxcas_start_filter(int stream_id, unsigned int sequence, int type);

/* RETURN VALUE: status
 * -1 : error
 *  0 : timeout
 *  1 : success
 */
int openxcas_stop_filter(int stream_id, int type);

/* RETURN VALUE: status
 * -1 : error
 *  0 : success
 */
int openxcas_remove_filter(int stream_id, int type);

/* RETURN VALUE: status
 * -1 : error
 *  0 : success
 */
int openxcas_filter_callback(int stream_id, unsigned int sequence, int type,
    struct stOpenXCAS_Data * openxcas_data);


int openxcas_send_private_message(int stream_id, unsigned int sequence, int msg_type,
      unsigned char *msg_buf, unsigned int msg_size);


const char * openxcas_get_time(void);













/* RETURN VALUE: filter_index
 * -1   : error
 * >= 0 : success
 */
int openxcas_start_filter_ex(int stream_id, unsigned int sequence,
    unsigned short pid, unsigned char * mask, unsigned char * comp,
    filter_callback callback_func);

/* RETURN VALUE: status
 * -1 : error
 *  0 : success
 */
int openxcas_stop_filter_ex(int stream_id, unsigned int sequence,
      int filter_index);


int openxcas_filter_callback_ex(int stream_id, unsigned int sequence,
    struct stOpenXCAS_Data * openxcas_data);

/* RETURN VALUE: status
 * -1 : error
 *  0 : timeout
 *  1 : success
 */
int openxcas_create_cipher_ex(int stream_id, unsigned int sequence,
    unsigned short ca_system_id,
    unsigned short ecm_pid,
    unsigned short video_pid, unsigned short video_ecm_pid,
    unsigned short audio_pid, unsigned short audio_ecm_pid,
    unsigned short data_pid, unsigned short data_ecm_pid);

/* RETURN VALUE: status
 * -1 : error
 *  0 : timeout
 *  1 : success
 */
int openxcas_destory_cipher_ex(int stream_id, unsigned int sequence);

/* RETURN VALUE: status
 * -1 : error
 *  0 : timeout
 *  1 : success
 */
int openxcas_set_key_ex(int stream_id, unsigned int sequence,
    unsigned short ca_system_id,
    unsigned short ecm_pid,
    unsigned char * even, unsigned char * odd);


#ifdef __cplusplus
}
#endif

#endif
