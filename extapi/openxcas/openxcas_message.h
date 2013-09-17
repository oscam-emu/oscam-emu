#ifndef __OPENXCAS_MESSAGE_H__
#define __OPENXCAS_MESSAGE_H__

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef TRUE
#define TRUE  (!FALSE)
#endif

#define OPENXCAS_VERSION        "1.5.0"

#define OPENXCAS_MODULE_MAX       8
#define OPENXCAS_MODULE_NAME_LEN    32
#define OPENXCAS_DAEMON_NAME_LEN    64
#define OPENXCAS_PATH_LEN       128
#define OPENXCAS_VERSION_LEN      32

#define OPENXCAS_SECTION_LEN      4096

enum eOPENXCAS_STREAM_ID {
  OPENXCAS_STREAM_1 = 0,
  OPENXCAS_STREAM_2,
  OPENXCAS_STREAM_MAX,
};

enum eECMKEYTYPE {
  ECM_KEY_UNKNOWN = 0,
  ECM_KEY_EVEN_ODD,
  ECM_KEY_EVEN,
  ECM_KEY_ODD,
};

enum eOPENXCAS_COMMAND {
  OPENXCAS_UKNOWN_MSG = 0,

  /* OpenXCAS manager --> OpenXCAS module */
  OPENXCAS_SELECT_CHANNEL = 100,
  OPENXCAS_START_PMT_ECM,
  OPENXCAS_STOP_PMT_ECM,
  OPENXCAS_START_CAT_EMM,
  OPENXCAS_STOP_CAT_EMM,
  OPENXCAS_ECM_CALLBACK,
  OPENXCAS_EMM_CALLBACK,
  OPENXCAS_QUIT,
  OPENXCAS_BIG_MSG_FROM_MANAGER,
  OPENXCAS_SMALL_MSG_FROM_MANAGER,

  /* OpenXCAS module --> OpenXCAS manager */
  OPENXCAS_START_ECM_FILTER = 200,
  OPENXCAS_STOP_ECM_FILTER,
  OPENXCAS_START_EMM_FILTER,
  OPENXCAS_STOP_EMM_FILTER,
  OPENXCAS_SET_KEY,
  OPENXCAS_KEY_NOT_FOUND,
  OPENXCAS_TERMINATED,
  OPENXCAS_BIG_MSG_FROM_MODULE,
  OPENXCAS_SMALL_MSG_FROM_MODULE,

  /* API v2.0 */
  /* OpenXCAS manager --> OpenXCAS module */
  OPENXCAS_PID_FILTER_CALLBACK = 300,

  /* OpenXCAS module --> OpenXCAS manager */
  OPENXCAS_START_PID_FILTER = 400,
  OPENXCAS_STOP_PID_FILTER,
  OPENXCAS_CREATE_CIPHER,
  OPENXCAS_DESTROY_CIPHER,
  OPENXCAS_SET_KEY_V2,

  /*
   * COMMAND 1XXX : reserved for sending internal message in module
   * example: use for smartcard
   *
   */
  OPENXCAS_PRIVIATE_CMD_START = 1000,
};

/* section buf + header info */
#define OPENXCAS_MSG_MAX_LEN    (OPENXCAS_SECTION_LEN + 36)


typedef void (*filter_callback) (int stream_id, unsigned int sequence, int filter_index, unsigned short pid, unsigned char *pBuf, int size);

typedef void (*ecmemm_callback) (int stream_id, unsigned int sequence, int cipher_index, unsigned int ca_system_id, unsigned char *pEcm, int Len, unsigned short pid);

typedef struct stOpenCASMessage {
  long mtype;   /* do not touch, used by message queue */

  int stream_id;
  unsigned int sequence;

  int cmd;

  int buf_len;
  unsigned char buf[OPENXCAS_MSG_MAX_LEN];
} openxcas_msg_t;

#pragma pack(1)

struct stOpenXCAS_Data {
  unsigned short ca_system_id;
  unsigned short cipher_index;
  unsigned short pid;

  int filter_index;

  int len;
  unsigned char buf[OPENXCAS_SECTION_LEN];
};

struct stOpenXCASChannel {
  /* If current av is transtered from satellite,
   * latitude & polarisation is meaningful.
   * If polarisation is (-1), channel source is unknown
   * If polarisation is (-2), channel source is DVB-T
   * If polarisation is (-3), channel source is DVB-C
   * If polarisation is (-4), channel source is ATSC
   * If polarisation is (-5), channel source is ISDB-T
   * If polarisation is 0, then DVB-S(horizontal)
   * If polarisation is 1, then DVB-S(vertical)
   */
  int polarisation;
  short latitude;

  unsigned long frequency;

  unsigned short service_id;

  unsigned short v_pid;
  unsigned short a_pid;
  unsigned short d_pid;
};

#pragma pack()

#endif
