/*
 *  Created on: 23.04.2010
 *      Author: alno
 */
#ifndef MODULE_CCCAM_DATA_H_
#define MODULE_CCCAM_DATA_H_

#include "cscrypt/rc6.h"
#include "cscrypt/idea.h"

#define CAID_KEY 0x20

#define CC_MAXMSGSIZE 0x400 //by Project::Keynation: Buffer size is limited on "O" CCCam to 1024 bytes
#define CC_MAX_PROV   32
#define SWAPC(X, Y) do { char p; p = *X; *X = *Y; *Y = p; } while(0)

#if (defined(WIN32) || defined(__CYGWIN__)) && !defined(MSG_WAITALL)
#  define MSG_WAITALL 0
#endif

#define MINIMIZE_NONE 0
#define MINIMIZE_HOPS 1
#define MINIMIZE_CAID 2
#define MINIMIZE_TRANSPARENT 3

#define CCCAM_MODE_NOTINIT 0
#define CCCAM_MODE_NORMAL 1
#define CCCAM_MODE_SHUTDOWN 0xFF

#define QUITERROR 1

#define MIN_RATING -25
#define MAX_RATING 25

#define HOP_RATING 5

typedef enum {
	DECRYPT, ENCRYPT
} cc_crypt_mode_t;

typedef enum {
	MSG_CLI_DATA = 0,
	MSG_CW_ECM = 1,
	MSG_EMM_ACK = 2,
	MSG_CARD_REMOVED = 4,
	MSG_CMD_05 = 5,
	MSG_KEEPALIVE = 6,
	MSG_NEW_CARD = 7,
	MSG_SRV_DATA = 8,
	MSG_CMD_0A = 0x0a,
	MSG_CMD_0B = 0x0b,
	MSG_CMD_0C = 0x0c, // CCCam 2.2.x fake client checks
	MSG_CMD_0D = 0x0d, // "
	MSG_CMD_0E = 0x0e, // "
	MSG_NEW_CARD_SIDINFO = 0x0f,
	MSG_SLEEPSEND = 0x80, //Sleepsend support
	MSG_CACHE_PUSH = 0x81, //CacheEx Cache-Push In/Out
	MSG_CW_NOK1 = 0xfe, //Node no more available
	MSG_CW_NOK2 = 0xff, //No decoding
	MSG_NO_HEADER = 0xffff
} cc_msg_type_t;

struct cc_crypt_block {
	uint8_t keytable[256];
	uint8_t state;
	uint8_t counter;
	uint8_t sum;
};

struct cc_srvid {
	uint16_t sid;
	uint16_t chid;
	uint8_t ecmlen;
};

struct cc_srvid_block {
	uint16_t sid;
	uint16_t chid;
	uint8_t  ecmlen;
	time_t   blocked_till;
};

struct cc_provider {
	uint32_t prov;  //provider
	uint8_t sa[4]; //shared address
};

typedef enum {
	CT_LOCALCARD = 1,
	CT_CARD_BY_SERVICE_READER = 2,
	CT_CARD_BY_SERVICE_USER = 3,
	CT_CARD_BY_CAID1 = 4,
	CT_CARD_BY_CAID2 = 5,
	CT_CARD_BY_CAID3 = 6,
	CT_REMOTECARD = 10
} cc_card_type;

struct cc_card {
	uint32_t id; // cccam card (share) id - reader
	uint32_t remote_id;
	uint16_t caid;
	uint8_t hop;
	uint8_t reshare;
	uint8_t hexserial[8]; // card serial (for au)
	LLIST *providers; // providers (struct cc_provider)
	LLIST *badsids; // sids that have failed to decode (struct cc_srvid)
	LLIST *goodsids; //sids that could decoded (struct cc_srvid)
	LLIST *remote_nodes; //remote note id, 8 bytes
	struct s_reader  *origin_reader;
	uint32_t origin_id;
	cc_card_type card_type;
	int8_t aufilter;
	struct s_sidtab *sidtab; //pointer to sidtab entry if card_type = CT_CARD_BY_SERVICE
	uint64_t grp;
	uint8_t rdr_reshare;
	SIDTABBITS sidtabno;
	time_t timeout;
	uint8_t is_ext;
	int8_t rating;
};

typedef enum {
	MODE_UNKNOWN = 0,
	MODE_PLAIN = 1,
	MODE_AES = 2,
	MODE_CC_CRYPT = 3,
	MODE_RC4_CRYPT = 4,
	MODE_LEN0 = 5,
} cc_cmd05_mode;

typedef enum {
	MODE_CMD_0x0C_NONE = 0,
	MODE_CMD_0x0C_RC6 = 1,
	MODE_CMD_0x0C_RC4 = 2,
	MODE_CMD_0x0C_CC_CRYPT = 3,
	MODE_CMD_0x0C_AES = 4,
	MODE_CMD_0x0C_IDEA = 5,
} cc_cmd0c_mode;


struct cc_extended_ecm_idx {
	uint8_t send_idx;
	uint16_t ecm_idx;
	struct cc_card *card;
	struct cc_srvid srvid;
	uint8_t free_card;
	struct timeb	tps;
	uint32_t cccam_id;
};

struct cc_data {
	uint8_t g_flag;
	char *prefix;

	struct cc_crypt_block block[2]; // crypto state blocks

	uint8_t node_id[8], // client node id
		peer_node_id[8], // server node id
		peer_version[8], // server version
		dcw[16]; // control words
	uint8_t cmd0b_aeskey[16];
	uint8_t cmd05_aeskey[16];
	struct cc_crypt_block cmd05_cryptkey;

	uint8_t is_oscam_cccam;
	uint8_t cmd05_active;
	int32_t cmd05_data_len;
	uint8_t cmd05_data[256];
	cc_cmd05_mode cmd05_mode;
	int32_t cmd05_offset;

	cc_cmd0c_mode cmd0c_mode;
	struct cc_crypt_block cmd0c_cryptkey;
	RC6KEY cmd0c_RC6_cryptkey;
	AES_KEY cmd0c_AES_key;
	IDEA_KEY_SCHEDULE cmd0c_IDEA_dkey;

	uint8_t receive_buffer[CC_MAXMSGSIZE];
	uint8_t send_buffer[CC_MAXMSGSIZE];

	LLIST *cards; // cards list

	int32_t max_ecms;
	int32_t ecm_counter;
	int32_t card_added_count;
	int32_t card_removed_count;
	uint8_t just_logged_in; //true for checking NOK direct after login
	uint8_t key_table; //key for CMD 0B

	LLIST *pending_emms; //pending emm list

	uint32_t recv_ecmtask;

	struct cc_card *last_emm_card;
	int32_t server_ecm_pending;                    //initialized by server
	uint16_t server_ecm_idx;

	CS_MUTEX_LOCK lockcmd;
	int8_t ecm_busy;
	CS_MUTEX_LOCK cards_busy;
	struct timeb ecm_time;
	time_t answer_on_keepalive;
	uint8_t last_msg;
	uint8_t cmd05NOK;

	char remote_version[7];
	char remote_build[7];
	char remote_oscam[200];

	uint8_t cccam220;
	uint32_t remote_build_nr;
	uint8_t sleepsend;

	//Extended Mode for SPECIAL clients:
	uint8_t extended_mode;
	LLIST *extended_ecm_idx;

	//stats:
	int32_t num_hop1;
	int32_t num_hop2;
	int32_t num_hopx;

	int32_t num_reshare0;
	int32_t num_reshare1;
	int32_t num_reshare2;
	int32_t num_resharex;

	char* nok_message;
};

#endif
