#ifndef _MODULE_MCA_H_
#define _MODULE_MCA_H_

#include "extapi/openxcas/openxcas_message.h"

#define MCA_DVBI "/tmp/mdvbi"
#define MCA_DESC "/tmp/mdesc"
#define MCA_FLT  "/tmp/mflt"

enum eOPENXCAS_FILTER_TYPE {
  OPENXCAS_FILTER_UNKNOWN = 0,
  OPENXCAS_FILTER_ECM,
  OPENXCAS_FILTER_EMM,
};

#define ECM_PIDS_MATRIX 20
#define MAX_FILTER_MATRIX 10

struct s_ecmpids_matrix
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t ECM_PID;
	uint16_t EMM_PID;
	int32_t irdeto_maxindex;
	int32_t irdeto_curindex;
	int32_t irdeto_cycle;
	int32_t checked;
	int32_t status;
	unsigned char table;
	int32_t index;
	uint32_t streams;
};

typedef struct filter_s_matrix
{
	uint32_t fd; //FilterHandle
	int32_t pidindex;
	int32_t pid;
	uint16_t type;
	int32_t count;
} FILTERTYPE_MATRIX;

struct s_emmpids_matrix
{
	uint16_t CAID;
	uint32_t PROVID;
	uint16_t PID;
	uint8_t type;
};

typedef struct demux_s_matrix
{
	int32_t demux_index;
	FILTERTYPE_MATRIX demux_fd[MAX_FILTER_MATRIX];
	int32_t ca_mask;
	int32_t adapter_index;
	int32_t socket_fd;
	int32_t ECMpidcount;
	struct s_ecmpids_matrix ECMpids[ECM_PIDS_MATRIX];
	int32_t EMMpidcount;
	struct s_emmpids_matrix EMMpids[ECM_PIDS_MATRIX];
	int32_t STREAMpidcount;
	uint16_t STREAMpids[ECM_PIDS_MATRIX];
	int32_t pidindex;
	int32_t curindex;
	int32_t tries;
	int32_t max_status;
	uint16_t program_number;
	unsigned char lastcw[2][8];
	int32_t emm_filter;
	uchar hexserial[8];
	struct s_reader *rdr;
	char pmt_file[30];
	int32_t pmt_time;
} DEMUXMATRIX;

int mca_open(void);
int mca_exit(void);
int mca_get_message(openxcas_msg_t * message, int timeout);
int mca_write_flt(DEMUXMATRIX * demux_matrix, int timeout);
int mca_set_key(unsigned char * mca_cw);
int mca_capmt_remove_duplicates(uchar *capmt, int len);

void mca_ecm_callback(int32_t stream_id, uint32_t sequence, int32_t cipher_index, uint32_t caid, unsigned char *ecm_data, int32_t l, uint16_t pid);
void mca_ex_callback(int32_t stream_id, uint32_t seq, int32_t idx, uint32_t pid, unsigned char *ecm_data, int32_t l);
void mca_send_dcw(struct s_client *client, ECM_REQUEST *er);

void * mca_main_thread(void * cli);

#if defined(HAVE_DVBAPI) && defined(WITH_MCA)
void mca_init(void);
void mca_close(void);
#else
static inline void mca_init(void) { }
static inline void mca_close(void) { }
#endif

#endif
