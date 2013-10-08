#ifndef MODULE_DVBAPI_STAPI_H_
#define MODULE_DVBAPI_STAPI_H_

#include "module-dvbapi.h"

struct STDEVICE
{
	char name[20];
	uint32_t SessionHandle;
	uint32_t SignalHandle;
	pthread_t thread;
	struct filter_s demux_fd[MAX_DEMUX][MAX_FILTER];
};

struct read_thread_param
{
	int32_t id;
	struct s_client *cli;
};

#define BUFFLEN 1024
#define PROCDIR "/proc/stpti4_core/"

/* These functions are in liboscam_stapi.a */
extern uint32_t oscam_stapi_Capability(char *name);
extern char *oscam_stapi_LibVersion(void);
extern uint32_t oscam_stapi_Open(char *name, uint32_t *sessionhandle);
extern uint32_t oscam_stapi_SignalAllocate(uint32_t sessionhandle, uint32_t *signalhandle);
extern uint32_t oscam_stapi_FilterAllocate(uint32_t sessionhandle, uint32_t *filterhandle);
extern uint32_t oscam_stapi_SlotInit(uint32_t sessionhandle, uint32_t signalhandle, uint32_t *bufferhandle, uint32_t *slothandle, uint16_t pid);
extern uint32_t oscam_stapi_FilterSet(uint32_t filterhandle, uchar *filt, uchar *mask);
extern uint32_t oscam_stapi_FilterAssociate(uint32_t filterhandle, uint32_t slothandle);
extern uint32_t oscam_stapi_SlotDeallocate(uint32_t slothandle);
extern uint32_t oscam_stapi_BufferDeallocate(uint32_t bufferhandle);
extern uint32_t oscam_stapi_FilterDeallocate(uint32_t filterhandle);
extern uint32_t oscam_stapi_Close(uint32_t sessionhandle);
extern uint32_t oscam_stapi_CheckVersion(void);
extern uint32_t oscam_stapi_DescramblerAssociate(uint32_t deschandle, uint32_t slot);
extern uint32_t oscam_stapi_DescramblerDisassociate(uint32_t deschandle, uint32_t slot);
extern uint32_t oscam_stapi_DescramblerAllocate(uint32_t sessionhandle, uint32_t *deschandle);
extern uint32_t oscam_stapi_DescramblerDeallocate(uint32_t deschandle);
extern uint32_t oscam_stapi_DescramblerSet(uint32_t deschandle, int32_t parity, uchar *cw);
extern uint32_t oscam_stapi_SignalWaitBuffer(uint32_t signalhandle, uint32_t *qbuffer, int32_t timeout);
extern uint32_t oscam_stapi_BufferReadSection(uint32_t bufferhandle, uint32_t *filterlist, int32_t maxfilter, uint32_t *filtercount, int32_t *crc, uchar *buf, int32_t bufsize, uint32_t *size);
extern uint32_t oscam_stapi_SignalAbort(uint32_t signalhandle);
extern uint32_t oscam_stapi_PidQuery(char *name, uint16_t pid);
extern uint32_t oscam_stapi_BufferFlush(uint32_t bufferhandle);
extern uint32_t oscam_stapi_SlotClearPid(uint32_t slot);

int32_t stapi_open(void);
int32_t stapi_set_filter(int32_t demux_id, uint16_t pid, uchar *filter, uchar *mask, int32_t num, char *pmtfile);
int32_t stapi_remove_filter(int32_t demux_id, int32_t num, char *pmtfile);
int32_t stapi_set_pid(int32_t demux_id, int32_t num, int32_t idx, uint16_t pid, char *pmtfile);
int32_t stapi_write_cw(int32_t demux_id, uchar *cw, uint16_t *, int32_t, char *pmtfile);
int32_t stapi_do_set_filter(int32_t demux_id, FILTERTYPE *filter, uint16_t *pids, int32_t pidcount, uchar *filt, uchar *mask, int32_t dev_id);
int32_t stapi_do_remove_filter(int32_t demux_id, FILTERTYPE *filter, int32_t dev_id);
void *stapi_read_thread(void *);

#endif
