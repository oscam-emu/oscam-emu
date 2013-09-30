#include "globals.h"

#ifdef HAVE_DVBAPI

#include "module-dvbapi.h"
#include "module-cacheex.h"
#include "module-dvbapi-azbox.h"
#include "module-dvbapi-mca.h"
#include "module-dvbapi-coolapi.h"
#include "module-dvbapi-stapi.h"
#include "module-stat.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-config.h"
#include "oscam-ecm.h"
#include "oscam-emm.h"
#include "oscam-files.h"
#include "oscam-net.h"
#include "oscam-reader.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "reader-irdeto.h"

// tunemm_caid_map
#define FROM_TO 0
#define TO_FROM 1

// These are declared in module-dvbapi-mca.c
extern int32_t openxcas_provid;
extern uint16_t openxcas_sid, openxcas_caid, openxcas_ecm_pid;

int32_t pausecam = 0, disable_pmt_files=0, pmt_stopdescrambling_done = 0, pmt_stopmarking = 0, pmthandling = 0;
DEMUXTYPE demux[MAX_DEMUX];
struct s_dvbapi_priority *dvbapi_priority;
struct s_client *dvbapi_client;

const char *boxdesc[] = { "none", "dreambox", "duckbox", "ufs910", "dbox2", "ipbox", "ipbox-pmt", "dm7000", "qboxhd", "coolstream", "neumo", "pc" };

static const struct box_devices devices[BOX_COUNT] = {
	/* QboxHD (dvb-api-3)*/	{ "/tmp/virtual_adapter/", 	"ca%d",		"demux%d",			"/tmp/camd.socket", DVBAPI_3  },
	/* dreambox (dvb-api-3)*/	{ "/dev/dvb/adapter%d/",	"ca%d", 		"demux%d",			"/tmp/camd.socket", DVBAPI_3 },
	/* dreambox (dvb-api-1)*/	{ "/dev/dvb/card%d/",	"ca%d",		"demux%d",			"/tmp/camd.socket", DVBAPI_1 },
	/* neumo (dvb-api-1)*/	{ "/dev/",			"demuxapi",		"demuxapi",			"/tmp/camd.socket", DVBAPI_1 },
	/* sh4      (stapi)*/	{ "/dev/stapi/", 		"stpti4_ioctl",	"stpti4_ioctl",		"/tmp/camd.socket", STAPI },
	/* coolstream*/		{ "/dev/cnxt/", 		"null",		"null",			"/tmp/camd.socket", COOLAPI }
};

static int32_t selected_box=-1;
static int32_t selected_api=-1;
static int32_t dir_fd=-1;
static int32_t ca_fd[8];
static LLIST *channel_cache;

struct s_emm_filter {
	int32_t 	demux_id;
	uchar 		filter[32];
	uint16_t 	caid;
	uint32_t	provid;
	uint16_t	pid;
	int32_t 	count;
	uint32_t 	num;
	time_t 		time_started;
};

static LLIST *ll_emm_active_filter;
static LLIST *ll_emm_inactive_filter;
static LLIST *ll_emm_pending_filter;

struct s_channel_cache {
	uint16_t	caid;
	uint32_t 	prid;
	uint16_t	srvid;
	uint16_t	pid;
	uint32_t	chid;
};

struct s_channel_cache *find_channel_cache(int32_t demux_id, int32_t pidindex, int8_t caid_and_prid_only)
{
	struct s_ecmpids *p = &demux[demux_id].ECMpids[pidindex];
	struct s_channel_cache *c;
	LL_ITER it;

	if (!channel_cache)
		channel_cache = ll_create("channel cache");

	it = ll_iter_create(channel_cache);
	while ((c=ll_iter_next(&it))) {
	
		if (caid_and_prid_only) {
			if (p->CAID == c->caid && (p->PROVID == c->prid || p->PROVID ==0)) // PROVID ==0 some provider no provid in PMT table
				return c;
		} else {
			if (demux[demux_id].program_number == c->srvid
				&& p->CAID == c->caid
				&& p->ECM_PID == c->pid
				&&(p->PROVID == c->prid || p->PROVID ==0)){ // PROVID ==0 some provider no provid in PMT table
 
#ifdef WITH_DEBUG
				char buf[ECM_FMT_LEN];
				ecmfmt(c->caid, 0, c->prid, c->chid, c->pid, c->srvid, 0, 0, 0, 0, buf, ECM_FMT_LEN, 0, 0);
				cs_debug_mask(D_DVBAPI, "[DVBAPI] found in channel cache: %s", buf);
#endif
				return c;
			}
		}
	}
	return NULL;
}

int32_t edit_channel_cache(int32_t demux_id, int32_t pidindex, uint8_t add)
{
	struct s_ecmpids *p = &demux[demux_id].ECMpids[pidindex];
	struct s_channel_cache *c;
	LL_ITER it;
	int32_t count = 0;

	if (!channel_cache)
		channel_cache = ll_create("channel cache");

	it = ll_iter_create(channel_cache);
	while ((c=ll_iter_next(&it))) {
		if (demux[demux_id].program_number == c->srvid
			&& p->CAID == c->caid
			&& p->ECM_PID == c->pid
			&& (p->PROVID == c->prid || p->PROVID ==0)
			&& p->CHID == c->chid){
			if (add)
				return 0; //already added
			ll_iter_remove_data(&it);
			count++;
		}
	}

	if (add) {
		if (!cs_malloc(&c, sizeof(struct s_channel_cache)))
			return count;
		c->srvid = demux[demux_id].program_number;
		c->caid = p->CAID;
		c->pid = p->ECM_PID;
		c->prid = p->PROVID;
		c->chid = p->CHID;
		ll_append(channel_cache, c);
#ifdef WITH_DEBUG
		char buf[ECM_FMT_LEN];
		ecmfmt(c->caid, 0, c->prid, c->chid, c->pid, c->srvid, 0, 0, 0, 0, buf, ECM_FMT_LEN, 0, 0);
		cs_debug_mask(D_DVBAPI, "[DVBAPI] added to channel cache: %s", buf);
#endif
		count++;
	}

	return count;
}

int32_t add_emmfilter_to_list(int32_t demux_id, uchar *filter, uint16_t caid, uint32_t provid, uint16_t emmpid, int32_t count, int32_t num, time_t now)
{
	if (!ll_emm_active_filter)
		ll_emm_active_filter = ll_create("ll_emm_active_filter");

	if (!ll_emm_inactive_filter)
		ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter");

	if (!ll_emm_pending_filter)
		ll_emm_pending_filter = ll_create("ll_emm_pending_filter");

	struct s_emm_filter *filter_item;
	if (!cs_malloc(&filter_item,sizeof(struct s_emm_filter)))
		return 0;

	filter_item->demux_id 		= demux_id;
	memcpy(filter_item->filter, filter, 32);
	filter_item->caid			= caid;
	filter_item->provid			= provid;
	filter_item->pid			= emmpid;
	filter_item->count			= count;
	filter_item->num			= num;
	filter_item->time_started	= now;
	if (num>0){
		ll_append(ll_emm_active_filter, filter_item);
		cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d added to active emmfilters (CAID %04X PROVID %06X EMMPID %04X)",
			filter_item->demux_id, filter_item->num, filter_item->caid, filter_item->provid, filter_item->pid);
	}
	else if (num<0){
		ll_append(ll_emm_pending_filter, filter_item);
		cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d added to pending emmfilters (CAID %04X PROVID %06X EMMPID %04X)",
			filter_item->demux_id, filter_item->num, filter_item->caid, filter_item->provid, filter_item->pid);
	}
	else{
		ll_append(ll_emm_inactive_filter, filter_item);
		cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d added to inactive emmfilters (CAID %04X PROVID %06X EMMPID %04X)",
			filter_item->demux_id, filter_item->num, filter_item->caid, filter_item->provid, filter_item->pid);
	}
	return 1;
}

int32_t is_emmfilter_in_list_internal(LLIST *ll, uchar *filter, uint16_t emmpid, uint32_t provid) 
{
	struct s_emm_filter *filter_item;
	LL_ITER itr;
	if (ll_count(ll) > 0) {
		itr = ll_iter_create(ll);
		while ((filter_item=ll_iter_next(&itr))) {
			if (!memcmp(filter_item->filter, filter, 32) && filter_item->pid == emmpid && filter_item->provid == provid)
				return 1;
		}
	}
	return 0;
}

int32_t is_emmfilter_in_list(uchar *filter, uint16_t emmpid, uint32_t provid) 
{
	if (!ll_emm_active_filter)
		ll_emm_active_filter = ll_create("ll_emm_active_filter");

	if (!ll_emm_inactive_filter)
		ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter");

	if (!ll_emm_pending_filter)
		ll_emm_pending_filter = ll_create("ll_emm_pending_filter");

	if (is_emmfilter_in_list_internal(ll_emm_active_filter, filter, emmpid,provid))
		return 1;
	if (is_emmfilter_in_list_internal(ll_emm_inactive_filter, filter, emmpid,provid))
		return 1;
	if (is_emmfilter_in_list_internal(ll_emm_pending_filter, filter, emmpid,provid))
		return 1;

	return 0;
}

struct s_emm_filter *get_emmfilter_by_filternum_internal(LLIST *ll, int32_t demux_id, uint32_t num) 
{
	struct s_emm_filter *filter;
	LL_ITER itr;
	if (ll_count(ll) > 0) {
		itr = ll_iter_create(ll);
		while ((filter=ll_iter_next(&itr))) {
			if (filter->demux_id == demux_id && filter->num == num)
				return filter;
		}
	}
	return NULL;
}

struct s_emm_filter *get_emmfilter_by_filternum(int32_t demux_id, uint32_t num) 
{
	if (!ll_emm_active_filter)
		ll_emm_active_filter = ll_create("ll_emm_active_filter");

	if (!ll_emm_inactive_filter)
		ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter");

	if (!ll_emm_pending_filter)
		ll_emm_pending_filter = ll_create("ll_emm_pending_filter");

	struct s_emm_filter *emm_filter = NULL;
	emm_filter = get_emmfilter_by_filternum_internal(ll_emm_active_filter, demux_id, num);
	if (emm_filter)
		return emm_filter;
	emm_filter = get_emmfilter_by_filternum_internal(ll_emm_inactive_filter, demux_id, num);
	if (emm_filter)
		return emm_filter;
	emm_filter = get_emmfilter_by_filternum_internal(ll_emm_pending_filter, demux_id, num);
	if (emm_filter)
		return emm_filter;

	return NULL;
}

int8_t remove_emmfilter_from_list_internal(LLIST *ll, int32_t demux_id, uint16_t caid, uint32_t provid, uint16_t pid, uint32_t num) 
{
	struct s_emm_filter *filter;
	LL_ITER itr;
	if (ll_count(ll) > 0) {
		itr = ll_iter_create(ll);
		while ((filter=ll_iter_next(&itr))) {
			if (filter->demux_id == demux_id && filter->caid == caid && filter->provid == provid && filter->pid == pid && filter->num == num) {
				ll_iter_remove_data(&itr);
				return 1;
			}
		}
	}
	return 0;
}

void remove_emmfilter_from_list(int32_t demux_id, uint16_t caid, uint32_t provid, uint16_t pid, uint32_t num) 
{
	if (ll_emm_active_filter && remove_emmfilter_from_list_internal(ll_emm_active_filter, demux_id, caid, provid, pid, num))
		return;
	if (ll_emm_inactive_filter && remove_emmfilter_from_list_internal(ll_emm_inactive_filter, demux_id, caid, provid, pid, num))
		return;
	if (ll_emm_pending_filter && remove_emmfilter_from_list_internal(ll_emm_pending_filter, demux_id, caid, provid, pid, num))
		return;
}

int32_t dvbapi_set_filter(int32_t demux_id, int32_t api, uint16_t pid, uint16_t caid, uint32_t provid, uchar *filt, uchar *mask, int32_t timeout, int32_t pidindex, int32_t count, int32_t type, int8_t add_to_emm_list) {
#if defined WITH_AZBOX || defined WITH_MCA
		openxcas_caid = demux[demux_id].ECMpids[pidindex].CAID;
		openxcas_ecm_pid = pid;

  	return 1;
#endif

	int32_t ret=-1,n=-1,i;

	for (i=0; i<MAX_FILTER && demux[demux_id].demux_fd[i].fd>0; i++);

	if (i>=MAX_FILTER) {
		cs_debug_mask(D_DVBAPI,"no free filter");
		return -1;
	}
	n=i;

	demux[demux_id].demux_fd[n].pidindex = pidindex;
	demux[demux_id].demux_fd[n].pid      = pid;
	demux[demux_id].demux_fd[n].caid     = caid;
	demux[demux_id].demux_fd[n].provid   = provid;
	demux[demux_id].demux_fd[n].type     = type;
	demux[demux_id].demux_fd[n].count    = count;

	switch(api) {
		case DVBAPI_3:
			ret = demux[demux_id].demux_fd[n].fd = dvbapi_open_device(0, demux[demux_id].demux_index, demux[demux_id].adapter_index);
			if (ret < 0) return ret; // return if device cant be opened!
			struct dmx_sct_filter_params sFP2;

			memset(&sFP2,0,sizeof(sFP2));

			sFP2.pid			= pid;
			sFP2.timeout		= timeout;
			sFP2.flags			= DMX_IMMEDIATE_START;
			if(cfg.dvbapi_boxtype == BOXTYPE_NEUMO) {
				//DeepThought: on dgs/cubestation and neumo images, perhaps others
				//the following code is needed to descramble
				sFP2.filter.filter[0]=filt[0];
				sFP2.filter.mask[0]=mask[0];
				sFP2.filter.filter[1]=0;
				sFP2.filter.mask[1]=0;
				sFP2.filter.filter[2]=0;
				sFP2.filter.mask[2]=0;
				memcpy(sFP2.filter.filter+3,filt+1,16-3);
				memcpy(sFP2.filter.mask+3,mask+1,16-3);
				//DeepThought: in the drivers of the dgs/cubestation and neumo images, 
				//dvbapi 1 and 3 are somehow mixed. In the kernel drivers, the DMX_SET_FILTER
				//ioctl expects to receive a dmx_sct_filter_params structure (DVBAPI 3) but
				//due to a bug its sets the "positive mask" wrongly (they should be all 0).
				//On the other hand, the DMX_SET_FILTER1 ioctl also uses the dmx_sct_filter_params
				//structure, which is incorrect (it should be  dmxSctFilterParams).
				//The only way to get it right is to call DMX_SET_FILTER1 with the argument
				//expected by DMX_SET_FILTER. Otherwise, the timeout parameter is not passed correctly.
				ret=ioctl(demux[demux_id].demux_fd[n].fd, DMX_SET_FILTER1, &sFP2);
			} 
			else {
				memcpy(sFP2.filter.filter,filt,16);
				memcpy(sFP2.filter.mask,mask,16);
				ret=ioctl(demux[demux_id].demux_fd[n].fd, DMX_SET_FILTER, &sFP2);
			}
			break;
			
		case DVBAPI_1:
			ret = demux[demux_id].demux_fd[n].fd = dvbapi_open_device(0, demux[demux_id].demux_index, demux[demux_id].adapter_index);
			if (ret < 0) return ret; // return if device cant be opened!
			struct dmxSctFilterParams sFP1;

			memset(&sFP1,0,sizeof(sFP1));

			sFP1.pid			= pid;
			sFP1.timeout		= timeout;
			sFP1.flags			= DMX_IMMEDIATE_START;
			memcpy(sFP1.filter.filter,filt,16);
			memcpy(sFP1.filter.mask,mask,16);
			ret=ioctl(demux[demux_id].demux_fd[n].fd, DMX_SET_FILTER1, &sFP1);

			break;
#ifdef WITH_STAPI
		case STAPI:
			ret=stapi_set_filter(demux_id, pid, filt, mask, n, demux[demux_id].pmt_file);
			if (ret !=0)
				demux[demux_id].demux_fd[n].fd = ret;
			else
				ret = -1; // error setting filter!
			break;
#endif
#ifdef WITH_COOLAPI
		case COOLAPI:
			demux[demux_id].demux_fd[n].fd = coolapi_open_device(demux[demux_id].demux_index, demux_id);
			if(demux[demux_id].demux_fd[n].fd > 0)
				ret = coolapi_set_filter(demux[demux_id].demux_fd[n].fd, n, pid, filt, mask, type);
			break;
#endif
		default:
			break;
	}
	if (ret !=-1){ // filter set succesfull
		cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d Filter #%d started succesfully (caid %04X provid %06X pid %04X)", demux_id, n+1, caid, provid, pid);
		if (type==TYPE_EMM && add_to_emm_list)
			add_emmfilter_to_list(demux_id, filt, caid, provid, pid, count, n+1, time((time_t *) 0));
	}
	else{
		cs_log("ERROR: Could not start demux filter (api: %d errno=%d %s)", selected_api, errno, strerror(errno));
	}
	return ret;
}

static int32_t dvbapi_detect_api(void) {
#ifdef WITH_COOLAPI
	selected_api=COOLAPI;
	selected_box = 5;
	disable_pmt_files = 1;
	cs_log("Detected Coolstream API");
	return 1;
#else
	int32_t i,devnum=-1, dmx_fd=0, boxnum = sizeof(devices)/sizeof(struct box_devices);
	char device_path[128], device_path2[128];

	for (i=0;i<boxnum;i++) {
		snprintf(device_path2, sizeof(device_path2), devices[i].demux_device, 0);
		snprintf(device_path, sizeof(device_path), devices[i].path, 0);
		strncat(device_path, device_path2, sizeof(device_path)-strlen(device_path)-1);
		if ((dmx_fd = open(device_path, O_RDWR | O_NONBLOCK)) > 0) {
			devnum=i;
			int32_t ret = close(dmx_fd);
			if (ret < 0) cs_log("ERROR: Could not close demuxer fd (errno=%d %s)", errno, strerror(errno));
			break;
		}
	}

	if (devnum == -1) return 0;
	selected_box = devnum;
	if (selected_box > -1)
		selected_api=devices[selected_box].api;

#ifdef WITH_STAPI
	if (devnum == 4 && stapi_open() == 0) {
		cs_log("ERROR: stapi: setting up stapi failed.");
		return 0;
	}
#endif
	if (cfg.dvbapi_boxtype == BOXTYPE_NEUMO){
		selected_api=DVBAPI_3; //DeepThought
	}
	cs_log("[DVBAPI] Detected %s Api: %d, userconfig boxtype: %d", device_path, selected_api, cfg.dvbapi_boxtype);
#endif
	return 1;
}

static int32_t dvbapi_read_device(int32_t dmx_fd, unsigned char *buf, int32_t length)
{
	int32_t len, rc;
	struct pollfd pfd[1];

	pfd[0].fd = dmx_fd;
	pfd[0].events = (POLLIN | POLLPRI);

	rc = poll(pfd, 1, 7000);
	if (rc<1) {
		cs_log("ERROR: Read on %d timed out (errno=%d %s)", dmx_fd, errno, strerror(errno));
		return -1;
	}

	len = read(dmx_fd, buf, length);

	if (len<1)
		cs_log("ERROR: Read error on fd %d (errno=%d %s)", dmx_fd, errno, strerror(errno));
	else cs_ddump_mask(D_TRACE, buf, len, "[DVBAPI] Readed:");
	return len;
}

int32_t dvbapi_open_device(int32_t type, int32_t num, int32_t adapter) {
	int32_t dmx_fd;
	int32_t ca_offset=0;
	char device_path[128], device_path2[128];

	if (type==0) {
		snprintf(device_path2, sizeof(device_path2), devices[selected_box].demux_device, num);
		snprintf(device_path, sizeof(device_path), devices[selected_box].path, adapter);

		strncat(device_path, device_path2, sizeof(device_path)-strlen(device_path)-1);
	} else {
		if (cfg.dvbapi_boxtype==BOXTYPE_DUCKBOX || cfg.dvbapi_boxtype==BOXTYPE_DBOX2 || cfg.dvbapi_boxtype==BOXTYPE_UFS910)
			ca_offset=1;

		if (cfg.dvbapi_boxtype==BOXTYPE_QBOXHD)
			num=0;

		if (cfg.dvbapi_boxtype==BOXTYPE_PC)
			num=0;

		snprintf(device_path2, sizeof(device_path2), devices[selected_box].ca_device, num+ca_offset);
		snprintf(device_path, sizeof(device_path), devices[selected_box].path, adapter);

		strncat(device_path, device_path2, sizeof(device_path)-strlen(device_path)-1);
	}

	if ((dmx_fd = open(device_path, O_RDWR | O_NONBLOCK)) < 0) {
		cs_log("ERROR: Can't open device %s (errno=%d %s)", device_path, errno, strerror(errno));
		return -1;
	}

	cs_debug_mask(D_DVBAPI, "DEVICE open (%s) fd %d", device_path, dmx_fd);
	
	return dmx_fd;
}

int32_t dvbapi_open_netdevice(int32_t UNUSED(type), int32_t UNUSED(num), int32_t adapter) {
	int32_t socket_fd;

	socket_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socket_fd == -1) {
		cs_log("ERROR: Failed create socket (%d %s)", errno, strerror(errno));
	} else {
		struct sockaddr_in saddr;
		fcntl(socket_fd, F_SETFL, O_NONBLOCK);
		bzero(&saddr, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(PORT + adapter); // port = PORT + adapter number
		saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		int32_t r = connect(socket_fd, (struct sockaddr *) &saddr, sizeof(saddr));
		if (r<0) {
			cs_log("ERROR: Failed to connect socket (%d %s), at localhost, port=%d", errno, strerror(errno), PORT + adapter);
			int32_t ret = close(socket_fd);
			if (ret < 0) cs_log("ERROR: Could not close socket fd (errno=%d %s)", errno, strerror(errno));
			socket_fd = -1;
		}
	}

	cs_debug_mask(D_DVBAPI, "NET DEVICE open (port = %d) fd %d", PORT + adapter, socket_fd);
	return socket_fd;
}

uint16_t tunemm_caid_map(uint8_t direct, uint16_t caid, uint16_t srvid)
{
	int32_t i;
	struct s_client *cl = cur_client();
	TUNTAB *ttab;
	ttab = &cl->ttab;

	if (direct) {
		for (i = 0; i<ttab->n; i++) {
			if (caid==ttab->bt_caidto[i]
				&& (srvid==ttab->bt_srvid[i] || ttab->bt_srvid[i] == 0xFFFF || !ttab->bt_srvid[i]))
				return ttab->bt_caidfrom[i];
		}
	} else {
		for (i = 0; i<ttab->n; i++) {
			if (caid==ttab->bt_caidfrom[i]
				&& (srvid==ttab->bt_srvid[i] || ttab->bt_srvid[i] == 0xFFFF || !ttab->bt_srvid[i]))
				return ttab->bt_caidto[i];
		}
	}
	return caid;
}

int32_t dvbapi_stop_filter(int32_t demux_index, int32_t type) {
	int32_t g, ret = -1;

	for (g=0;g<MAX_FILTER;g++) {
		if (demux[demux_index].demux_fd[g].type==type) {
			ret = dvbapi_stop_filternum(demux_index, g);
		}
	}
	if (ret == -1) return 0; // on error return 0
	else return 1;
}

int32_t dvbapi_stop_filternum(int32_t demux_index, int32_t num) {
	int32_t retfilter=-1, retfd=-1, fd = demux[demux_index].demux_fd[num].fd;
	if (fd>0) {
		cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d stop Filter #%d (fd: %d api: %d, caid: %04X, provid: %06X, %spid: %04X)", 
			demux_index, num+1, fd, selected_api, demux[demux_index].demux_fd[num].caid, demux[demux_index].demux_fd[num].provid,
			(demux[demux_index].demux_fd[num].type==TYPE_ECM ?"ecm":"emm"), demux[demux_index].demux_fd[num].pid);

		switch(selected_api) {
			case DVBAPI_3:
				retfilter=ioctl(fd,DMX_STOP); // for modern dvbapi boxes, they do give filter status back to us
				break;
			
			case DVBAPI_1:
#if defined(__powerpc__)
				ioctl(fd,DMX_STOP); // for old boxes dvbapi1 complaint like dm500 ppcold, no action feedback.
				retfilter = 1; // set always succesfull, but we will never know for sure
#else
				retfilter=ioctl(fd,DMX_STOP); // for modern dvbapi boxes, they do give filter status back to us
#endif
				break;
			
#ifdef WITH_STAPI
			case STAPI:
				retfilter=stapi_remove_filter(demux_index, num, demux[demux_index].pmt_file);
				if (retfilter != 1){ // stapi returns 0 for error, 1 for all ok
					retfilter = -1;
				}
				break;
#endif
#ifdef WITH_COOLAPI
			case COOLAPI:
				retfilter=coolapi_remove_filter(fd, num);
				retfd=coolapi_close_device(fd);
				break;
#endif
			default:
				break;
		}
		if (retfilter < 0){
			cs_log("ERROR: Demuxer #%d could not stop Filter #%d (fd:%d api:%d errno=%d %s)", demux_index, num+1, fd, selected_api, errno, strerror(errno));
		}
#ifndef WITH_COOLAPI // no fd close for coolapi and stapi, all others do close fd!
		retfd = close(fd);
		if (errno == 9) retfd = 0; // no error on bad file descriptor
		if (selected_api == STAPI) retfd = 0; // stapi closes its own filter fd!
#endif
		if (retfd){ 
			cs_log("ERROR: Demuxer #%d could not close fd of Filter #%d (fd=%d api:%d errno=%d %s)", demux_index, num+1, fd,
				selected_api, errno, strerror(errno));
		}
		
		if (demux[demux_index].demux_fd[num].type == TYPE_ECM){ //ecm filter stopped: reset index!
			demux[demux_index].ECMpids[demux[demux_index].demux_fd[num].pidindex].index=0; 
		}
		
		if (demux[demux_index].demux_fd[num].type == TYPE_EMM && demux[demux_index].demux_fd[num].pid != 0x001){ // If emm type remove from emm filterlist
			remove_emmfilter_from_list(demux_index, demux[demux_index].demux_fd[num].caid, demux[demux_index].demux_fd[num].provid, demux[demux_index].demux_fd[num].pid, num+1);
		}
		demux[demux_index].demux_fd[num].fd=0;
		demux[demux_index].demux_fd[num].type=0;
	}
	if (retfilter <0) return retfilter; // error on remove filter
	if (retfd <0) return retfd; // error on close filter fd
	return 1; // all ok!
}

void dvbapi_start_filter(int32_t demux_id, int32_t pidindex, uint16_t pid, uint16_t caid, uint32_t provid, uchar table, uchar mask, int32_t timeout, int32_t type, int32_t count)
{
	uchar filter[32];
	memset(filter,0,32);

	filter[0]=table;
	filter[16]=mask;

	cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d try to start new filter for caid: %04X, provid: %06X, pid: %04X", demux_id, caid, provid, pid);
	dvbapi_set_filter(demux_id, selected_api, pid, caid, provid, filter, filter+16, timeout, pidindex, count, type, 0);
}

static int32_t dvbapi_find_emmpid(int32_t demux_id, uint8_t type, uint16_t caid, uint32_t provid) {
	int32_t k;
	int32_t bck = -1;
	for (k=0; k<demux[demux_id].EMMpidcount; k++) {
		if (demux[demux_id].EMMpids[k].CAID == caid
			&& demux[demux_id].EMMpids[k].PROVID == provid
			&& (demux[demux_id].EMMpids[k].type & type))
			return k;
		else if (demux[demux_id].EMMpids[k].CAID == caid
			&& (!demux[demux_id].EMMpids[k].PROVID || !provid)
			&& (demux[demux_id].EMMpids[k].type & type) && bck)
			bck = k;
	}
	return bck;
}

int32_t dvbapi_start_emm_filter(int32_t demux_index) {
	unsigned int j, fcount=0, fcount_added=0;
	const char *typtext[] = { "UNIQUE", "SHARED", "GLOBAL", "UNKNOWN" };

	if (!demux[demux_index].EMMpidcount)
		return 0;
	fcount = demux[demux_index].emm_filter;
	
	//if (demux[demux_index].emm_filter)
	//	return 0;


	struct s_csystem_emm_filter *dmx_filter = NULL;
	unsigned int filter_count = 0;
	uint16_t caid, ncaid;

	struct s_reader *rdr = NULL;
	struct s_client *cl = cur_client();
	if (!cl || !cl->aureader_list)
		return 0;

	LL_ITER itr = ll_iter_create(cl->aureader_list);
	while ((rdr = ll_iter_next(&itr))) {

		if (!rdr->client || rdr->audisabled !=0 || !rdr->enable || (!is_network_reader(rdr) && rdr->card_status != CARD_INSERTED))
			continue; 

		caid = ncaid = rdr->caid;

		struct s_cardsystem *cs;
		if (!rdr->caid)
			cs = get_cardsystem_by_caid(rdr->csystem.caids[0]); //Bulcrypt
		else
			cs = get_cardsystem_by_caid(rdr->caid);

		if (cs) {
			if (chk_is_betatunnel_caid(rdr->caid) == 1)
				ncaid = tunemm_caid_map(TO_FROM, rdr->caid, demux[demux_index].program_number);
			if (rdr->caid != ncaid && dvbapi_find_emmpid(demux_index, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL, ncaid, 0) > -1)
			{
				cs->get_tunemm_filter(rdr, &dmx_filter, &filter_count);
				caid = ncaid;
				cs_debug_mask(D_DVBAPI, "[EMM Filter] setting emm filter for betatunnel: %04X -> %04X", caid, rdr->caid);
			} else {
				cs->get_emm_filter(rdr, &dmx_filter, &filter_count);
			}
		} else {
			cs_debug_mask(D_DVBAPI, "[EMM Filter] cardsystem for emm filter for %s not found", rdr->label);
			continue;
		}

		for (j = 0; j < filter_count ; j++) {
			if (dmx_filter[j].enabled == 0)
				continue;

			uchar filter[32];
			memset (filter, 0, sizeof(filter)); // reset filter
			uint32_t usefilterbytes = 16; // default use all filters
			memcpy(filter, dmx_filter[j].filter, usefilterbytes);
			memcpy(filter + 16, dmx_filter[j].mask, usefilterbytes);
			int32_t emmtype = dmx_filter[j].type;
			int32_t l=-1;

			if ( (filter[0] && (((1<<(filter[0] % 0x80)) & rdr->b_nano) && !((1<<(filter[0] % 0x80)) & rdr->s_nano))) )
				continue;

			if ((rdr->blockemm & emmtype) && !(((1<<(filter[0] % 0x80)) & rdr->s_nano) || (rdr->saveemm & emmtype)))
				continue;

			if(rdr->caid == 0x100) {
				uint32_t seca_provid = 0;
				if (emmtype == EMM_SHARED)
					seca_provid = ((filter[1] << 8) | filter[2]);
				l = dvbapi_find_emmpid(demux_index, emmtype, 0x0100, seca_provid);
			} else {
				// provid 0 is safe since oscam sets filter with e.g. rdr->sa & doesn't add filter twice (is_emmfilter_in_list)
				if (!rdr->caid) {
					l = dvbapi_find_emmpid(demux_index, emmtype, rdr->csystem.caids[0], 0); //Bulcrypt
					if (l<0)
						l = dvbapi_find_emmpid(demux_index, emmtype, rdr->csystem.caids[1], 0);
				} else {
					if (rdr->auprovid) {
						l = dvbapi_find_emmpid(demux_index, emmtype, caid, rdr->auprovid);
						if (l<0)
							l = dvbapi_find_emmpid(demux_index, emmtype, caid, 0);
					} else {
						l = dvbapi_find_emmpid(demux_index, emmtype, caid, 0);
					}
				}
			}
			if (l>-1) {
				 //filter already in list?
				if (is_emmfilter_in_list(filter, demux[demux_index].EMMpids[l].PID, demux[demux_index].EMMpids[l].PROVID)) {
					fcount_added++;
					continue;
				}

				uint32_t typtext_idx = 0;
				int32_t ret = -1;
				while (((emmtype >> typtext_idx) & 0x01) == 0 && typtext_idx < sizeof(typtext) / sizeof(const char *)){
					++typtext_idx;
				}

				cs_ddump_mask(D_DVBAPI, filter, 32, "[EMM Filter] starting emm filter type %s, pid: 0x%04X", typtext[typtext_idx], demux[demux_index].EMMpids[l].PID);
				fcount++; // increase total number of emmfilters
				if (fcount>demux[demux_index].max_emm_filter) {
					add_emmfilter_to_list(demux_index, filter, demux[demux_index].EMMpids[l].CAID, demux[demux_index].EMMpids[l].PROVID, demux[demux_index].EMMpids[l].PID, fcount, 0, 0);
				} else {
					ret = dvbapi_set_filter(demux_index, selected_api, demux[demux_index].EMMpids[l].PID, demux[demux_index].EMMpids[l].CAID,
						demux[demux_index].EMMpids[l].PROVID, filter, filter+16, 0, demux[demux_index].pidindex, fcount, TYPE_EMM, 1);
				}
				if (ret !=-1){
					demux[demux_index].emm_filter++; // increase total active filters
				}
				else { // not set succesfull so add it to the list for try again later on!
					add_emmfilter_to_list(demux_index, filter, demux[demux_index].EMMpids[l].CAID, demux[demux_index].EMMpids[l].PROVID, demux[demux_index].EMMpids[l].PID, fcount, 0, 0);
				}
			}
		}
		// dmx_filter not use below this point
		NULLFREE(dmx_filter);
	}

	if (fcount)
		cs_debug_mask(D_DVBAPI,"[EMM Filter] %i matching emm filter found", fcount);
	if (fcount_added) {
		//demux[demux_index].emm_filter=1;
		cs_debug_mask(D_DVBAPI,"[EMM Filter] %i matching emm filter skipped because they are already active on same emmpid:provid", fcount_added);
	}
	if (fcount == abs(demux[demux_index].emm_filter)) return 0;
	else return 1;
}

void dvbapi_add_ecmpid_int(int32_t demux_id, uint16_t caid, uint16_t ecmpid, uint32_t provid) {
	int32_t n,added=0;
	
	if (demux[demux_id].ECMpidcount>=ECM_PIDS)
		return;
	
	int32_t stream = demux[demux_id].STREAMpidcount-1;
	for (n=0;n<demux[demux_id].ECMpidcount;n++) {
		if (stream>-1 && demux[demux_id].ECMpids[n].CAID == caid && demux[demux_id].ECMpids[n].ECM_PID == ecmpid) {
			if (!demux[demux_id].ECMpids[n].streams) {
				//we already got this caid/ecmpid as global, no need to add the single stream
				cs_log("[SKIP STREAM %d] CAID: %04X ECM_PID: %04X PROVID: %06X", n, caid, ecmpid, provid);
				continue;
			}
			added=1;
			demux[demux_id].ECMpids[n].streams |= (1 << stream);
			cs_log("[ADD STREAM %d] CAID: %04X ECM_PID: %04X PROVID: %06X", n, caid, ecmpid, provid);
		}
	}

	if (added==1)
		return;
	for (n=0;n<demux[demux_id].ECMpidcount;n++) { // check for existing pid
		if (demux[demux_id].ECMpids[n].CAID == caid && demux[demux_id].ECMpids[n].ECM_PID == ecmpid)
		return; // found same pid -> skip
	}
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].ECM_PID = ecmpid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CAID = caid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].PROVID = provid;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].CHID = 0x10000; // reset CHID
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].checked = 0;
	//demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].index = 0;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].status = 0;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].tries = 0xFE;
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].streams = 0; // reset streams!
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].irdeto_curindex = 0xFE; // reset
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].irdeto_curindex=0xFE; // reset
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].irdeto_maxindex=0; // reset 
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].irdeto_cycle=0xFE; // reset
	demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].table=0;
	
	if (stream>-1)
		demux[demux_id].ECMpids[demux[demux_id].ECMpidcount].streams |= (1 << stream);

	cs_log("[ADD PID %d] CAID: %04X ECM_PID: %04X PROVID: %06X", demux[demux_id].ECMpidcount, caid, ecmpid, provid);
	if (caid>>8 == 0x06) demux[demux_id].emmstart = 1; // marker to fetch emms early irdeto needs them!
	
	demux[demux_id].ECMpidcount++;
}

void dvbapi_add_ecmpid(int32_t demux_id, uint16_t caid, uint16_t ecmpid, uint32_t provid) {
	dvbapi_add_ecmpid_int(demux_id, caid, ecmpid, provid);
	struct s_dvbapi_priority *joinentry;

	for (joinentry=dvbapi_priority; joinentry != NULL; joinentry=joinentry->next) {
		if ((joinentry->type != 'j')
			|| (joinentry->caid && joinentry->caid != caid)
			|| (joinentry->provid && joinentry->provid != provid)
			|| (joinentry->ecmpid && joinentry->ecmpid 	!= ecmpid)
			|| (joinentry->srvid && joinentry->srvid != demux[demux_id].program_number))
			continue;
		cs_debug_mask(D_DVBAPI,"[PMT] Join ECMPID %04X:%06X:%04X to %04X:%06X:%04X",
			caid, provid, ecmpid, joinentry->mapcaid, joinentry->mapprovid, joinentry->mapecmpid);
		dvbapi_add_ecmpid_int(demux_id, joinentry->mapcaid, joinentry->mapecmpid, joinentry->mapprovid);
	}
}

void dvbapi_add_emmpid(struct s_reader *testrdr, int32_t demux_id, uint16_t caid, uint16_t emmpid, uint32_t provid, uint8_t type) {
	char typetext[40];
	cs_strncpy(typetext, ":", sizeof(typetext));

	uint16_t ncaid = caid;
	
	if (chk_is_betatunnel_caid(caid) == 2)
		ncaid = tunemm_caid_map(FROM_TO, caid, demux[demux_id].program_number);

	struct s_cardsystem *cs;
		cs = get_cardsystem_by_caid(ncaid);

	if (!cs) {
		cs_debug_mask(D_DVBAPI,"[IGNORE EMMPID] cardsystem for caid %04X not found (ignoring)", ncaid);
		return;
	}

	if (type & 0x01) strcat(typetext, "UNIQUE:");
	if (type & 0x02) strcat(typetext, "SHARED:");
	if (type & 0x04) strcat(typetext, "GLOBAL:");
	if (type & 0xF8) strcat(typetext, "UNKNOWN:");

	if (emm_reader_match(testrdr, ncaid, provid)) {
		uint16_t i;
		for (i = 0; i < demux[demux_id].EMMpidcount; i++) {
			if ((demux[demux_id].EMMpids[i].PID == emmpid)
				&& (demux[demux_id].EMMpids[i].CAID == caid)
				&& (demux[demux_id].EMMpids[i].PROVID == provid)
				&& (demux[demux_id].EMMpids[i].type == type)) {
				cs_debug_mask(D_DVBAPI,"[SKIP EMMPID] CAID: %04X EMM_PID: %04X PROVID: %06X TYPE %s (same as emmpid #%d)",
					caid, emmpid, provid, typetext, i);
				return;
			} else {
				if (demux[demux_id].EMMpids[i].CAID == ncaid && ncaid != caid) {
					cs_debug_mask(D_DVBAPI,"[SKIP EMMPID] CAID: %04X EMM_PID: %04X PROVID: %06X TYPE %s (caid %04X present)",
						caid, emmpid, provid, typetext, ncaid);
					return;
				}
			}
		}
		demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].PID = emmpid;
		demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].CAID = caid;
		demux[demux_id].EMMpids[demux[demux_id].EMMpidcount].PROVID = provid;
		demux[demux_id].EMMpids[demux[demux_id].EMMpidcount++].type = type;
		cs_debug_mask(D_DVBAPI,"[ADD EMMPID #%d] CAID: %04X EMM_PID: %04X PROVID: %06X TYPE %s",
			demux[demux_id].EMMpidcount-1, caid, emmpid, provid, typetext);
	}
	else {
		cs_debug_mask(D_DVBAPI,"[IGNORE EMMPID] CAID: %04X EMM_PID: %04X PROVID: %06X TYPE %s (no match)",
			caid, emmpid, provid, typetext);
	}
}

void dvbapi_parse_cat(int32_t demux_id, uchar *buf, int32_t len) {
#ifdef WITH_COOLAPI
	// driver sometimes reports error if too many emm filter 
	// but adding more ecm filter is no problem
	// ... so ifdef here instead of limiting MAX_FILTER
	demux[demux_id].max_emm_filter = 14;
#else
	if (cfg.dvbapi_requestmode == 1) {
		uint16_t ecm_filter_needed=0,n;
		for (n=0; n<demux[demux_id].ECMpidcount; n++) {
			if (demux[demux_id].ECMpids[n].status > -1)
				ecm_filter_needed++;
		}
		if (MAX_FILTER-ecm_filter_needed<=0)
			demux[demux_id].max_emm_filter = 0;
		else
			demux[demux_id].max_emm_filter = MAX_FILTER-ecm_filter_needed;
	} else {
		demux[demux_id].max_emm_filter = MAX_FILTER-1;
	}
#endif
	uint16_t i, k;
	struct s_reader *testrdr = NULL;

	cs_ddump_mask(D_DVBAPI, buf, len, "cat:");

	struct s_client *cl = cur_client();
	if (!cl || !cl->aureader_list)
		return;

	LL_ITER itr = ll_iter_create(cl->aureader_list);
	while ((testrdr = ll_iter_next(&itr))) { // make a list of all readers
		if (!testrdr->client
			|| (testrdr->audisabled !=0)
			|| (!testrdr->enable)
			|| (!is_network_reader(testrdr) && testrdr->card_status != CARD_INSERTED)) {
			cs_debug_mask(D_DVBAPI,"Reader %s au disabled or not enabled-> skip!", testrdr->label); //only parse au enabled readers that are enabled
			continue; 
		} 
		cs_debug_mask(D_DVBAPI,"Reader %s au enabled -> parsing cat for emm pids!", testrdr->label);

		for (i = 8; i < (((buf[1] & 0x0F) << 8) | buf[2]) - 1; i += buf[i + 1] + 2) {
			if (buf[i] != 0x09) continue;
			if (demux[demux_id].EMMpidcount >= ECM_PIDS) break;

			uint16_t caid=((buf[i + 2] << 8) | buf[i + 3]);
			uint16_t emm_pid=(((buf[i + 4] & 0x1F) << 8) | buf[i + 5]);
			uint32_t emm_provider = 0;

			switch (caid >> 8) {
				case 0x01:
					dvbapi_add_emmpid(testrdr, demux_id, caid, emm_pid, 0, EMM_UNIQUE|EMM_GLOBAL);
					for (k = i+7; k < i+buf[i+1]+2; k += 4) {
						emm_provider = (buf[k+2] << 8| buf[k+3]);
						emm_pid = (buf[k] & 0x0F) << 8 | buf[k+1];
						dvbapi_add_emmpid(testrdr,demux_id, caid, emm_pid, emm_provider, EMM_SHARED);
					}
					break;
				case 0x05:
					for (k = i+6; k < i+buf[i+1]+2; k += buf[k+1]+2) {
						if (buf[k]==0x14) {
							emm_provider = buf[k+2] << 16 | (buf[k+3] << 8| (buf[k+4] & 0xF0));
							dvbapi_add_emmpid(testrdr,demux_id, caid, emm_pid, emm_provider, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL);
						}
					}
					break;
				case 0x18:
					emm_provider = (buf[i+1] == 0x07) ? (buf[i+6] << 16 | (buf[i+7] << 8| (buf[i+8]))) : 0;
					dvbapi_add_emmpid(testrdr,demux_id, caid, emm_pid, emm_provider, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL);
					break;
				default:
					dvbapi_add_emmpid(testrdr,demux_id, caid, emm_pid, 0, EMM_UNIQUE|EMM_SHARED|EMM_GLOBAL);
					break;
			}
		}
	}
	return;
}

static pthread_mutex_t lockindex;
int32_t dvbapi_get_descindex(int32_t demux_index) {
	int32_t i,j,idx=1,fail=1;
	if (cfg.dvbapi_boxtype == BOXTYPE_NEUMO) {
		idx=0;
		sscanf(demux[demux_index].pmt_file, "pmt%3d.tmp", &idx);
		idx++; // fixup
		return idx;
	}
	pthread_mutex_lock(&lockindex); // to avoid race when readers become responsive!
	while (fail) {
		fail=0;
		for (i=0;i<MAX_DEMUX;i++) {
			for (j=0;j<demux[i].ECMpidcount;j++) { 
				if (demux[i].ECMpids[j].index==idx) {
					idx++;
					fail=1;
					break;
				}
			}
		}
	}
	pthread_mutex_unlock(&lockindex); // and release it!
	return idx;
}

void dvbapi_set_pid(int32_t demux_id, int32_t num, int32_t idx) {
	int32_t i;
	//if (demux[demux_id].pidindex == -1) return;

	switch(selected_api) {
#ifdef WITH_STAPI
		case STAPI:
			stapi_set_pid(demux_id, num, idx, demux[demux_id].STREAMpids[num], demux[demux_id].pmt_file);
			break;
#endif
#ifdef WITH_COOLAPI
		case COOLAPI:
			break;
#endif
		default:
			for (i=0;i<8;i++) {
				if (demux[demux_id].ca_mask & (1 << i)) {
					if (ca_fd[i]<=0) {
						if (cfg.dvbapi_boxtype == BOXTYPE_PC)
							ca_fd[i]=dvbapi_open_netdevice(1, i, demux[demux_id].adapter_index);
						else
							ca_fd[i]=dvbapi_open_device(1, i, demux[demux_id].adapter_index);
					}
					if (ca_fd[i]>0) {
						ca_pid_t ca_pid2;
						memset(&ca_pid2,0,sizeof(ca_pid2));
						ca_pid2.pid = demux[demux_id].STREAMpids[num];
						ca_pid2.index = idx;

						if (cfg.dvbapi_boxtype == BOXTYPE_PC) {
							// preparing packet
							int32_t request = CA_SET_PID;
							unsigned char packet[sizeof(request) + sizeof(ca_pid2)];
							memcpy(&packet, &request, sizeof(request));
							memcpy(&packet[sizeof(request)], &ca_pid2, sizeof(ca_pid2));

							// sending data
							send(ca_fd[i], &packet, sizeof(packet), 0);
						} else {
							// This ioctl fails on dm500 but that is OK.
							if (ioctl(ca_fd[i], CA_SET_PID, &ca_pid2)==-1)
								cs_debug_mask(D_TRACE|D_DVBAPI,"[DVBAPI] Demuxer #%d stream #%d ERROR: ioctl(CA_SET_PID) pid=0x%04x index=%d (errno=%d %s)",
									demux_id, num+1, ca_pid2.pid, ca_pid2.index, errno, strerror(errno));
							else
								cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d stream #%d CA_SET_PID pid=0x%04x index=%d", demux_id, num+1,
									ca_pid2.pid, ca_pid2.index);
						}
					}
				}
			}
			break;
	}
	return;
}

void dvbapi_stop_descrambling(int32_t demux_id) {
	int32_t i;
	if (demux[demux_id].program_number==0) return;
	char channame[32];
	i = demux[demux_id].pidindex;
	if(i<0) i=0;
	get_servicename(dvbapi_client, demux[demux_id].program_number, demux[demux_id].ECMpidcount>0 ? demux[demux_id].ECMpids[i].CAID : 0, channame);
	cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d stop descrambling program number %04X (%s)", demux_id, demux[demux_id].program_number, channame);
	dvbapi_stop_filter(demux_id, TYPE_EMM);
	if (demux[demux_id].ECMpidcount>0){
		dvbapi_stop_filter(demux_id, TYPE_ECM);
		demux[demux_id].pidindex=-1;
		demux[demux_id].curindex=-1;
	
		for (i=0;i<demux[demux_id].STREAMpidcount;i++) {
			dvbapi_set_pid(demux_id, i, -1);
		}
		
		if(cfg.dvbapi_reopenonzap && selected_api != STAPI){ // dont use reopen on zap on ET brand boxes! but VU+ needs it coz after timeout black picture!
			for (i=0;i<8;i++) {
				if (ca_fd[i]>0 && (demux[demux_id].ca_mask & (1 << i))) {
					int8_t j, found = 0;
					// Check for other demuxes running on same ca device
					for(j = 0; j < MAX_DEMUX; ++j){
						if(j != demux_id && (demux[j].ca_mask & (1 << i))) {
							found = 1;
							break;
						}
					}
					
					if(!found){
						cs_debug_mask(D_DVBAPI, "[DVBAPI] Closing unused demux device ca%d (fd=%d).", i, ca_fd[i]);
						int32_t ret = close(ca_fd[i]);
						if (ret < 0) cs_log("ERROR: Could not close demuxer fd (errno=%d %s)", errno, strerror(errno));
						ca_fd[i] = 0;
					}
				}
			}
		}
	}
	
	memset(&demux[demux_id], 0 ,sizeof(DEMUXTYPE));
	demux[demux_id].pidindex=-1; 
	demux[demux_id].curindex=-1;
	
	unlink(ECMINFO_FILE);
	return;
}

int32_t dvbapi_start_descrambling(int32_t demux_id, int32_t pid, int8_t checked) {
	int32_t started = 0; // in case ecmfilter started = 1
	int32_t fake_ecm = 0;
	ECM_REQUEST *er;
	struct s_reader *rdr;
	if (!(er=get_ecmtask())) return started;
	demux[demux_id].ECMpids[pid].checked = checked+1; // mark this pid as checked!
	
	struct s_dvbapi_priority *p;
	for (p=dvbapi_priority; p != NULL ; p = p->next) {
		if ((p->type != 'p')
			|| (p->caid && p->caid != demux[demux_id].ECMpids[pid].CAID)
			|| (p->provid && p->provid != demux[demux_id].ECMpids[pid].PROVID)
			|| (p->ecmpid && p->ecmpid != demux[demux_id].ECMpids[pid].ECM_PID)
			|| (p->srvid && p->srvid != demux[demux_id].program_number))
			continue;
		// if found chid and first run apply chid filter, on forced pids always apply!
		if (p->type == 'p' && p->chid <0x10000 && (demux[demux_id].ECMpids[pid].checked == 1 || (p && p->force))){ 
			if (demux[demux_id].ECMpids[pid].CHID < 0x10000){ // channelcache delivered chid
				er->chid = demux[demux_id].ECMpids[pid].CHID;
			}
			else {
				er->chid = p->chid; // no channelcache or no chid in use, so use prio chid
				demux[demux_id].ECMpids[pid].CHID = p->chid;
			}
			//cs_log("********* CHID %04X **************", demux[demux_id].ECMpids[pid].CHID);
			break; // we only accept one!
		}
		else{
			if (demux[demux_id].ECMpids[pid].CHID < 0x10000){ // channelcache delivered chid
				er->chid = demux[demux_id].ECMpids[pid].CHID;
			}
			else { // no channelcache or no chid in use
				er->chid = 0;
				demux[demux_id].ECMpids[pid].CHID = 0x10000;
			}
		}
	}
	er->srvid = demux[demux_id].program_number;
	er->caid  = demux[demux_id].ECMpids[pid].CAID;
	er->pid   = demux[demux_id].ECMpids[pid].ECM_PID;
	er->prid  = demux[demux_id].ECMpids[pid].PROVID;
	er->vpid  = demux[demux_id].ECMpids[pid].VPID;
	
	for (rdr=first_active_reader; rdr != NULL ; rdr=rdr->next){
		int8_t match = matching_reader(er, rdr); // check for matching reader
		if ((time(NULL) - rdr->emm_last) > 3600 && rdr->needsemmfirst && er->caid >> 8 == 0x06){ 
			cs_log("[DVBAPI] Warning reader %s received no emms for the last %d seconds -> skip, this reader needs emms first!", rdr->label,
				(int) (time(NULL) - rdr->emm_last) );
			continue; // skip this card needs to process emms first before it can be used for descramble
		}
		if (p && p->force) match = 1; // forced pid always started!
#ifdef WITH_LB
		if (!match && cfg.lb_auto_betatunnel) { //if this reader does not match, check betatunnel for it
			uint16_t caid = lb_get_betatunnel_caid_to(er->caid);
			if (caid) {
				uint16_t save_caid = er->caid;
				er->caid = caid;
				match = matching_reader(er, rdr); // check for matching reader
				er->caid = save_caid;
			}
		}
#endif
		if (!match && chk_is_betatunnel_caid(er->caid)) // these caids might be tunneled invisible by peers
			match = 1; // so make it a match to try it!
#ifdef CS_CACHEEX			
		if (!match && (cacheex_is_match_alias(dvbapi_client, er))){ // check if cache-ex is matching
			match = 1; // so make it a match to try it!
		}
#endif
		// BISS or FAKE CAID
		// ecm stream pid is fake, so send out one fake ecm request
		// special treatment: if we asked the cw first without starting a filter the cw request will be killed due to no ecmfilter started
		if (demux[demux_id].ECMpids[pid].CAID == 0xFFFF || (demux[demux_id].ECMpids[pid].CAID >> 8) == 0x26) {
			int32_t j,n;
			er->ecmlen=5;
			er->ecm[1] = 0x00;
			er->ecm[2] = 0x02;
			i2b_buf(2, er->srvid, er->ecm+3);

			for (j=0, n=5; j<demux[demux_id].STREAMpidcount; j++, n+=2) {
				i2b_buf(2, demux[demux_id].STREAMpids[j], er->ecm+n);
				er->ecm[2] += 2;
				er->ecmlen += 2;
			}
			
			cs_log("[DVBAPI] Demuxer #%d trying to descramble PID #%d CAID %04X PROVID %06X ECMPID %04X ANY CHID VPID %04X", demux_id, pid,
				demux[demux_id].ECMpids[pid].CAID, demux[demux_id].ECMpids[pid].PROVID, demux[demux_id].ECMpids[pid].ECM_PID,
				demux[demux_id].ECMpids[pid].VPID);
				
			demux[demux_id].curindex=pid; // set current pid to the fresh started one
			
			dvbapi_start_filter(demux_id, pid, demux[demux_id].ECMpids[pid].ECM_PID, demux[demux_id].ECMpids[pid].CAID,
				demux[demux_id].ECMpids[pid].PROVID, 0x80, 0xF0, 3000, TYPE_ECM, 0);
			started = 1;
			
			request_cw(dvbapi_client, er, demux_id, 0); // do not register ecm since this try!
			fake_ecm = 1;
			break; // we started an ecmfilter so stop looking for next matching reader!
		}
		if (match){ // if matching reader found check for irdeto cas if local irdeto card check if it received emms in last 60 minutes
			
			if (er->caid >> 8 == 0x06){ // irdeto cas init irdeto_curindex to wait for first index (00)
				if (demux[demux_id].ECMpids[pid].irdeto_curindex==0xFE) demux[demux_id].ECMpids[pid].irdeto_curindex = 0x00;
			}
			
			if (p && p->chid<0x10000){ // do we prio a certain chid?
				cs_log("[DVBAPI] Demuxer #%d trying to descramble PID #%d CAID %04X PROVID %06X ECMPID %04X CHID %04X VPID %04X", demux_id, pid,
					demux[demux_id].ECMpids[pid].CAID, demux[demux_id].ECMpids[pid].PROVID, demux[demux_id].ECMpids[pid].ECM_PID,
					demux[demux_id].ECMpids[pid].CHID, demux[demux_id].ECMpids[pid].VPID);
			}
			else{
				cs_log("[DVBAPI] Demuxer #%d trying to descramble PID #%d CAID %04X PROVID %06X ECMPID %04X ANY CHID VPID %04X", demux_id, pid,
					demux[demux_id].ECMpids[pid].CAID, demux[demux_id].ECMpids[pid].PROVID, demux[demux_id].ECMpids[pid].ECM_PID,
					demux[demux_id].ECMpids[pid].VPID);
			}
				
			demux[demux_id].curindex=pid; // set current pid to the fresh started one
			
			dvbapi_start_filter(demux_id, pid, demux[demux_id].ECMpids[pid].ECM_PID, demux[demux_id].ECMpids[pid].CAID,
				demux[demux_id].ECMpids[pid].PROVID, 0x80, 0xF0, 3000, TYPE_ECM, 0);
			started = 1;
			break; // we started an ecmfilter so stop looking for next matching reader!
		}
	}
	if (demux[demux_id].curindex!=pid){
		cs_log("[DVBAPI] Demuxer #%d impossible to descramble PID #%d CAID %04X PROVID %06X ECMPID %04X (NO MATCHING READER)", demux_id, pid,
				demux[demux_id].ECMpids[pid].CAID, demux[demux_id].ECMpids[pid].PROVID, demux[demux_id].ECMpids[pid].ECM_PID);
				demux[demux_id].ECMpids[pid].checked = 3; // flag this pid as checked
				demux[demux_id].ECMpids[pid].status = -1; // flag this pid as unusable
				edit_channel_cache(demux_id, pid, 0); // remove this pid from channelcache
	}
	if (!fake_ecm) free(er);
	return started;
}

struct s_dvbapi_priority *dvbapi_check_prio_match_emmpid(int32_t demux_id, uint16_t caid, uint32_t provid, char type) {
	struct s_dvbapi_priority *p;
	int32_t i;

	uint16_t ecm_pid=0;
	for (i=0; i<demux[demux_id].ECMpidcount; i++) {
		if ((demux[demux_id].ECMpids[i].CAID==caid) && (demux[demux_id].ECMpids[i].PROVID==provid)) {
			ecm_pid=demux[demux_id].ECMpids[i].ECM_PID;
			break;
		}
	}

	if (!ecm_pid)
		return NULL;

	for (p=dvbapi_priority, i=0; p != NULL; p=p->next, i++) {
		if (p->type != type
			|| (p->caid && p->caid != caid)
			|| (p->provid && p->provid != provid)
			|| (p->ecmpid && p->ecmpid != ecm_pid)
			|| (p->srvid && p->srvid != demux[demux_id].program_number)
			|| (p->type == 'i' && (p->chid < 0x10000)))
			continue;
		return p;
	}
	return NULL;
}

struct s_dvbapi_priority *dvbapi_check_prio_match(int32_t demux_id, int32_t pidindex, char type) {
	struct s_dvbapi_priority *p;
	struct s_ecmpids *ecmpid = &demux[demux_id].ECMpids[pidindex];
	int32_t i;

	for (p=dvbapi_priority, i=0; p != NULL; p=p->next, i++) {
		if (p->type != type
			|| (p->caid && p->caid != ecmpid->CAID)
			|| (p->provid && p->provid != ecmpid->PROVID)
			|| (p->ecmpid && p->ecmpid != ecmpid->ECM_PID)
			|| (p->srvid && p->srvid != demux[demux_id].program_number)
			//|| (p->type == 'i' && (p->chid > -1)))  ///????
			|| (p->chid<0x10000 && p->chid != ecmpid->CHID))
			continue;
		return p;
	}
	return NULL;
}

void dvbapi_process_emm (int32_t demux_index, int32_t filter_num, unsigned char *buffer, uint32_t len) {
	EMM_PACKET epg;

	cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d fetched emm data", demux_index, filter_num+1); // emm shown with -d64
	
	struct s_emm_filter *filter = get_emmfilter_by_filternum(demux_index, filter_num+1);
	
	if (!filter){
		cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d no filter matches -> SKIP!", demux_index, filter_num+1);
		return;
	}

	uint32_t provider = filter->provid;
	uint16_t caid = filter->caid;

	struct s_dvbapi_priority *mapentry =dvbapi_check_prio_match_emmpid(filter->demux_id, filter->caid, filter->provid, 'm');
	if (mapentry) {
		cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d mapping EMM from %04X:%06X to %04X:%06X", demux_index, caid, provider, mapentry->mapcaid,
			mapentry->mapprovid);
		caid = mapentry->mapcaid;
		provider = mapentry->mapprovid;
	}

	memset(&epg, 0, sizeof(epg));

	i2b_buf(2, caid, epg.caid);
	i2b_buf(4, provider, epg.provid);

	epg.emmlen=len;
	memcpy(epg.emm, buffer, epg.emmlen);

#ifdef READER_IRDETO
	if (chk_is_betatunnel_caid(caid) == 2) {
		uint16_t ncaid = tunemm_caid_map(FROM_TO, caid, demux[demux_index].program_number);
		if (caid != ncaid) {
			irdeto_add_emm_header(&epg);
			i2b_buf(2, ncaid, epg.caid);
		}
	}
#endif

	do_emm(dvbapi_client, &epg);
}

void dvbapi_read_priority(void) {
	FILE *fp;
	char token[128], str1[128];
	char type;
	int32_t i, ret, count=0;

	const char *cs_prio="oscam.dvbapi";

	fp = fopen(get_config_filename(token, sizeof(token), cs_prio), "r");

	if (!fp) {
		cs_debug_mask(D_DVBAPI, "ERROR: Can't open priority file %s", token);
		return;
	}

	if (dvbapi_priority) {
		cs_debug_mask(D_DVBAPI, "reread priority file %s", cs_prio);
		struct s_dvbapi_priority *o, *p;
		for (p = dvbapi_priority; p != NULL; p = o) {
			o = p->next;
			free(p);
		}
		dvbapi_priority = NULL;
	}

	while (fgets(token, sizeof(token), fp)) {
		// Ignore comments and empty lines
		if (token[0]=='#' || token[0]=='/' || token[0]=='\n' || token[0]=='\r' || token[0]=='\0')
			continue;
		if (strlen(token)>100) continue;

		memset(str1, 0, 128);

		for (i=0; i<(int)strlen(token) && token[i]==' '; i++);
		if (i  == (int)strlen(token) - 1) //empty line or all spaces
			continue;

		for (i=0;i<(int)strlen(token);i++) {
			if ((token[i]==':' || token[i]==' ') && token[i+1]==':') { 	// if "::" or " :"
				memmove(token+i+2, token+i+1, strlen(token)-i+1); //insert extra position
				token[i+1]='0';		//and fill it with NULL
			}
			if (token[i]=='#' || token[i]=='/') {
				token[i]='\0';
				break;
			}
		}

		type = 0;
#ifdef WITH_STAPI
		uint32_t disablefilter=0;
		ret = sscanf(trim(token), "%c: %63s %63s %d", &type, str1, str1+64, &disablefilter);
#else
		ret = sscanf(trim(token), "%c: %63s %63s", &type, str1, str1+64);
#endif
		type = tolower(type);

		if (ret<1 || (type != 'p' && type != 'i' && type != 'm' && type != 'd' && type != 's' && type != 'l'
			&& type != 'j' && type != 'a' && type != 'x')) {
			//fprintf(stderr, "Warning: line containing %s in %s not recognized, ignoring line\n", token, cs_prio);
			//fprintf would issue the warning to the command line, which is more consistent with other config warnings
			//however it takes OSCam a long time (>4 seconds) to reach this part of the program, so the warnings are reaching tty rather late
			//which leads to confusion. So send the warnings to log file instead
			cs_debug_mask(D_DVBAPI, "WARN: line containing %s in %s not recognized, ignoring line\n", token, cs_prio);
			continue;
		}

		struct s_dvbapi_priority *entry;
		if (!cs_malloc(&entry, sizeof(struct s_dvbapi_priority))) {
			ret = fclose(fp);
			if (ret < 0) cs_log("ERROR: Could not close oscam.dvbapi fd (errno=%d %s)", errno, strerror(errno));
			return;
		}

		entry->type=type;
		entry->next=NULL;

		count++;

#ifdef WITH_STAPI
		if (type=='s') {
			strncpy(entry->devname, str1, 29);
			strncpy(entry->pmtfile, str1+64, 29);

			entry->disablefilter=disablefilter;

			cs_debug_mask(D_DVBAPI, "stapi prio: ret=%d | %c: %s %s | disable %d",
				ret, type, entry->devname, entry->pmtfile, disablefilter);

			if (!dvbapi_priority) {
				dvbapi_priority=entry;
			} else {
 				struct s_dvbapi_priority *p;
				for (p = dvbapi_priority; p->next != NULL; p = p->next);
				p->next = entry;
			}
			continue;
		}
#endif

		char c_srvid[34];
		c_srvid[0]='\0';
		uint32_t caid=0, provid=0, srvid=0, ecmpid=0;
		uint32_t chid=0x10000; //chid=0 is a valid chid
		ret = sscanf(str1, "%4x:%6x:%33[^:]:%4x:%4x"SCNx16, &caid, &provid, c_srvid, &ecmpid, &chid);
		if (ret < 1) {
			cs_log("[DVBAPI] Error in oscam.dvbapi: ret=%d | %c: %04X %06X %s %04X %04X",
				ret, type, caid, provid, c_srvid, ecmpid, chid);
			continue; // skip this entry!
		}
		else {
			cs_debug_mask(D_DVBAPI, "[DVBAPI] Parsing rule: ret=%d | %c: %04X %06X %s %04X %04X",
				ret, type, caid, provid, c_srvid, ecmpid, chid);
		}

		entry->caid=caid;
		entry->provid=provid;
		entry->ecmpid=ecmpid;
		entry->chid=chid;

		uint32_t delay=0, force=0, mapcaid=0, mapprovid=0, mapecmpid=0;
		switch (type) {
			case 'd':
				sscanf(str1+64, "%4d", &delay);
				entry->delay=delay;
				break;
			case 'l':
				entry->delay = dyn_word_atob(str1+64);
				if (entry->delay == -1) entry->delay = 0;
				break;
			case 'p':
				sscanf(str1+64, "%1d", &force);
				entry->force=force;
				break;
			case 'm':
				sscanf(str1+64, "%4x:%6x", &mapcaid, &mapprovid);
				entry->mapcaid=mapcaid;
				entry->mapprovid=mapprovid;
				break;
			case 'a':
			case 'j':
				sscanf(str1+64, "%4x:%6x:%4x", &mapcaid, &mapprovid, &mapecmpid);
				entry->mapcaid=mapcaid;
				entry->mapprovid=mapprovid;
				entry->mapecmpid=mapecmpid;
				break;
		}

		if (c_srvid[0]=='=') {
			struct s_srvid *this;

			for (i=0;i<16;i++)
			for (this = cfg.srvid[i]; this != NULL; this = this->next) {
				if (strcmp(this->prov, c_srvid+1)==0) {
					struct s_dvbapi_priority *entry2;
					if (!cs_malloc(&entry2,sizeof(struct s_dvbapi_priority)))
						continue;
					memcpy(entry2, entry, sizeof(struct s_dvbapi_priority));

					entry2->srvid=this->srvid;

					cs_debug_mask(D_DVBAPI, "[DVBAPI] prio srvid: ret=%d | %c: %04X %06X %04X %04X %04X -> map %04X %06X %04X | prio %d | delay %d",
						ret, entry2->type, entry2->caid, entry2->provid, entry2->srvid, entry2->ecmpid, entry2->chid,
						entry2->mapcaid, entry2->mapprovid, entry2->mapecmpid, entry2->force, entry2->delay);

					if (!dvbapi_priority) {
						dvbapi_priority=entry2;
					} else {
 						struct s_dvbapi_priority *p;
						for (p = dvbapi_priority; p->next != NULL; p = p->next);
						p->next = entry2;
					}
				}
			}
			free(entry);
			continue;
		} else {
			sscanf(c_srvid, "%4x", &srvid);
			entry->srvid=srvid;
		}

		cs_debug_mask(D_DVBAPI, "[DVBAPI] prio: ret=%d | %c: %04X %06X %04X %04X %04X -> map %04X %06X %04X | prio %d | delay %d",
			ret, entry->type, entry->caid, entry->provid, entry->srvid, entry->ecmpid, entry->chid, entry->mapcaid,
			entry->mapprovid, entry->mapecmpid, entry->force, entry->delay);

		if (!dvbapi_priority) {
			dvbapi_priority=entry;
		} else {
 			struct s_dvbapi_priority *p;
			for (p = dvbapi_priority; p->next != NULL; p = p->next);
			p->next = entry;
		}
	}

	cs_debug_mask(D_DVBAPI, "[DVBAPI] Read %d entries from %s", count, cs_prio);

	ret = fclose(fp);
	if (ret < 0) cs_log("ERROR: Could not close oscam.dvbapi fd (errno=%d %s)", errno, strerror(errno));
	return;
}

void dvbapi_resort_ecmpids(int32_t demux_index) {
	int32_t n, cache=0, prio=1, highest_prio=0, matching_done=0, found = -1;
	uint16_t btun_caid=0;

	for (n=0; n<demux[demux_index].ECMpidcount; n++) {
		demux[demux_index].ECMpids[n].status=0;
		demux[demux_index].ECMpids[n].checked=0;
	}

	demux[demux_index].max_status=0;
	demux[demux_index].curindex = -1;
	demux[demux_index].pidindex = -1;
	
	struct s_channel_cache *c;
	
	if (cfg.dvbapi_requestmode == 1) {
		for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
			c = find_channel_cache(demux_index, n, 0);
			if (c!=NULL) {
				found = n;
				break;
			}
		}
		if (found != -1) {	// Found in cache
			for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
				if (n != found){
					demux[demux_index].ECMpids[n].status = -1;
					if (c->chid < 0x10000) demux[demux_index].ECMpids[n].CHID = c->chid;
				}
				else{
					demux[demux_index].ECMpids[n].status = 1;
				}
			}
			demux[demux_index].max_emm_filter = MAX_FILTER-1;
			demux[demux_index].max_status = 1;
			cs_debug_mask(D_DVBAPI, "[DVBAPI] Found channel in cache, start descrambling pid %d ", found); 
			return;
		}
	} else {
		// prioritize CAIDs which already decoded same caid:provid
		for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
			c = find_channel_cache(demux_index, n, 1);
			if (c!=NULL) {
				cache=1; //found cache entry
				demux[demux_index].ECMpids[n].status = prio;
				cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (found caid/provid in cache - weight: %d)", n,
						demux[demux_index].ECMpids[n].CAID,demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, 
						demux[demux_index].ECMpids[n].status);
			}
		}

		// prioritize CAIDs which already decoded same caid:provid:srvid
		for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
			c = find_channel_cache(demux_index, n, 0);
			if (c!=NULL) {
				cache=2; //found cache entry with higher priority
				demux[demux_index].ECMpids[n].status = prio*2;
				if (c->chid < 0x10000) demux[demux_index].ECMpids[n].CHID = c->chid;
				cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (found caid/provid/srvid in cache - weight: %d)", n,
						demux[demux_index].ECMpids[n].CAID,demux[demux_index].ECMpids[n].PROVID, demux[demux_index].ECMpids[n].ECM_PID, 
						demux[demux_index].ECMpids[n].status);
			}
		}
	}

	// prioritize & ignore according to oscam.dvbapi and cfg.preferlocalcards
	if (!dvbapi_priority) cs_debug_mask(D_DVBAPI,"[DVBAPI] No oscam.dvbapi found or no valid rules are parsed!");
	
	if (dvbapi_priority) {		
		struct s_reader *rdr;
		ECM_REQUEST *er;
		if (!cs_malloc(&er, sizeof(ECM_REQUEST)))
			return;
		
		int32_t add_prio=0; // make sure that p: values overrule cache
		if (cache==1)
			add_prio = prio;
		else if (cache==2)
			add_prio = prio*2;
		
		// reverse order! makes sure that user defined p: values are in the right order
		int32_t p_order = demux[demux_index].ECMpidcount;

		highest_prio = (prio * demux[demux_index].ECMpidcount) + p_order;

		struct s_dvbapi_priority *p;
		for (p = dvbapi_priority; p != NULL; p = p->next) {
			if (p->type != 'p' && p->type != 'i')
				continue;
			for (n = 0; n < demux[demux_index].ECMpidcount; n++) {
				if (!cache && demux[demux_index].ECMpids[n].status != 0)
					continue;
				else if (cache==1 && (demux[demux_index].ECMpids[n].status < 0 || demux[demux_index].ECMpids[n].status > prio))
					continue;
				else if (cache==2 && (demux[demux_index].ECMpids[n].status < 0 || demux[demux_index].ECMpids[n].status > prio*2))
					continue;

				er->caid = er->ocaid = demux[demux_index].ECMpids[n].CAID;
				er->prid = demux[demux_index].ECMpids[n].PROVID;
				er->pid = demux[demux_index].ECMpids[n].ECM_PID;
				er->srvid = demux[demux_index].program_number;
				er->client = cur_client();

				btun_caid = chk_on_btun(SRVID_MASK, er->client, er);
				if (p->type == 'p' && btun_caid)
					er->caid = btun_caid;

				if (p->caid && p->caid != er->caid)
					continue;
				if (p->provid && p->provid != er->prid)
					continue;
				if (p->ecmpid && p->ecmpid != er->pid)
					continue;
				if (p->srvid && p->srvid != er->srvid)
					continue;
				
				if (p->type == 'i') { // check if ignored by dvbapi
					if (p->chid == 0x10000){ // ignore all? disable pid
						demux[demux_index].ECMpids[n].status = -1;
					}
					cs_debug_mask(D_DVBAPI,"[IGNORE PID %d] %04X:%06X:%04X:%04X (file)", n, demux[demux_index].ECMpids[n].CAID,
						demux[demux_index].ECMpids[n].PROVID,demux[demux_index].ECMpids[n].ECM_PID, (uint16_t) p->chid);
					continue;
				}

				if (p->type == 'p') {
					if (demux[demux_index].ECMpids[n].status == -1) //skip ignores
						continue;

					matching_done = 1;

					for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
						if (cfg.preferlocalcards && !is_network_reader(rdr)
							&& rdr->card_status == CARD_INSERTED) {	// cfg.preferlocalcards = 1 local reader

							if (matching_reader(er, rdr)) {
								if (cache==2 && demux[demux_index].ECMpids[n].status==1)
									demux[demux_index].ECMpids[n].status++;
								else if (cache && !demux[demux_index].ECMpids[n].status)
									demux[demux_index].ECMpids[n].status += add_prio;
								//priority*ECMpidcount should overrule network reader
								demux[demux_index].ECMpids[n].status += (prio * demux[demux_index].ECMpidcount) + (p_order--);
								cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X:%04X (localrdr: %s weight: %d)",
									n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
									demux[demux_index].ECMpids[n].ECM_PID, (uint16_t) p->chid, rdr->label,
									demux[demux_index].ECMpids[n].status);
								break;
							} else {
								if (!rdr->next) // no match so ignore it!
									demux[demux_index].ECMpids[n].status = -1;
							}
						} else {	// cfg.preferlocalcards = 0 or cfg.preferlocalcards = 1 and no local reader
							if (matching_reader(er, rdr)) {
								if (cache==2 && demux[demux_index].ECMpids[n].status==1)
									demux[demux_index].ECMpids[n].status++;
								else if (cache && !demux[demux_index].ECMpids[n].status)
									demux[demux_index].ECMpids[n].status += add_prio;
								demux[demux_index].ECMpids[n].status += prio + (p_order--);
								cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X:%04X (rdr: %s weight: %d)",
									n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
									demux[demux_index].ECMpids[n].ECM_PID, (uint16_t) p->chid, rdr->label,
									demux[demux_index].ECMpids[n].status);
								break;
							} else {
								if (!rdr->next) // no match so ignore it!
									demux[demux_index].ECMpids[n].status = -1;
							}
						}
					}
					if (demux[demux_index].ECMpids[n].status == -1)
						cs_debug_mask(D_DVBAPI,"[IGNORE PID %d] %04X:%06X:%04X:%04X (no matching reader)", n, demux[demux_index].ECMpids[n].CAID, 
							demux[demux_index].ECMpids[n].PROVID,demux[demux_index].ECMpids[n].ECM_PID, (uint16_t) p->chid);
				}
			}
		}
		free(er);
	} 

	if (!matching_done) {	//works if there is no oscam.dvbapi or if there is oscam.dvbapi but not p rules in it
		if (dvbapi_priority && !matching_done) 
			cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d no prio rules in oscam.dvbapi matches!", demux_index);

		struct s_reader *rdr;
		ECM_REQUEST *er;
		if (!cs_malloc(&er, sizeof(ECM_REQUEST)))
			return;

		highest_prio = prio*2;

		for (n=0; n<demux[demux_index].ECMpidcount; n++) {
			if (demux[demux_index].ECMpids[n].status == -1)	//skip ignores
				continue;

			er->caid = er->ocaid = demux[demux_index].ECMpids[n].CAID;
			er->prid = demux[demux_index].ECMpids[n].PROVID;
			er->pid = demux[demux_index].ECMpids[n].ECM_PID;
			er->srvid = demux[demux_index].program_number;
			er->client = cur_client();

			btun_caid = chk_on_btun(SRVID_MASK, er->client, er);
			if (btun_caid)
				er->caid = btun_caid;

			for (rdr=first_active_reader; rdr ; rdr=rdr->next) {
				if (cfg.preferlocalcards 
						&& !is_network_reader(rdr) 
						&& rdr->card_status==CARD_INSERTED) {	// cfg.preferlocalcards = 1 local reader
					if (matching_reader(er, rdr)) {
						demux[demux_index].ECMpids[n].status += prio*2;
						cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (localrdr: %s weight: %d)",
							n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
							demux[demux_index].ECMpids[n].ECM_PID, rdr->label,
							demux[demux_index].ECMpids[n].status);
						break;
					} else {
						if (!rdr->next)	// no match so ignore it!
							demux[demux_index].ECMpids[n].status = -1;
					}
				} else {	// cfg.preferlocalcards = 0 or cfg.preferlocalcards = 1 and no local reader
					if (matching_reader(er, rdr)) {
						demux[demux_index].ECMpids[n].status += prio;
						cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (rdr: %s weight: %d)",
							n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
							demux[demux_index].ECMpids[n].ECM_PID, rdr->label, demux[demux_index].ECMpids[n].status);
						break;
					} else {
						if (!rdr->next)	// no match so ignore it!
							demux[demux_index].ECMpids[n].status = -1;
					}
				}
			}
			if (demux[demux_index].ECMpids[n].status == -1)
				cs_debug_mask(D_DVBAPI,"[IGNORE PID %d] %04X:%06X:%04X (no matching reader)", n, demux[demux_index].ECMpids[n].CAID,
				demux[demux_index].ECMpids[n].PROVID,demux[demux_index].ECMpids[n].ECM_PID);
		}
		free(er);
	}

	if (cache==1)
		highest_prio += prio;
	else if (cache==2)
		highest_prio += prio*2;

	highest_prio++;

	for (n=0; n<demux[demux_index].ECMpidcount; n++){
		int32_t nr;
		SIDTAB *sidtab;
		ECM_REQUEST er;
		er.caid  = demux[demux_index].ECMpids[n].CAID;
		er.prid  = demux[demux_index].ECMpids[n].PROVID;
		er.srvid = demux[demux_index].program_number;

		for (nr=0, sidtab=cfg.sidtab; sidtab; sidtab=sidtab->next, nr++) {
			if (sidtab->num_caid | sidtab->num_provid | sidtab->num_srvid) {
				if ((cfg.dvbapi_sidtabs.no&((SIDTABBITS)1<<nr)) && (chk_srvid_match(&er, sidtab))) {
					demux[demux_index].ECMpids[n].status = -1; //ignore
					cs_debug_mask(D_DVBAPI,"[IGNORE PID %d] %04X:%06X:%04X (service %s) pos %d",
						n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
						demux[demux_index].ECMpids[n].ECM_PID, sidtab->label, nr);
				}
				if ((cfg.dvbapi_sidtabs.ok&((SIDTABBITS)1<<nr)) && (chk_srvid_match(&er, sidtab))) {
					demux[demux_index].ECMpids[n].status = highest_prio++; //priority
					cs_debug_mask(D_DVBAPI,"[PRIORITIZE PID %d] %04X:%06X:%04X (service: %s position: %d)",
						n, demux[demux_index].ECMpids[n].CAID, demux[demux_index].ECMpids[n].PROVID,
						demux[demux_index].ECMpids[n].ECM_PID, sidtab->label,
						demux[demux_index].ECMpids[n].status);
				}
			}
		}
	}

	highest_prio = 0;
	for (n=0; n<demux[demux_index].ECMpidcount; n++){
		if (demux[demux_index].ECMpids[n].status > highest_prio) highest_prio = demux[demux_index].ECMpids[n].status; // find highest prio pid
		if (demux[demux_index].ECMpids[n].status == 0) demux[demux_index].ECMpids[n].checked = 2; // set pids with no status to no prio run 
	}
	
	struct s_dvbapi_priority *match;
	for (match = dvbapi_priority; match != NULL; match = match->next) {
		if (match->type != 'p')
			continue;
		if (!match || !match->force) // only evaluate forced prio's
			continue;
		for (n=0; n<demux[demux_index].ECMpidcount; n++){
			if(match->caid &&  match->caid != demux[demux_index].ECMpids[n].CAID) continue;
			if(match->provid && match->provid != demux[demux_index].ECMpids[n].PROVID) continue;
			if(match->srvid && match->srvid != demux[demux_index].program_number) continue;
			if(match->ecmpid && match->ecmpid != demux[demux_index].ECMpids[n].ECM_PID) continue;
			if(match->chid && match->chid <0x10000) demux[demux_index].ECMpids[n].CHID = match->chid;
			demux[demux_index].ECMpids[n].status = ++highest_prio;
			cs_debug_mask(D_DVBAPI,"[FORCED PID %d] %04X:%06X:%04X:%04X", n, demux[demux_index].ECMpids[n].CAID, 
				demux[demux_index].ECMpids[n].PROVID,demux[demux_index].ECMpids[n].ECM_PID, (uint16_t) match->chid);
			demux[demux_index].max_status = highest_prio; // register maxstatus
			demux[demux_index].ECMpids[n].checked = 0; // set forced pid to prio run 
			return; // we only accept one forced pid!
		}
	}
	demux[demux_index].max_status = highest_prio; // register maxstatus
	return;
}


void dvbapi_parse_descriptor(int32_t demux_id, uint32_t info_length, unsigned char *buffer) {
	// int32_t ca_pmt_cmd_id = buffer[i + 5];
	uint32_t descriptor_length=0;
	uint32_t j,u;

	if (info_length<1)
		return;

	if (buffer[0]==0x01) {
		buffer=buffer+1;
		info_length--;
	}

	for (j = 0; j < info_length; j += descriptor_length + 2) {
		descriptor_length = buffer[j+1];
		
		if (buffer[j] == 0x81 && descriptor_length == 8) { // private descriptor of length 8, assume enigma/tvh
			demux[demux_id].enigma_namespace = (buffer[j+2] << 24 | buffer[j+3] << 16 | buffer[j+4] << 8 | buffer[j+5]);
			demux[demux_id].tsid = (buffer[j+6] << 8 | buffer[j+7]);
			demux[demux_id].onid = (buffer[j+8] << 8 | buffer[j+9]);			
			cs_debug_mask(D_DVBAPI, "[pmt] type: %02x length: %d (assuming enigma private descriptor: namespace %04x tsid %02x onid %02x)", 
					buffer[j], descriptor_length, demux[demux_id].enigma_namespace, demux[demux_id].tsid, demux[demux_id].onid);		
		} else {
			cs_debug_mask(D_DVBAPI, "[pmt] type: %02x length: %d", buffer[j], descriptor_length);
		}		

		if (buffer[j] != 0x09) continue;
		if (demux[demux_id].ECMpidcount>=ECM_PIDS) break;
		
		int32_t descriptor_ca_system_id = (buffer[j+2] << 8) | buffer[j+3];
		int32_t descriptor_ca_pid = ((buffer[j+4] & 0x1F) << 8) | buffer[j+5];
		int32_t descriptor_ca_provider = 0;		

		if (descriptor_ca_system_id >> 8 == 0x01) {
			for (u=2; u<descriptor_length; u+=15) {
				descriptor_ca_pid = ((buffer[j+2+u] & 0x1F) << 8) | buffer[j+2+u+1];
				descriptor_ca_provider = (buffer[j+2+u+2] << 8) | buffer[j+2+u+3];
				dvbapi_add_ecmpid(demux_id, descriptor_ca_system_id, descriptor_ca_pid, descriptor_ca_provider);
			}
		} else {
			if (descriptor_ca_system_id >> 8 == 0x05 && descriptor_length == 0x0F && buffer[j+12] == 0x14)
				descriptor_ca_provider = buffer[j+14] << 16 | (buffer[j+15] << 8| (buffer[j+16] & 0xF0));

			if (descriptor_ca_system_id >> 8 == 0x18 && descriptor_length == 0x07)
				descriptor_ca_provider = (buffer[j+7] << 8| (buffer[j+8]));

			if (descriptor_ca_system_id >> 8 == 0x4A && descriptor_length == 0x05)
				descriptor_ca_provider = buffer[j+6];

			dvbapi_add_ecmpid(demux_id, descriptor_ca_system_id, descriptor_ca_pid, descriptor_ca_provider);
		}
	}

	// Apply mapping:
	if (dvbapi_priority) {
		struct s_dvbapi_priority *mapentry;
		for (j = 0; (int32_t)j < demux[demux_id].ECMpidcount; j++) {
			mapentry = dvbapi_check_prio_match(demux_id, j, 'm');
			if (mapentry) {
				cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d mapping ECM from %04X:%06X to %04X:%06X", demux_id,
						demux[demux_id].ECMpids[j].CAID, demux[demux_id].ECMpids[j].PROVID,
						mapentry->mapcaid, mapentry->mapprovid);
				demux[demux_id].ECMpids[j].CAID = mapentry->mapcaid;
				demux[demux_id].ECMpids[j].PROVID = mapentry->mapprovid;
			}
		}
	}
}

void request_cw(struct s_client *client, ECM_REQUEST *er, int32_t demux_id, uint8_t delayed_ecm_check)
{
	int32_t filternum = dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd -> even and visaversa
#if defined WITH_AZBOX || defined WITH_MCA
	if (filternum) {}
#else
	if (filternum<0) {
		cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d not requesting cw -> ecm filter was killed!", demux_id);
		return;
	}
#endif
	get_cw(client, er);
#if defined WITH_AZBOX || defined WITH_MCA
	if (delayed_ecm_check) {}
#else
	if (delayed_ecm_check) memcpy(demux[demux_id].demux_fd[filternum].ecmd5, er->ecmd5, CS_ECMSTORESIZE); // register this ecm as latest request for this filter
	else memset(demux[demux_id].demux_fd[filternum].ecmd5,0,CS_ECMSTORESIZE); // zero out ecmcheck!
#endif
#ifdef WITH_DEBUG
	char buf[ECM_FMT_LEN];
	format_ecm(er, buf, ECM_FMT_LEN);
	cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d request cw for ecm %s", demux_id, buf);
#endif
}

void dvbapi_try_next_caid(int32_t demux_id, int8_t checked) {
	
	int32_t n, j, found = -1, started = 0;
	
	int32_t status=demux[demux_id].max_status;
		
	for (j = status; j >= 0; j--) {	// largest status first!
		
		for (n=0; n<demux[demux_id].ECMpidcount; n++) {
			//cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d PID #%d checked = %d status = %d (searching for pid with status = %d)", demux_id, n,
			//	demux[demux_id].ECMpids[n].checked, demux[demux_id].ECMpids[n].status, j);
			if (demux[demux_id].ECMpids[n].checked == checked && demux[demux_id].ECMpids[n].status == j) {
				found = n;
#if defined WITH_AZBOX || defined WITH_MCA
				openxcas_provid = demux[demux_id].ECMpids[found].PROVID;
				openxcas_caid = demux[demux_id].ECMpids[found].CAID;
				openxcas_ecm_pid = demux[demux_id].ECMpids[found].ECM_PID;
#endif
				if((demux[demux_id].ECMpids[found].CAID >> 8) == 0x06) demux[demux_id].emmstart = 0; // fixup for cas that need emm first!
				started = dvbapi_start_descrambling(demux_id, found, checked);
				if (cfg.dvbapi_requestmode == 0 && started == 1) return; // in requestmode 0 we only start 1 ecm request at the time
			}
		}
	}

	if (found == -1 && demux[demux_id].pidindex == -1) {
		cs_log("[DVBAPI] Demuxer #%d no suitable readers found that can be used for decoding!", demux_id);
		return;
	}
}

static void getDemuxOptions(int32_t demux_id, unsigned char *buffer, uint16_t *ca_mask, uint16_t *demux_index, uint16_t *adapter_index){
	*ca_mask=0x01, *demux_index=0x00, *adapter_index=0x00;

	if (buffer[17]==0x82 && buffer[18]==0x02) {
		// enigma2
		*ca_mask = buffer[19];
		*demux_index = buffer[20];
	}

	if (cfg.dvbapi_boxtype == BOXTYPE_IPBOX_PMT) {
		*ca_mask = demux_id + 1;
		*demux_index = demux_id;
	}

	if (cfg.dvbapi_boxtype == BOXTYPE_QBOXHD && buffer[17]==0x82 && buffer[18]==0x03) {
		// ca_mask = buffer[19]; // with STONE 1.0.4 always 0x01
		*demux_index = buffer[20]; // with STONE 1.0.4 always 0x00
		*adapter_index = buffer[21]; // with STONE 1.0.4 adapter index can be 0,1,2
		*ca_mask = (1 << *adapter_index); // use adapter_index as ca_mask (used as index for ca_fd[] array)
	}

	if (cfg.dvbapi_boxtype == BOXTYPE_PC && buffer[7]==0x82 && buffer[8]==0x02) {
		*demux_index = buffer[9]; // it is always 0 but you never know
		*adapter_index = buffer[10]; // adapter index can be 0,1,2
		*ca_mask = (1 << *adapter_index); // use adapter_index as ca_mask (used as index for ca_fd[] array)
	}
}

int32_t dvbapi_parse_capmt(unsigned char *buffer, uint32_t length, int32_t connfd, char *pmtfile) {
	uint32_t i, running = 0;
	int32_t j;
	int32_t demux_id=-1;
	uint16_t ca_mask, demux_index, adapter_index;
#define LIST_MORE 0x00    //*CA application should append a 'MORE' CAPMT object to the list and start receiving the next object
#define LIST_FIRST 0x01   //*CA application should clear the list when a 'FIRST' CAPMT object is received, and start receiving the next object
#define LIST_LAST 0x02   //*CA application should append a 'LAST' CAPMT object to the list and start working with the list
#define LIST_ONLY 0x03   //*CA application should clear the list when an 'ONLY' CAPMT object is received, and start working with the object
#define LIST_ADD 0x04    //*CA application should append an 'ADD' CAPMT object to the current list and start working with the updated list
#define LIST_UPDATE 0x05 //*CA application should replace an entry in the list with an 'UPDATE' CAPMT object, and start working with the updated list

#ifdef WITH_COOLAPI
	int32_t ca_pmt_list_management = LIST_ONLY;
#else
	int32_t ca_pmt_list_management = buffer[0];
#endif
	uint32_t program_number = (buffer[1] << 8) | buffer[2];
	uint32_t program_info_length = ((buffer[4] & 0x0F) << 8) | buffer[5];

	cs_ddump_mask(D_DVBAPI, buffer, length, "capmt:");
	cs_log("[DVBAPI] Receiver sends PMT command %d for channel %04X", ca_pmt_list_management, program_number);
	if ((ca_pmt_list_management == LIST_FIRST || ca_pmt_list_management == LIST_ONLY) && pmt_stopmarking == 0){
		for (i = 0; i < MAX_DEMUX; i++) {
			if (demux[i].program_number == 0) continue; // skip empty demuxers
			if (demux[i].socket_fd != connfd) continue; // skip demuxers belonging to other ca pmt connection
			demux[i].stopdescramble = 1; // Mark for deletion if not used again by following pmt objects.
			cs_debug_mask(D_DVBAPI,"[DVBAPI] Marked demuxer #%d/%d to stop decoding", i, MAX_DEMUX);
			pmt_stopmarking = 1;
			pmt_stopdescrambling_done = 0;
		}
	}
	for (i = 0; i < MAX_DEMUX; i++) { // search current demuxers for running the same program as the one we received in this PMT object
		if (demux[i].program_number == 0) continue;
	
#ifdef WITH_COOLAPI
		if (connfd>0 && demux[i].program_number==program_number) {
#else
		if ((connfd>0 && demux[i].socket_fd == connfd) && demux[i].program_number == program_number){
#endif
			getDemuxOptions(i, buffer, &ca_mask, &demux_index, &adapter_index);
			cs_log("[DVBAPI] Receiver wants to demux srvid %04X on adapter %04X camask %04X index %04X", program_number, adapter_index, ca_mask, demux_index);
			
			if (ca_pmt_list_management == LIST_UPDATE || ca_pmt_list_management == LIST_LAST) {//PMT Update */
				
				if (demux[i].adapter_index != adapter_index || demux[i].demux_index!=demux_index){
					cs_log("[DVBAPI] Demuxer #%d PMT update for decoding of SRVID %04X on additional demuxer! ", i, program_number);
					demux[i].stopdescramble = 0;
				}
				else{
					demux_id = i;
					demux[demux_id].curindex = -1;
					demux[demux_id].ca_mask = ca_mask; 
					demux[demux_id].pidindex = -1;
					demux[demux_id].STREAMpidcount=0;
					if(demux[demux_id].ECMpidcount != 0) running = 1; // fix for channel changes from fta to scrambled
					demux[demux_id].ECMpidcount=0;
					demux[demux_id].ECMpids[0].streams = 0; // reset first ecmpid streams!
					demux[demux_id].EMMpidcount=0;
					demux[i].stopdescramble = 0;
					running = 1;
					cs_log("[DVBAPI] Demuxer #%d PMT update for decoding of SRVID %04X", i, program_number);
				}
			}
				
			if (ca_pmt_list_management != LIST_UPDATE && ca_pmt_list_management != LIST_LAST){ 
				demux_id=i;
				if(demux[demux_id].adapter_index==adapter_index && demux[demux_id].demux_index==demux_index){
					cs_log("[DVBAPI] Demuxer #%d continue decoding of SRVID %04X", i, demux[i].program_number);
#if defined WITH_AZBOX || defined WITH_MCA
					openxcas_sid = program_number;
#endif
					demux[i].stopdescramble = 0;
					// stop descramble old demuxers from this ca pmt connection that arent used anymore 
					if ((ca_pmt_list_management == LIST_LAST) || (ca_pmt_list_management == LIST_ONLY)){
						for (j = 0; j < MAX_DEMUX; j++) {
							if (demux[j].program_number == 0) continue;
							if (demux[j].stopdescramble == 1) dvbapi_stop_descrambling(j); // Stop descrambling and remove all demuxer entries not in new PMT.
						}
						pmt_stopdescrambling_done = 1; // mark stopdescrambling as done!
					}
					demux[demux_id].ca_mask = ca_mask; // set ca_mask, it might have been changed!
					if(demux[demux_id].ECMpidcount == 0) running = 0; // fix for channel changes from fta to scrambled
					else return demux_id; // since we are continueing decoding here it ends!
				}
			}
			
			break; // no need to explore other demuxers since we have a found!
		}
	}
	 // stop descramble old demuxers from this ca pmt connection that arent used anymore
	if (((ca_pmt_list_management == LIST_LAST) || (ca_pmt_list_management == LIST_ONLY)) && pmt_stopdescrambling_done == 0){
		for (j = 0; j < MAX_DEMUX; j++) {
			if (demux[j].program_number == 0) continue;
			if (demux[j].stopdescramble == 1) dvbapi_stop_descrambling(j); // Stop descrambling and remove all demuxer entries not in new PMT.
		}
	}
	

	if (demux_id==-1){
		for (demux_id=0; demux_id<MAX_DEMUX && demux[demux_id].program_number>0; demux_id++);
	}

	if (demux_id>=MAX_DEMUX) {
		cs_log("ERROR: No free id (MAX_DEMUX)");
		return -1;
	}
	
	demux[demux_id].program_number=program_number; // do this early since some prio items use them!
	
	demux[demux_id].enigma_namespace=0;
	demux[demux_id].tsid=0;
	demux[demux_id].onid=0;

	if (pmtfile)
		cs_strncpy(demux[demux_id].pmt_file, pmtfile, sizeof(demux[demux_id].pmt_file));

	if (program_info_length > 1 && program_info_length < length)
		dvbapi_parse_descriptor(demux_id, program_info_length-1, buffer+7);

	uint32_t es_info_length=0, vpid = 0;
	struct s_dvbapi_priority *addentry;

	for (i = program_info_length + 6; i < length; i += es_info_length + 5) {
		int32_t stream_type = buffer[i];
		uint16_t elementary_pid = ((buffer[i + 1] & 0x1F) << 8) | buffer[i + 2];
		es_info_length = ((buffer[i + 3] & 0x0F) << 8) | buffer[i + 4];

		cs_debug_mask(D_DVBAPI, "[pmt] stream_type: %02x pid: %04x length: %d", stream_type, elementary_pid, es_info_length);

		if (demux[demux_id].STREAMpidcount >= ECM_PIDS)
			break;

		demux[demux_id].STREAMpids[demux[demux_id].STREAMpidcount++]=elementary_pid;
		// find and register videopid
		if (!vpid && (stream_type == 01 || stream_type == 02 || stream_type == 0x10 || stream_type == 0x1B)) vpid = elementary_pid; 
		
		if (es_info_length != 0 && es_info_length < length) {
			dvbapi_parse_descriptor(demux_id, es_info_length, buffer+i+5);
		} else {
			for (addentry=dvbapi_priority; addentry != NULL; addentry=addentry->next) {
				if (addentry->type != 'a'
					|| (addentry->ecmpid && addentry->ecmpid != elementary_pid)
					|| (addentry->srvid != demux[demux_id].program_number))
					continue;
				cs_debug_mask(D_DVBAPI,"[pmt] Add Fake FFFF:%06x:%04x for unencrypted stream on srvid %04X", addentry->mapprovid, addentry->mapecmpid, demux[demux_id].program_number);
				dvbapi_add_ecmpid(demux_id, 0xFFFF, addentry->mapecmpid, addentry->mapprovid);
				break;
			}
		}
	}
	for(j = 0; j < demux[demux_id].ECMpidcount; j++){
		demux[demux_id].ECMpids[j].VPID=vpid; // register found vpid on all ecmpids of this demuxer
	}
	cs_log("Found %d ECMpids and %d STREAMpids in PMT", demux[demux_id].ECMpidcount, demux[demux_id].STREAMpidcount);
	
	getDemuxOptions(demux_id, buffer, &ca_mask, &demux_index, &adapter_index);
	cs_log("[DVBAPI] Receiver wants to demux srvid %04X on adapter %04X camask %04X index %04X",
		demux[demux_id].program_number, adapter_index, ca_mask, demux_index);
	demux[demux_id].adapter_index=adapter_index;
	demux[demux_id].ca_mask=ca_mask;
	demux[demux_id].rdr=NULL;
	demux[demux_id].demux_index=demux_index;
	demux[demux_id].socket_fd=connfd;
	demux[demux_id].stopdescramble = 0; // remove deletion mark!
	
	char channame[32];
	get_servicename(dvbapi_client, demux[demux_id].program_number, demux[demux_id].ECMpidcount>0 ? demux[demux_id].ECMpids[0].CAID : 0, channame);
	cs_log("New program number: %04X (%s) [pmt_list_management %d]", program_number, channame, ca_pmt_list_management);

	cs_capmt_notify(&demux[demux_id]);
	
	cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d demux_index: %2d ca_mask: %02x program_info_length: %3d ca_pmt_list_management %02x",
		demux_id, demux[demux_id].demux_index, demux[demux_id].ca_mask, program_info_length, ca_pmt_list_management);
	
	struct s_dvbapi_priority *xtraentry;
	int32_t k, l, m, xtra_demux_id;

	for (xtraentry=dvbapi_priority; xtraentry != NULL; xtraentry=xtraentry->next) {
		if (xtraentry->type != 'x') continue;

		for(j = 0; j <= demux[demux_id].ECMpidcount; ++j){
			if ((xtraentry->caid && xtraentry->caid != demux[demux_id].ECMpids[j].CAID)
				|| (xtraentry->provid && xtraentry->provid 	!= demux[demux_id].ECMpids[j].PROVID)
				|| (xtraentry->ecmpid && xtraentry->ecmpid 	!= demux[demux_id].ECMpids[j].ECM_PID)
				|| (xtraentry->srvid && xtraentry->srvid != demux[demux_id].program_number))
				continue;

			cs_log("[pmt] Mapping %04X:%06X:%04X:%04X to xtra demuxer/ca-devices", xtraentry->caid, xtraentry->provid, xtraentry->ecmpid, xtraentry->srvid);

			for (xtra_demux_id=0; xtra_demux_id<MAX_DEMUX && demux[xtra_demux_id].program_number>0; xtra_demux_id++)
				;

			if (xtra_demux_id>=MAX_DEMUX) {
				cs_log("Found no free demux device for xtra streams.");
				continue;
			}
			// copy to new demuxer
			getDemuxOptions(demux_id, buffer, &ca_mask, &demux_index, &adapter_index);
			demux[xtra_demux_id].ECMpids[0] = demux[demux_id].ECMpids[j];
			demux[xtra_demux_id].ECMpidcount = 1;
			demux[xtra_demux_id].STREAMpidcount = 0;
			demux[xtra_demux_id].program_number=demux[demux_id].program_number;
			demux[xtra_demux_id].demux_index=demux_index;
			demux[xtra_demux_id].adapter_index=adapter_index;
			demux[xtra_demux_id].ca_mask=ca_mask;
			demux[xtra_demux_id].socket_fd=connfd;
			demux[xtra_demux_id].stopdescramble = 0; // remove deletion mark!
			demux[xtra_demux_id].rdr=NULL;
			demux[xtra_demux_id].curindex=-1;			

			// add streams to xtra demux
			for(k = 0; k < demux[demux_id].STREAMpidcount; ++k){
				if(!demux[demux_id].ECMpids[j].streams || demux[demux_id].ECMpids[j].streams & (1 << k)){
					demux[xtra_demux_id].ECMpids[0].streams |= (1 << demux[xtra_demux_id].STREAMpidcount);
					demux[xtra_demux_id].STREAMpids[demux[xtra_demux_id].STREAMpidcount] = demux[demux_id].STREAMpids[k];
					++demux[xtra_demux_id].STREAMpidcount;

					// shift stream associations in normal demux because we will remove the stream entirely
					for(l = 0; l < demux[demux_id].ECMpidcount; ++l){
						for(m = k; m < demux[demux_id].STREAMpidcount-1; ++m){
							if(demux[demux_id].ECMpids[l].streams & (1 << (m+1))){
								demux[demux_id].ECMpids[l].streams |= (1 << m);
							} else {
								demux[demux_id].ECMpids[l].streams &= ~(1 << m);
							}
						}
					}

					// remove stream association from normal demux device
					for(l = k; l < demux[demux_id].STREAMpidcount-1; ++l){
						demux[demux_id].STREAMpids[l] = demux[demux_id].STREAMpids[l+1];
					}
					--demux[demux_id].STREAMpidcount;
					--k;
				}
			}

			// remove ecmpid from normal demuxer
			for(k = j; k < demux[demux_id].ECMpidcount; ++k){
				demux[demux_id].ECMpids[k] = demux[demux_id].ECMpids[k+1];
			}
			--demux[demux_id].ECMpidcount;
			--j;

			if(demux[xtra_demux_id].STREAMpidcount > 0){
				dvbapi_resort_ecmpids(xtra_demux_id);
				dvbapi_try_next_caid(xtra_demux_id,0);
			} else {
				cs_log("[pmt] Found no streams for xtra demuxer. Not starting additional decoding on it.");
			}

			if(demux[demux_id].STREAMpidcount < 1){
				cs_log("[pmt] Found no streams for normal demuxer. Not starting additional decoding on it.");
#if defined WITH_AZBOX || defined WITH_MCA
				openxcas_sid = program_number;
#endif
				return xtra_demux_id;
			}
		}
	}
	
	if(cfg.dvbapi_au>0 && demux[demux_id].emmstart == 1 ){ // irdeto fetch emm cat direct!
		demux[demux_id].emmstart = time(NULL); // trick to let emm fetching start after 30 seconds to speed up zapping
		dvbapi_start_filter(demux_id, demux[demux_id].pidindex, 0x001, 0x001, 0x01, 0x01, 0xFF, 0, TYPE_EMM, 1); //CAT
	}
	else demux[demux_id].emmstart = time(NULL); // for all other caids delayed start!

        // set channel srvid+caid 
        dvbapi_client->last_srvid = demux[demux_id].program_number; 
        dvbapi_client->last_caid = 0; 
        // reset idle-Time 
        dvbapi_client->last=time((time_t*)0);

#if defined WITH_AZBOX || defined WITH_MCA
	openxcas_sid = program_number;
#endif
        if(demux[demux_id].ECMpidcount == 0) return demux_id; // for FTA it ends here!
	
	if (running == 0){ // only start demuxer if it wasnt running
		dvbapi_resort_ecmpids(demux_id);
		dvbapi_try_next_caid(demux_id,0);
	}	
	return demux_id;
}


void dvbapi_handlesockmsg (unsigned char *buffer, uint32_t len, int32_t connfd) {
	uint32_t val=0, size=0, i, k;
	pmt_stopmarking = 0; // to stop_descrambling marking in PMT 6 mode
	
	for (k = 0; k < len; k += 3 + size + val) {
		if (buffer[0+k] != 0x9F || buffer[1+k] != 0x80) {
			cs_debug_mask(D_DVBAPI,"[DVBAPI] Received unknown PMT command: %02x", buffer[0+k]);
			break;
		}

		if (k>0 && cfg.dvbapi_pmtmode != 6) {
			cs_log("Unsupported capmt. Please report");
			cs_dump(buffer, len, "capmt: (k=%d)", k);
		}
		if (k>0 && cfg.dvbapi_pmtmode == 6)
			cs_ddump_mask(D_DVBAPI, buffer+k, len-k,"[DVBAPI] Parsing next PMT object(s):");

		if (buffer[3+k] & 0x80) {
			val = 0;
			size = buffer[3+k] & 0x7F;
			for (i = 0; i < size; i++)
				val = (val << 8) | buffer[i + 1 + 3 + k];
			size++;
		} else	{
			val = buffer[3+k] & 0x7F;
			size = 1;
		}
		switch(buffer[2+k]) {
			case 0x32:
				/*if (buffer[size+3+k] == 0x00 && cfg.dvbapi_pmtmode == 6){ // LIST_MORE only for pmtmode 6, read more input from ca pmt server!
					int32_t pmtlen = recv(connfd, (buffer+len), (sizeof(buffer)-len), MSG_DONTWAIT);
					if (pmtlen<1){
						cs_debug_mask(D_DVBAPI,"[DVBAPI] Error: received PMT LIST_MORE command but no additional PMT object received!");
					}
					else{
						len += pmtlen;
						cs_debug_mask(D_DVBAPI,"[DVBAPI] Received PMT LIST_MORE command and additional PMT object(s) received!");
						dvbapi_parse_capmt(buffer + size + 3 + k, val, connfd, NULL);
						break;
					}
				}*/
				dvbapi_parse_capmt(buffer + size + 3 + k, val, connfd, NULL);
				break;
			case 0x3f:
				// 9F 80 3f 04 83 02 00 <demux index>
				cs_ddump_mask(D_DVBAPI, buffer, len, "capmt 3f:");
				// ipbox fix
				if (cfg.dvbapi_boxtype==BOXTYPE_IPBOX) {
					int32_t demux_index=buffer[7+k];
					for (i = 0; i < MAX_DEMUX; i++) {
						if (demux[i].demux_index == demux_index) {
							dvbapi_stop_descrambling(i);
							break;
						}
					}
					// check do we have any demux running on this fd
					int16_t execlose = 1;
					for (i = 0; i < MAX_DEMUX; i++) {
						if (demux[i].socket_fd == connfd) {
							 execlose = 0;
							 break;
						}
					}
					if (execlose){
						int32_t ret = close(connfd);
						if (ret < 0) cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno));
					}
				} else {
					if (cfg.dvbapi_pmtmode != 6){
						int32_t ret = close(connfd);
						if (ret < 0) cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno));
					}
				}
				break;
			default:
				cs_debug_mask(D_DVBAPI,"handlesockmsg() unknown command");
				cs_dump(buffer, len, "unknown command:");
				break;
		}
	}
}

int32_t dvbapi_init_listenfd(void) {
	int32_t clilen,listenfd;
	struct sockaddr_un servaddr;

	memset(&servaddr, 0, sizeof(struct sockaddr_un));
	servaddr.sun_family = AF_UNIX;
	cs_strncpy(servaddr.sun_path, devices[selected_box].cam_socket_path, sizeof(servaddr.sun_path));
	clilen = sizeof(servaddr.sun_family) + strlen(servaddr.sun_path);

	if ((unlink(devices[selected_box].cam_socket_path) < 0) && (errno != ENOENT))
		return 0;
	if ((listenfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return 0;
	if (bind(listenfd, (struct sockaddr *)&servaddr, clilen) < 0)
		return 0;
	if (listen(listenfd, 5) < 0)
		return 0;

	// change the access right on the camd.socket
	// this will allow oscam to run as root if needed
	// and still allow non root client to connect to the socket
	chmod(devices[selected_box].cam_socket_path, S_IRWXU | S_IRWXG | S_IRWXO);

	return listenfd;
}

static pthread_mutex_t event_handler_lock;

void event_handler(int32_t UNUSED(signal)) {
	struct stat pmt_info;
	char dest[1024];
	DIR *dirp;
	struct dirent entry, *dp = NULL;
	int32_t i, pmt_fd;
	uchar mbuf[2048]; // dirty fix: larger buffer needed for CA PMT mode 6 with many parallel channels to decode
	if (dvbapi_client != cur_client()) return;

	pthread_mutex_lock(&event_handler_lock);

	if (cfg.dvbapi_boxtype == BOXTYPE_PC)
		pausecam = 0;
	else {
		int32_t standby_fd = open(STANDBY_FILE, O_RDONLY);
		pausecam = (standby_fd > 0) ? 1 : 0;
		if (standby_fd> 0) {
			int32_t ret = close(standby_fd);
			if (ret < 0) cs_log("ERROR: Could not close standby fd (errno=%d %s)", errno, strerror(errno));
		}
	}

	if (cfg.dvbapi_boxtype==BOXTYPE_IPBOX || cfg.dvbapi_pmtmode == 1) {
		pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	for (i=0;i<MAX_DEMUX;i++) {
		if (demux[i].pmt_file[0] != 0) {
			snprintf(dest, sizeof(dest), "%s%s", TMPDIR, demux[i].pmt_file);
			pmt_fd = open(dest, O_RDONLY);
			if(pmt_fd>0) {
				if (fstat(pmt_fd, &pmt_info) != 0) {
					int32_t ret = close(pmt_fd);
					if (ret < 0) cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno));
					continue;
				}

				if ((time_t)pmt_info.st_mtime != demux[i].pmt_time) {
					cs_log("PMT file %s is updated -> stop descrambling demuxer #%d", dest, i);
				 	dvbapi_stop_descrambling(i);
				}

				int32_t ret = close(pmt_fd);
				if (ret < 0) cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno));
				continue;
			} else {
				cs_log("Could not open PMT file %s -> stop descrambling demuxer #%d", dest, i);
				dvbapi_stop_descrambling(i);
			}
		}
	}

	if (disable_pmt_files) {
		pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	dirp = opendir(TMPDIR);
	if (!dirp) {
		cs_debug_mask(D_DVBAPI,"opendir failed (errno=%d %s)", errno, strerror(errno));
		pthread_mutex_unlock(&event_handler_lock);
		return;
	}

	while (!cs_readdir_r(dirp, &entry, &dp)) {
		if (!dp) break;

		if (strlen(dp->d_name) < 7)
			continue;
		if (strncmp(dp->d_name, "pmt", 3)!=0 || strncmp(dp->d_name+strlen(dp->d_name)-4, ".tmp", 4)!=0)
			continue;
#ifdef WITH_STAPI
		struct s_dvbapi_priority *p;
		for (p=dvbapi_priority; p != NULL; p=p->next) { // stapi: check if there is a device connected to this pmt file!
			if (p->type!='s') continue; // stapi rule?
			if (strcmp(dp->d_name, p->pmtfile)!=0) continue; // same file?
			break; // found match!
		}
		if (p == NULL){
			cs_debug_mask(D_DVBAPI, "No matching S: line in oscam.dvbapi for pmtfile %s -> skip!", dp->d_name);
			continue;
		}
#endif
		snprintf(dest, sizeof(dest), "%s%s", TMPDIR, dp->d_name);
		pmt_fd = open(dest, O_RDONLY);
		if (pmt_fd < 0)
			continue;

		if (fstat(pmt_fd, &pmt_info) != 0){
			int32_t ret = close(pmt_fd);
			if (ret < 0) cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno));
			continue;
		}

		int32_t found=0;
		for (i=0;i<MAX_DEMUX;i++) {
			if (strcmp(demux[i].pmt_file, dp->d_name)==0) {
				if ((time_t)pmt_info.st_mtime == demux[i].pmt_time) {
				 	found=1;
					continue;
				}
				dvbapi_stop_descrambling(i);
			}
		}
		if (found){
			int32_t ret = close(pmt_fd);
			if (ret < 0) cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno));
			continue;
		}

		cs_debug_mask(D_DVBAPI,"found pmt file %s", dest);
		cs_sleepms(100);

		uint32_t len = read(pmt_fd,mbuf,sizeof(mbuf));
		int32_t ret = close(pmt_fd);
		if (ret < 0) cs_log("ERROR: Could not close PMT fd (errno=%d %s)", errno, strerror(errno));

		if (len < 1) {
			cs_debug_mask(D_DVBAPI,"pmt file %s have invalid len!", dest);
			continue;
		}

		int32_t pmt_id;

#ifdef QBOXHD
		uint32_t j1,j2;
		// QboxHD pmt.tmp is the full capmt written as a string of hex values
		// pmt.tmp must be longer than 3 bytes (6 hex chars) and even length
		if ((len<6) || ((len%2) != 0) || ((len/2)>sizeof(dest))) {
			cs_debug_mask(D_DVBAPI,"error parsing QboxHD pmt.tmp, incorrect length");
			continue;
		}

		for(j2=0,j1=0;j2<len;j2+=2,j1++) {
			if (sscanf((char*)mbuf+j2, "%02X", (unsigned int*)dest+j1) != 1) {
				cs_debug_mask(D_DVBAPI,"error parsing QboxHD pmt.tmp, data not valid in position %d",j2);
				pthread_mutex_unlock(&event_handler_lock);
				return;
			}
		}

		cs_ddump_mask(D_DVBAPI, (unsigned char *)dest, len/2, "QboxHD pmt.tmp:");
		pmt_id = dvbapi_parse_capmt((unsigned char *)dest+4, (len/2)-4, -1, dp->d_name);
#else
		if (len>sizeof(dest)) {
			cs_debug_mask(D_DVBAPI,"event_handler() dest buffer is to small for pmt data!");
			continue;
		}
		if (len<16){
			cs_debug_mask(D_DVBAPI,"event_handler() received pmt is too small! (%d < 16 bytes!)", len);
			continue;
		}
		cs_ddump_mask(D_DVBAPI, mbuf,len,"pmt:");

		dest[0] = 0x03;
		dest[1] = mbuf[3];
		dest[2] = mbuf[4];

		i2b_buf(2, (((mbuf[10] & 0x0F) << 8) | mbuf[11])+1, (uchar*)dest+4);
		dest[6] = 0;

		memcpy(dest + 7, mbuf + 12, len - 12 - 4);

		pmt_id = dvbapi_parse_capmt((uchar*)dest, 7 + len - 12 - 4, -1, dp->d_name);
#endif

		if (pmt_id>=0) {
			cs_strncpy(demux[pmt_id].pmt_file, dp->d_name, sizeof(demux[pmt_id].pmt_file));
			demux[pmt_id].pmt_time = (time_t)pmt_info.st_mtime;
		}

		if (cfg.dvbapi_pmtmode == 3) {
			disable_pmt_files=1;
			break;
		}
	}
	closedir(dirp);
	pthread_mutex_unlock(&event_handler_lock);
}

void *dvbapi_event_thread(void *cli) {
	struct s_client * client = (struct s_client *) cli;
	pthread_setspecific(getclient, client);
	set_thread_name(__func__);
	while(1) {
		cs_sleepms(750);
		event_handler(0);
	}

	return NULL;
}

void dvbapi_process_input(int32_t demux_id, int32_t filter_num, uchar *buffer, int32_t len) {
	struct s_ecmpids *curpid = &demux[demux_id].ECMpids[demux[demux_id].demux_fd[filter_num].pidindex];
	uint32_t pid = demux[demux_id].demux_fd[filter_num].pidindex;
	uint32_t chid = 0x10000;

	if (demux[demux_id].demux_fd[filter_num].type==TYPE_ECM) {
		if (len != (((buffer[1] & 0xf) << 8) | buffer[2]) + 3){ // invalid CAT length
			cs_debug_mask(D_DVBAPI, "[DVBAPI] Received an ECM with invalid CAT length!");
			return;
		}

		if (!(buffer[0] == 0x80 || buffer[0] == 0x81)){
			cs_debug_mask(D_DVBAPI, "[DVBAPI] Received an ECM with invalid ecmtable ID %02X -> ignoring!", buffer[0]);
			return;
		}
		
		if (curpid->table == buffer[0] && curpid->CAID>>8 != 0x06) // wait for odd / even ecm change (only not for irdeto!)
			return;
		
		if (curpid->CAID>>8 == 0x06){ //irdeto cas
			// 80 70 39 53 04 05 00 88
			// 81 70 41 41 01 06 00 13 00 06 80 38 1F 52 93 D2
			//if (buffer[5]>20) return;
			if (curpid->irdeto_maxindex != buffer[5]) { //6, register max irdeto index
				cs_debug_mask(D_DVBAPI,"Found %d IRDETO ECM CHIDs", buffer[5]+1);
				curpid->irdeto_maxindex = buffer[5]; // numchids = 7 (0..6)
			}
		}	
		
		ECM_REQUEST *er;
		if (!(er=get_ecmtask())) return;

		er->srvid = demux[demux_id].program_number;

		er->tsid = demux[demux_id].tsid;
		er->onid = demux[demux_id].onid;
		er->ens = demux[demux_id].enigma_namespace;

		er->caid  = curpid->CAID;
		er->pid   = curpid->ECM_PID;
		er->prid  = curpid->PROVID;
		er->vpid  = curpid->VPID;
		er->ecmlen= len;
		memcpy(er->ecm, buffer, er->ecmlen);
		
		chid = get_subid(er); // fetch chid or fake chid
		er->chid = (chid != 0?chid:0x10000); // if not zero apply, otherwise use no chid value 0x10000 
		
		if (curpid->CAID>>8 == 0x06){ //irdeto cas
			cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d ECMTYPE %02X CAID %04X PROVID %06X ECMPID %04X IRDETO INDEX %02X MAX INDEX %02X CHID %04X CYCLE %02X VPID %04X", demux_id, er->ecm[0], er->caid, er->prid, er->pid, er->ecm[4], er->ecm[5], er->chid, curpid->irdeto_cycle, er->vpid);
		
			if (curpid->irdeto_curindex != buffer[4]){ // old style wrong irdeto index 
				if(curpid->irdeto_curindex == 0xFE){ // check if this ecmfilter just started up
					curpid->irdeto_curindex = buffer[4]; // on startup set the current index to the irdeto index of the ecm
				}
				else { // we are already running and not interested in this ecm
					curpid->table=0;
					dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this ecm doesnt match with current irdeto index
					free(er);
					return;
				}
			}
		}
		else{
			cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d ECMTYPE %02X CAID %04X PROVID %06X ECMPID %04X FAKECHID %04X (unique part in ecm)",
				demux_id, er->ecm[0], er->caid, er->prid, er->pid, er->chid);
		}
		
		if ((curpid->CHID <0x10000) && chid != curpid->CHID){ // check for matching chid (unique ecm part in case of non-irdeto cas)
			if (curpid->CAID>>8 == 0x06){
				
				if ((curpid->irdeto_cycle < 0xFE) && curpid->irdeto_cycle == buffer[4]){ // if same: we cycled all indexes but no luck!
					struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match(demux_id, pid, 'p');
					if (!forceentry || !forceentry->force){ // forced pid? keep trying the forced ecmpid, no force kill ecm filter
						if (curpid->checked == 2) curpid->checked = 3;
						if (curpid->checked == 1){
							curpid->checked = 2;
							curpid->CHID = 0x10000;
						}
						dvbapi_stop_filternum(demux_id, filter_num); // stop this ecm filter!
						free(er);
						return;
					}
				}
				if(curpid->irdeto_cycle == 0xFE) curpid->irdeto_cycle = buffer[4]; // register irdeto index of current ecm
				
				curpid->irdeto_curindex++; // set check on next index
				if(curpid->irdeto_curindex>curpid->irdeto_maxindex) curpid->irdeto_curindex=0; // check if we reached max irdeto index, if so reset to 0
				
				curpid->table=0;
				dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this ecm doesnt match with current irdeto index
				free(er);
				return;	
			}
			else{ // all nonirdeto cas systems
				struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match(demux_id, pid, 'p');
				curpid->table=0;
				dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this ecm doesnt match with current irdeto index
				if (forceentry && forceentry->force) {
					free(er);
					return; // forced pid? keep trying the forced ecmpid!
				}
				if (curpid->checked == 2) curpid->checked = 3;
				if (curpid->checked == 1){
					curpid->checked = 2;
					curpid->CHID = 0x10000;
				}
				dvbapi_stop_filternum(demux_id, filter_num); // stop this ecm filter!
				free(er);
				return;
			}
		}
		
		struct s_dvbapi_priority *p;
		
		for (p = dvbapi_priority; p != NULL; p = p->next) {
			if (p->type != 'l'
				|| (p->caid && p->caid != curpid->CAID)
				|| (p->provid && p->provid != curpid->PROVID)
				|| (p->ecmpid && p->ecmpid != curpid->ECM_PID)
				|| (p->srvid && p->srvid != demux[demux_id].program_number))
				continue;

			if (p->delay == len && p->force < 6) {
				p->force++;
				free(er);
				return;
			}
			if (p->force >= 6)
				p->force=0;
		}
		
		if (!curpid->PROVID)
			curpid->PROVID = chk_provid(buffer, curpid->CAID);
			
		if ((curpid->CAID >> 8) == 0x06) {// irdeto: wait for the correct index 
			if (buffer[4] != curpid->irdeto_curindex) { 
				curpid->table=0;
				dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this ecm doesnt match with current irdeto index
				free(er);
				return;
			}
			// we have an ecm with the correct irdeto index 
			for (p=dvbapi_priority; p != NULL ; p = p->next) { // check for ignore!
				if ((p->type != 'i')
					|| (p->caid && p->caid != curpid->CAID)
					|| (p->provid && p->provid != curpid->PROVID)
					|| (p->ecmpid && p->ecmpid != curpid->ECM_PID)
					|| (p->srvid && p->srvid != demux[demux_id].program_number))
					continue;

				if (p->type == 'i' && (p->chid < 0x10000 && p->chid == chid)){  // found a ignore chid match with current ecm -> ignoring this irdeto index
					curpid->irdeto_curindex++;
					if (curpid->irdeto_curindex > curpid->irdeto_maxindex) { // check if curindex is over the max 
						curpid->irdeto_curindex = 0;
					}
					curpid->table=0;
					dvbapi_set_section_filter(demux_id, er); // set ecm filter to odd + even since this chid has to be ignored!
					free(er);
					return;
				}
			}
		}
		curpid->table = er->ecm[0];
		request_cw(dvbapi_client, er, demux_id, 1); // register this ecm for delayed ecm response check
	}

	if (demux[demux_id].demux_fd[filter_num].type==TYPE_EMM) {
		if (buffer[0]==0x01) { //CAT
			cs_debug_mask(D_DVBAPI, "receiving cat");
			dvbapi_parse_cat(demux_id, buffer, len);

			dvbapi_stop_filternum(demux_id, filter_num);
			return;
		}
		dvbapi_process_emm(demux_id, filter_num, buffer, len);
	}

	// emm filter iteration
	if (!ll_emm_active_filter)
		ll_emm_active_filter = ll_create("ll_emm_active_filter");

	if (!ll_emm_inactive_filter)
		ll_emm_inactive_filter = ll_create("ll_emm_inactive_filter");

	if (!ll_emm_pending_filter)
		ll_emm_pending_filter = ll_create("ll_emm_pending_filter");

	uint32_t filter_count = ll_count(ll_emm_active_filter)+ll_count(ll_emm_inactive_filter);

	if (demux[demux_id].max_emm_filter > 0 
		&& ll_count(ll_emm_inactive_filter) > 0 
		&& filter_count > demux[demux_id].max_emm_filter) {

		int32_t filter_queue = ll_count(ll_emm_inactive_filter);
		int32_t stopped=0, started=0;
		time_t now = time((time_t *) 0);

		struct s_emm_filter *filter_item;
		LL_ITER itr;
		itr = ll_iter_create(ll_emm_active_filter);

		while ((filter_item=ll_iter_next(&itr))) {
			if (!ll_count(ll_emm_inactive_filter) || started == filter_queue)
				break;

			if (abs(now-filter_item->time_started) > 45) {
				struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match_emmpid(filter_item->demux_id, filter_item->caid,
					filter_item->provid, 'p');

				if (!forceentry || (forceentry && !forceentry->force)) {
					cs_debug_mask(D_DVBAPI,"[EMM Filter] removing emm filter %i num %i on demux index %i",
						filter_item->count, filter_item->num, filter_item->demux_id);
					dvbapi_stop_filternum(filter_item->demux_id, filter_item->num-1);
					ll_iter_remove_data(&itr);
					add_emmfilter_to_list(filter_item->demux_id, filter_item->filter, filter_item->caid,
						filter_item->provid, filter_item->pid, filter_item->count, -1, 0);
					stopped++;
				}
			}
			
			int32_t ret;
			if (stopped>started) {
				struct s_emm_filter *filter_item2;
				LL_ITER itr2 = ll_iter_create(ll_emm_inactive_filter);

				while ((filter_item2=ll_iter_next(&itr2))) {
					cs_ddump_mask(D_DVBAPI, filter_item2->filter, 32, "[EMM Filter] starting emm filter %i, pid: 0x%04X on demux index %i",
						filter_item2->count, filter_item2->pid, filter_item2->demux_id);
					ret = dvbapi_set_filter(filter_item2->demux_id, selected_api, filter_item2->pid, filter_item2->caid,
						filter_item2->provid, filter_item2->filter, filter_item2->filter+16, 0,
						demux[filter_item2->demux_id].pidindex, filter_item2->count, TYPE_EMM, 1);
					if (ret !=-1) {
						ll_iter_remove_data(&itr2);
						started++;
						break;
					}
				}
			}
		}

		itr = ll_iter_create(ll_emm_pending_filter);

		while ((filter_item=ll_iter_next(&itr))) {
			add_emmfilter_to_list(filter_item->demux_id, filter_item->filter, filter_item->caid,
				filter_item->provid, filter_item->pid, filter_item->count, 0, 0);
			ll_iter_remove_data(&itr);
		}
	}
}

static void * dvbapi_main_local(void *cli) {

#ifdef WITH_AZBOX
	return azbox_main_thread(cli);
#endif
#ifdef WITH_MCA
	selected_box = selected_api = 0; // Prevent compiler warning about out of bounds array access
	return mca_main_thread(cli);
#endif

	int32_t i,j;
	struct s_client * client = (struct s_client *) cli;
	client->thread=pthread_self();
	pthread_setspecific(getclient, cli);

	dvbapi_client=cli;

	int32_t maxpfdsize=(MAX_DEMUX*MAX_FILTER)+MAX_DEMUX+2;
	struct pollfd pfd2[maxpfdsize];
	struct timeb start, end;  // start time poll, end time poll
#define PMT_SERVER_SOCKET "/tmp/.listen.camd.socket"
	struct sockaddr_un saddr;
	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, PMT_SERVER_SOCKET, 107);
	saddr.sun_path[107] = '\0';
	
	int32_t rc,pfdcount,g,connfd,clilen;
	int32_t ids[maxpfdsize], fdn[maxpfdsize], type[maxpfdsize];
	struct sockaddr_un servaddr;
	ssize_t len=0;
	uchar mbuf[1024];

	struct s_auth *account;
	int32_t ok=0;
	for (account = cfg.account; account != NULL; account=account->next) {
		if ((ok = streq(cfg.dvbapi_usr, account->usr)))
			break;
	}
	cs_auth_client(client, ok ? account : (struct s_auth *)(-1), "dvbapi");

	memset(demux, 0, sizeof(struct demux_s) * MAX_DEMUX);
	memset(ca_fd, 0, sizeof(ca_fd));

	dvbapi_read_priority();
	dvbapi_detect_api();

	if (selected_box == -1 || selected_api==-1) {
		cs_log("ERROR: Could not detect DVBAPI version.");
		return NULL;
	}

	if (cfg.dvbapi_pmtmode == 1)
		disable_pmt_files=1;

	int32_t listenfd = -1;
	if (cfg.dvbapi_boxtype != BOXTYPE_IPBOX_PMT && cfg.dvbapi_pmtmode != 2 && cfg.dvbapi_pmtmode != 5 && cfg.dvbapi_pmtmode !=6) {
		listenfd = dvbapi_init_listenfd();
		if (listenfd < 1) {
			cs_log("ERROR: Could not init camd.socket.");
			return NULL;
		}
	}

	pthread_mutex_init(&event_handler_lock, NULL);
	
	for (i=0; i<MAX_DEMUX; i++){ // init all demuxers!
		demux[i].pidindex=-1;
		demux[i].curindex=-1;
	}

	if (cfg.dvbapi_pmtmode != 4 && cfg.dvbapi_pmtmode != 5 && cfg.dvbapi_pmtmode != 6) {
		struct sigaction signal_action;
		signal_action.sa_handler = event_handler;
		sigemptyset(&signal_action.sa_mask);
		signal_action.sa_flags = SA_RESTART;
		sigaction(SIGRTMIN + 1, &signal_action, NULL);

		dir_fd = open(TMPDIR, O_RDONLY);
		if (dir_fd >= 0) {
			fcntl(dir_fd, F_SETSIG, SIGRTMIN + 1);
			fcntl(dir_fd, F_NOTIFY, DN_MODIFY | DN_CREATE | DN_DELETE | DN_MULTISHOT);
			event_handler(SIGRTMIN + 1);
		}
	} else {
		pthread_t event_thread;
		int32_t ret = pthread_create(&event_thread, NULL, dvbapi_event_thread, (void*) dvbapi_client);
		if(ret){
			cs_log("ERROR: Can't create dvbapi event thread (errno=%d %s)", ret, strerror(ret));
			return NULL;
		} else
			pthread_detach(event_thread);
	}

	if (listenfd !=-1){
		pfd2[0].fd = listenfd;
		pfd2[0].events = (POLLIN|POLLPRI);
		type[0]=1;
	}
	
#ifdef WITH_COOLAPI
	system("pzapit -rz");
#endif
	cs_ftime(&start); // register start time
	while (1) {
		if (pausecam) // for dbox2, STAPI or PC in standby mode dont parse any ecm/emm or try to start next filter
			continue;

		if (cfg.dvbapi_pmtmode ==6){
			if (listenfd <0){
				cs_log("[DVBAPI] PMT6: Trying connect to enigma CA PMT listen socket...");
				/* socket init */
				if ((listenfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
					cs_log("socket error (errno=%d)\n", errno);
					listenfd = -1;
				}
		
				if (connect(listenfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
					cs_log("socket connect error (errno=%d)\n", errno);
					listenfd = -1;
				}
				else{
					pfd2[0].fd = listenfd;
					pfd2[0].events = (POLLIN|POLLPRI);
					type[0]=1;
					cs_log("[DVBAPI] PMT6 CA PMT Server connected on fd %d!", listenfd);
				}
			}
			
		}
		pfdcount = (listenfd > -1) ? 1 : 0;
		
		for (i=0;i<MAX_DEMUX;i++) {
			if(demux[i].program_number==0) continue; // only evalutate demuxers that have channels assigned

			uint32_t ecmcounter =0, emmcounter = 0;
			for (g=0;g<MAX_FILTER;g++) {
				if (demux[i].demux_fd[g].fd>0 && selected_api != STAPI && selected_api != COOLAPI) {
					pfd2[pfdcount].fd = demux[i].demux_fd[g].fd;
					pfd2[pfdcount].events = (POLLIN|POLLPRI);
					ids[pfdcount]=i;
					fdn[pfdcount]=g;
					type[pfdcount++]=0;
				}
				if (demux[i].demux_fd[g].type == TYPE_ECM) ecmcounter++; // count ecm filters to see if demuxing is possible anyway
				if (demux[i].demux_fd[g].type == TYPE_EMM) emmcounter++; // count emm filters also
			}
			if (ecmcounter != demux[i].old_ecmfiltercount || emmcounter != demux[i].old_emmfiltercount){ // only produce log if something changed
				cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d has %d ecmpids, %d streampids, %d ecmfilters and %d emmfilters", i, demux[i].ECMpidcount,
					demux[i].STREAMpidcount, ecmcounter, emmcounter);
				demux[i].old_ecmfiltercount = ecmcounter; // save new amount of ecmfilters
				demux[i].old_emmfiltercount = emmcounter; // save new amount of emmfilters
			}
			
			// delayed emm start for non irdeto caids
			if (cfg.dvbapi_au>0 && demux[i].EMMpidcount == 0 && ((time(NULL)-demux[i].emmstart)>30) && emmcounter == 0){ //start emm cat
				demux[i].emmstart = time(NULL); // trick to let emm fetching start after 30 seconds to speed up zapping
				dvbapi_start_filter(i, demux[i].pidindex, 0x001, 0x001, 0x01, 0x01, 0xFF, 0, TYPE_EMM, 1); //CAT
				continue; // proceed with next demuxer
			}
			
			//early start for irdeto since they need emm before ecm (pmt emmstart = 1 if detected caid 0x06)
			int32_t emmstarted = 0;
			if (cfg.dvbapi_au && demux[i].EMMpidcount > 0){ // check every time since share readers might give us new filters due to hexserial change
				if(!emmcounter){
					demux[i].emmstart = time(NULL);
					emmstarted = dvbapi_start_emm_filter(i); // start emmfiltering if emmpids are found
				}
				else {
					if((time(NULL)-demux[i].emmstart)>30){
						demux[i].emmstart = time(NULL);
						emmstarted = dvbapi_start_emm_filter(i); // start emmfiltering delayed if filters already were running
					}
				}
				if (emmstarted && !emmcounter) continue; // proceed with next demuxer if no emms where running before
			}
			
			if (ecmcounter == 0 && demux[i].ECMpidcount > 0){ // Restart decoding all caids we have ecmpids but no ecm filters!
				
				int32_t started = 0;
				
				for (g=0; g<demux[i].ECMpidcount; g++){ // avoid race: not all pids are asked and checked out yet!
					if(demux[i].ECMpids[g].checked == 0 && demux[i].ECMpids[g].status >=0){ // check if prio run is done
						dvbapi_try_next_caid(i, 0); // not done, so start next prio pid
						started = 1;
						break;
					}
				}
				if (started) continue; // if started a filter proceed with next demuxer
				
				if (g == demux[i].ECMpidcount){ // all usable pids (with prio) are tried, lets start over again without prio!
					for (g=0; g<demux[i].ECMpidcount; g++){ // avoid race: not all pids are asked and checked out yet!
						if(demux[i].ECMpids[g].checked == 2 && demux[i].ECMpids[g].status >=0){ // check if noprio run is done
							demux[i].ECMpids[g].irdeto_curindex=0xFE;
							demux[i].ECMpids[g].irdeto_maxindex=0;
							demux[i].ECMpids[g].irdeto_cycle=0xFE;
							demux[i].ECMpids[g].tries=0xFE;
							demux[i].ECMpids[g].table=0;
							demux[i].ECMpids[g].CHID=0x10000; // remove chid prio
							dvbapi_try_next_caid(i, 2); // not done, so start next no prio pid
							started = 1;
							break;
						}
					}
				}
				if (started) continue; // if started a filter proceed with next demuxer
				
				if (g == demux[i].ECMpidcount){ // all usable pids are tried, lets start over again!
					cs_log("[DVBAPI] Demuxer #%d (re)starting decodingrequests on all %d ecmpids!", i, demux[i].ECMpidcount);
					cs_sleepms(300); // add a little timeout
					for (g=0; g<demux[i].ECMpidcount; g++) { // reinit some used things from second run (without prio)
						demux[i].ECMpids[g].checked=0;
						demux[i].ECMpids[g].irdeto_curindex=0xFE;
						demux[i].ECMpids[g].irdeto_maxindex=0;
						demux[i].ECMpids[g].irdeto_cycle=0xFE;
						demux[i].ECMpids[g].table=0;
						edit_channel_cache(i, g, 0); // remove this pid from channelcache since we had no founds on any ecmpid!
					}
					dvbapi_resort_ecmpids(i);
					dvbapi_try_next_caid(i,0);
				}
			}
			
			if (demux[i].socket_fd>0 && cfg.dvbapi_pmtmode != 6) {
				rc=0;
				if (cfg.dvbapi_boxtype==BOXTYPE_IPBOX) {
					for (j = 0; j < pfdcount; j++) {
						if (pfd2[j].fd == demux[i].socket_fd) {
							rc=1;
							break;
						}
					}
					if (rc==1) continue;
				}

				pfd2[pfdcount].fd=demux[i].socket_fd;
				pfd2[pfdcount].events = (POLLIN|POLLPRI);
				ids[pfdcount]=i;
				type[pfdcount++]=1;
			}
		}

		while (1){
			rc = poll(pfd2, pfdcount, 300);
			if (listenfd == -1 && cfg.dvbapi_pmtmode == 6) break;
			if (rc<0)
				continue;
			break;
		}
		
		if (rc > 0){
			cs_ftime(&end); // register end time
			cs_debug_mask(D_TRACE, "[DVBAPI] new events occurred on %d of %d handlers after %ld ms inactivity", rc, pfdcount,
			1000*(end.time-start.time)+end.millitm-start.millitm);
			cs_ftime(&start); // register new start time for next poll
		}

		for (i = 0; i < pfdcount&&rc>0; i++) {
			if (pfd2[i].revents == 0) continue; // skip sockets with no changes
				rc--; //event handled!
				cs_debug_mask(D_TRACE, "[DVBAPI] now handling fd %d that reported event %d", pfd2[i].fd, pfd2[i].revents);

			if (pfd2[i].revents & (POLLHUP | POLLNVAL | POLLERR)) {
				if (type[i]==1) {
					for (j=0;j<MAX_DEMUX;j++) {
						if (demux[j].socket_fd==pfd2[i].fd) { // if listenfd closes stop all assigned decoding!
							dvbapi_stop_descrambling(j);
						}
					}
					int32_t ret = close(pfd2[i].fd);
					if (ret < 0 && errno != 9) cs_log("ERROR: Could not close demuxer socket fd (errno=%d %s)", errno, strerror(errno));
					if (pfd2[i].fd==listenfd && cfg.dvbapi_pmtmode ==6){
						listenfd=-1;
					}
				}
				else { // type = 0
					int32_t demux_index=ids[i];
					int32_t n=fdn[i];
					dvbapi_stop_filternum(demux_index,n); // stop filter since its giving errors and wont return anything good. 
				}
				continue; // continue with other events
			}
			
			if (pfd2[i].revents & (POLLIN|POLLPRI)) {
				if (type[i]==1 && pmthandling == 0) {
					pmthandling = 1; // pmthandling in progress!
					if (pfd2[i].fd==listenfd && cfg.dvbapi_pmtmode == 6){
						int32_t size = 0;
						uint32_t pmtlen = 0;
						do {
							size = recv(listenfd, (mbuf+pmtlen), (sizeof(mbuf)-pmtlen), MSG_DONTWAIT);
							if (size > 0) pmtlen +=size;
						} while (size > 0 && pmtlen < sizeof(mbuf));
						if (pmtlen < 3) {
							cs_debug_mask(D_DVBAPI, "[DVBAPI] CA PMT server message too short!");
							pmthandling = 0; // pmthandling done!
							continue;
						}
						if (!(pmtlen < sizeof(mbuf))){
							cs_log("[DVBAPI] ***** WARNING: PMT BUFFER OVERFLOW, PLEASE REPORT! ****** ");
						}
						cs_ddump_mask(D_DVBAPI, mbuf, pmtlen, "New PMT info from server (total size: %d)", pmtlen);
						disable_pmt_files=1;
						dvbapi_handlesockmsg(mbuf, pmtlen, listenfd);
						pmthandling = 0; // pmthandling done!
						continue; // continue with other events!
					}
					
					if (cfg.dvbapi_pmtmode != 6) {							
						
						if(pfd2[i].fd==listenfd) {
							clilen = sizeof(servaddr);
							connfd = accept(listenfd, (struct sockaddr *)&servaddr, (socklen_t *)&clilen);
							cs_debug_mask(D_DVBAPI, "new socket connection fd: %d", connfd);

							if (cfg.dvbapi_pmtmode == 3 || cfg.dvbapi_pmtmode == 0 ) disable_pmt_files=1;

							if (connfd <= 0) {
								cs_debug_mask(D_DVBAPI,"accept() returns error on fd event %d (errno=%d %s)", pfd2[i].revents, errno, strerror(errno));
								pmthandling = 0; // pmthandling done!
								continue;
							}
						} else {
							cs_debug_mask(D_DVBAPI, "PMT Update on socket %d.", pfd2[i].fd);
							connfd = pfd2[i].fd;
						}

						len = read(connfd, mbuf, sizeof(mbuf));

						if (len < 3) {
							cs_debug_mask(D_DVBAPI, "camd.socket: too small message received");
							pmthandling = 0; // pmthandling done!
							continue; // no msg received continue with other events!
						}
						dvbapi_handlesockmsg(mbuf, len, connfd);
						pmthandling = 0; // pmthandling done!
						continue; // continue with other events!
					}
				} else { // type==0
					int32_t demux_index=ids[i];
					int32_t n=fdn[i];

					if ((len=dvbapi_read_device(pfd2[i].fd, mbuf, sizeof(mbuf))) <= 0) {
						dvbapi_stop_filternum(demux_index,n); // stop filter since its giving errors and wont return anything good.
						continue;
					}
					
					if (pfd2[i].fd==(int)demux[demux_index].demux_fd[n].fd) {
						dvbapi_process_input(demux_index,n,mbuf,len);
					}
				}
			continue; // continue with other events!
			}
		}
	}
	return NULL;
}

void dvbapi_write_cw(int32_t demux_id, uchar *cw, int32_t pid) {
	int32_t n;
	int8_t cwEmpty = 0;
	unsigned char nullcw[8];
	memset(nullcw, 0, 8);
	ca_descr_t ca_descr;
	memset(&ca_descr,0,sizeof(ca_descr));

	if(memcmp(demux[demux_id].lastcw[0],nullcw,8)==0
		&& memcmp(demux[demux_id].lastcw[1],nullcw,8)==0)
		cwEmpty = 1; // to make sure that both cws get written on constantcw
    
	for (n=0;n<2;n++) {
		char lastcw[9*3];
		char newcw[9*3];
		cs_hexdump(0, demux[demux_id].lastcw[n], 8, lastcw, sizeof(lastcw));
		cs_hexdump(0, cw+(n*8), 8, newcw, sizeof(newcw));

		if (((memcmp(cw+(n*8),demux[demux_id].lastcw[0],8)!=0
			&& memcmp(cw+(n*8),demux[demux_id].lastcw[1],8)!=0) || cwEmpty)
			&& memcmp(cw+(n*8),nullcw,8)!=0) { // check if already delivered and new cw part is valid!
			int32_t idx = dvbapi_ca_setpid (demux_id, pid); // prepare ca
			ca_descr.index = idx;
			ca_descr.parity = n;
			cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d writing %s part (%s) of controlword, replacing expired (%s)", demux_id, (n == 1?"even":"odd"),
				newcw, lastcw);
			memcpy(demux[demux_id].lastcw[n],cw+(n*8),8);
			memcpy(ca_descr.cw,cw+(n*8),8);

#ifdef WITH_COOLAPI
			cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d write cw%d index: %d (ca_mask %d)", demux_id, n, ca_descr.index, demux[demux_id].ca_mask);
			coolapi_write_cw(demux[demux_id].ca_mask, demux[demux_id].STREAMpids, demux[demux_id].STREAMpidcount, &ca_descr);
#else
			int32_t i;
			for (i=0;i<8;i++) {
				if (demux[demux_id].ca_mask & (1 << i)) {
					cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d write cw%d index: %d (ca%d)", demux_id, n, ca_descr.index, i);
					if (ca_fd[i]<=0) {
						if (cfg.dvbapi_boxtype == BOXTYPE_PC)
							ca_fd[i]=dvbapi_open_netdevice(1, i, demux[demux_id].adapter_index);
						else
							ca_fd[i]=dvbapi_open_device(1, i, demux[demux_id].adapter_index);
						if (ca_fd[i]<=0)
							continue; // proceed next stream
					}

					if (cfg.dvbapi_boxtype == BOXTYPE_PC) {
						// preparing packet
						int32_t request = CA_SET_DESCR;
						unsigned char packet[sizeof(request) + sizeof(ca_descr)];
						memcpy(&packet, &request, sizeof(request));
						memcpy(&packet[sizeof(request)], &ca_descr, sizeof(ca_descr));
						// sending data
						send(ca_fd[i], &packet, sizeof(packet), 0);
					} else {
#if defined(__powerpc__)
						ioctl(ca_fd[i], CA_SET_DESCR, &ca_descr); // ppcold return value never given!
#else
						int32_t ret = ioctl(ca_fd[i], CA_SET_DESCR, &ca_descr);
						if (ret <0)
							cs_log("ERROR: ioctl(CA_SET_DESCR): %s", strerror(errno));
#endif
					}
				}
			}
#endif
		}
	}
}

void delayer(ECM_REQUEST *er)
{
	if (cfg.dvbapi_delayer <= 0) return;

	struct timeb tpe;
	cs_ftime(&tpe);
	int32_t t = 1000 * (tpe.time-er->tps.time) + tpe.millitm-er->tps.millitm;
	if (t < cfg.dvbapi_delayer) {
		cs_debug_mask(D_DVBAPI, "delayer: t=%dms, cfg=%dms -> delay=%dms", t, cfg.dvbapi_delayer, cfg.dvbapi_delayer-t);
		cs_sleepms(cfg.dvbapi_delayer-t);
	}
}

void dvbapi_send_dcw(struct s_client *client, ECM_REQUEST *er)
{
#ifdef WITH_AZBOX
	azbox_send_dcw(client, er);
	return;
#endif

#ifdef WITH_MCA
	mca_send_dcw(client, er);
	return;
#endif

	int32_t i,j,handled = 0;

	
	for (i=0;i<MAX_DEMUX;i++) {
		uint32_t nocw_write = 0; // 0 = write cw, 1 = dont write cw to hardware demuxer
		if (demux[i].program_number == 0) continue; // ignore empty demuxers
		if (demux[i].program_number != er->srvid) continue; // skip ecm response for other srvid
		demux[i].rdr=er->selected_reader;
		for (j=0; j<demux[i].ECMpidcount; j++){ // check for matching ecmpid
			if ((demux[i].ECMpids[j].CAID == er->caid || demux[i].ECMpids[j].CAID == er->ocaid)
				&& demux[i].ECMpids[j].ECM_PID == er->pid
				&& demux[i].ECMpids[j].PROVID == er->prid
				&& demux[i].ECMpids[j].VPID == er->vpid)
				break;
		}
		if (j==demux[i].ECMpidcount) continue; // ecm response srvid ok but no matching ecmpid, perhaps this for other demuxer  
		
		cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d %scontrolword received for PID #%d CAID %04X PROVID %06X ECMPID %04X CHID %04X VPID %04X", i, 
			(er->rc >= E_NOTFOUND?"no ":""), j, er->caid, er->prid, er->pid, er->chid, er->vpid);
						
		if (er->rc < E_NOTFOUND){ // check for delayed response on already expired ecmrequest
			uint32_t status= dvbapi_check_ecm_delayed_delivery(i, er);
				
			uint32_t comparecw0 = 0, comparecw1 = 0;
			char ecmd5[17*3];
			cs_hexdump(0, er->ecmd5, 16, ecmd5, sizeof(ecmd5)); 
			
			if (status == 1){ // wrong ecmhash
				cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d not interested in response ecmhash %s (requested different one)", i, ecmd5);
				continue; 
			}
			if (status == 2){ // no filter
				cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d not interested in response ecmhash %s (filter already killed)", i, ecmd5);
				continue;
			}
				
			if (status == 0 || status == 3 || status == 4){ // 0=matching ecm hash, 2=no filter, 3=table reset, 4=cache-ex response
				if ( memcmp(er->cw,demux[i].lastcw[0],8) == 0 && memcmp(er->cw+8,demux[i].lastcw[1],8) == 0 ){ // check for matching controlword
					comparecw0 = 1;
				}
				else if ( memcmp(er->cw,demux[i].lastcw[1],8) == 0 && memcmp(er->cw+8,demux[i].lastcw[0],8) == 0 ){ // check for matching controlword
					comparecw1 = 1;
				}
				if (comparecw0 == 1 || comparecw1 == 1){
					cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d duplicate controlword ecm response hash %s (duplicate controlword!)", i, ecmd5);
					nocw_write = 1;
				}
			}
				
			if (status == 3){ // table reset
				cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d luckyshot new controlword ecm response hash %s (ecm table reset)", i, ecmd5);
			}
				
			if (status == 4){ // no check on cache-ex responses!
				cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d new controlword from cache-ex reader (no ecmhash check possible)", i);
			}
		}
		handled = 1; // mark this ecm response as handled	
		if (er->rc < E_NOTFOUND && cfg.dvbapi_requestmode==0 && (demux[i].pidindex==-1) && er->caid!=0) {
			demux[i].ECMpids[j].tries = 0xFE; // reset timeout retry flag
			demux[i].ECMpids[j].irdeto_cycle = 0xFE; // reset irdetocycle
			demux[i].curindex = j;
			demux[i].ECMpids[j].checked = 3;
			cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d descrambling PID #%d CAID %04X PROVID %06X ECMPID %04X CHID %02X VPID %04X",
				i, demux[i].curindex, er->caid, er->prid, er->pid, er->chid, er->vpid);
		}
			
		if (er->rc < E_NOTFOUND && cfg.dvbapi_requestmode==1 && er->caid!=0	&& demux[i].ECMpids[j].checked != 3) { // FOUND
				
			int32_t t,o,ecmcounter=0;
				
			for (t=0;t<demux[i].ECMpidcount;t++) { //check this pid with controlword FOUND for higher status:
				if (t!=j && demux[i].ECMpids[j].status >= demux[i].ECMpids[t].status) { 
					demux[i].ECMpids[t].checked = 3; // mark index t as low status
						
					for (o = 0; o < MAX_FILTER; o++) { // check if ecmfilter is in use & stop all ecmfilters of lower status pids
						if (demux[i].demux_fd[o].fd > 0 && demux[i].demux_fd[o].type == TYPE_ECM && demux[i].demux_fd[o].pidindex == t){
							dvbapi_stop_filternum(i, o); // ecmfilter belongs to lower status pid -> kill!
						}
					}
				}
			}
				
			for (o = 0; o < MAX_FILTER; o++) if (demux[i].demux_fd[o].type == TYPE_ECM) ecmcounter++; // count all ecmfilters
				
			demux[i].curindex = j;
				
			if (ecmcounter == 1){ // if total found running ecmfilters is 1 -> we found the "best" pid
				edit_channel_cache(i, j, 1);
				demux[i].ECMpids[j].checked = 3; // mark best pid last ;)
			}
				
				cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d descrambling PID #%d CAID %04X PROVID %06X ECMPID %04X CHID %02X VPID %04X",
					i, demux[i].curindex, er->caid, er->prid, er->pid, er->chid, er->vpid);
		}
			
		if (er->rc >= E_NOTFOUND) { // not found on requestmode 0 + 1
			struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match(i, j, 'p');
				
			if (forceentry && forceentry->force){ // forced pid? keep trying the forced ecmpid!
				if ((er->caid >> 8) != 0x06 || forceentry->chid <0x10000) { //all cas or irdeto cas with forced prio chid
					demux[i].ECMpids[j].table=0;
					dvbapi_set_section_filter(i, er);
					continue;
				}
				else { // irdeto cas without chid prio forced
					if (demux[i].ECMpids[j].irdeto_curindex==0xFE) demux[i].ECMpids[j].irdeto_curindex = 0x00; // init irdeto current index to first one
					if (!(demux[i].ECMpids[j].irdeto_curindex+1 > demux[i].ECMpids[j].irdeto_maxindex)) { // check for last / max chid				
						cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d trying next irdeto chid of FORCED PID #%d CAID %04X PROVID %06X ECMPID %04X", i,
						j, er->caid, er->prid, er->pid);
						demux[i].ECMpids[j].irdeto_curindex++; // irdeto index one up
						demux[i].ECMpids[j].table=0;
						dvbapi_set_section_filter(i, er);
						continue;
					}
				}
			}
				
			// in case of timeout or fatal LB event give this pid another try but no more than 1 try
			if ((er->rc == E_TIMEOUT || (er->rcEx && er->rcEx <=E2_CCCAM_NOCARD)) && demux[i].ECMpids[j].tries == 0xFE){ 
				demux[i].ECMpids[j].tries = 1;
				demux[i].ECMpids[j].table = 0;
				dvbapi_set_section_filter(i, er);
				continue;
			}
			else{ // all not found responses exception: first timeout response and first fatal loadbalancer response
				demux[i].ECMpids[j].CHID = 0x10000; // get rid of this prio chid since it failed!
				demux[i].ECMpids[j].tries = 0xFE; // reset timeout retry
			}
				
			if ((er->caid >> 8) == 0x06) {
				if (demux[i].ECMpids[j].irdeto_curindex==0xFE) demux[i].ECMpids[j].irdeto_curindex = 0x00; // init irdeto current index to first one
				if (!(demux[i].ECMpids[j].irdeto_curindex+1 > demux[i].ECMpids[j].irdeto_maxindex)) { // check for last / max chid				
					cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d trying next irdeto chid of PID #%d CAID %04X PROVID %06X ECMPID %04X VPID %04X", i,
					j, er->caid, er->prid, er->pid, er->vpid);
					demux[i].ECMpids[j].irdeto_curindex++; // irdeto index one up
					demux[i].ECMpids[j].table=0;
					dvbapi_set_section_filter(i, er);
					continue;
				}
			}
				
			edit_channel_cache(i, j, 0); // remove this pid from channelcache	
			demux[i].ECMpids[j].irdeto_maxindex = 0;
			demux[i].ECMpids[j].irdeto_curindex = 0xFE;
			demux[i].ECMpids[j].tries = 0xFE; // reset timeout retry flag
			demux[i].ECMpids[j].irdeto_cycle = 0xFE; // reset irdetocycle
			demux[i].ECMpids[j].table = 0;
			demux[i].ECMpids[j].checked = 3; // flag ecmpid as checked
			demux[i].ECMpids[j].status = -1; // flag ecmpid as unusable
			int32_t found = 1; // setup for first run
			int32_t filternum = -1;
				
			while (found >0){ // disable all ecm + emm filters for this notfound
				found = 0;
				filternum = dvbapi_get_filternum(i,er, TYPE_ECM); // get ecm filternumber
				if (filternum > -1){ // in case valid filter found
					int32_t fd = demux[i].demux_fd[filternum].fd;
					if (fd>0){ // in case valid fd
						dvbapi_stop_filternum(i, filternum); // stop ecmfilter
						found = 1;
					}
				}
				if (er->caid >> 8 == 0x06){ // in case irdeto cas stop old emm filters
					filternum = dvbapi_get_filternum(i,er, TYPE_EMM); // get emm filternumber
					if (filternum > -1){ // in case valid filter found
						int32_t fd = demux[i].demux_fd[filternum].fd;	
						if (fd>0){ // in case valid fd
							dvbapi_stop_filternum(i, filternum); // stop emmfilter
							found = 1;
						}
					}
				}
			}
			
			continue;
		}
			
			
		// below this should be only run in case of ecm answer is found
			
		demux[i].pidindex = demux[i].curindex; // set current index as *the* pid to descramble 
		uint32_t chid = get_subid(er); // derive current chid in case of irdeto, or a unique part of ecm on other cas systems  
		demux[i].ECMpids[j].CHID = (chid != 0?chid:0x10000); // if not zero apply, otherwise use no chid value 0x10000 
		edit_channel_cache(i, j, 1); // do it here to here after the right CHID is registered
			
		//dvbapi_set_section_filter(i, er);  is not needed anymore (unsure)
		demux[i].ECMpids[j].tries = 0xFE; // reset timeout retry flag
		demux[i].ECMpids[j].irdeto_cycle = 0xFE; // reset irdeto cycle
		
		if (nocw_write) continue; // cw was already written by another filter so it ends here!
		
		struct s_dvbapi_priority *delayentry=dvbapi_check_prio_match(i, demux[i].pidindex, 'd');
		if (delayentry) {
			if (delayentry->delay<1000) {
				cs_debug_mask(D_DVBAPI, "wait %d ms", delayentry->delay);
				cs_sleepms(delayentry->delay);
			}
		}

		delayer(er);

		switch (selected_api) {
#ifdef WITH_STAPI
			case STAPI:
				stapi_write_cw(i, er->cw, demux[i].STREAMpids, demux[i].STREAMpidcount, demux[i].pmt_file);
				break;
#endif
			default:
				dvbapi_write_cw(i, er->cw, j);
				break;
		}

		// reset idle-Time
		client->last=time((time_t*)0);

		FILE *ecmtxt;
		ecmtxt = fopen(ECMINFO_FILE, "w");
		if(ecmtxt != NULL && er->rc < E_NOTFOUND) {
			char tmp[25];
			fprintf(ecmtxt, "caid: 0x%04X\npid: 0x%04X\nprov: 0x%06X\n", er->caid, er->pid, (uint) er->prid);
			switch (er->rc) {
				case 0: 
					if (er->selected_reader) {
						fprintf(ecmtxt, "reader: %s\n", er->selected_reader->label);
						if (is_cascading_reader(er->selected_reader))
							fprintf(ecmtxt, "from: %s\n", er->selected_reader->device);
						else
							fprintf(ecmtxt, "from: local\n");
						fprintf(ecmtxt, "protocol: %s\n", reader_get_type_desc(er->selected_reader, 1));
						fprintf(ecmtxt, "hops: %d\n", er->selected_reader->currenthops);
					}
					break;

				case 1:	
					fprintf(ecmtxt, "reader: Cache\n");
					fprintf(ecmtxt, "from: cache1\n");
					fprintf(ecmtxt, "protocol: none\n");
					break;

				case 2:	
					fprintf(ecmtxt, "reader: Cache\n");
					fprintf(ecmtxt, "from: cache2\n");
					fprintf(ecmtxt, "protocol: none\n");
					break;

				case 3:	
					fprintf(ecmtxt, "reader: Cache\n");
					fprintf(ecmtxt, "from: cache3\n");
					fprintf(ecmtxt, "protocol: none\n");
					break;
			}
			fprintf(ecmtxt, "ecm time: %.3f\n", (float) client->cwlastresptime/1000);
			fprintf(ecmtxt, "cw0: %s\n", cs_hexdump(1,demux[i].lastcw[0],8, tmp, sizeof(tmp)));
			fprintf(ecmtxt, "cw1: %s\n", cs_hexdump(1,demux[i].lastcw[1],8, tmp, sizeof(tmp)));
			int32_t ret = fclose(ecmtxt);
			if (ret < 0) cs_log("ERROR: Could not close ecmtxt fd (errno=%d %s)", errno, strerror(errno));
				ecmtxt = NULL;
		}
		if (ecmtxt) {
			int32_t ret = fclose(ecmtxt);
			if (ret < 0) cs_log("ERROR: Could not close ecmtxt fd (errno=%d %s)", errno, strerror(errno));
				ecmtxt = NULL;
		}

	}
	if (handled == 0) {
		cs_debug_mask(D_DVBAPI,"[DVBAPI] Unhandled ECM response received for CAID %04X PROVID %06X ECMPID %04X CHID %04X VPID %04X",
			er->caid, er->prid, er->pid, er->chid, er->vpid);
	}
	
}

static void * dvbapi_handler(struct s_client * cl, uchar* UNUSED(mbuf), int32_t module_idx) {
	// cs_log("dvbapi loaded fd=%d", idx);
	if (cfg.dvbapi_enabled == 1) {
		cl = create_client(get_null_ip());
		cl->module_idx = module_idx;
		cl->typ='c';
		int32_t ret = pthread_create(&cl->thread, NULL, dvbapi_main_local, (void*) cl);
		if(ret){
			cs_log("ERROR: Can't create dvbapi handler thread (errno=%d %s)", ret, strerror(ret));
			return NULL;
		} else
			pthread_detach(cl->thread);
	}

	return NULL;
}

int32_t dvbapi_set_section_filter(int32_t demux_index, ECM_REQUEST *er) {

	if (!er) return -1;
	
	if (selected_api != DVBAPI_3 && selected_api != DVBAPI_1 && selected_api != STAPI){ // only valid for dvbapi3, dvbapi1 and STAPI
		return 0;
	}
	int32_t n = dvbapi_get_filternum(demux_index, er, TYPE_ECM);
	if (n<0) return -1; // in case no valid filter found;
	
	int32_t fd = demux[demux_index].demux_fd[n].fd;	
	if (fd<1) return-1 ; // in case no valid fd
	
	uchar filter[16];
	uchar mask[16];
	memset(filter,0,16);
	memset (mask,0,16);
		
	struct s_ecmpids *curpid = &demux[demux_index].ECMpids[demux[demux_index].demux_fd[n].pidindex];
	if (curpid->table != er->ecm[0] && curpid->table !=0) return -1; // if current ecmtype differs from latest requested ecmtype do not apply section filtering!
	uint8_t ecmfilter = 0;
	
	if (er->ecm[0]==0x80) ecmfilter = 0x81; // current processed ecm is even, next will be filtered for odd
	else ecmfilter = 0x80; // current processed ecm is odd, next will be filtered for even
	
	if (curpid->table != 0){ // cycle ecmtype from odd to even or even to odd
		filter[0]= ecmfilter; // only accept new ecms (if previous odd, filter for even and visaversa)
		mask[0]=0xFF;
			cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d set ecmtable to %s (CAID %04X PROVID %06X FD %d)", demux_index, n+1,
				(ecmfilter == 0x80?"EVEN":"ODD"), curpid->CAID, curpid->PROVID, fd);		
	}
	else{ // not decoding right now so we are interessted in all ecmtypes!
		filter[0]=0x80; // set filter to wait for any ecms
		mask[0]=0xF0;
		cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d set ecmtable to ODD+EVEN (CAID %04X PROVID %06X FD %d)", demux_index, n+1, 
			curpid->CAID, curpid->PROVID, fd);
	}
	uint32_t offset = 0;
	uint32_t pid = demux[demux_index].demux_fd[n].pidindex;
	
	struct s_dvbapi_priority *forceentry=dvbapi_check_prio_match(demux_index, pid, 'p');
	//cs_log("**** curpid->CHID %04X, checked = %d, er->chid = %04X *****", curpid->CHID, curpid->checked, er->chid);
	// checked 3 to make sure we dont set chid filter and no such ecm in dvbstream except for forced pids!
	if(curpid->CHID < 0x10000 && (curpid->checked==3 || (forceentry && forceentry->force))){ 

		switch (er->caid>>8){  
			case 0x01:	offset = 7; break; // seca  
			case 0x05:	offset = 8; break; // viaccess  
			case 0x06:	offset = 6; break; // irdeto  
			case 0x09:	offset = 11; break; // videoguard
			case 0x4A:	// DRE-Crypt, Bulcrypt,Tongang and others? 
						if (!(er->caid == 0x4AEE)) // Bulcrypt excluded for now
						offset = 6; 
						break; 
		}
	}
	
	int32_t irdetomatch = 1; // check if wanted irdeto index is the one the delivers current chid! 
	if (curpid->CAID >>8 == 0x06){
		if(curpid->irdeto_curindex == er->ecm[4]) irdetomatch = 1; // ok apply chid filtering
		else irdetomatch = 0; // skip chid filtering but apply irdeto index filtering
	}

	if(offset && irdetomatch){ // we have a cas with chid or unique part in checked ecm
		i2b_buf(2, curpid->CHID, filter+(offset-2));
		mask[(offset-2)]=0xFF;
		mask[(offset-1)]=0xFF;
		cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d set chid to %04X on fd %d", demux_index, n+1, curpid->CHID, fd);
	}
	else{
		if(curpid->CAID >> 8 == 0x06 && (curpid->irdeto_curindex < 0xFE)){ // on irdeto we can always apply irdeto index filtering!
			filter[2]=curpid->irdeto_curindex;
			mask[2]=0xFF;
			cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d set irdetoindex to %d on fd %d", demux_index, n+1, curpid->irdeto_curindex, fd);
		}
		else{ // all other cas systems also cas systems without chid or unique ecm part
			cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d Filter #%d set chid to ANY CHID on fd %d", demux_index, n+1, fd);
		}
	}

	int32_t ret = dvbapi_activate_section_filter(fd, curpid->ECM_PID, filter, mask);
	if (ret < 0){ // something went wrong setting filter!
		cs_log("[DVBAPI] Demuxer #%d Filter #%d (fd %d) error setting section filtering -> stop filter!", demux_index, n+1, fd);
		ret = dvbapi_stop_filternum(demux_index, n);
		if (ret == -1) {
			cs_log("[DVBAPI] Demuxer #%d Filter #%d (fd %d) stopping filter failed -> kill all filters of this demuxer!", demux_index, n+1, fd);
			dvbapi_stop_filter(demux_index, TYPE_EMM);
			dvbapi_stop_filter(demux_index, TYPE_ECM);
		}
		return -1;
	}
	return n;
}

int32_t dvbapi_activate_section_filter (int32_t fd, int32_t pid, uchar *filter, uchar *mask){ 

	int32_t ret = -1;
	switch(selected_api) {
		case DVBAPI_3: {
			struct dmx_sct_filter_params sFP2;
			memset(&sFP2,0,sizeof(sFP2));
			sFP2.pid			= pid;
			sFP2.timeout		= 0;
			sFP2.flags			= DMX_IMMEDIATE_START;
			if(cfg.dvbapi_boxtype == BOXTYPE_NEUMO) {
				//DeepThought: on dgs/cubestation and neumo images, perhaps others
				//the following code is needed to descramble
				sFP2.filter.filter[0]=filter[0];
				sFP2.filter.mask[0]=mask[0];
				sFP2.filter.filter[1]=0;
				sFP2.filter.mask[1]=0;
				sFP2.filter.filter[2]=0;
				sFP2.filter.mask[2]=0;
				memcpy(sFP2.filter.filter+3,filter+1,16-3);
				memcpy(sFP2.filter.mask+3,mask+1,16-3);
				//DeepThought: in the drivers of the dgs/cubestation and neumo images, 
				//dvbapi 1 and 3 are somehow mixed. In the kernel drivers, the DMX_SET_FILTER
				//ioctl expects to receive a dmx_sct_filter_params structure (DVBAPI 3) but
				//due to a bug its sets the "positive mask" wrongly (they should be all 0).
				//On the other hand, the DMX_SET_FILTER1 ioctl also uses the dmx_sct_filter_params
				//structure, which is incorrect (it should be  dmxSctFilterParams).
				//The only way to get it right is to call DMX_SET_FILTER1 with the argument
				//expected by DMX_SET_FILTER. Otherwise, the timeout parameter is not passed correctly.
				ret=ioctl(fd, DMX_SET_FILTER1, &sFP2);
			} 
			else {
				memcpy(sFP2.filter.filter,filter,16);
				memcpy(sFP2.filter.mask,mask,16);
				ret=ioctl(fd, DMX_SET_FILTER, &sFP2);
			}
			break;
		}

		case DVBAPI_1: {
			struct dmxSctFilterParams sFP1;
			memset(&sFP1,0,sizeof(sFP1));
			sFP1.pid = pid;
			sFP1.timeout = 0;
			sFP1.flags = DMX_IMMEDIATE_START;
			memcpy(sFP1.filter.filter,filter,16);
			memcpy(sFP1.filter.mask,mask,16);
			ret = ioctl(fd, DMX_SET_FILTER1, &sFP1);
			break;
		}
#ifdef WITH_STAPI
		case STAPI: {
			ret = oscam_stapi_FilterSet(fd, filter, mask);
			if (ret) ret = -1;
			break;
		}
#endif
/*#ifdef WITH_COOLAPI    ******* NOT IMPLEMENTED YET ********
		case COOLAPI: {
			coolapi_set_filter(demux[demux_id].demux_fd[n].fd, n, pid, filter, mask, TYPE_ECM);
			break;
		}
#endif
*/
		default:
			break;
	}
	return ret;
}


int32_t dvbapi_check_ecm_delayed_delivery(int32_t demux_index, ECM_REQUEST *er) {
	int32_t filternum = dvbapi_get_filternum(demux_index, er, TYPE_ECM);
	if (filternum < 0) return 2; // if no matching filter act like ecm response is delayed
	struct s_ecmpids *curpid = &demux[demux_index].ECMpids[demux[demux_index].demux_fd[filternum].pidindex];
	if (curpid->table ==0) return 3; // on change table act like ecm response is found
	if (er->rc == E_CACHEEX) return 4; // on cache-ex response act like ecm response is found
	char nullcw[CS_ECMSTORESIZE];
	memset(nullcw, 0, CS_ECMSTORESIZE);
	
	if(memcmp(demux[demux_index].demux_fd[filternum].ecmd5, nullcw, CS_ECMSTORESIZE)){
		char ecmd5[17*3];
		cs_hexdump(0, demux[demux_index].demux_fd[filternum].ecmd5, 16, ecmd5, sizeof(ecmd5));
		cs_debug_mask(D_DVBAPI, "[DVBAPI] Demuxer #%d requested controlword for ecm %s on fd %d", demux_index, ecmd5, demux[demux_index].demux_fd[filternum].fd);
		return memcmp(demux[demux_index].demux_fd[filternum].ecmd5, er->ecmd5, CS_ECMSTORESIZE); // 1 = no response on the ecm we request last for this fd!	
	} else return 0;
}

int32_t dvbapi_get_filternum(int32_t demux_index, ECM_REQUEST *er, int32_t type) {
	if (!er) return -1;
		
	int32_t n;
	int32_t fd = -1;
	
	for (n = 0; n < MAX_FILTER; n++) { // determine fd
		if (demux[demux_index].demux_fd[n].fd > 0 && demux[demux_index].demux_fd[n].type == type ) { // check for valid and right type (ecm or emm)
			if ((demux[demux_index].demux_fd[n].pid == er->pid) &&
				((demux[demux_index].demux_fd[n].provid == er->prid) || demux[demux_index].demux_fd[n].provid == 0) &&
				((demux[demux_index].demux_fd[n].caid == er->caid) ||(demux[demux_index].demux_fd[n].caid == er->ocaid))){ // current ecm pid?
					fd = demux[demux_index].demux_fd[n].fd; // found!
					break;
			}
		}
	}
	if (fd > 0 && demux[demux_index].demux_fd[n].provid == 0) demux[demux_index].demux_fd[n].provid = er->prid; // hack to fill in provid into demuxer
	
	return (fd > 0?n:fd); // return -1(fd) on not found, on found return filternumber(n)
}

int32_t dvbapi_ca_setpid(int32_t demux_index, int32_t pid) {
	int32_t idx = -1, n;
	for (n=0; n<demux[demux_index].ECMpidcount; n++) { // cleanout old indexes of pids that have now status ignore (=no decoding possible!) 
		if (demux[demux_index].ECMpids[n].status == -1 || demux[demux_index].ECMpids[n].checked == 0) demux[demux_index].ECMpids[n].index = 0; // reset index!
	}
	
	idx = demux[demux_index].ECMpids[pid].index;
		
	if (!idx){ // if no indexer for this pid get one!
		idx = dvbapi_get_descindex(demux_index);
		demux[demux_index].ECMpids[pid].index= idx;
		cs_debug_mask(D_DVBAPI,"[DVBAPI] Demuxer #%d PID: #%d CAID: %04X ECMPID: %04X is using index %d", demux_index, pid,
			demux[demux_index].ECMpids[pid].CAID, demux[demux_index].ECMpids[pid].ECM_PID, idx-1);
	
		for (n=0;n<demux[demux_index].STREAMpidcount;n++) {
			if (!demux[demux_index].ECMpids[pid].streams || (demux[demux_index].ECMpids[pid].streams & (1 << n)))
				dvbapi_set_pid(demux_index, n, idx-1); // enable streampid
			else
				dvbapi_set_pid(demux_index, n, -1); // disable streampid
		}
	}
	
	return idx-1; // return caindexer
}
/*
 *	protocol structure
 */

void module_dvbapi(struct s_module *ph)
{
	ph->desc="dvbapi";
	ph->type=MOD_CONN_SERIAL;
	ph->listenertype = LIS_DVBAPI;
	ph->s_handler=dvbapi_handler;
	ph->send_dcw=dvbapi_send_dcw;
}
#endif // HAVE_DVBAPI
