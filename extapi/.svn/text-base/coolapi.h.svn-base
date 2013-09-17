#ifndef _COOLAPI_H_
#define _COOLAPI_H_

/* timeouts in ETU */
typedef struct
{
   uint16_t  CardActTime;
   uint16_t  CardDeactTime;  
   uint16_t  ATRSTime; 
   uint16_t  ATRDTime; 
   uint32_t  BLKTime;
   uint32_t  CHTime;
   uint8_t   CHGuardTime;
   uint8_t   BKGuardTime;  
} CNXT_SMC_TIMEOUT;

typedef struct
{
   uint8_t   		TXRetries;
   uint8_t   		RXRetries;
} CNXT_SMC_RETRIES;

typedef enum 
{
   CNXT_SMC_CONV_DIRECT = 0,
   CNXT_SMC_CONV_INVERSE,
   CNXT_SMC_CONV_LAST = CNXT_SMC_CONV_INVERSE
} CNXT_SMC_CONVENTION;

typedef struct
{
   CNXT_SMC_CONVENTION	convention;
   uint8_t				protocol;
   uint8_t				FI;
   uint8_t				N;
   uint8_t				DI;
   uint8_t				PI1;
   uint8_t				PI2;
   uint8_t				II;
   uint8_t				historical[15];
   uint8_t				length;
   CNXT_SMC_RETRIES		retries;
   uint8_t				filterprotocolbytes;
} CNXT_SMC_COMM;

/* These functions are implemented in libnxp and are used in coolstream */
int32_t cnxt_cbuf_init(void *);
int32_t cnxt_cbuf_get_used(void *buffer, uint32_t * bytes_used);
int32_t cnxt_cbuf_attach(void *handle, int32_t type, void * channel);
int32_t cnxt_cbuf_detach(void *handle, int32_t type, void * channel);
int32_t cnxt_cbuf_close(void * handle);
int32_t cnxt_cbuf_read_data(void * handle, void *buffer, uint32_t size, uint32_t * ret_size);
int32_t cnxt_cbuf_flush(void * handle, int);

void cnxt_kal_initialize(void);
void cnxt_kal_terminate(void);
void cnxt_drv_init(void);
void cnxt_drv_term(void);

int32_t cnxt_dmx_init(void *);
int32_t cnxt_dmx_close(void * handle);
int32_t cnxt_dmx_channel_close(void * channel);
int32_t cnxt_dmx_open_filter(void * handle, void *flt);
int32_t cnxt_dmx_close_filter(void * filter);
int32_t cnxt_dmx_channel_attach(void * channel, int32_t param1, int32_t param2, void * buffer);
int32_t cnxt_dmx_channel_detach(void * channel, int32_t param1, int32_t param2, void * buffer);
int32_t cnxt_dmx_channel_attach_filter(void * channel, void * filter);
int32_t cnxt_dmx_channel_detach_filter(void * channel, void * filter);
int32_t cnxt_dmx_set_channel_buffer(void * channel, int32_t param1, void * buffer);
int32_t cnxt_dmx_set_channel_pid(void * channel, uint32_t pid);
int32_t cnxt_dmx_get_channel_from_pid(void * device, uint16_t pid, void * channel);
int32_t cnxt_dmx_set_channel_key(void * channel, int32_t param1, uint32_t parity, unsigned char *cw, uint32_t len);
int32_t cnxt_dmx_channel_ctrl(void * channel, int32_t param1, int32_t param2);

int32_t cnxt_smc_init(void *);

int32_t cnxt_smc_open(void *cool_handle, int32_t *, void *, void *);
int32_t cnxt_smc_enable_flow_control(void *cool_handle, int32_t enable);
int32_t cnxt_smc_get_state(void *cool_handle, int32_t *state);
int32_t cnxt_smc_get_clock_freq(void *cool_handle, uint32_t *clk);
int32_t cnxt_smc_reset_card(void *cool_handle, int32_t timeout, void *, void *);
int32_t cnxt_smc_get_atr(void *cool_handle, unsigned char *buf, int32_t *buflen);
int32_t cnxt_smc_get_comm_parameters(void *cool_handle, CNXT_SMC_COMM *comm);
int32_t cnxt_smc_get_config_timeout(void *cool_handle, CNXT_SMC_TIMEOUT *timeout);
int32_t cnxt_smc_set_config_timeout(void *cool_handle, CNXT_SMC_TIMEOUT timeout);
int32_t cnxt_smc_set_convention(void *cool_handle, CNXT_SMC_CONVENTION conv);
int32_t cnxt_smc_start_pps(void *cool_handle, uint8_t *params, uint8_t *response, uint8_t *len, int32_t setfd);
int32_t cnxt_smc_get_F_D_factors (void *cool_handle, uint16_t *F, uint8_t *D);
int32_t cnxt_smc_set_F_D_factors (void *cool_handle, uint16_t F, uint8_t D);
int32_t cnxt_smc_read_write(void *cool_handle, int8_t async, uint8_t *sent, uint32_t size, uint8_t *cardbuffer, uint32_t *cardbuflen, int32_t rw_timeout, void *tag);
int32_t cnxt_smc_set_clock_freq(void *cool_handle, int32_t clk);
int32_t cnxt_smc_set_filter_protocol_bytes (void *cool_handle, int32_t enable);
int32_t cnxt_smc_close(void *cool_handle);

/* Error checking */
#define CNXT_STATUS_ERRORS 108
static const char* const cnxt_status[CNXT_STATUS_ERRORS] = {
	"OK",
	"ALREADY_INIT",
	"NOT_INIT",
	"INTERNAL_ERROR",
	"BAD_HANDLE",
	"BAD_PARAMETER",
	"BAD_LENGTH",
	"BAD_UNIT",
	"RESOURCE_ERROR",
	"CLOSED_HANDLE",
	"TIMEOUT",
	"NOT_ATTACHED",
	"NOT_SUPPORTED",
	"REOPENED_HANDLE",
	"INVALID",
	"DESTROYED",
	"DISCONNECTED",
	"BUSY",
	"IN_USE",
	"CANCELLED",
	"UNDEFINED",
	"UNKNOWN",
	"NOT_FOUND",
	"NOT_AVAILABLE",
	"NOT_COMPATIBLE",
	"NOT_IMPLEMENTED",
	"EMPTY",
	"FULL",
	"FAILURE",
	"ALREADY_ATTACHED",
	"ALREADY_DONE",
	"ASLEEP",
	"BAD_ATTACHMENT",
	"BAD_COMMAND",
	"BAD_GPIO",
	"BAD_INDEX",
	"BAD_MODE",
	"BAD_PID",
	"BAD_PLANE",
	"BAD_PTR",
	"BAD_RECT",
	"BAD_RGN_HANDLE",
	"BAD_SIZE",
	"INT_HANDLED",
	"INT_NOT_HANDLED",
	"NOT_SET",
	"NOT_HOOKED",
	"CC_NOT_ENABLED",
	"CLOSED_RGN",
	"COMPLETE",
	"DEMOD_ERROR",
	"INVALID_NODE",
	"DUPLICATE_NODE",
	"HARDWARE_NOT_FOUND",
	"HDCP_AUTH_FAILED",
	"HDCP_BAD_BKSV",
	"ILLEGAL_OPERATION",
	"INCOMPATIBLE_FORMATS",
	"INVALID_DEVICE",
	"INVALID_EDGE",
	"INVALID_NUMBER",
	"INVALID_STATE",
	"INVALID_TYPE",
	"NO_BUFFER",
	"NO_DESTINATION_BUF",
	"NO_OSD",
	"NO_PALETTE",
	"NO_ACK",
	"RECEIVER_HDMI_INCAPABLE",
	"RECEIVER_NOT_ATTACHED",
	"ADJUSTED",
	"CLIPPED",
	"CLIPRECT_ADJUSTED",
	"NOT_ALIGNED",
	"FIXUP_OK",
	"FIXUP_OPTION_ERROR",
	"FIXUP_ZERO_RECT",
	"UNABLE_TO_FIXUP_AND_PRESERVE",
	"UNABLE_TO_FIXUP_X",
	"UNABLE_TO_FIXUP_Y",
	"OUT_OF_BOUNDS",
	"OUTSIDE_CLIP_RECT",
	"RECT_CLIPPED",
	"RECT_ENCLOSED",
	"RECT_FIXED_UP",
	"RECT_INCLUDES",
	"RECT_NO_OVERLAP",
	"RECT_OVERLAP",
	"RECT_ZERO_AREA",
	"SERVICE_LIST_NOT_READY",
	"SERVICE_LIST_READY",
	"STOPPED",
	"SUSPENDED",
	"TERMINATED",
	"TOO_MUCH_DATA",
	"WIPE_NONE",
	"NOT_STOPPED",
	"INT_NOT_COMPLETE",
	"NOT_ALLOWED",
	"DUPLICATE_PID",
	"MAX_FILTERS_ATTACHED",
	"HW_NOT_READY",
	"OUTPUT_BUF_FULL",
	"REJECTED",
	"INVALID_PID",
	"EOF",
	"BOF",
	"MISSING_DATA"
};

#define coolapi_check_error(label, ret) \
do { \
	if (ret) { \
		cs_log("[%s:%d] %s: API ERROR %d (%s%s)", \
			__func__, \
			__LINE__ , \
			label, \
			ret, \
			ret > CNXT_STATUS_ERRORS ? "UNKNOWN" : "CNXT_STATUS_", \
			ret > CNXT_STATUS_ERRORS ? ""        : cnxt_status[ret] \
		); \
	} \
} while(0)

#if defined(HAVE_DVBAPI) && (defined(WITH_COOLAPI) || defined(WITH_SU980))
extern void coolapi_open_all(void);
extern void coolapi_close_all(void);
#else
static inline void coolapi_open_all(void) { }
static inline void coolapi_close_all(void) { }
#endif

#endif
