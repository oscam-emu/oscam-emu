#ifndef _MODULE_COOLAPI_H_
#define _MODULE_COOLAPI_H_

#define MAX_COOL_DMX 4

typedef struct s_cool_filter
{
    int32_t     fd;
    int32_t     channel;
    int32_t     pid;
    uchar       filter16[16];
    uchar       mask16[16];
} S_COOL_FILTER;

typedef struct s_cool_chanhandle
{
    int32_t     pid;
    void      *buffer1;
    void      *buffer2;
    void      *channel;
    int32_t     demux_index;
} S_COOL_CHANHANDLE;

struct cool_dmx
{
    int32_t     opened;
    int32_t     fd;
    uchar       buffer[4096];
    void       *buffer1;
    void       *buffer2;
    void       *channel;
    void       *filter;
    void       *device;
    int32_t     pid;
    pthread_mutex_t mutex;
    int32_t     demux_index;
    int32_t     demux_id;
    int32_t     filter_num;
    int32_t     type;
};
typedef struct cool_dmx dmx_t;

typedef struct
{
    int32_t  type;
    uint32_t size;
    int32_t unknown1;
    int16_t unknown2;
    int32_t unknown3;
    int32_t unknown[4];
} buffer_open_arg_t;

typedef struct
{
    int32_t type;
    int32_t unknown[2];
} channel_open_arg_t;

typedef struct
{
    uint32_t number;
    int32_t unknown1;
    int32_t unknown2;
    int32_t unknown3;
    int32_t unknown4;
    int32_t unknown5;
    int32_t unknown6;
    int32_t unknown[6];
} device_open_arg_t;

typedef struct
{
    uint32_t    length;
    uint8_t     filter[18]; //strange: initialization with max 18 possible but length limited to 12
    uint8_t     mask[18];
    uint8_t     nmask[18];
    int8_t      fvernum;
    int8_t      crcchange;
    int8_t      keeprbytes;
    int32_t     mode;
} filter_set_t;


typedef enum
{
    CONTINUOUS_ACQUIRE   = 0,
    ONE_SHOT_ACQUIRE,
    TOGGLE_ACQUIRE
} DATA_ACQUIRE_MODE;

typedef enum
{
    DATA_ACQUIRED = 1,
    CHANNEL_TIMEOUT,
    CRC_ERROR,
    BUF_OVERFLOW,
    PES_ERROR,
    COPY_DONE,
    CHANNEL_INFO
} DATA_ACQUIRE_STATUS;

typedef struct
{
    uint32_t PTSLow;
    uint32_t PTSHi;
} DMX_PTS;

typedef struct
{
    void                *channel;
    DATA_ACQUIRE_STATUS  type;
    DMX_PTS              ptssnapshop;
    DATA_ACQUIRE_MODE    mode;
    void                *buf;
    uint32_t             len;
    uint32_t             num;
    void                *filters[64];
    void                *tags[64];
} dmx_callback_data_t;

/* These functions are implemented in libnxp */
int32_t cnxt_cbuf_open(void **handle, buffer_open_arg_t *arg, void *, void *);
int32_t cnxt_dmx_open(void **device, device_open_arg_t *arg, void *, void *);
int32_t cnxt_dmx_channel_open(void *device, void **channel, channel_open_arg_t *arg, void *callback, void *);
int32_t cnxt_dmx_set_filter(void *handle, filter_set_t *arg, void *);
int32_t cnxt_dmx_channel_suspend(void *handle, int32_t enable);

/* Local coolapi functions */
void coolapi_open(void);
int32_t coolapi_set_filter (int32_t fd, int32_t num, int32_t pid, uchar *flt, uchar *mask, int32_t type);
int32_t coolapi_remove_filter (int32_t fd, int32_t num);
int32_t coolapi_open_device (int32_t demux_index, int32_t demux_id);
int32_t coolapi_close_device(int32_t fd);
int32_t coolapi_read(dmx_t *dmx, dmx_callback_data_t *data);
int32_t coolapi_write_cw(int32_t mask, uint16_t *STREAMpids, int32_t count, ca_descr_t *ca_descr);
int32_t coolapi_set_pid (int32_t demux_id, int32_t num, int32_t idx, int32_t pid);

#endif
