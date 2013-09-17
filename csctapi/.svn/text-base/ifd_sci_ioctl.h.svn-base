#ifndef _sci_ioctl_h_
#define _sci_ioctl_h_

/* constants */
#define DEVICE_NAME			"sci_dev"

#define SCI_IOW_MAGIC			's'

#ifdef STB04SCI
//--------------------------------------------------------------------------
// reset sci_parameters are optional, i.e. may be NULL
// (but not: ioctl (fd, STB04SCI_RESET),
// rather ioctl (fd, STB04SCI_RESET, NULL))
//--------------------------------------------------------------------------

#define IOCTL_SET_RESET							_IO (0x64,	1)
#define IOCTL_SET_MODES							_IOW(0x64,	2, SCI_MODES)
#define IOCTL_GET_MODES							_IOR(0x64,	3, SCI_MODES)
#define IOCTL_SET_PARAMETERS				_IOW(0x64,	4, SCI_PARAMETERS)
#define IOCTL_GET_PARAMETERS				_IOR(0x64,	5, SCI_PARAMETERS)
#define IOCTL_CLOCK_START						_IO (0x64,	6)
#define IOCTL_CLOCK_STOP						_IO (0x64,	7)
#define IOCTL_GET_IS_CARD_PRESENT		_IO (0x64,	8)
#define IOCTL_GET_IS_CARD_ACTIVATED	_IO (0x64,	9)
#define IOCTL_SET_DEACTIVATE				_IO (0x64, 10)
#define IOCTL_SET_ATR_READY					_IO (0x64, 11)
#define IOCTL_GET_ATR_STATUS				_IO (0x64, 12)
#define IOCTL_DUMP_REGS							_IO (0x64, 20)

#elif defined(__CYGWIN__)
/* ioctl cmd table */
#define IOCTL_SET_RESET							1
#define IOCTL_SET_MODES							2
#define IOCTL_GET_MODES							3
#define IOCTL_SET_PARAMETERS				4
#define IOCTL_GET_PARAMETERS				5
#define IOCTL_SET_CLOCK_START				6
#define IOCTL_SET_CLOCK_STOP				7
#define IOCTL_GET_IS_CARD_PRESENT		8
#define IOCTL_GET_IS_CARD_ACTIVATED	9
#define IOCTL_SET_DEACTIVATE				10
#define IOCTL_SET_ATR_READY					11
#define IOCTL_GET_ATR_STATUS				12
#define IOCTL_DUMP_REGS							13
#else
#define IOCTL_SET_RESET							_IOW(SCI_IOW_MAGIC, 1,	uint32_t)
#define IOCTL_SET_MODES							_IOW(SCI_IOW_MAGIC, 2,	SCI_MODES)
#define IOCTL_GET_MODES							_IOW(SCI_IOW_MAGIC, 3,	SCI_MODES)
#define IOCTL_SET_PARAMETERS				_IOW(SCI_IOW_MAGIC, 4,	SCI_PARAMETERS)
#define IOCTL_GET_PARAMETERS				_IOW(SCI_IOW_MAGIC, 5,	SCI_PARAMETERS)
#define IOCTL_SET_CLOCK_START				_IOW(SCI_IOW_MAGIC, 6,	uint32_t)
#define IOCTL_SET_CLOCK_STOP				_IOW(SCI_IOW_MAGIC, 7,	uint32_t)
#define IOCTL_GET_IS_CARD_PRESENT		_IOW(SCI_IOW_MAGIC, 8,	uint32_t)
#define IOCTL_GET_IS_CARD_ACTIVATED	_IOW(SCI_IOW_MAGIC, 9,	uint32_t)
#define IOCTL_SET_DEACTIVATE				_IOW(SCI_IOW_MAGIC, 10, uint32_t)
#define IOCTL_SET_ATR_READY					_IOW(SCI_IOW_MAGIC, 11, uint32_t)
#define IOCTL_GET_ATR_STATUS				_IOW(SCI_IOW_MAGIC, 12, uint32_t)
#define IOCTL_DUMP_REGS							_IOW(SCI_IOW_MAGIC, 20, uint32_t)
#endif

/* MAJOR NUM OF DEVICE DRVIER */
#define MAJOR_NUM			169

#endif /* _sci_ioctl_h_ */
