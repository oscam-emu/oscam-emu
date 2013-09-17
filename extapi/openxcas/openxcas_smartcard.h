#ifndef __OPENXCARD_SMARTCARD_H__
#define __OPENXCARD_SMARTCARD_H__

/* from LINUX_BSP/include/asm/tango2/scard.h  */
/* ioctl commands for user level applications */

#define SCARD_IOC_MAGIC     'S'
#define SCARD_IOC_WARMRESET _IO(SCARD_IOC_MAGIC, 0)
#define SCARD_IOC_CLOCKSTOP _IO(SCARD_IOC_MAGIC, 1)
#define SCARD_IOC_CLOCKSTART  _IO(SCARD_IOC_MAGIC, 2)
#define SCARD_IOC_CHECKCARD _IO(SCARD_IOC_MAGIC, 3)

#define SMARTCARD_DEV "/dev/scard"

#endif
