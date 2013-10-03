/*
    io_serial.h
    Serial port input/output definitions

    This file is part of the Unix driver for Towitoko smartcard readers
    Copyright (C) 2000 Carlos Prados <cprados@yahoo.com>

    This version is modified by doz21 to work in a special manner ;)

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _IO_SERIAL_
#define _IO_SERIAL_

#define IO_Serial_DTR_Set(reader) {int32_t _dtr = 1; IO_Serial_DTR_RTS(reader, &_dtr, NULL);}
#define IO_Serial_DTR_Clr(reader) {int32_t _dtr = 0; IO_Serial_DTR_RTS(reader, &_dtr, NULL);}
#define IO_Serial_RTS_Set(reader) {int32_t _rts = 1; IO_Serial_DTR_RTS(reader, NULL, &_rts);}
#define IO_Serial_RTS_Clr(reader) {int32_t _rts = 0; IO_Serial_DTR_RTS(reader, NULL, &_rts);}

//Type of parity of the serial device
//Chosen to Smartreader definition
//Since for io_serial it doesnt matter which values we choose
#if defined(__CYGWIN__)
#undef  PARITY_NONE
#undef  PARITY_ODD
#undef  PARITY_EVEN
#undef  PARITY_MARK
#undef  PARITY_SPACE
#endif

#define PARITY_NONE     0
#define PARITY_ODD      1
#define PARITY_EVEN     2
#define PARITY_MARK     3
#define PARITY_SPACE    4
/* Values for the modem lines */
#define IO_SERIAL_HIGH      1
#define IO_SERIAL_LOW           0

/* Maximum size of PnP Com ID */
#define IO_SERIAL_PNPID_SIZE        256

/*
 * Exported functions declaration
 */

/* IO_Serial creation and deletion */
void IO_Serial_Flush (struct s_reader *reader);

/* Initialization and closing */
bool IO_Serial_InitPnP (struct s_reader *reader);
int32_t IO_Serial_Close (struct s_reader *reader);

/* Transmission properties */
bool IO_Serial_DTR_RTS_dbox2(struct s_reader *reader, int32_t *dtr, int32_t *rts);
bool IO_Serial_DTR_RTS(struct s_reader *reader, int32_t *dtr, int32_t *rts);
void IO_Serial_Ioctl_Lock(struct s_reader *reader, int32_t);

bool IO_Serial_SetBitrate (struct s_reader *reader, uint32_t bitrate, struct termios *tio);
bool IO_Serial_SetParams (struct s_reader *reader, uint32_t bitrate, uint32_t bits, int32_t parity, uint32_t stopbits, int32_t *dtr, int32_t *rts);
bool IO_Serial_SetProperties (struct s_reader *reader, struct termios newtio);
int32_t IO_Serial_SetParity (struct s_reader *reader, unsigned char parity);

/* Input and output */
bool IO_Serial_Read (struct s_reader *reader, uint32_t delay, uint32_t timeout, uint32_t size, unsigned char *data);
bool IO_Serial_Write (struct s_reader *reader, uint32_t delay, uint32_t timeout, uint32_t size, const unsigned char *data);
void IO_Serial_Sendbreak (struct s_reader *reader, int32_t duration);
bool IO_Serial_WaitToRead (struct s_reader *reader, uint32_t delay_us, uint32_t timeout_us);

int32_t IO_Serial_Receive(struct s_reader *reader, unsigned char *buffer, uint32_t size, uint32_t delay, uint32_t timeout);
int32_t IO_Serial_Transmit(struct s_reader *reader, unsigned char *buffer, uint32_t size, uint32_t expectedlen, uint32_t delay, uint32_t timeout);
int32_t IO_Serial_GetStatus(struct s_reader *reader, int32_t *status);
int32_t IO_Serial_SetBaudrate(struct s_reader *reader, uint32_t baudrate);

#endif /* IO_SERIAL */
