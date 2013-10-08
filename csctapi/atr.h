/*
    atr.h
    ISO 7816 ICC's answer to reset abstract data type definitions

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

#ifndef _ATR_
#define _ATR_

/*
 * Exported constants definition
 */
#define ATR_TIMEOUT         1000000
#define DEFAULT_BAUDRATE    9600

/* Return values */
#define ATR_OK      0   /* ATR could be parsed and data returned */
#define ATR_NOT_FOUND   1   /* Data not present in ATR */
#define ATR_MALFORMED   2   /* ATR could not be parsed */
#define ATR_IO_ERROR    2   /* I/O stream error */

/* Paramenters */
#define ATR_MAX_SIZE        33  /* Maximum size of ATR byte array */
#define ATR_MAX_HISTORICAL  15  /* Maximum number of historical bytes */
#define ATR_MAX_PROTOCOLS   7   /* Maximun number of protocols */
#define ATR_MAX_IB      4   /* Maximum number of interface bytes per protocol */
#define ATR_CONVENTION_DIRECT   0   /* Direct convention */
#define ATR_CONVENTION_INVERSE  1   /* Inverse convention */
#define ATR_PROTOCOL_TYPE_T0    0   /* Protocol type T=0 */
#define ATR_PROTOCOL_TYPE_T1    1   /* Protocol type T=1 */
#define ATR_PROTOCOL_TYPE_T2    2   /* Protocol type T=2 */
#define ATR_PROTOCOL_TYPE_T3    3   /* Protocol type T=3 */
#define ATR_PROTOCOL_TYPE_T14   14  /* Protocol type T=14 */
#define ATR_INTERFACE_BYTE_TA   0   /* Interface byte TAi */
#define ATR_INTERFACE_BYTE_TB   1   /* Interface byte TBi */
#define ATR_INTERFACE_BYTE_TC   2   /* Interface byte TCi */
#define ATR_INTERFACE_BYTE_TD   3   /* Interface byte TDi */
#define ATR_PARAMETER_F     0   /* Parameter F */
#define ATR_PARAMETER_D     1   /* Parameter D */
#define ATR_PARAMETER_I     2   /* Parameter I */
#define ATR_PARAMETER_P     3   /* Parameter P */
#define ATR_PARAMETER_N     4   /* Parameter N */
#define ATR_INTEGER_VALUE_FI    0   /* Integer value FI */
#define ATR_INTEGER_VALUE_DI    1   /* Integer value DI */
#define ATR_INTEGER_VALUE_II    2   /* Integer value II */
#define ATR_INTEGER_VALUE_PI1   3   /* Integer value PI1 */
#define ATR_INTEGER_VALUE_N 4   /* Integer value N */
#define ATR_INTEGER_VALUE_PI2   5   /* Integer value PI2 */

/* Default values for paramenters */
#define ATR_DEFAULT_FI 1
#define ATR_DEFAULT_D   1
#define ATR_DEFAULT_I   50
#define ATR_DEFAULT_N   0
#define ATR_DEFAULT_P   5

/*
 * Exported data types definition
 */

typedef struct s_ATR
{
	unsigned length;
	unsigned char TS;
	unsigned char T0;
	struct
	{
		unsigned char value;
		bool present;
	}
	ib[ATR_MAX_PROTOCOLS][ATR_MAX_IB], TCK;
	unsigned pn;
	unsigned char hb[ATR_MAX_HISTORICAL];
	unsigned hbn;
}
ATR;

/*
 * Exported variables declaration
 */

extern const uint32_t atr_fs_table[16];
extern const uint32_t atr_f_table[16];
extern const double atr_d_table[16];

/*
 * Exported functions declaraton
 */

/* Initialization */
int32_t ATR_InitFromArray(ATR *atr, const unsigned char buffer[ATR_MAX_SIZE], uint32_t length);

/* General smartcard characteristics */
int32_t ATR_GetConvention(ATR *atr, int32_t *convention);
int32_t ATR_GetNumberOfProtocols(ATR *atr, uint32_t *number_protocols);
int32_t ATR_GetProtocolType(ATR *atr, uint32_t number_protocol, unsigned char *protocol_type);

/* ATR parameters and integer values */
int32_t ATR_GetInterfaceByte(ATR *atr, uint32_t number, int32_t character, unsigned char *ib);
int32_t ATR_GetIntegerValue(ATR *atr, int32_t name, unsigned char *value);
int32_t ATR_GetParameter(ATR *atr, int32_t name, uint32_t *parameter);
int32_t ATR_GetHistoricalBytes(ATR *atr, unsigned char *hist, uint32_t *length);
int32_t ATR_GetCheckByte(ATR *atr, unsigned char *check_byte);
int32_t ATR_GetFsMax(ATR *atr, uint32_t *fsmax);

/* Raw ATR retrieving */
int32_t ATR_GetRaw(ATR *atr, unsigned char *buffer, uint32_t *lenght);
int32_t ATR_GetSize(ATR *atr, uint32_t *size);

/* Invert order of bits in a byte: b7->b0, b0->b7 */
#ifndef INVERT_BYTE
#define INVERT_BYTE(a) ( \
                         (((a) << 7) & 0x80) | \
                         (((a) << 5) & 0x40) | \
                         (((a) << 3) & 0x20) | \
                         (((a) << 1) & 0x10) | \
                         (((a) >> 1) & 0x08) | \
                         (((a) >> 3) & 0x04) | \
                         (((a) >> 5) & 0x02) | \
                         (((a) >> 7) & 0x01)   \
                       )
#endif

#endif /* _ATR_ */
