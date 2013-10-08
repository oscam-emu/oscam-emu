/*
    protocol_t1.c
    Handling of ISO 7816 T=1 protocol

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

#include "../globals.h"
#include "../oscam-time.h"
#ifdef WITH_CARDREADER
#include "icc_async.h"

#define OK 0
#define ERROR 1

/* Buffer sizes */
#define T1_BLOCK_MAX_SIZE                259

/* Types of block */
#define T1_BLOCK_I                0x00
#define T1_BLOCK_R_OK             0x80
#define T1_BLOCK_R_EDC_ERR        0x81
#define T1_BLOCK_R_OTHER_ERR      0x82
#define T1_BLOCK_S_RESYNCH_REQ    0xC0
#define T1_BLOCK_S_RESYNCH_RES    0xE0
#define T1_BLOCK_S_IFS_REQ        0xC1
#define T1_BLOCK_S_IFS_RES        0xE1
#define T1_BLOCK_S_ABORT_REQ      0xC2
#define T1_BLOCK_S_ABORT_RES      0xE2
#define T1_BLOCK_S_WTX_REQ        0xC3
#define T1_BLOCK_S_WTX_RES        0xE3
#define T1_BLOCK_S_VPP_ERR        0xE4

#define T1_BLOCK_NAD        0x00

#define T1_Block_GetNS(a)   ((a[1] >> 6) & 0x01)
#define T1_Block_GetMore(a) ((a[1] >> 5) & 0x01)
#define T1_Block_GetNR(a)   ((a[1] >> 4) & 0x01)
#define T1_Block_GetLen(a)  a[2]


static unsigned char T1_Block_LRC(unsigned char *data, uint32_t length)
{
	unsigned char lrc = 0x00;
	uint32_t i;
	for(i = 0; i < length; i++)
		{ lrc ^= data[i]; }
	return lrc;
}

static int32_t T1_Block_SendIBlock(struct s_reader *reader, uint8_t *block_data, unsigned char len, unsigned char *inf, unsigned char ns, int32_t more,                    uint32_t timeout)
{
	int length = len + 4;

	block_data[0] = T1_BLOCK_NAD;
	block_data[1] = T1_BLOCK_I | ((ns << 6) & 0x40);
	if(more)
		{ block_data[1] |= 0x20; }
	block_data[2] = len;
	if(len != 0x00)
		{ memcpy(block_data + 3, inf, len); }
	block_data[len + 3] = T1_Block_LRC(block_data, len + 3);

	return ICC_Async_Transmit(reader, length, 0, block_data, 0, timeout);
}

static int32_t T1_Block_SendRBlock(struct s_reader *reader, uint8_t *block_data, unsigned char type, unsigned char nr, uint32_t timeout)
{
	int length = 4;

	block_data[0] = T1_BLOCK_NAD;
	block_data[1] = type | ((nr << 4) & 0x10);
	block_data[2] = 0x00;
	block_data[3] = T1_Block_LRC(block_data, 3);

	return ICC_Async_Transmit(reader, length, 0, block_data, 0, timeout);
}

static int32_t T1_Block_SendSBlock(struct s_reader *reader, uint8_t *block_data, unsigned char type, unsigned char len, unsigned char *inf, uint32_t timeout)
{
	int length = 4 + len;

	block_data[0] = T1_BLOCK_NAD;
	block_data[1] = type;
	block_data[2] = len;
	if(len != 0x00)
		{ memcpy(block_data + 3, inf, len); }

	block_data[len + 3] = T1_Block_LRC(block_data, len + 3);

	return ICC_Async_Transmit(reader, length, 0, block_data, 0, timeout);
}

static int32_t Protocol_T1_ReceiveBlock(struct s_reader *reader, uint8_t *block_data, uint32_t *block_length, uint8_t *rsp_type, uint32_t timeout)
{
	int32_t ret, length;

	/* Receive four mandatory bytes */
	if(ICC_Async_Receive(reader, 4, block_data, 0, timeout))
		{ ret = ERROR; }
	else
	{
		length = block_data[2];
		if(length != 0x00)
		{
			*block_length = (length + 4 > T1_BLOCK_MAX_SIZE) ? T1_BLOCK_MAX_SIZE : length + 4;

			/* Receive remaining bytes */
			if(ICC_Async_Receive(reader, *block_length - 4, block_data + 4, 0, timeout))
				{ ret = ERROR; }
			else
				{ ret = OK; }
		}
		else
		{
			ret = OK;
			*block_length = 4;
		}
	}
	*rsp_type = ((block_data[1] & 0x80) == T1_BLOCK_I) ? T1_BLOCK_I : (block_data[1] & 0xEF);

	return ret;
}

int32_t Protocol_T1_Command(struct s_reader *reader, unsigned char *command, uint16_t command_len, unsigned char *rsp, uint16_t *lr)
{
	uint8_t block_data[T1_BLOCK_MAX_SIZE];
	uint8_t rsp_type, bytes, nr, wtx;
	uint16_t counter;
	int32_t ret, timeout;
	bool more;
	uint32_t block_length = 0;
	if(command[1] == T1_BLOCK_S_IFS_REQ)
	{
		uint8_t inf = command[3];

		/* Create an IFS request S-Block */
		timeout = ICC_Async_GetTimings(reader, reader->CWT);  // we are going to send: CWT timeout
		//cs_sleepus(reader->block_delay); // we were receiving, now sending so wait BGT time
		ret = T1_Block_SendSBlock(reader, block_data, T1_BLOCK_S_IFS_REQ, 1, &inf, timeout);
		rdr_debug_mask(reader, D_IFD, "Protocol: Sending block S(IFS request, %d)", inf);

		/* Receive a block */

		timeout = ICC_Async_GetTimings(reader, reader->BWT); // we are going to receive so set Block Waiting Timeout!
		//cs_sleepus(reader->block_delay); // we were sending, now receiving so wait BGT time
		ret = Protocol_T1_ReceiveBlock(reader, block_data, &block_length, &rsp_type, timeout);

		if(ret == OK)
		{
			/* Positive IFS Response S-Block received */
			if(rsp_type == T1_BLOCK_S_IFS_RES)
			{
				rdr_debug_mask(reader, D_IFD, "Protocol: Received block S(IFS response, %d)", block_data[3]);
			}
		}

		return ret;
	}
	else if(command[1] == T1_BLOCK_S_RESYNCH_REQ)
	{
		/* Create an Resynch request S-Block */
		timeout = ICC_Async_GetTimings(reader, reader->CWT);  // we are going to send: CWT timeout
		//cs_sleepus(reader->block_delay); // we were receiving, now sending so wait BGT time
		ret = T1_Block_SendSBlock(reader, block_data, T1_BLOCK_S_RESYNCH_REQ, 0, NULL, timeout);
		rdr_debug_mask(reader, D_IFD, "Protocol: Sending block S(RESYNCH request)");

		/* Receive a block */
		timeout = ICC_Async_GetTimings(reader, reader->BWT); // we are going to receive so set Block Waiting Timeout!
		//cs_sleepus(reader->block_delay); // we were sending, now receiving so wait BGT time
		ret = Protocol_T1_ReceiveBlock(reader, block_data, &block_length, &rsp_type, timeout);

		if(ret == OK)
		{
			/* Positive IFS Response S-Block received */
			if(rsp_type == T1_BLOCK_S_RESYNCH_RES)
			{
				rdr_debug_mask(reader, D_IFD, "Protocol: Received block S(RESYNCH response)");
				reader->ns = 0;
			}
		}
		return ret;
	}

	/* Calculate the number of bytes to send */
	counter = 0;
	bytes = MIN(command_len, reader->ifsc);

	/* See if chaining is needed */
	more = (command_len > reader->ifsc);

	/* Increment ns */
	reader->ns = (reader->ns == 1) ? 0 : 1; //toggle from 0 to 1 and back

	/* Create an I-Block */
	timeout = ICC_Async_GetTimings(reader, reader->CWT);  // we are going to send: CWT timeout
	//cs_sleepus(reader->block_delay); // we were receiving, now sending so wait BGT time
	ret = T1_Block_SendIBlock(reader, block_data, bytes, command, reader->ns, more, timeout);
	rdr_debug_mask(reader, D_IFD, "Sending block I(%d,%d)", reader->ns, more);

	while((ret == OK) && more)
	{
		/* Receive a block */

		timeout = ICC_Async_GetTimings(reader, reader->BWT); // we are going to receive so set Block Waiting Timeout!
		//cs_sleepus(reader->block_delay); // we were sending, now receiving so wait BGT time
		ret = Protocol_T1_ReceiveBlock(reader, block_data, &block_length, &rsp_type, timeout);

		if(ret == OK)
		{
			/* Positive ACK R-Block received */
			if(rsp_type == T1_BLOCK_R_OK)
			{
				rdr_debug_mask(reader, D_IFD, "Protocol: Received block R(%d)", T1_Block_GetNR(block_data));

				/* Increment ns  */
				reader->ns = (reader->ns == 1) ? 0 : 1; //toggle from 0 to 1 and back

				/* Calculate the number of bytes to send */
				counter += bytes;
				bytes = MIN(command_len - counter, reader->ifsc);

				/* See if chaining is needed */
				more = (command_len - counter > reader->ifsc);

				/* Send an I-Block */
				timeout = ICC_Async_GetTimings(reader, reader->CWT);  // we are going to send: CWT timeout
				//cs_sleepus(reader->block_delay); // we were receiving, now sending so wait BGT time
				ret = T1_Block_SendIBlock(reader, block_data, bytes, command + counter, reader->ns, more, timeout);
				rdr_debug_mask(reader, D_IFD, "Protocol: Sending block I(%d,%d)", reader->ns, more);

			}
			else
			{
				rdr_debug_mask(reader, D_TRACE, "ERROR: T1 Command %02X not implemented", rsp_type);
				return ERROR;
			}
		}
		else
		{
			rdr_debug_mask(reader, D_TRACE, "ERROR: T1 Command returned error");
			return ERROR;
		}
	}

	/* Reset counter */
	counter = 0;
	more = 1;
	wtx = 1;

	while((ret == OK) && more)
	{

		/* Receive a block */
		timeout = ICC_Async_GetTimings(reader, wtx * reader->BWT); // we are going to receive so set Block Waiting Timeout!
		//cs_sleepus(reader->block_delay); // we were sending, now receiving so wait BGT time
		ret = Protocol_T1_ReceiveBlock(reader, block_data, &block_length, &rsp_type, timeout);
		wtx = 1; // reset WTX value since its only valid for first received I block

		if(ret == OK)
		{
			if(rsp_type == T1_BLOCK_I)
			{
				rdr_debug_mask(reader, D_IFD, "Protocol: Received block I(%d,%d)", T1_Block_GetNS(block_data), T1_Block_GetMore(block_data));

				bytes = T1_Block_GetLen(block_data);

				/* Calculate nr */
				nr = (T1_Block_GetNS(block_data) + 1) % 2;

				if(counter + bytes > T1_BLOCK_MAX_SIZE) { return ERROR; }

				memcpy(rsp + counter, block_data + 3, bytes);
				counter += bytes;

				/* See if chaining is requested */
				more = T1_Block_GetMore(block_data);

				if(more)
				{
					/* Send R-Block */
					timeout = ICC_Async_GetTimings(reader, reader->CWT);  // we are going to send: CWT timeout
					//cs_sleepus(reader->block_delay); // we were receiving, now sending so wait BGT time
					ret = T1_Block_SendRBlock(reader, block_data, T1_BLOCK_R_OK, nr, timeout);
					rdr_debug_mask(reader, D_IFD, "Protocol: Sending block R(%d)", nr);
				}
			}
			else if(rsp_type == T1_BLOCK_S_WTX_REQ)      /* WTX Request S-Block received */
			{
				/* Get wtx multiplier */
				wtx = block_data[3];
				rdr_debug_mask(reader, D_IFD, "Protocol: Received block S(WTX request, %d)", wtx);

				/* Send an WTX response S-Block */
				timeout = ICC_Async_GetTimings(reader, reader->CWT);  // we are going to send: CWT timeout
				//cs_sleepus(reader->block_delay); // we were receiving, now sending so wait BGT time
				ret = T1_Block_SendSBlock(reader, block_data, T1_BLOCK_S_WTX_RES, 1, &wtx, timeout);
				rdr_debug_mask(reader, D_IFD, "Protocol: Sending block S(WTX response, %d)", wtx);
			}
			else
			{
				rdr_debug_mask(reader, D_TRACE, "ERROR: T1 Command %02X not implemented in Receive Block", rsp_type);
				ret = ERROR; //not implemented
			}
		}
	}

	if(ret == OK)
		{ *lr = counter; }

	return ret;
}
#endif
