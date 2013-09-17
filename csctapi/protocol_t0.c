/*
    protocol_t0.c
    Handling of ISO 7816 T=0 protocol

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

#ifdef WITH_CARDREADER
#include "../oscam-time.h"
#include "icc_async.h"
#include "protocol_t0.h"
/*
 * Not exported constants definition
 */

#define OK 0
#define ERROR 1

#define PROTOCOL_T0_MAX_NULLS          200
#define PROTOCOL_T0_DEFAULT_WI         10
#define PROTOCOL_T0_MAX_SHORT_COMMAND  260
#define PROTOCOL_T0_MAX_SHORT_RESPONSE 258

#define PROTOCOL_T14_MAX_NULLS          200
#define PROTOCOL_T14_DEFAULT_WI         10
#define PROTOCOL_T14_MAX_SHORT_COMMAND  260
#define PROTOCOL_T14_MAX_SHORT_RESPONSE 258

/* Types of APDU's */
#define APDU_CASE_1	0x0001	/* Nor send neither receive data */
#define APDU_CASE_2S	0x0002	/* Receive data (1..256) */
#define APDU_CASE_3S	0x0003	/* Send data (1..255) */
#define APDU_CASE_4S	0x0004	/* Send data (1..255) and receive data (1..256) */
#define APDU_CASE_2E	0x0102	/* Receive data (1..65536) */
#define APDU_CASE_3E	0x0103	/* Send data (1..65535) */
#define APDU_CASE_4E	0x0104	/* Send data (1..65535) and receive data (1..65536) */
#define APDU_MALFORMED		5	/* Malformed APDU */

/* Timings in ATR are not used in T=0 cards */
/* #undef PROTOCOL_T0_USE_DEFAULT_TIMINGS */

/*
 * Not exported functions declaration
 */

static int32_t Protocol_T0_Case2E (struct s_reader * reader, unsigned char * command, uint16_t command_len, unsigned char * rsp, uint16_t * lr);

static int32_t Protocol_T0_Case3E (struct s_reader * reader, unsigned char * command, unsigned char * rsp, uint16_t * lr);

static int32_t Protocol_T0_Case4E (struct s_reader * reader, unsigned char * command, uint16_t command_len, unsigned char * rsp, uint16_t * lr);

static int32_t Protocol_T0_ExchangeTPDU (struct s_reader *reader, unsigned char * command, uint16_t command_len, unsigned char * rsp, uint16_t * lr);

static int32_t APDU_Cmd_Case (unsigned char * command, uint16_t command_len)
{
	unsigned char B1;
	uint16_t B2B3;
	uint32_t L;
	int32_t res;
	
	/* Calculate length of body */
	L = MAX(command_len - 4, 0);
	
	/* Case 1 */
	if (L == 0)
		res = APDU_CASE_1;
	else {
		/* Get first byte of body */
		B1 = command[4];
		
		if ((B1 != 0) && (L == (uint32_t)B1 + 1))
			res = APDU_CASE_2S;
		else if (L == 1)
			res = APDU_CASE_3S;
		else if ((B1 != 0) && (L == (uint32_t)B1 + 2))
			res = APDU_CASE_4S;
		else if ((B1 == 0) && (L>2)) {
			/* Get second and third byte of body */
			B2B3 = (((uint16_t)(command[5]) << 8) | command[6]);
			
			if ((B2B3 != 0) && (L == (uint32_t)B2B3 + 3))
				res = APDU_CASE_2E;
			else if (L == 3)
				res = APDU_CASE_3E;
			else if ((B2B3 != 0) && (L == (uint32_t)B2B3 + 5))
				res = APDU_CASE_4E;
			else
				res = APDU_MALFORMED;
		}
		else
			res = APDU_MALFORMED;
	}
	return res;
}

/*
 * Exported funtions definition
 */

int32_t Protocol_T0_Command (struct s_reader * reader, unsigned char * command, uint16_t command_len, unsigned char * rsp, uint16_t * lr)
{
	*lr = 0; //will be returned in case of error
	if (command_len < 5) //APDU_CASE_1 or malformed
		return ERROR;
	int32_t cmd_case = APDU_Cmd_Case (command, command_len);
	switch (cmd_case) {
		case APDU_CASE_2E:
			return Protocol_T0_Case2E (reader, command, command_len, rsp, lr);
		case APDU_CASE_3E:
			return Protocol_T0_Case3E (reader, command, rsp, lr);
		case APDU_CASE_4E:
			return Protocol_T0_Case4E (reader, command, command_len, rsp, lr);
		case APDU_CASE_4S:
			command_len--; //FIXME this should change 4S to 2S/3S command
		case APDU_CASE_2S:
		case APDU_CASE_3S:
			return Protocol_T0_ExchangeTPDU(reader, command, command_len, rsp, lr);
		default:
			rdr_debug_mask(reader, D_IFD, "Protocol: T=0: Invalid APDU");
			return ERROR;
	}
}

/*
 * Not exported functions definition
 */


static int32_t Protocol_T0_Case2E (struct s_reader * reader, unsigned char * command, uint16_t command_len, unsigned char * rsp, uint16_t * lr)
{
	unsigned char buffer[PROTOCOL_T0_MAX_SHORT_COMMAND];
	unsigned char tpdu_rsp[CTA_RES_LEN];
	uint16_t tpdu_lr = 0;
	uint32_t i;
	
	uint32_t Lc = (((uint32_t)(command[5]) << 8) | command[6]);
	if (Lc < 256)
	{
		/* MAP APDU onto command TPDU */
		memcpy(buffer, command, 4);
		buffer[4] = (unsigned char) Lc;
		memcpy (buffer + 5, command + 7, buffer[4]);
		return Protocol_T0_ExchangeTPDU(reader, buffer, buffer[4] + 5, rsp, lr);
	}

		/* Prepare envelope TPDU */
		buffer[0] = command[0];
		buffer[1] = 0xC2;
		buffer[2] = 0x00;
		buffer[3] = 0x00;
		
		for (i = 0; i < command_len; i += buffer[4])
		{
			/* Create envelope command TPDU */
			buffer[4] = MIN (255, command_len - i);
			memcpy (buffer + 5, command + i, buffer[4]);
			call (Protocol_T0_ExchangeTPDU(reader, buffer, buffer[4] + 5, tpdu_rsp, &tpdu_lr));
				/*  Card does support envelope command */
				if (tpdu_rsp[tpdu_lr - 2] == 0x90)
				{
					/* This is not the last segment */
					if (buffer[4] + i < command_len)
						tpdu_lr = 0;
					else {
						memcpy(rsp, tpdu_rsp, tpdu_lr); // Map response TPDU onto APDU
						*lr = tpdu_lr;
					}
				}	
				else /* Card does not support envelope command or error */
				{
					memcpy(rsp, tpdu_rsp, tpdu_lr); // Map response TPDU onto APDU
					*lr = tpdu_lr;
					break;
				}
		}
	return OK;
}


static int32_t Protocol_T0_Case3E (struct s_reader * reader, unsigned char * command, unsigned char * rsp, uint16_t * lr)
{
	int32_t ret;
	unsigned char buffer[5];
	unsigned char tpdu_rsp[CTA_RES_LEN];
	uint16_t tpdu_lr = 0;
	int32_t Lm, Lx;

	uint32_t Le = ((((uint32_t)(command[5]) << 8) | command[6]) == 0 ? 65536 : (((uint32_t)(command[5]) << 8) | command[6]));
	memcpy(buffer, command, 4);//Map APDU command onto TPDU

	if (Le <= 256)
	{
		buffer[4] = (unsigned char)Le;
		return Protocol_T0_ExchangeTPDU(reader, buffer, 5, rsp, lr); //this was Case3S !!!
	}

	/* Map APDU onto command TPDU */
	buffer[4] = 0x00;
	call (Protocol_T0_ExchangeTPDU(reader, buffer, 5 , tpdu_rsp, &tpdu_lr));

	if (tpdu_rsp[tpdu_lr - 2] == 0x6C) {/* Le not accepted, La indicated */
		/* Map command APDU onto TPDU */
		memcpy (buffer, command, 4);
		buffer[4] = tpdu_rsp[tpdu_lr - 1];

		/* Delete response TPDU */
		tpdu_lr = 0;
		
		return Protocol_T0_ExchangeTPDU(reader, buffer, 5, rsp, lr); //Reissue command
	}
	
	memcpy(rsp, tpdu_rsp, tpdu_lr);//Map response TPDU onto APDU without change , also for SW1 = 0x67
	*lr = tpdu_lr;
	ret = OK;
	if (tpdu_rsp[tpdu_lr - 2] == 0x61) {/* Command processed, Lx indicated */
		Lx = (tpdu_rsp[tpdu_lr - 1] == 0x00) ? 256 : tpdu_rsp[tpdu_lr - 1];
		Lm = Le - (*lr - 2);
		
		/* Prepare Get Response TPDU */
		buffer[0] = command[0];
		buffer[1] = 0xC0;
		buffer[2] = 0x00;
		buffer[3] = 0x00;
		
		while (Lm > 0)
		{
			buffer[4] = (unsigned char) MIN (Lm, Lx);
			call (Protocol_T0_ExchangeTPDU(reader, buffer, 5, tpdu_rsp, &tpdu_lr));

			/* Append response TPDU to APDU  */
			if ((*lr + tpdu_lr) > CTA_RES_LEN) {
				rdr_log(reader, "TPDU Append error, new length %i exceeds max length %i", *lr + tpdu_lr, CTA_RES_LEN);
				return ERROR;
			}
			memcpy (rsp + (*lr - 2), tpdu_rsp, tpdu_lr);
			*lr += tpdu_lr;
			
			/* Delete response TPDU */
			tpdu_lr = 0;
			
			Lm = Le - (*lr - 2);
		}/* Lm == 0 */
	} 
	return ret;
}


static int32_t Protocol_T0_Case4E (struct s_reader * reader, unsigned char * command, uint16_t command_len, unsigned char * rsp, uint16_t * lr)
{
	int32_t ret;
	unsigned char buffer[PROTOCOL_T0_MAX_SHORT_COMMAND];
	unsigned char tpdu_rsp[CTA_RES_LEN];
	memset(tpdu_rsp, 0, sizeof(tpdu_rsp));
	uint16_t tpdu_lr = 0;
	int32_t Le;
	
	uint32_t Lc = (((uint32_t)(command[5]) << 8) | command[6]);
	/* 4E1 */
	if (Lc < 256) {
		/* Map APDU onto command TPDU */
		memcpy(buffer,command,4);
		buffer[4] = (unsigned char) Lc;
		memcpy (buffer + 5, command, buffer[4]);
		ret = Protocol_T0_ExchangeTPDU(reader, buffer, buffer[4] + 5, tpdu_rsp, &tpdu_lr);
	}
	else /* 4E2 */
		ret = Protocol_T0_Case2E (reader, command, command_len, tpdu_rsp, &tpdu_lr);
	
	/* 4E1 a) b) and c) */
	if (ret == OK)
	{
		Le = ((((uint32_t)(command[command_len - 2]) << 8) | command[command_len - 1]) == 0 ? 65536 : (((uint32_t)(command[command_len - 2]) << 8) | command[command_len - 1]));
		if (tpdu_lr > 1 && tpdu_rsp[tpdu_lr - 2] == 0x61)
		{
			/* Lm == (Le - APDU_Rsp_RawLen (tpdu_rsp)) == 0 */
			if (tpdu_rsp[tpdu_lr - 1] != 0x00)
				Le = MIN(tpdu_rsp[tpdu_lr - 1], Le);
			
			/* Delete response TPDU */
			tpdu_lr = 0;
			
			/* Prepare extended Get Response APDU command */
			buffer[0] = command[0];
			buffer[1] = 0xC0;
			buffer[2] = 0x00;
			buffer[3] = 0x00;
			buffer[4] = 0x00;     /* B1 = 0x00 */
			buffer[5] = (unsigned char) (Le >> 8);  /* B2 = BL-1 */
			buffer[6] = (unsigned char) (Le & 0x00FF);      /* B3 = BL */
			ret = Protocol_T0_Case3E (reader, buffer, rsp, lr);
		}
		else if (tpdu_lr > 1 && (tpdu_rsp[tpdu_lr - 2] & 0xF0) == 0x60)
		{
			/* Map response TPDU onto APDU without change */
			memcpy(rsp, tpdu_rsp, tpdu_lr);
			*lr = tpdu_lr;
		}
		else
		{
			/* Delete response TPDU */
			tpdu_lr = 0;
			
			/* Prepare extended Get Response APDU command */
			buffer[0] = command[0];
			buffer[1] = 0xC0;
			buffer[2] = 0x00;
			buffer[3] = 0x00;
			buffer[4] = 0x00;     /* B1 = 0x00 */
			buffer[5] = (unsigned char) Le >> 8;  /* B2 = BL-1 */
			buffer[6] = (unsigned char) Le & 0x00FF;      /* B3 = BL */
			ret = Protocol_T0_Case3E (reader, buffer, rsp, lr);
		}
	}
	return ret;
}


static int32_t Protocol_T0_ExchangeTPDU (struct s_reader *reader, unsigned char * command, uint16_t command_len, unsigned char * rsp, uint16_t * lr)
{
	unsigned char buffer[PROTOCOL_T0_MAX_SHORT_RESPONSE];
	unsigned char *data;
	int32_t Lc, Le, sent, recved, expectedlen;
	int32_t nulls, cmd_case;
	int32_t timeout;
	*lr = 0; //in case of error this will be returned
	
	cmd_case = APDU_Cmd_Case (command, command_len);
	switch (cmd_case) {
		case APDU_CASE_2S:
			Lc = command[4];
			Le = 0;
			expectedlen = 1;
			data = command + 5;	
			break;
		case APDU_CASE_3S:
			Lc = 0;
			Le = command[4];
			if (!Le)
				expectedlen = 2;
			else
				expectedlen = 1+Le+2;
			data = NULL;	
			break;
		default:
			rdr_debug_mask(reader, D_TRACE, "ERROR: invalid cmd_case = %i in Protocol_T0_ExchangeTPDU",cmd_case);
			return ERROR;
	}
	timeout = ICC_Async_GetTimings (reader, reader->char_delay); // we are going to send: char delay timeout
	if (ICC_Async_Transmit (reader, 5, expectedlen, command, 0, timeout)!=OK) return ERROR;		//Send header bytes
	
	/* Initialise counters */
	nulls = 0;
	sent = 0;
	recved = 0;
	
	/* 
	* Let's be a bit paranoid with buffer sizes within this loop
	* so it doesn't overflow reception and transmission buffers
	* if card does not strictly respect the protocol
	*/
	
	while (recved < PROTOCOL_T0_MAX_SHORT_RESPONSE)
	{
		timeout = ICC_Async_GetTimings (reader, reader->read_timeout); // we are going to receive: WWT timeout
		if (ICC_Async_Receive (reader, 1, buffer + recved, 0, timeout) != OK) return ERROR;//Read one procedure byte
		
		/* NULL byte received */
		if (buffer[recved] == 0x60) {
			nulls++;
			if (nulls >= PROTOCOL_T0_MAX_NULLS) {								//Maximum number of nulls reached 
				rdr_debug_mask(reader, D_TRACE, "ERROR: %s: Maximum number of nulls reached: %d", __func__, nulls);
				return ERROR;
			}
		}
		else if ((buffer[recved] & 0xF0) == 0x60 || (buffer[recved] & 0xF0) == 0x90) /* SW1 byte received */
		{
			rdr_debug_mask(reader, D_TRACE, "SW1: %02X", buffer[recved]&0xf0);
			recved++;
			if (recved >= PROTOCOL_T0_MAX_SHORT_RESPONSE) {
				rdr_debug_mask(reader, D_TRACE, "ERROR: %s: Maximum short response exceeded: %d", __func__, recved);
				return ERROR;
			}
			timeout = ICC_Async_GetTimings (reader, reader->read_timeout); // we are going to receive: WWT timeout
			if (ICC_Async_Receive (reader, 1, buffer + recved, 0, timeout) !=OK) return ERROR; //Read SW2 byte
			rdr_debug_mask(reader, D_TRACE, "SW2: %02X", buffer[recved]&0xf0);
			recved++;
			break;
		}
		else if ((buffer[recved] & 0x0E) == (command[1] & 0x0E)) /* ACK byte received */
		{//printf("ack\n");
			/* Reset null's counter */
			nulls = 0;
			
			/* Case 2 command: send data */
			if (cmd_case == APDU_CASE_2S) {
				if (sent >= Lc) {
					rdr_debug_mask(reader, D_TRACE, "ERROR: %s: ACK byte: sent=%d exceeds Lc=%d", __func__, sent, Lc);
					return ERROR;
				}
				timeout = ICC_Async_GetTimings (reader, reader->char_delay); // we are going to send: char delay timeout
				if(ICC_Async_Transmit(reader, MAX (Lc - sent, 0), 2, data + sent, 0, timeout)!=OK) return ERROR; /* Send remaining data bytes */
				sent = Lc;
				continue;
			}
			else /* Case 3 command: receive data */
			{
				if (recved >= PROTOCOL_T0_MAX_SHORT_RESPONSE) {
					rdr_debug_mask(reader, D_TRACE, "ERROR: %s: Case 3 ACK - maximum short response exceeded: %d", __func__, recved);
					return ERROR;
				}
				
				/* 
				* Le <= PROTOCOL_T0_MAX_SHORT_RESPONSE - 2 for short commands 
				*/
				
				/* Read remaining data bytes */
				timeout = ICC_Async_GetTimings (reader, reader->read_timeout); // we are going to receive: WWT timeout
				if (ICC_Async_Receive(reader, MAX (Le - recved, 0), buffer + recved, 0, timeout) != OK) return ERROR;
				recved = Le;
				continue;
			}
		}
		else if ((buffer[recved] & 0x0E) == ((~command[1]) & 0x0E)) /* ~ACK byte received */
		{//printf("~ack\n");
			nulls = 0;																								//Reset null's counter
			
			/* Case 2 command: send data */
			if (cmd_case == APDU_CASE_2S) {
				if (sent >= Lc) {
					rdr_debug_mask(reader, D_TRACE, "ERROR: %s: ~ACK byte: sent=%d exceeds Lc=%d", __func__, sent, Lc);
					return ERROR;
				}
				timeout = ICC_Async_GetTimings (reader, reader->char_delay); // we are going to send: char delay timeout
				if(ICC_Async_Transmit (reader, 1, 1, data + sent, 0, timeout)!=OK) return ERROR;	//Send next data byte
				sent++;
				continue;
			}
			else {/* Case 3 command: receive data */
				if (recved >= PROTOCOL_T0_MAX_SHORT_RESPONSE) {
					rdr_debug_mask(reader, D_TRACE, "ERROR: %s: Case 3 ~ACK - maximum short response exceeded: %d", __func__, recved);
					return ERROR;
				}
				timeout = ICC_Async_GetTimings (reader, reader->read_timeout); // we are going to receive: WWT timeout
				if(ICC_Async_Receive (reader, 1, buffer + recved, 0, timeout)!=OK) return ERROR;//Read next data byte
				recved++;
				continue;
			}
		}
		else { /* Anything else received */
			rdr_debug_mask(reader, D_TRACE, "ERROR: %s: Received unexpected character: %02X", __func__, buffer[recved]);
			return ERROR;
		}
	}//while
		
	memcpy(rsp, buffer, recved);
	*lr = recved;
	return OK;
}

int32_t Protocol_T14_ExchangeTPDU (struct s_reader *reader, unsigned char * cmd_raw, uint16_t command_len, unsigned char * rsp, uint16_t * lr)
{
	unsigned char buffer[PROTOCOL_T14_MAX_SHORT_RESPONSE];
	int32_t recved;
	int32_t cmd_case;
	int32_t timeout;
	unsigned char ixor = 0x3E;
	unsigned char ixor1 = 0x3F;
	int32_t i;
	int32_t cmd_len = (int32_t) command_len;
	*lr = 0; //in case of error this is returned
	
	/* Parse APDU */
	cmd_case = APDU_Cmd_Case (cmd_raw, cmd_len);
	for(i=0; i<cmd_len; i++)
		ixor^=cmd_raw[i];
	
	/* Check case of command */
	if ((cmd_case != APDU_CASE_2S) && (cmd_case != APDU_CASE_3S)) {
		rdr_debug_mask(reader, D_TRACE, "ERROR: invalid cmd_case = %i in Protocol_T14_ExchangeTPDU", cmd_case);
		return ERROR;
	}
	
	buffer[0] = 0x01; //send 0x01 byte
	memcpy(buffer+1, cmd_raw, cmd_len); // apdu
	buffer[cmd_len+1] = ixor; // xor byte
		
	/* Send apdu */
	timeout = ICC_Async_GetTimings (reader, reader->char_delay); // we are going to send: char delay timeout
	if(ICC_Async_Transmit (reader, cmd_len+2, 0, buffer, 0, timeout)!=OK) return ERROR;//send apdu
	if(cmd_raw[0] == 0x02 && cmd_raw[1] == 0x09) cs_sleepms(2500); //FIXME why wait? -> needed for init on overclocked T14 cards
	
	timeout = ICC_Async_GetTimings (reader, reader->read_timeout); // we are going to receive: WWT timeout
	if(ICC_Async_Receive (reader, 8, buffer, 0, timeout)!=OK) return ERROR;	//Read one procedure byte
	recved = (int32_t)buffer[7];
	if(recved){
		timeout = ICC_Async_GetTimings (reader, reader->read_timeout); // we are going to receive: WWT timeout
		if (ICC_Async_Receive (reader, recved, buffer + 8, 0 , timeout)!=OK) return ERROR;
	}
	timeout = ICC_Async_GetTimings (reader, reader->read_timeout); // we are going to receive: WWT timeout
	if(ICC_Async_Receive (reader, 1, &ixor, 0, timeout)!=OK) return ERROR;
	for(i=0; i<8+recved; i++)		
		ixor1^=buffer[i];
	if(ixor1 != ixor) {
		rdr_debug_mask(reader, D_TRACE, "ERROR: invalid checksum = %02X expected %02X", ixor1, ixor);
		return ERROR;
	}
	memcpy(buffer + 8 + recved, buffer + 2, 2);
	*lr = recved + 2;
	memcpy(rsp, buffer + 8, *lr); 
	return OK;
}
#endif
