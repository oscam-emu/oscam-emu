/*
 * Header file for Smartmouse/Phoenix reader.
 */
#ifndef _CSCTAPI_IFD_PHOENIX_H_
#define _CSCTAPI_IFD_PHOENIX_H_

int32_t Phoenix_Init (struct s_reader * reader);
int32_t Phoenix_GetStatus (struct s_reader * reader, int32_t * status);
int32_t Phoenix_Reset (struct s_reader * reader, ATR * atr);
int32_t Phoenix_Close (struct s_reader * reader);
int32_t Phoenix_FastReset (struct s_reader * reader, int32_t delay);

#endif
