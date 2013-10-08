#ifndef _sci_global_h_
#define _sci_global_h_

#define SCI_CLASS_A                 1   /* only 5V Vcc to Smart Card */
#define SCI_CLASS_B                 2   /* only 3V Vcc to Smart Card */
#define SCI_CLASS_AB                3   /* 5V or 3V Vcc to Smart Card */
#define SCI_NUMBER_OF_CONTROLLERS   2   /* number of SCI controllers */

#define SCI_BUFFER_SIZE             512

#define SCI_CLOCK_STOP_DISABLED     0
#define SCI_CLOCK_STOP_LOW          1
#define SCI_CLOCK_STOP_HIGH         2

#define SCI_MAX_ATR_SIZE            33

#define SCI_MAX_F                   80000000
#define SCI_MAX_ETU                 0xFFF
#define SCI_MAX_WWT                 0xFFFFFFFF
#define SCI_MAX_CWT                 0xFFFF
#define SCI_MAX_BWT                 0xFFFFFFFF
#define SCI_MAX_EGT                 0xFF

#define SCI_MIN_F                   1000000
#define SCI_MIN_ETU                 8
#define SCI_MIN_WWT                 12
#define SCI_MIN_CWT                 12
#define SCI_MIN_BWT                 971
#define SCI_MIN_EGT                 0

#define SCI_SYNC                    0x00000001
#define SCI_DATA_ANY                0x00000002

/* Reserved for Future Use defined as 0 */
#define RFU                         0

/* error codes */
typedef enum
{
	SCI_ERROR_OK = 0,
	SCI_ERROR_DRIVER_NOT_INITIALIZED = -1691,
	SCI_ERROR_FAIL,
	SCI_ERROR_KERNEL_FAIL,
	SCI_ERROR_NO_ATR,
	SCI_ERROR_TS_CHARACTER_INVALID,
	SCI_ERROR_LRC_FAIL,
	SCI_ERROR_CRC_FAIL,
	SCI_ERROR_LENGTH_FAIL,
	SCI_ERROR_PARITY_FAIL,
	SCI_ERROR_RX_OVERFLOW_FAIL,
	SCI_ERROR_TX_OVERFLOW_FAIL,
	SCI_ERROR_TX_UNDERRUN_FAIL,
	SCI_ERROR_CARD_NOT_PRESENT,
	SCI_ERROR_CARD_NOT_ACTIVATED,
	SCI_ERROR_AWT_TIMEOUT,
	SCI_ERROR_WWT_TIMEOUT,
	SCI_ERROR_CWT_TIMEOUT,
	SCI_ERROR_BWT_TIMEOUT,
	SCI_ERROR_PARAMETER_OUT_OF_RANGE,
	SCI_ERROR_TRANSACTION_ABORTED,
	SCI_ERROR_CLOCK_STOP_DISABLED,
	SCI_ERROR_TX_PENDING,
	SCI_ERROR_ATR_PENDING
}
SCI_ERROR;

/* SCI driver modes */
typedef struct sci_modes
{
	int32_t emv2000;
	int32_t dma;
	int32_t man_act;
	int32_t rw_mode;
}
SCI_MODES;

/* SCI communication parameters */
typedef struct sci_parameters
{
	unsigned char T;
	uint32_t fs;
	uint32_t ETU;
	uint32_t WWT;
	uint32_t CWT;
	uint32_t BWT;
	uint32_t EGT;
	uint32_t clock_stop_polarity;
	unsigned char check;
	unsigned char P;
	unsigned char I;
	unsigned char U;
}
SCI_PARAMETERS;

/* SCI ATR status */
typedef enum
{
	SCI_WITHOUT_ATR = 0,
	SCI_ATR_READY
}
SCI_ATR_STATUS;

#endif /* _sci_global_h_ */
