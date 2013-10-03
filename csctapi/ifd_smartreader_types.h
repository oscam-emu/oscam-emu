// FTDI defines
#ifndef __SMARTREADER_TYPES_H__
#define __SMARTREADER_TYPES_H__
/* Definitions for flow control */
#define SIO_RESET          0 /* Reset the port */
#define SIO_MODEM_CTRL     1 /* Set the modem control register */
#define SIO_SET_FLOW_CTRL  2 /* Set flow control register */
#define SIO_SET_BAUD_RATE  3 /* Set baud rate */
#define SIO_SET_DATA       4 /* Set the data characteristics of the port */

#define FTDI_DEVICE_OUT_REQTYPE (LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT)
#define FTDI_DEVICE_IN_REQTYPE (LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_IN)
/* Requests */
#define SIO_RESET_REQUEST             SIO_RESET
#define SIO_SET_BAUDRATE_REQUEST      SIO_SET_BAUD_RATE
#define SIO_SET_DATA_REQUEST          SIO_SET_DATA
#define SIO_SET_FLOW_CTRL_REQUEST     SIO_SET_FLOW_CTRL
#define SIO_SET_MODEM_CTRL_REQUEST    SIO_MODEM_CTRL
#define SIO_POLL_MODEM_STATUS_REQUEST 0x05
#define SIO_SET_EVENT_CHAR_REQUEST    0x06
#define SIO_SET_ERROR_CHAR_REQUEST    0x07
#define SIO_SET_LATENCY_TIMER_REQUEST 0x09
#define SIO_GET_LATENCY_TIMER_REQUEST 0x0A
#define SIO_SET_BITMODE_REQUEST       0x0B
#define SIO_READ_PINS_REQUEST         0x0C
#define SIO_READ_EEPROM_REQUEST       0x90
#define SIO_WRITE_EEPROM_REQUEST      0x91
#define SIO_ERASE_EEPROM_REQUEST      0x92

#define SIO_RESET_SIO 0
#define SIO_RESET_PURGE_RX 1
#define SIO_RESET_PURGE_TX 2

#define SIO_DISABLE_FLOW_CTRL 0x0
#define SIO_RTS_CTS_HS (0x1 << 8)
#define SIO_DTR_DSR_HS (0x2 << 8)
#define SIO_XON_XOFF_HS (0x4 << 8)

#define SIO_SET_DTR_MASK 0x1
#define SIO_SET_DTR_HIGH ( 1 | ( SIO_SET_DTR_MASK  << 8))
#define SIO_SET_DTR_LOW  ( 0 | ( SIO_SET_DTR_MASK  << 8))
#define SIO_SET_RTS_MASK 0x2
#define SIO_SET_RTS_HIGH ( 2 | ( SIO_SET_RTS_MASK << 8 ))
#define SIO_SET_RTS_LOW ( 0 | ( SIO_SET_RTS_MASK << 8 ))

#define SIO_RTS_CTS_HS (0x1 << 8)
/** FTDI chip type */
enum smartreader_chip_type { TYPE_AM = 0, TYPE_BM = 1, TYPE_2232C = 2, TYPE_R = 3, TYPE_2232H = 4, TYPE_4232H = 5 };
/** Parity mode for smartreader_set_line_property() */
enum smartreader_parity_type { NONE = 0, ODD = 1, EVEN = 2, MARK = 3, SPACE = 4 };
/** Number of stop bits for smartreader_set_line_property() */
enum smartreader_stopbits_type { STOP_BIT_1 = 0, STOP_BIT_15 = 1, STOP_BIT_2 = 2 };
/** Number of bits for smartreader_set_line_property() */
enum smartreader_bits_type { BITS_7 = 7, BITS_8 = 8 };
/** Break type for smartreader_set_line_property2() */
enum smartreader_break_type { BREAK_OFF = 0, BREAK_ON = 1 };

/** Port interface for chips with multiple interfaces */
enum smartreader_interface
{
    INTERFACE_ANY = 0,
    INTERFACE_A   = 1,
    INTERFACE_B   = 2,
    INTERFACE_C   = 3,
    INTERFACE_D   = 4
};

struct s_reader_types
{
    char *name;
    uint8_t in_ep;
    uint8_t out_ep;
    int32_t index;
    int32_t interface;
};

const struct s_reader_types reader_types[] =
{
    {"SR", 0x01, 0x82, INTERFACE_A, 0},
    {"SRv2", 0x02, 0x81, INTERFACE_A, 0},
    {"Infinity", 0x01, 0x81, INTERFACE_A, 0},
    {"TripleP1", 0x02, 0x81, INTERFACE_A, 0},
    {"TripleP2", 0x04, 0x83, INTERFACE_B, 1},
    {"TripleP3", 0x06, 0x85, INTERFACE_C, 2}
};

#endif // __SMARTREADER_TYPES_H__
// end of FTDI defines
