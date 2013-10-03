#ifndef MODULE_LED_H_
#define MODULE_LED_H_

#define  LED1A           0
#define  LED1B           1
#define  LED2            2
#define  LED3            3
#define  LED_OFF         0
#define  LED_ON          1
#define  LED_BLINK_ON    2
#define  LED_BLINK_OFF   3
#define  LED_DEFAULT     10
#define  LED_STOP_THREAD 100
#define  ARM_LED_TIMEOUT 3 //Dont blink for actions which are < ARM_LED_TIMEOUT seconds ago

// QBOX led structures
typedef struct
{
    uint16_t H;                                     // range 0-359
    unsigned char S;                                // range 0-99
    unsigned char V;                                // range 0-99
} qboxhd_led_color_struct;

typedef struct
{
    unsigned char red;                              // first 5 bit used (&0x1F)
    unsigned char green;                            // first 5 bit used (&0x1F)
    unsigned char blue;                             // first 5 bit used (&0x1F)
} qboxhdmini_led_color_struct;

#define QBOXHD_LED_DEVICE              "/dev/sw0"
#define QBOXHD_SET_LED_ALL_PANEL_COLOR _IO(0xBC, 13)    // payload = 3byte [H][S][V]
#define QBOXHD_LED_COLOR_RED        359  // only H value, S and V values are always == 99
#define QBOXHD_LED_COLOR_GREEN      120
#define QBOXHD_LED_COLOR_BLUE       230
#define QBOXHD_LED_COLOR_YELLOW     55
#define QBOXHD_LED_COLOR_MAGENTA    290

#define QBOXHDMINI_LED_DEVICE       "/dev/lpc_0"
#define QBOXHDMINI_IOSET_RGB        _IOWR('L', 6, qboxhdmini_led_color_struct)
#define QBOXHDMINI_LED_COLOR_RED     0x1F0000               // 3 bytes RGB , 5 bit used for each color
#define QBOXHDMINI_LED_COLOR_GREEN   0x001F00
#define QBOXHDMINI_LED_COLOR_BLUE    0x00001F
#define QBOXHDMINI_LED_COLOR_YELLOW  0x1F1F00
#define QBOXHDMINI_LED_COLOR_MAGENTA 0x1F001F

#define QBOXHD_LED_COLOR_OFF        -1   // all colors H,S,V and/or R,G,B == 0,0,0

#define QBOXHD_LED_BLINK_FAST       100  // blink milliseconds
#define QBOXHD_LED_BLINK_MEDIUM     200
#define QBOXHD_LED_BLINK_SLOW       400

#ifdef LEDSUPPORT
extern void led_init(void);
extern void led_stop(void);
extern void led_status_stopping(void);
extern void led_status_cw_not_found(ECM_REQUEST *er);
extern void led_status_default(void);
extern void led_status_starting(void);
extern void led_status_card_activation_error(void);
extern void led_status_found_cardsystem(void);
extern void led_status_unsupported_card_system(void);
extern void led_status_emm_ok(void);
extern void led_status_card_detected(void);
extern void led_status_card_ejected(void);
#else
static inline void led_init(void) { }
static inline void led_stop(void) { }
static inline void led_status_stopping(void) { }
static inline void led_status_cw_not_found(ECM_REQUEST *UNUSED(er)) { }
static inline void led_status_default(void) { }
static inline void led_status_starting(void) { }
static inline void led_status_card_activation_error(void) { }
static inline void led_status_found_cardsystem(void) { }
static inline void led_status_unsupported_card_system(void) { }
static inline void led_status_emm_ok(void) { }
static inline void led_status_card_detected(void) { }
static inline void led_status_card_ejected(void) { }
#endif

#endif
