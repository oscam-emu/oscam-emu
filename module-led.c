#include "globals.h"

#ifdef LEDSUPPORT

#include "module-led.h"
#include "oscam-string.h"
#include "oscam-time.h"

#if defined(__arm__)
struct s_arm_led
{
    int32_t led;
    int32_t action;
    time_t start_time;
};

static pthread_t arm_led_thread;
static LLIST *arm_led_actions;

#define ARM_LED_TYPES 3
#define ARM_LED_FILES 4

struct arm_leds
{
    char *machine;
    struct led_file
    {
        uint8_t id;
        char    *file;
    } leds[ARM_LED_FILES];
};

static const struct arm_leds arm_leds[ARM_LED_TYPES] =
{
    {
        "nslu2", {
            { LED1A, "red:status" },
            { LED1B, "green:ready" },
            { LED2,  "green:disk-1" },
            { LED3,  "green:disk-2" }
        },
    },
    {
        "dockstar", {
            { LED1A, "orange:misc" },
            { LED1B, "green:health" },
            { LED2,  "green:health" },
            { LED3,  "orange:misc" }
        },
    },
    {
        "wrt350nv2", {
            { LED1A, "orange:power" },
            { LED1B, "green:power" },
            { LED2,  "green:wireless" },
            { LED3,  "green:security" }
        },
    }
};

static int32_t arm_init_led_file(uint8_t led_type, uint8_t led_no, char *buf, int32_t buflen)
{
    uint8_t i;
    if (led_type >= ARM_LED_TYPES) return 0;
    if (led_no >= ARM_LED_FILES) return 0;
    for (i = 0; i < ARM_LED_FILES; i++)
    {
        if (arm_leds[led_type].leds[i].id == led_no)
        {
            return snprintf(buf, buflen, "/sys/class/leds/%s:%s/brightness",
                            arm_leds[led_type].machine, arm_leds[led_type].leds[i].file);
        }
    }
    return 0;
}

#define LED_TYPE_UNKNOWN 0xff
static uint8_t arm_led_type = LED_TYPE_UNKNOWN;

static void arm_detect_led_type(void)
{
    uint8_t i;
    char led_file[256];
    for (i = 0; i < ARM_LED_TYPES; i++)
    {
        if (!arm_init_led_file(i, 0, led_file, sizeof(led_file)))
            break;
        if (access(led_file, W_OK) == 0)
        {
            arm_led_type = i;
            cs_log("LED support for %s is activated.", arm_leds[arm_led_type].machine);
            break;
        }
    }
    if (arm_led_type == LED_TYPE_UNKNOWN)
        cs_log("LED support is not active. Can't detect machine type.");
}

static void arm_switch_led_from_thread(int32_t led, int32_t action)
{
    if (action < 2)   // only LED_ON and LED_OFF
    {
        char led_file[256];
        if (!arm_init_led_file(arm_led_type, led, led_file, sizeof(led_file)))
            return;
        FILE *f = fopen(led_file, "w");
        if (!f)
            return;
        fprintf(f, "%d", action);
        fclose(f);
    }
    else     // LED Macros
    {
        switch (action)
        {
        case LED_DEFAULT:
            arm_switch_led_from_thread(LED1A, LED_OFF);
            arm_switch_led_from_thread(LED1B, LED_OFF);
            arm_switch_led_from_thread(LED2, LED_ON);
            arm_switch_led_from_thread(LED3, LED_OFF);
            break;
        case LED_BLINK_OFF:
            arm_switch_led_from_thread(led, LED_OFF);
            cs_sleepms(100);
            arm_switch_led_from_thread(led, LED_ON);
            break;
        case LED_BLINK_ON:
            arm_switch_led_from_thread(led, LED_ON);
            cs_sleepms(300);
            arm_switch_led_from_thread(led, LED_OFF);
            break;
        }
    }
}

static void *arm_led_thread_main(void *UNUSED(thread_data))
{
    uint8_t running = 1;
    set_thread_name(__func__);
    while (running)
    {
        LL_ITER iter = ll_iter_create(arm_led_actions);
        struct s_arm_led *arm_led;
        while ((arm_led = ll_iter_next(&iter)))
        {
            int32_t led, action;
            time_t now, start;
            led = arm_led->led;
            action = arm_led->action;
            now = time((time_t)0);
            start = arm_led->start_time;
            ll_iter_remove_data(&iter);
            if (action == LED_STOP_THREAD)
            {
                running = 0;
                break;
            }
            if (now - start < ARM_LED_TIMEOUT)
            {
                arm_switch_led_from_thread(led, action);
            }
        }
        if (running)
        {
            sleep(60);
        }
    }
    ll_clear_data(arm_led_actions);
    pthread_exit(NULL);
    return NULL;
}

static void arm_led_start_thread(void)
{
    arm_detect_led_type();
    if (!cfg.enableled || arm_led_type == LED_TYPE_UNKNOWN)
        return;
    // call this after signal handling is done
    if (!arm_led_actions)
    {
        arm_led_actions = ll_create("arm_led_actions");
    }
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    cs_log("starting thread arm_led_thread");
    pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
    int32_t ret = pthread_create(&arm_led_thread, &attr, arm_led_thread_main, NULL);
    if (ret)
    {
        cs_log("ERROR: can't create arm_led_thread thread (errno=%d %s)", ret, strerror(ret));
    }
    else
    {
        cs_log("arm_led_thread thread started");
        pthread_detach(arm_led_thread);
    }
    pthread_attr_destroy(&attr);
}

static void arm_led(int32_t led, int32_t action)
{
    struct s_arm_led *data;
    if (!cfg.enableled || arm_led_type == LED_TYPE_UNKNOWN)
        return;
    if (!arm_led_actions)
    {
        arm_led_actions = ll_create("arm_led_actions");
    }
    if (cs_malloc(&data, sizeof(struct s_arm_led)))
    {
        data->start_time = time((time_t)0);
        data->led = led;
        data->action = action;
        ll_append(arm_led_actions, (void *)data);
    }
    if (arm_led_thread)
    {
        // arm_led_thread_main is not started at oscam startup
        // when first arm_led calls happen
        pthread_kill(arm_led_thread, OSCAM_SIGNAL_WAKEUP);
    }
}

static void arm_led_stop_thread(void)
{
    if (!cfg.enableled || arm_led_type == LED_TYPE_UNKNOWN)
        return;
    arm_led(0, LED_STOP_THREAD);
}
#else
static inline void arm_led_start_thread(void) { }
static inline void arm_led_stop_thread(void) { }
static inline void arm_led(int32_t UNUSED(led), int32_t UNUSED(action)) { }
#endif


#ifdef QBOXHD
static void qboxhd_led_blink(int32_t color, int32_t duration)
{
    int32_t f;
    if (cfg.enableled != 2)
        return;
    // try QboxHD-MINI first
    if ((f = open(QBOXHDMINI_LED_DEVICE, O_RDWR | O_NONBLOCK)) > -1)
    {
        qboxhdmini_led_color_struct qbminiled;
        uint32_t qboxhdmini_color = 0x000000;
        if (color != QBOXHD_LED_COLOR_OFF)
        {
            switch (color)
            {
            case QBOXHD_LED_COLOR_RED:
                qboxhdmini_color = QBOXHDMINI_LED_COLOR_RED;
                break;
            case QBOXHD_LED_COLOR_GREEN:
                qboxhdmini_color = QBOXHDMINI_LED_COLOR_GREEN;
                break;
            case QBOXHD_LED_COLOR_BLUE:
                qboxhdmini_color = QBOXHDMINI_LED_COLOR_BLUE;
                break;
            case QBOXHD_LED_COLOR_YELLOW:
                qboxhdmini_color = QBOXHDMINI_LED_COLOR_YELLOW;
                break;
            case QBOXHD_LED_COLOR_MAGENTA:
                qboxhdmini_color = QBOXHDMINI_LED_COLOR_MAGENTA;
                break;
            }
            // set LED on with color
            qbminiled.red = (uchar)((qboxhdmini_color & 0xFF0000) >> 16); // R
            qbminiled.green = (uchar)((qboxhdmini_color & 0x00FF00) >> 8); // G
            qbminiled.blue = (uchar)(qboxhdmini_color & 0x0000FF);     // B
            ioctl(f, QBOXHDMINI_IOSET_RGB, &qbminiled);
            cs_sleepms(duration);
        }
        // set LED off
        qbminiled.red = 0;
        qbminiled.green = 0;
        qbminiled.blue = 0;
        ioctl(f, QBOXHDMINI_IOSET_RGB, &qbminiled);
        close(f);
    }
    else if ((f = open(QBOXHD_LED_DEVICE, O_RDWR | O_NONBLOCK)) > -1)
    {
        qboxhd_led_color_struct qbled;
        if (color != QBOXHD_LED_COLOR_OFF)
        {
            // set LED on with color
            qbled.H = color;
            qbled.S = 99;
            qbled.V = 99;
            ioctl(f, QBOXHD_SET_LED_ALL_PANEL_COLOR, &qbled);
            cs_sleepms(duration);
        }
        // set LED off
        qbled.H = 0;
        qbled.S = 0;
        qbled.V = 0;
        ioctl(f, QBOXHD_SET_LED_ALL_PANEL_COLOR, &qbled);
        close(f);
    }
}
#else
static inline void qboxhd_led_blink(int32_t UNUSED(color), int32_t UNUSED(duration)) { }
#endif

void led_status_stopping(void)
{
    if (cfg.enableled == 1)
    {
        arm_led(LED1B, LED_OFF);
        arm_led(LED2,  LED_OFF);
        arm_led(LED3,  LED_OFF);
        arm_led(LED1A, LED_ON);
    }
    if (cfg.enableled == 2)
    {
        qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,  QBOXHD_LED_BLINK_FAST);
        qboxhd_led_blink(QBOXHD_LED_COLOR_RED,     QBOXHD_LED_BLINK_FAST);
        qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,   QBOXHD_LED_BLINK_FAST);
        qboxhd_led_blink(QBOXHD_LED_COLOR_BLUE,    QBOXHD_LED_BLINK_FAST);
        qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA, QBOXHD_LED_BLINK_FAST);
    }
}

void led_status_cw_not_found(ECM_REQUEST *er)
{
    if (!er->rc)
        arm_led(LED2, LED_BLINK_OFF);
    if (er->rc < E_NOTFOUND)
    {
        qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN, QBOXHD_LED_BLINK_MEDIUM);
    }
    else if (er->rc <= E_STOPPED)
    {
        qboxhd_led_blink(QBOXHD_LED_COLOR_RED, QBOXHD_LED_BLINK_MEDIUM);
    }
}

void led_status_default(void)
{
    arm_led(LED1A, LED_DEFAULT);
    arm_led(LED1A, LED_ON);
}

void led_status_starting(void)
{
    arm_led(LED1A, LED_OFF);
    arm_led(LED1B, LED_ON);
    qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW,  QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_RED,     QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,   QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_BLUE,    QBOXHD_LED_BLINK_FAST);
    qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA, QBOXHD_LED_BLINK_FAST);
}

void led_status_card_activation_error(void)
{
    qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA, QBOXHD_LED_BLINK_MEDIUM);
}

void led_status_found_cardsystem(void)
{
    qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW, QBOXHD_LED_BLINK_MEDIUM);
    qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,  QBOXHD_LED_BLINK_MEDIUM);
    qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW, QBOXHD_LED_BLINK_MEDIUM);
    qboxhd_led_blink(QBOXHD_LED_COLOR_GREEN,  QBOXHD_LED_BLINK_MEDIUM);
}

void led_status_unsupported_card_system(void)
{
    qboxhd_led_blink(QBOXHD_LED_COLOR_MAGENTA, QBOXHD_LED_BLINK_MEDIUM);
}

void led_status_card_detected(void)
{
    qboxhd_led_blink(QBOXHD_LED_COLOR_YELLOW, QBOXHD_LED_BLINK_SLOW);
}

void led_status_card_ejected(void)
{
    qboxhd_led_blink(QBOXHD_LED_COLOR_RED, QBOXHD_LED_BLINK_SLOW);
}

void led_status_emm_ok(void)
{
    arm_led(LED3, LED_BLINK_ON);
    qboxhd_led_blink(QBOXHD_LED_COLOR_BLUE, QBOXHD_LED_BLINK_MEDIUM);
}

void led_init(void)
{
    arm_led_start_thread();
}

void led_stop(void)
{
    arm_led_stop_thread();
}

#endif
