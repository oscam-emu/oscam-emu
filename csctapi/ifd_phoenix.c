/*
        ifd_phoenix.c
        This module provides IFD handling functions for Smartmouse/Phoenix reader.
*/

#include "../globals.h"

#ifdef CARDREADER_PHOENIX
#include "../oscam-time.h"
#include "icc_async.h"
#include "ifd_db2com.h"
#include "ifd_phoenix.h"
#include "io_serial.h"

#define OK 0
#define ERROR 1

#define GPIO_PIN (1 << (reader->detect - 4))

static inline int reader_use_gpio(struct s_reader *reader)
{
    return reader->use_gpio && reader->detect > 4;
}

static void set_gpio(struct s_reader *reader, int32_t level)
{
    int ret = 0;

    ret |= read(reader->gpio_outen, &reader->gpio, sizeof(reader->gpio));
    reader->gpio |= GPIO_PIN;
    ret |= write(reader->gpio_outen, &reader->gpio, sizeof(reader->gpio));

    ret |= read(reader->gpio_out, &reader->gpio, sizeof(reader->gpio));
    if (level > 0)
        reader->gpio |= GPIO_PIN;
    else
        reader->gpio &= ~GPIO_PIN;
    ret |= write(reader->gpio_out, &reader->gpio, sizeof(reader->gpio));

    rdr_debug_mask(reader, D_IFD, "%s level: %d ret: %d", __func__, level, ret);
}

static void set_gpio_input(struct s_reader *reader)
{
    int ret = 0;
    ret |= read(reader->gpio_outen, &reader->gpio, sizeof(reader->gpio));
    reader->gpio &= ~GPIO_PIN;
    ret |= write(reader->gpio_outen, &reader->gpio, sizeof(reader->gpio));
    rdr_debug_mask(reader, D_IFD, "%s ret:%d", __func__, ret);
}

static int32_t get_gpio(struct s_reader *reader)
{
    int ret = 0;
    set_gpio_input(reader);
    ret = read(reader->gpio_in, &reader->gpio, sizeof(reader->gpio));
    rdr_debug_mask(reader, D_IFD, "%s ok:%d ret:%d", __func__, reader->gpio & GPIO_PIN, ret);
    if (reader->gpio & GPIO_PIN)
        return OK;
    else
        return ERROR;
}

int32_t Phoenix_Init (struct s_reader *reader)
{
    // First set card in reset state, to not change any parameters while communication ongoing
    IO_Serial_RTS_Set(reader);
    if (reader->crdr.flush) IO_Serial_Flush(reader);

    // define reader->gpio number used for card detect and reset. ref to globals.h
    if (reader_use_gpio(reader))
    {
        reader->gpio_outen = open("/dev/gpio/outen", O_RDWR);
        reader->gpio_out   = open("/dev/gpio/out",   O_RDWR);
        reader->gpio_in    = open("/dev/gpio/in",    O_RDWR);
        rdr_debug_mask(reader, D_IFD, "init gpio_outen:%d gpio_out:%d gpio_in:%d",
                       reader->gpio_outen, reader->gpio_out, reader->gpio_in);
        set_gpio_input(reader);
    }

    rdr_debug_mask(reader, D_IFD, "Initializing reader type=%d", reader->typ);

    /* Default serial port settings */
    if (reader->atr[0] == 0)
    {
        if (IO_Serial_SetParams (reader, DEFAULT_BAUDRATE, 8, PARITY_EVEN, 2, NULL, NULL)) return ERROR;
        if (reader->crdr.flush) IO_Serial_Flush(reader);
    }
    return OK;
}

int32_t Phoenix_GetStatus (struct s_reader *reader, int32_t *status)
{
    // detect card via defined reader->gpio
    if (reader_use_gpio(reader))
    {
        *status = !get_gpio(reader);
        return OK;
    }
    else
    {
        return IO_Serial_GetStatus(reader, status);
    }
}

int32_t Phoenix_Reset (struct s_reader *reader, ATR *atr)
{
    rdr_debug_mask(reader, D_IFD, "Resetting card");
    int32_t ret;
    int32_t i;
    unsigned char buf[ATR_MAX_SIZE];
    int32_t parity[3] = {PARITY_EVEN, PARITY_ODD, PARITY_NONE};

    call (IO_Serial_SetBaudrate(reader, DEFAULT_BAUDRATE));

    for (i = 0; i < 3; i++)
    {
        if (reader->crdr.flush) IO_Serial_Flush(reader);
        if (reader->crdr.set_parity) IO_Serial_SetParity (reader, parity[i]);

        ret = ERROR;

        IO_Serial_Ioctl_Lock(reader, 1);
        if (reader_use_gpio(reader))
            set_gpio(reader, 0);
        else
            IO_Serial_RTS_Set(reader);

        cs_sleepms(50);

        // felix: set card reset hi (inactive)
        if (reader_use_gpio(reader))
            set_gpio_input(reader);
        else
            IO_Serial_RTS_Clr(reader);
        cs_sleepms(50);
        IO_Serial_Ioctl_Lock(reader, 0);

        int32_t n = 0;
        while (n < ATR_MAX_SIZE && !IO_Serial_Read(reader, 0, ATR_TIMEOUT, 1, buf + n))
            n++;
        if (n == 0)
            continue;
        if (ATR_InitFromArray (atr, buf, n) != ERROR)
            ret = OK;
        // Succesfully retrieve ATR
        if (ret == OK)
            break;
    }

    return ret;
}

int32_t Phoenix_Close (struct s_reader *reader)
{
    rdr_debug_mask(reader, D_IFD, "Closing phoenix device %s", reader->device);
    if (reader_use_gpio(reader))
    {
        if (reader->gpio_outen > -1)
            close(reader->gpio_outen);
        if (reader->gpio_out > -1)
            close(reader->gpio_out);
        if (reader->gpio_in > -1)
            close(reader->gpio_in);
    }
    IO_Serial_Close(reader);
    return OK;
}

/*
int32_t Phoenix_FastReset (struct s_reader * reader, int32_t delay)
{
    IO_Serial_Ioctl_Lock(reader, 1);
    if (reader_use_gpio(reader))
        set_gpio(reader, 0);
    else
        IO_Serial_RTS_Set(reader);

    cs_sleepms(delay);

    // set card reset hi (inactive)
    if (reader_use_gpio(reader))
        set_gpio_input(reader);
    else
        IO_Serial_RTS_Clr(reader);

    IO_Serial_Ioctl_Lock(reader, 0);

    cs_sleepms(50);

    IO_Serial_Flush(reader);
    return 0;

}
*/
static int32_t mouse_init(struct s_reader *reader)
{
    if (detect_db2com_reader(reader))
    {
        cardreader_db2com(&reader->crdr);
        return reader->crdr.reader_init(reader);
    }

    reader->handle = open (reader->device,  O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (reader->handle < 0)
    {
        rdr_log(reader, "ERROR: Opening device %s (errno=%d %s)",
                reader->device, errno, strerror(errno));
        return ERROR;
    }
    if (Phoenix_Init(reader))
    {
        rdr_log(reader, "ERROR: Phoenix_Init returns error");
        Phoenix_Close (reader);
        return ERROR;
    }
    return OK;
}

void cardreader_mouse(struct s_cardreader *crdr)
{
    crdr->desc          = "mouse";
    crdr->typ           = R_MOUSE;
    crdr->flush         = 1;
    crdr->read_written  = 1;
    crdr->need_inverse  = 1;
    crdr->reader_init   = mouse_init;
    crdr->get_status    = Phoenix_GetStatus;
    crdr->activate      = Phoenix_Reset;
    crdr->transmit      = IO_Serial_Transmit;
    crdr->receive       = IO_Serial_Receive;
    crdr->close         = Phoenix_Close;
    crdr->set_parity    = IO_Serial_SetParity;
    crdr->set_baudrate  = IO_Serial_SetBaudrate;
}
#endif
