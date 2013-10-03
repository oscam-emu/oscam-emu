/*
        ifd_stinger.c
        This module provides IFD handling functions for Stinger USB.
Usage:

Stinger Dedicated parameters.
cardmhz = real card clock (see smartcard docs)
mhz = stinger card clock (343, 400, 480, 600, 800, 1200)
detect = Inverted CTS

Ex.
[reader]
label    = stinger_UP
protocol = stinger
detect   = !cts
device   = /dev/ttyUSB4
group    = 2
cardmhz = 357
mhz = 600
emmcache = 1,3,2
services = services2
...

*/

#include "../globals.h"

#ifdef CARDREADER_STINGER

#include "../oscam-time.h"
#include "icc_async.h"
#include "ifd_db2com.h"
#include "ifd_phoenix.h"
#include "io_serial.h"

#define OK 0
#define ERROR 1
#define STINGER_DELAY 150

#define GPIO_PIN (1 << (reader->detect - 4))

static int32_t Stinger_Set_Clock (struct s_reader *reader, unsigned int c);

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

static bool Stinger_IO_Serial_WaitToWrite (struct s_reader *reader, uint32_t delay_us, uint32_t timeout_us)
{
    struct pollfd ufds;
    struct timeb start, end;
    int32_t ret_val;
    int32_t out_fd;
    int32_t polltimeout = timeout_us / 1000;

#if !defined(WITH_COOLAPI) && !defined(WITH_AZBOX)

    if (reader->typ == R_INTERNAL) return OK; // needed for internal readers, otherwise error!
#endif
    if (delay_us > 0)
        cs_sleepus (delay_us); // wait in us
    out_fd = reader->handle;

    ufds.fd = out_fd;
    ufds.events = POLLOUT;
    ufds.revents = 0x0000;
    cs_ftime(&start); // register start time
    while (1)
    {
        ret_val = poll(&ufds, 1, polltimeout);
        cs_ftime(&end); // register end time
        switch (ret_val)
        {
        case 0:
            rdr_log(reader, "ERROR: not ready to write, timeout=%ld ms", 1000 * (end.time - start.time) + end.millitm - start.millitm);
            return ERROR;
        case -1:
            if (errno == EINTR || errno == EAGAIN)
            {
                cs_sleepus(1);
                if (timeout_us > 0)
                {
                    polltimeout = (timeout_us / 1000) - (1000 * (end.time - start.time) + end.millitm - start.millitm);
                    if (polltimeout < 0) polltimeout = 0;
                }
                continue;
            }
            rdr_log(reader, "ERROR: %s: timeout=%ld ms (errno=%d %s)", __func__, 1000 * (end.time - start.time) + end.millitm - start.millitm, errno, strerror(errno));
            return ERROR;
        default:
            if (((ufds.revents) & POLLOUT) == POLLOUT)
                return OK;
            else
                return ERROR;
        }
    }
}


bool Stinger_IO_Serial_Write (struct s_reader *reader, uint32_t delay, uint32_t timeout, uint32_t size, const unsigned char *data)
{
    if (timeout == 0)  // General fix for readers not communicating timeout and delay
    {
        if (reader->char_delay != 0) timeout = reader->char_delay; else timeout = 1000000;
        rdr_debug_mask(reader, D_DEVICE, "Warning: write timeout 0 changed to %d us", timeout);
    }
    uint32_t count, to_send, i_w;
    unsigned char data_w[512];

    to_send = (delay ? 1 : size); // calculate chars to send at one
    rdr_debug_mask(reader, D_DEVICE, "Write timeout %d us, write delay %d us, to send %d char(s), chunksize %d char(s)", timeout, delay, size, to_send);

    for (count = 0; count < size; count += to_send)
    {
        if (count + to_send > size)
        {
            to_send = size - count;
        }
        uint16_t errorcount = 0, to_do = to_send;
        for (i_w = 0; i_w < to_send; i_w++)
            data_w [i_w] = data [count + i_w];
        rdr_ddump_mask(reader, D_DEVICE, data_w + (to_send - to_do), to_do, "Sending:");
AGAIN:
        if (!Stinger_IO_Serial_WaitToWrite (reader, delay, timeout))
        {
            while (to_do != 0)
            {
                int32_t u = write (reader->handle, data_w + (to_send - to_do), to_do);
                if (u < 1)
                {
                    if (errno == EINTR) continue; //try again in case of Interrupted system call
                    if (errno == EAGAIN) goto AGAIN; //EAGAIN needs a select procedure again
                    errorcount++;
                    int16_t written = count + to_send - to_do;
                    if (u != 0)
                    {
                        rdr_log(reader, "ERROR: %s: Written=%d of %d (errno=%d %s)",
                                __func__, written , size, errno, strerror(errno));
                    }
                    if (errorcount > 10)  //exit if more than 10 errors
                    {
                        return ERROR;
                    }
                }
                else
                {
                    to_do -= u;
                    errorcount = 0;
                }
            }
        }
        else
        {
            rdr_log(reader, "Timeout in Stinger_IO_Serial_WaitToWrite, delay=%d us, timeout=%d us", delay, timeout);
            if (reader->crdr.read_written && reader->written > 0)   // these readers need to read all transmitted chars before they can receive!
            {
                unsigned char buf[256];
                rdr_debug_mask(reader, D_DEVICE, "Reading %d echoed transmitted chars...", reader->written);
                int32_t n = reader->written;
                if (IO_Serial_Read (reader, 0, 9990000, n, buf)) // use 9990000 = aprox 10 seconds (since written chars could be hughe!)
                    return ERROR;
                reader->written = 0;
                rdr_debug_mask(reader, D_DEVICE, "Reading of echoed transmitted chars done!");
            }
            return ERROR;
        }
    }

    return OK;
}



static int32_t Stinger_Get_Info(struct s_reader *reader, unsigned char *sc, unsigned char *parity, unsigned int *baudrate)
{
    unsigned char buf[64];
    memset(buf, 0, 64);

    //DTR down
    IO_Serial_DTR_Set(reader);
    buf[0] = 0;

    Stinger_IO_Serial_Write(reader, 0, 10, 1, buf);
    int32_t n = 0;
    while (n < 32 && !IO_Serial_Read(reader, 0, ATR_TIMEOUT, 1, buf + n))
        n++;

    //DTR up
    IO_Serial_DTR_Clr(reader);

    *sc = 0xFF;
    *baudrate = 0xFF;
    *parity = 0xFF;


    if (n == 0)
    {
        rdr_log(reader, "Stinger_Get_Info: n %d", n);
        return ERROR;
    }
    if (buf[0] == 0x00)

    {
        /* Reader */
        if ( (buf[1] == 0x01) || (buf[1] == 0x02) )
        {
            *sc = buf[1] - 1;
        }
        else
        {
            rdr_log(reader, "Stinger_Get_Info: buf[1] %d", buf[1]);
            return ERROR;
        }
        /* Baudrate */
        if ( (buf[25] == 0x00) || (buf[25] == 0x01) || (buf[25] == 0x02) )
        {
            *baudrate = buf[25];
        }
        else
        {
            rdr_log(reader, "Stinger_Get_Info: buf[25] %d", buf[25]);
            return ERROR;
        }
        /* Parity */
        if ( (buf[26] == 0x00) || (buf[26] == 0x01) || (buf[26] == 0x02) )
        {
            *parity = buf[26];
        }
        else
        {
            rdr_log(reader, "Stinger_Get_Info: buf[26] %d", buf[26]);
            return ERROR;
        }
        return OK;

    }
    else
    {
        rdr_log(reader, "Stinger_Get_Info: buf[0] %d", buf[0]);
        return ERROR;
    }


}

int32_t Stinger_Init (struct s_reader *reader)
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
        if (IO_Serial_SetParams (reader, DEFAULT_BAUDRATE, 8, PARITY_NONE, 2, NULL, NULL)) return ERROR;
        if (reader->crdr.flush) IO_Serial_Flush(reader);
    }

    return OK;
}


int32_t Stinger_Reset (struct s_reader *reader, ATR *atr)
{
    rdr_debug_mask(reader, D_IFD, "Resetting card");
    int32_t ret;
    int32_t i;
    unsigned char buf[ATR_MAX_SIZE];

    IO_Serial_SetParams (reader, DEFAULT_BAUDRATE, 8, PARITY_NONE, 2, NULL, NULL);


    for (i = 0; i < 1; i++)
    {
        if (reader->crdr.flush) IO_Serial_Flush(reader);


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

        while (n < 1 && !IO_Serial_Read(reader, 0, ATR_TIMEOUT, 1, buf + n))
            n++;

        while (n < ATR_MAX_SIZE && !IO_Serial_Read(reader, 0, 900000, 1, buf + n))
            n++;


        if (n == 0)
            continue;
        if (ATR_InitFromArray (atr, buf, n) != ERROR)
            ret = OK;
        // Succesfully retrieve ATR
        if (ret == OK)
            break;
    }


    if (ret == OK)
    {
        IO_Serial_SetParams (reader, 115200, 8, PARITY_NONE, 1/*2*/, NULL, NULL);
        return OK;
    }
    else
        return ret;
}

static int32_t stinger_mouse_init(struct s_reader *reader)
{


    unsigned int clock_mhz = 0;


    if (detect_db2com_reader(reader))
    {
        cardreader_db2com(&reader->crdr);
        return reader->crdr.reader_init(reader);
    }

    clock_mhz = reader->mhz;

    if (reader->mhz != reader->cardmhz)
        reader->mhz = reader->cardmhz;


    reader->handle = open (reader->device,  O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (reader->handle < 0)
    {
        rdr_log(reader, "ERROR: Opening device %s (errno=%d %s)",
                reader->device, errno, strerror(errno));
        return ERROR;
    }


    if (Stinger_Init(reader))
    {
        rdr_log(reader, "ERROR: Stinger_Init returns error");
        Phoenix_Close (reader);

        return ERROR;
    }


    // SET CLOCK

    cs_sleepms(200);
    Stinger_Set_Clock(reader, clock_mhz);

    return OK;
}



int32_t Stinger_IO_Serial_SetBaudrate(struct s_reader *reader, uint32_t baudrate)
{
    unsigned char dat[8];
    unsigned char p = 0xFF;
    unsigned int b = 0xFF;
    unsigned char s = 0xFF;
    memset(dat, 0, 8);
    rdr_debug_mask(reader, D_IFD, "Setting baudrate to %u", baudrate);

    if (baudrate == 9600)
    {
        dat[2] = 0;
    }
    else if (baudrate == 38400)
    {
        dat[2] = 1;
    }
    else if (baudrate == 115200)
    {
        dat[2] = 2;
    }
    else
    {
        rdr_debug_mask(reader, D_IFD, "Baudrate value not supported");
        return ERROR;
    }


    Stinger_Get_Info(reader, &s, &p, &b);


    if ( (s == 0xFF) || (p == 0xFF) || (b == 0xFF) )
    {
        rdr_debug_mask(reader, D_IFD, "Stinger_Get_Info error");
        return ERROR;
    }

    //Stinger cmds
    dat[0] = 0x03;
    dat[1] = s;
    dat[3] = p;


    //DTR down
    IO_Serial_DTR_Set(reader);

    Stinger_IO_Serial_Write(reader, 0, 10, 4, dat);


    int32_t n = 0;
    while (n < 2 && !IO_Serial_Read(reader, 0, 300000, 1, dat + n))
        n++;


    //DTR up
    IO_Serial_DTR_Clr(reader);

    reader->current_baudrate = baudrate; //so if update fails, reader->current_baudrate is not changed either


    return OK;

}

int32_t Stinger_IO_Serial_SetParity(struct s_reader *reader, unsigned char parity)
{

    //Stinger cmds
    unsigned char dat[4];
    unsigned char p = 0xFF;
    unsigned int b = 0xFF;
    unsigned char s = 0xFF;

    if (parity == PARITY_NONE)
    {
        dat[3] = 0;
    }
    else if (parity == PARITY_ODD)
    {
        dat[3] = 1;
    }
    else if (parity == PARITY_EVEN)
    {
        dat[3] = 2;
    }
    else
    {
        rdr_debug_mask(reader, D_IFD, "Parity value not supported");
        return ERROR;
    }


    Stinger_Get_Info(reader, &s, &p, &b);

    if ( (s == 0xFF) || (p == 0xFF) || (b == 0xFF) )
    {
        rdr_debug_mask(reader, D_IFD, "Stinger_Get_Info error");
        return ERROR;
    }

    //Stinger cmd
    dat[0] = 0x03;
    dat[1] = s;
    dat[2] = b;


    //DTR down
    IO_Serial_DTR_Set(reader);

    Stinger_IO_Serial_Write(reader, 0, 10, 4, dat);

    int32_t n = 0;
    while (n < 2 && !IO_Serial_Read(reader, 0, 300000, 1, dat + n))
        n++;

    //DTR up
    IO_Serial_DTR_Clr(reader);

    return OK;
}


static int32_t Stinger_Set_Clock (struct s_reader *reader, unsigned int c)
{
    rdr_debug_mask(reader, D_IFD, "Setting Smartcard clock at: %d", c);
    unsigned char p = 0xFF;
    unsigned int b = 0xFF;
    unsigned char s = 0xFF;
    unsigned char dat[3];

    Stinger_Get_Info(reader, &s, &p, &b);

    if ( (s == 0xFF) || (p == 0xFF) || (b == 0xFF) )
    {
        rdr_debug_mask(reader, D_IFD, "Stinger_Get_Info error");
        return ERROR;
    }

    //Stinger cmd
    dat[0] = 0x02;          // Set Clock COMMAND
    dat[1] = s;

    if (c == 343)
    {
        dat[2] = 1;
    }
    else if (c == 400)
    {
        dat[2] = 2;
    }
    else if (c == 480)
    {
        dat[2] = 3;
    }
    else if (c == 600)
    {
        dat[2] = 4;
    }
    else if (c == 800)
    {
        dat[2] = 5;
    }
    else if (c == 1200)
    {
        dat[2] = 6;
    }
    else
    {
        rdr_debug_mask(reader, D_IFD, "Clock speed not recognized. Check configuration");
        return ERROR;
    }

    //DTR down
    IO_Serial_DTR_Set(reader);

    // SEND Command
    Stinger_IO_Serial_Write(reader, 0, 10, 3, dat);

    int32_t n = 0;
    while (n < 2 && !IO_Serial_Read(reader, 0, 300000, 1, dat + n))
        n++;

    //DTR up
    IO_Serial_DTR_Clr(reader);
    rdr_debug_mask(reader, D_IFD, "Smartcard clock at %d set", c);
    return OK;
}


void cardreader_stinger(struct s_cardreader *crdr)
{
    crdr->desc          = "stinger";
    crdr->typ           = R_MOUSE;
    crdr->flush         = 1;
    crdr->read_written  = 1;
    crdr->need_inverse  = 1;
    crdr->reader_init   = stinger_mouse_init;
    crdr->get_status    = Phoenix_GetStatus;
    crdr->activate      = Stinger_Reset;
    crdr->transmit      = IO_Serial_Transmit;
    crdr->receive       = IO_Serial_Receive;
    crdr->close         = Phoenix_Close;
    crdr->set_parity    = Stinger_IO_Serial_SetParity;
    crdr->set_baudrate  = Stinger_IO_Serial_SetBaudrate;
}
#endif
