/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "../globals.h"

#ifdef CARDREADER_SC8IN1
#include "../oscam-lock.h"
#include "../oscam-string.h"
#include "../oscam-time.h"
#include "atr.h"
#include "ifd_phoenix.h"
#include "io_serial.h"

#define OK 0
#define ERROR 1

struct s_sc8in1_display
{
    char *text;
    uint16_t text_length;
    uint16_t char_change_time;
    uint16_t last_char;
    uint8_t blocking;
    struct s_sc8in1_display *next;
};

struct sc8in1_data
{
    struct termios stored_termio[8];
    uint16_t current_slot;
    uint32_t current_baudrate;
    struct s_reader *current_reader;
    unsigned char cardstatus;
    unsigned char mcr_type;
    CS_MUTEX_LOCK sc8in1_lock;
    struct s_sc8in1_display *display;
    CS_MUTEX_LOCK sc8in1_display_lock;
    unsigned char display_running;
    pthread_t display_thread;
};

#ifdef WITH_DEBUG
static int32_t Sc8in1_DebugSignals(struct s_reader *reader, uint16_t slot, const char *extra)
{
    uint32_t msr;
    if (ioctl(reader->handle, TIOCMGET, &msr) < 0)
        return ERROR;
    rdr_debug_mask(reader, D_DEVICE, "SC8in1: Signals(%s): Slot: %i, DTR: %u, RTS: %u",
                   extra, slot, msr & TIOCM_DTR ? 1 : 0, msr & TIOCM_RTS ? 1 : 0);
    return OK;
}
#else
#define Sc8in1_DebugSignals(a, b, c) {}
#endif

static int32_t Sc8in1_NeedBaudrateChange(struct s_reader *reader, uint32_t desiredBaudrate, struct termios *current, struct termios *new, uint8_t cmdMode)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    // Returns 1 if we need to change the baudrate
    if ((desiredBaudrate != crdr_data->current_baudrate) ||
            (reader->mhz != reader->cardmhz) ||
            (cmdMode == 0 && memcmp(current, new, sizeof(struct termios))))
    {
        cs_debug_mask(D_TRACE, "Sc8in1_NeedBaudrateChange 1");
        return 1;
    }
    cs_debug_mask(D_TRACE, "Sc8in1_NeedBaudrateChange 0");
    return 0;
}

static int32_t Sc8in1_SetBaudrate(struct s_reader *reader, uint32_t baudrate, struct termios *termio, uint8_t cmdMode)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    /* Get current settings */
    struct termios tio;
    if (termio == NULL)
    {
        call(tcgetattr(reader->handle, &tio) != 0);
    }
    else
    {
        tio = *termio;
        if (baudrate == 0)
        {
            baudrate = reader->current_baudrate;
            if (baudrate == 0)
            {
                baudrate = 9600;
            }
        }
    }
    rdr_debug_mask(reader, D_IFD, "Sc8in1 Setting baudrate to %u", baudrate);
    rdr_debug_mask(reader, D_TRACE, "Sc8in1 Setting baudrate to %u, reader br=%u, currentBaudrate=%u, cmdMode=%u",
                   baudrate, reader->current_baudrate, crdr_data->current_baudrate, cmdMode);
    call (IO_Serial_SetBitrate (reader, baudrate, &tio));
    crdr_data->current_baudrate = baudrate;
    call (IO_Serial_SetProperties(reader, tio));
    if (cmdMode == 0)
    {
        reader->current_baudrate = baudrate;
    }
    return OK;
}

static int32_t sc8in1_tcdrain(struct s_reader *reader)
{
    while (1)
    {
        int32_t tcdrain_ret = tcdrain(reader->handle);
        if (tcdrain_ret == -1)
        {
            if (errno == EINTR)
            {
                //try again in case of Interrupted system call
                continue;
            }
            else
                rdr_log(reader, "ERROR: %s: (errno=%d %s)", __func__, errno, strerror(errno));
            return ERROR;
        }
        break;
    }
    return OK;
}

static int32_t sc8in1_command(struct s_reader *reader, unsigned char *buff,
                              uint16_t lenwrite, uint16_t lenread, uint8_t enableEepromWrite, unsigned char UNUSED(getStatusMode),
                              uint8_t selectSlotMode)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    struct termios termio, termiobackup;
    uint32_t currentBaudrate = 0;

    if ( ! reader->handle )
    {
        rdr_log(reader, "ERROR: SC8in1 Command no valid handle");
        return ERROR;
    }

    Sc8in1_DebugSignals(reader, reader->slot, "CMD10");

    // switch SC8in1 to command mode
    IO_Serial_DTR_Set(reader);
    tcflush(reader->handle, TCIOFLUSH);

    // backup data
    tcgetattr(reader->handle, &termio);
    memcpy(&termiobackup, &termio, sizeof(termio));

    if (selectSlotMode)
    {
        if (crdr_data->current_slot != 0)
        {
            memcpy(&crdr_data->stored_termio[crdr_data->current_slot - 1],
                   &termiobackup, sizeof(termiobackup)); //not if current_slot is undefined
        }
    }

    // set communication parameters
    termio.c_oflag = 0;
    termio.c_lflag = 0;
    termio.c_cc[VTIME] = 1; // working
    termio.c_cflag = B9600 | CS8 | CREAD | CLOCAL;

    // Do we need to set the baudrate?
    if (Sc8in1_NeedBaudrateChange(reader, 9600, &termiobackup, &termio, 1))
    {
        rdr_debug_mask(reader, D_TRACE, "Sc8in1_NeedBaudrateChange for SC8in1 command");
        // save current baudrate for later restore
        currentBaudrate = crdr_data->current_baudrate;
        crdr_data->current_baudrate = 9600;
        cfsetospeed(&termio, B9600);
        cfsetispeed(&termio, B9600);
        rdr_debug_mask(reader, D_DEVICE, "standard baudrate: cardmhz=%d mhz=%d -> effective baudrate %u", reader->cardmhz, reader->mhz, 9600);
    }
    if (tcsetattr(reader->handle, TCSANOW, &termio) < 0)
    {
        rdr_log(reader, "ERROR: SC8in1 Command error in set RS232 attributes");
        return ERROR;
    }
    if (reader->sc8in1_dtrrts_patch == 1)
    {
        IO_Serial_DTR_Set(reader);
    }
    Sc8in1_DebugSignals(reader, reader->slot, "CMD11");

    // enable EEPROM write
    if (enableEepromWrite)
    {
        unsigned char eepromBuff[3];
        eepromBuff[0] = 0x70;
        eepromBuff[1] = 0xab;
        eepromBuff[2] = 0xba;
        rdr_ddump_mask(reader, D_DEVICE, eepromBuff, 3, "Sending:");
        if (!write(reader->handle, eepromBuff, 3))
        {
            rdr_log(reader, "SC8in1 Command write EEPROM error");
            return ERROR;
        }
        tcflush(reader->handle, TCIOFLUSH);
    }
    // write cmd
    rdr_ddump_mask(reader, D_DEVICE, buff, lenwrite, "Sending:");
    int32_t dataWritten = 0, dataToWrite = lenwrite;
    while (dataWritten < lenwrite)
    {
        int32_t written = write(reader->handle, buff, dataToWrite);
        if (written == -1)
        {
            rdr_log(reader, "SC8in1 Command write error");
            return ERROR;
        }
        if (written == lenwrite)
        {
            break;
        }
        else
        {
            dataWritten += written;
            dataToWrite -= written;
        }
    }

    sc8in1_tcdrain(reader);

    if (IO_Serial_Read(reader, 0, 1000000, lenread, buff) == ERROR)
    {
        rdr_log(reader, "SC8in1 Command read error");
        return ERROR;
    }

    // Workaround for systems where tcdrain doesnt work properly
    if (lenread <= 0 && crdr_data->mcr_type)
    {
        unsigned char buff_echo_hack[2] = { 0x65, 'A' };
        rdr_ddump_mask(reader, D_DEVICE, &buff_echo_hack[0], 2, "Sending:");
        if (write(reader->handle, &buff_echo_hack[0], 2) != 2)
        {
            rdr_log(reader, "SC8in1 Echo command write error");
            return ERROR;
        }
        sc8in1_tcdrain(reader);
        if (IO_Serial_Read(reader, 0, 1000000, 1, &buff_echo_hack[0]) == ERROR)
        {
            rdr_log(reader, "SC8in1 Echo command read error");
            return ERROR;
        }
        if (buff_echo_hack[0] != 'A')
        {
            rdr_log(reader, "SC8in1 Echo command read wrong character");
        }
    }

    if (selectSlotMode)
    {
        memcpy(&termiobackup, &crdr_data->stored_termio[selectSlotMode - 1],
               sizeof(termiobackup));
        if (Sc8in1_NeedBaudrateChange(reader, reader->current_baudrate, &termio, &termiobackup, 1))
        {
            rdr_debug_mask(reader, D_TRACE, "Sc8in1_SetTermioForSlot for select slot");
            if (Sc8in1_SetBaudrate(reader, reader->current_baudrate, &termiobackup, 0))
            {
                rdr_log(reader, "ERROR: SC8in1 Command Sc8in1_SetBaudrate");
                return ERROR;
            }
        }
        else
        {
            if (tcsetattr(reader->handle, TCSANOW, &termiobackup) < 0)
            {
                rdr_log(reader, "ERROR: SC8in1 Command error in set RS232 attributes");
                return ERROR;
            }
        }
    }
    else
    {
        // restore baudrate only if changed
        if (currentBaudrate)
        {
            if (Sc8in1_SetBaudrate(reader, currentBaudrate, &termiobackup, 1))
            {
                rdr_log(reader, "ERROR: SC8in1 selectslot restore Bitrate attributes");
                return ERROR;
            }
        }
        else
        {
            // restore data
            if (tcsetattr(reader->handle, TCSANOW, &termiobackup) < 0)
            {
                rdr_log(reader, "ERROR: SC8in1 Command error in restore RS232 attributes");
                return ERROR;
            }
        }
    }

    Sc8in1_DebugSignals(reader, reader->slot, "CMD12");
    if (reader->sc8in1_dtrrts_patch == 1)
    {
        IO_Serial_DTR_Set(reader);
    }

    tcflush(reader->handle, TCIOFLUSH);

    // switch SC8in1 to normal mode
    IO_Serial_DTR_Clr(reader);

    Sc8in1_DebugSignals(reader, reader->slot, "CMD13");

    return OK;
}

static int32_t mcrReadStatus(struct s_reader *reader, unsigned char *status)
{
    unsigned char buff[2];
    buff[0] = 0x3f;
    if (sc8in1_command(reader, buff, 1, 2, 0, 1, 0) < 0)
        return ERROR;
    status[0] = buff[0];
    status[1] = buff[1];
    return OK;
}

static int32_t sc8in1ReadStatus(struct s_reader *reader, unsigned char *status)
{
    unsigned char buff[9]; // read 1 echo byte + 8 status bytes
    buff[0] = 0x47;
    if (sc8in1_command(reader, buff, 1, 9, 0, 1, 0) < 0)
        return ERROR;
    memcpy(&status[0], &buff[1], 8);
    return OK;
}


static int32_t mcrReadType(struct s_reader *reader, unsigned char *type)
{
    unsigned char buff[1];
    buff[0] = 0x74;
    if (sc8in1_command(reader, buff, 1, 1, 0, 0, 0) < 0)
        return ERROR;
    type[0] = buff[0];
    return OK;
}

static int32_t mcrReadVersion(struct s_reader *reader, unsigned char *version)
{
    unsigned char buff[1];
    buff[0] = 0x76;
    if (sc8in1_command(reader, buff, 1, 1, 0, 0, 0) < 0)
        return ERROR;
    version[0] = buff[0];
    return OK;
}

static int32_t mcrReadSerial(struct s_reader *reader, unsigned char *serial)
{
    unsigned char buff[2];
    buff[0] = 0x6e;
    if (sc8in1_command(reader, buff, 1, 2, 0, 0, 0) < 0)
        return ERROR;
    serial[0] = buff[1];
    serial[1] = buff[0];
    return OK;
}

/*static int32_t mcrWriteDisplayRaw(struct s_reader *reader, unsigned char data[7]) {
    unsigned char buff[8];
    buff[0] = 0x64;
    memcpy(&buff[1], &data[0], 7);
    if (sc8in1_command(reader, buff, 8, 0, 0, 0, 0) < 0)
        return ERROR;
    return OK;
}*/

static int32_t mcrWriteDisplayAscii(struct s_reader *reader, unsigned char data, unsigned char timeout)
{
    unsigned char buff[3];
    buff[0] = 0x61;
    buff[1] = data;
    buff[2] = timeout;
    if (sc8in1_command(reader, buff, 3, 0, 0, 0, 0) < 0)
        return ERROR;
    return OK;
}

static int32_t mcrWriteClock(struct s_reader *reader, unsigned char saveClock, unsigned char clock_val[2])
{
    unsigned char buff[3];
    buff[0] = 0x63;
    buff[1] = clock_val[0];
    buff[2] = clock_val[1];
    if (sc8in1_command(reader, buff, 3, 0, 0, 0, 0) < 0)
        return ERROR;
    if (saveClock)
    {
        buff[0] = 0x6d;
        if (sc8in1_command(reader, buff, 1, 0, 1, 0, 0) < 0)
            return ERROR;
    }
    return OK;
}

static int32_t mcrReadClock(struct s_reader *reader, unsigned char *clock_val)
{
    unsigned char buff[2];
    buff[0] = 0x67;
    if (sc8in1_command(reader, buff, 1, 2, 0, 0, 0) < 0)
        return ERROR;
    clock_val[0] = buff[0];
    clock_val[1] = buff[1];
    return OK;
}

static int32_t mcrWriteTimeout(struct s_reader *reader, unsigned char timeout[2])
{
    unsigned char buff[3];
    buff[0] = 0x6f;
    buff[1] = timeout[0];
    buff[2] = timeout[1];
    if (sc8in1_command(reader, buff, 3, 0, 1, 0, 0) < 0)
        return ERROR;
    return OK;
}

static int32_t mcrReadTimeout(struct s_reader *reader, unsigned char *timeout)
{
    unsigned char buff[2];
    buff[0] = 0x72;
    if (sc8in1_command(reader, buff, 1, 2, 0, 0, 0) < 0)
        return ERROR;
    timeout[0] = buff[1];
    timeout[1] = buff[0];
    return OK;
}

static int32_t mcrSelectSlot(struct s_reader *reader, unsigned char slot)
{
    // Select slot for MCR device.
    // Parameter slot is from 1-8
    unsigned char buff[2];
    buff[0] = 0x73;
    buff[1] = slot - 1;
    if (sc8in1_command(reader, buff, 2, 0, 0, 0, slot) < 0)
        return ERROR;
    return OK;
}

static int32_t sc8in1SelectSlot(struct s_reader *reader, unsigned char slot)
{
    // Select slot for SC8in1 device.
    // Parameter slot is from 1-8
    unsigned char buff[6];
    buff[0] = 0x53;
    buff[1] = slot & 0x0F;
    // Read 6 Bytes: 2 Bytes write cmd and 4 unknown Bytes.
    if (sc8in1_command(reader, buff, 2, 6, 0, 0, slot) < 0)
        return ERROR;
    return OK;
}

static int32_t MCR_DisplayText(struct s_reader *reader, char *text, uint16_t text_len, uint16_t ch_time, uint8_t blocking)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    struct s_sc8in1_display *display;
    if (cs_malloc(&display, sizeof(struct s_sc8in1_display)))
    {
        if (!cs_malloc(&display->text, text_len))
        {
            rdr_log(reader, "MCR_DisplayText: Out of memory.");
            free(display);
            return ERROR;
        }
        memcpy(display->text, text, text_len);
        display->text_length = text_len;
        display->char_change_time = ch_time;
        display->last_char = 0;
        display->blocking = blocking;
        display->next = NULL;
        cs_writelock(&crdr_data->sc8in1_display_lock);
        if (crdr_data->display == NULL)
        {
            crdr_data->display = display;
        }
        else
        {
            struct s_sc8in1_display *d = crdr_data->display;
            while (d != NULL)
            {
                if (d->next == NULL)
                {
                    d->next = display;
                    break;
                }
                else
                {
                    d = d->next;
                }
            }
        }
        cs_writeunlock(&crdr_data->sc8in1_display_lock);
    }
    else
    {
        rdr_log(reader, "MCR_DisplayText: Out of memory.");
        return ERROR;
    }
    return OK;
}

static int32_t mcrHelloOscam(struct s_reader *reader)
{
    // Display "OSCam" on MCR display
    char helloOscam[5] = {'O', 'S', 'C', 'a', 'm'};
    return MCR_DisplayText(reader, &helloOscam[0], 5, 100, 1);
}

static int32_t mcr_generateStatisticsForDisplay(struct s_reader *reader)
{
    // show number of clients
    struct s_client *cl;
    uint16_t numClients = 0;
    for ( cl = first_client; cl ; cl = cl->next )
    {
        if (cl->typ == 'c')
        {
            numClients++;
        }
    }
    char msg[8] = { 0 };
    int msgLen = snprintf(&msg[0], 8, "CN%i", numClients);
    if (msgLen > 0 && MCR_DisplayText(reader, msg, msgLen, 300, 0))
    {
        return ERROR;
    }
    return OK;
}

static void *mcr_update_display_thread(void *param)
{
    const uint16_t DEFAULT_SLEEP_TIME = 100;
    const int32_t STATISTICS_UPDATE_SECONDS = 60;
    struct s_reader *reader = (struct s_reader *)param;
    struct sc8in1_data *crdr_data = reader->crdr_data;
    time_t lastStatisticUpdateTime = time((time_t *)0);

    if (reader->typ != R_SC8in1 ||  ! crdr_data->mcr_type)
    {
        rdr_log(reader, "Error: mcr_update_display_thread reader no MCR8in1 reader");
        pthread_exit(NULL);
    }

    set_thread_name(__func__);

    while (crdr_data->display_running)
    {
        uint16_t display_sleep = DEFAULT_SLEEP_TIME;

        // Update statistics
        time_t currentTime = time((time_t *)0);
        if (currentTime - lastStatisticUpdateTime >= STATISTICS_UPDATE_SECONDS)
        {
            if (mcr_generateStatisticsForDisplay(reader))
            {
                rdr_log(reader, "ERROR: mcr_generateStatisticsForDisplay");
            }
            lastStatisticUpdateTime = currentTime;
        }

        cs_writelock(&crdr_data->sc8in1_display_lock);
        if (crdr_data->display != NULL)   // is there something to display?
        {
            cs_writeunlock(&crdr_data->sc8in1_display_lock);

            display_sleep = crdr_data->display->char_change_time;

            // display the next character
            cs_writelock(&crdr_data->sc8in1_lock);
            if (crdr_data->display->blocking)
            {
                uint16_t i = 0;
                for (i = 0; i < crdr_data->display->text_length; i++)
                {
                    if (mcrWriteDisplayAscii(crdr_data->current_reader,
                                             crdr_data->display->text[++crdr_data->display->last_char - 1], 0xFF))
                    {
                        rdr_log(reader, "SC8in1: Error in mcr_update_display_thread write");
                    }
                    cs_sleepms(display_sleep);
                }
            }
            else
            {
                if (mcrWriteDisplayAscii(crdr_data->current_reader,
                                         crdr_data->display->text[++crdr_data->display->last_char - 1], 0xFF))
                {
                    rdr_log(reader, "SC8in1: Error in mcr_update_display_thread write");
                }
            }
            cs_writeunlock(&crdr_data->sc8in1_lock);

            // remove the display struct if the text has been shown completely
            if (crdr_data->display->last_char == crdr_data->display->text_length)
            {
                cs_writelock(&crdr_data->sc8in1_display_lock);
                struct s_sc8in1_display *next = crdr_data->display->next;
                free(crdr_data->display->text);
                free(crdr_data->display);
                crdr_data->display = next;
                cs_writeunlock(&crdr_data->sc8in1_display_lock);
            }
        }
        else
        {
            cs_writeunlock(&crdr_data->sc8in1_display_lock);
        }
        cs_sleepms(display_sleep);
    }
    pthread_exit(NULL);
    return NULL;
}


static int32_t readSc8in1Status(struct s_reader *reader)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    // Reads the card status
    //
    // the bits in the return bytes:
    // bit0=1 means Slot1=Smartcard inside
    // bit1=1 means Slot2=Smartcard inside
    // bit2=1 means Slot3=Smartcard inside
    // bit3=1 means Slot4=Smartcard inside
    // bit4=1 means Slot5=Smartcard inside
    // bit5=1 means Slot6=Smartcard inside
    // bit6=1 means Slot7=Smartcard inside
    // bit7=1 means Slot8=Smartcard inside
    tcflush(reader->handle, TCIOFLUSH);
    if (crdr_data->mcr_type)
    {
        unsigned char buff[2];
        if (mcrReadStatus(reader, &buff[0]))
        {
            return (-1);
        }
        tcflush(reader->handle, TCIOFLUSH);
        return buff[0];
    }
    else
    {
        unsigned char buff[8];
        if (sc8in1ReadStatus(reader, &buff[0]))
        {
            return (-1);
        }
        if (buff[0] != 0x90)
        {
            return (-1);
        }
        tcflush(reader->handle, TCIOFLUSH);
        return buff[1];
    }
}

static int32_t Sc8in1_Selectslot(struct s_reader *reader, uint16_t slot)
{
    // selects the Smartcard Socket "slot"
    //
    struct sc8in1_data *crdr_data = reader->crdr_data;
    if (slot == crdr_data->current_slot)
        return OK;
    rdr_debug_mask(reader, D_TRACE, "SC8in1: select slot %i", slot);

#ifdef WITH_DEBUG
    struct timeval tv_start, tv_end;
    gettimeofday(&tv_start, 0);
#endif

    int32_t status = ERROR;
    if (crdr_data->mcr_type)
    {
        status = mcrSelectSlot(reader, slot);
    }
    else
    {
        status = sc8in1SelectSlot(reader, slot);
    }

    if (status == OK)
    {
        crdr_data->current_reader = reader;
        crdr_data->current_slot = slot;
    }
#ifdef WITH_DEBUG
    gettimeofday(&tv_end, 0);
    uint32_t elapsed = (tv_end.tv_sec - tv_start.tv_sec) * 1000000 + tv_end.tv_usec - tv_start.tv_usec;
    rdr_debug_mask(reader, D_DEVICE, "SC8in1 Selectslot in %ums", elapsed / 1000);
#endif
    return status;
}

static int32_t Sc8in1_Card_Changed(struct s_reader *reader)
{
    // returns the SC8in1 Status
    // 0= no card was changed (inserted or removed)
    // -1= one ore more cards were changed (inserted or removed)
    int32_t result;
    int32_t lineData;
    if (reader->handle == 0)
        return 0;
    ioctl(reader->handle, TIOCMGET, &lineData);
    result = (lineData & TIOCM_CTS) / TIOCM_CTS;
    return result - 1;
}

static int32_t Sc8in1_GetStatus(struct s_reader *reader, int32_t *in)
{
    // Only same thread my access serial port
    struct sc8in1_data *crdr_data = reader->crdr_data;
    if ((crdr_data->current_slot == reader->slot && Sc8in1_Card_Changed(reader)) || *in == -1)
    {
        int32_t i = readSc8in1Status(reader); //read cardstatus
        if (i < 0)
        {
            rdr_log(reader, "Sc8in1_GetStatus Error");
            return ERROR;
        }
        crdr_data->cardstatus = i;
        rdr_debug_mask(reader, D_TRACE, "SC8in1: Card status changed; cardstatus=0x%X", crdr_data->cardstatus);
    }
    *in = (crdr_data->cardstatus & 1 << (reader->slot - 1));
    return OK;
}

static int32_t Sc8in1_Init(struct s_reader *reader)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    //additional init, Phoenix_Init is also called for Sc8in1 !
    struct termios termio;
    int32_t i, speed, retval;
    uint16_t sc8in1_clock = 0;
    //unsigned char buff[3];

    Sc8in1_DebugSignals(reader, reader->slot, "I-1");

    // Clr DTR, which is set by phoenix_init
    IO_Serial_DTR_Clr(reader);

    tcgetattr(reader->handle, &termio);
    for (i = 0; i < 8; i++)
    {
        //init all stored termios to default comm settings after device init, before ATR
        memcpy(&crdr_data->stored_termio[i], &termio,
               sizeof(termio));
    }

    // Init sc8in1 config
    crdr_data->mcr_type = 0;
    crdr_data->current_reader = reader;

    // check for a MCR device and how many slots it has.
    unsigned char mcrType[1]; mcrType[0] = 0;
    // at least fritzbox7170 needs to issue this twice
    mcrReadType(reader, &mcrType[0]);
    mcrType[0] = 0;
    if ( ! mcrReadType(reader, &mcrType[0]) )
    {
        if (mcrType[0] == 4 || mcrType[0] == 8)
        {
            crdr_data->mcr_type = mcrType[0];
            rdr_log(reader, "SC8in1: MCR%u detected for device %s", crdr_data->mcr_type, reader->device);

            unsigned char version[1]; version[0] = 0;
            if ( ! mcrReadVersion(reader, &version[0]))
            {
                rdr_log(reader, "SC8in1: Version %u for device %s", (unsigned char)version[0], reader->device);
            }

            unsigned char serial[2]; serial[0] = 0; serial[1] = 0;
            if ( ! mcrReadSerial(reader, &serial[0]))
            {
                rdr_log(reader, "SC8in1: Serial %u for device %s", (uint16_t)serial[0], reader->device);
            }

            //now work-around the problem that timeout of MCR has to be 0 in case of USB
            unsigned char timeout[2]; timeout[0] = 0; timeout[1] = 0;
            retval = mcrReadTimeout(reader, &timeout[0]);
            if (retval)
            {
                rdr_log(reader, "SC8in1: Error reading timeout.");
            }
            else
            {
                rdr_log(reader, "SC8in1: Timeout %u for device %s", (uint16_t)timeout[0], reader->device);
            }
            if ((strstr(reader->device, "USB"))
                    && (retval == ERROR || timeout[0] != 0 || timeout[1] != 0))   //assuming we are connected thru USB and timeout is undetected or not zero
            {
                rdr_log(reader, "SC8in1: Detected Sc8in1 device connected with USB, setting timeout to 0 and writing to EEPROM");
                timeout[0] = 0; timeout[1] = 0;
                if (mcrWriteTimeout(reader, timeout))
                {
                    rdr_log(reader, "SC8in1: Error writing timeout.");
                }
            }

            // Start display thread
            crdr_data->display_running = 1;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
            if (pthread_create(&crdr_data->display_thread, &attr, mcr_update_display_thread, (void *)(reader)))
                rdr_log(reader, "ERROR: can't create MCR_DISPLAY_THREAD thread");
            else
            {
                rdr_log(reader, "MCR_DISPLAY_THREAD thread started");
            }
            pthread_attr_destroy(&attr);
        }
    }

    if ( ! crdr_data->mcr_type )
    {
        tcflush(reader->handle, TCIOFLUSH); // a non MCR reader might give longer answer
    }

    Sc8in1_DebugSignals(reader, reader->slot, "I0");

    struct s_reader *rdr;
    LL_ITER itr = ll_iter_create(configured_readers);
    while ((rdr = ll_iter_next(&itr))) //also do this for disabled readers, so we configure the clocks right for all readers
        if (rdr->crdr_data == crdr_data)   //corresponding slot
        {
            //check slot boundaries
            int32_t upper_slot = (crdr_data->mcr_type) ? crdr_data->mcr_type : 8; //set upper limit to 8 for non MCR readers
            if (rdr->slot <= 0 || rdr->slot > upper_slot)
            {
                rdr_log(reader, "ERROR: device %s has invalid slot number %i", rdr->device, rdr->slot);
                return ERROR;
            }

            // set initial current_baudrate which is needed by sc8in1_command
            rdr->current_baudrate = reader->current_baudrate;

            if (crdr_data->mcr_type)
            {
                //set RTS for every slot to 1 to prevent jitter/glitch detection problems
                Sc8in1_DebugSignals(reader, rdr->slot, "I1");
                mcrSelectSlot(reader, rdr->slot);
                Sc8in1_DebugSignals(reader, rdr->slot, "I2");
                IO_Serial_RTS_Set(reader);
                Sc8in1_DebugSignals(reader, rdr->slot, "I3");

                //calculate clock-bits
                switch (rdr->mhz)
                {
                case 357:
                case 358:
                    speed = 0;
                    break;
                case 368:
                case 369:
                    speed = 1;
                    break;
                case 600:
                    speed = 2;
                    break;
                case 800:
                    speed = 3;
                    break;
                default:
                    speed = 0;
                    rdr_log(reader, "ERROR: Sc8in1 cannot set clockspeed to %d", rdr->mhz);
                    break;
                }
                sc8in1_clock |= (speed << ((rdr->slot - 1) * 2));
            }
        }

    if (crdr_data->mcr_type)
    {
        sc8in1_clock = ((sc8in1_clock & 0xFF) << 8) | ((sc8in1_clock & 0xFF00) >> 8);

        //set clockspeeds for all slots
        unsigned char clockspeed[2];
        memcpy(&clockspeed, &sc8in1_clock, 2);
        if (mcrWriteClock(reader, 0, clockspeed))
        {
            rdr_log(reader, "ERROR: Sc8in1 cannot set clockspeed to %d", (uint16_t)clockspeed[0]);
        }

        // Clear RTS again
        itr = ll_iter_create(configured_readers);
        while ((rdr = ll_iter_next(&itr)))
        {
            if (rdr->crdr_data == crdr_data)
            {
                Sc8in1_DebugSignals(reader, rdr->slot, "I4");
                mcrSelectSlot(reader, rdr->slot);
                Sc8in1_DebugSignals(reader, rdr->slot, "I5");
                IO_Serial_RTS_Clr(reader);
                Sc8in1_DebugSignals(reader, rdr->slot, "I6");
                // Discard ATR
                unsigned char buff[1];
                while ( ! IO_Serial_Read(reader, 0, 500000, 1, &buff[0]) )
                {
                    cs_sleepms(1);
                }
                tcflush(reader->handle, TCIOFLUSH);
            }
        }

        //DEBUG get clockspeeds
        if (mcrReadClock(reader, &clockspeed[0]))
        {
            rdr_log(reader, "ERROR: Sc8in1 cannot read clockspeed");
        }
        static char *clock_mhz[] = { "3,57", "3,68", "6,00", "8,00" };
        uint16_t result = clockspeed[0] << 8 | clockspeed[1];
        for (i = 0; i < 8; i++)
        {
            rdr_log(reader, "Slot %i is clocked with %s mhz", i + 1, clock_mhz[(result >> (i * 2)) & 0X0003]);
        }
    }

    Sc8in1_Selectslot(reader, reader->slot);

    i = -1; //Flag for GetStatus init
    Sc8in1_GetStatus(reader, &i); //Initialize cardstatus
    // Gimmick
    if (crdr_data->mcr_type)
    {
        mcrHelloOscam(reader);
    }

    return OK;
}

static int32_t Sc8in1_GetActiveHandle(struct s_reader *reader, uint8_t onlyEnabledReaders)
{
    // Returns a handle to the serial port, if it exists in some other
    // slot of the same physical reader.
    // Or returns 0 otherwise.
    struct sc8in1_data *crdr_data = reader->crdr_data;
    struct s_reader *rdr;
    LL_ITER itr = ll_iter_create(configured_readers);
    while ((rdr = ll_iter_next(&itr)))
    {
        if (rdr->typ == R_SC8in1)
        {
            if ((reader != rdr) && (crdr_data == rdr->crdr_data)
                    && rdr->handle != 0 && (onlyEnabledReaders ? rdr->enable != 0 : 1))
            {
                return rdr->handle;
            }
        }
    }
    return OK;
}

static int32_t Sc8in1_Close(struct s_reader *reader)
{
    // Check if we are the last active slot for the reader,
    // then close the serial port. Otherwise select next acive slot.
    struct sc8in1_data *crdr_data = reader->crdr_data;
    rdr_debug_mask(reader, D_IFD, "Closing SC8in1 device %s", reader->device);
    bool status = ERROR;

    if (Sc8in1_GetActiveHandle(reader, 1))
    {
        rdr_debug_mask(reader, D_IFD, "Just deactivating SC8in1 device %s", reader->device);
        reader->written = 0;
        status = OK;
        // select next active reader slot, so getstatus still works
        if (crdr_data->current_slot == reader->slot)
        {
            struct s_reader *rdr;
            for (rdr = first_active_reader; rdr; rdr = rdr->next)
            {
                if (rdr->typ == R_SC8in1)
                {
                    if ((reader != rdr) && (crdr_data == rdr->crdr_data)
                            && rdr->handle != 0)
                    {
                        status = Sc8in1_Selectslot(rdr, rdr->slot);
                        break;
                    }
                }
            }
        }
    }
    else
    {
        if (crdr_data->mcr_type)
        {
            // disable reader threads
            crdr_data->display_running = 0;
            pthread_join(crdr_data->display_thread, NULL);
        }
        // disable other slots
        struct s_reader *rdr;
        LL_ITER itr = ll_iter_create(configured_readers);
        while ((rdr = ll_iter_next(&itr)))
        {
            if (rdr->typ == R_SC8in1)
            {
                if ((reader != rdr) && (crdr_data == rdr->crdr_data))
                {
                    rdr->handle = 0;
                }
            }
        }
        // close serial port
        if (reader->handle != 0)
        {
            status = IO_Serial_Close(reader);
            reader->handle = 0;
        }
    }

    return status;
}

static int32_t Sc8in1_SetSlotForReader(struct s_reader *reader)
{
    // Sets the slot for the reader if it is not set already
    int32_t pos = strlen(reader->device) - 2; //this is where : should be located; is also valid length of physical device name
    if (reader->device[pos] != 0x3a) //0x3a = ":"
        rdr_log(reader, "ERROR: '%c' detected instead of slot separator `:` at second to last position of device %s", reader->device[pos], reader->device);
    reader->slot = (uint16_t)reader->device[pos + 1] - 0x30;
    return OK;
}

static int32_t Sc8in1_InitLocks(struct s_reader *reader)
{
    // Create SC8in1_Configs and init locks.
    // Method is called once for every reader.
    // If there is already a Sc8in1 reader configured with the
    // same device (means same reader, different slot) then use
    // its sc8in1_config, otherwise create a new sc8in1_config and return.

    Sc8in1_SetSlotForReader(reader);

    // Get device name
    int32_t pos = strlen(reader->device) - 2;
    if (pos <= 0)
    {
        return ERROR;
    }
    if (reader->device[pos] != 0x3a) //0x3a = ":"
        rdr_log(reader, "ERROR: Sc8in1_InitLocks: '%c' detected instead of slot separator `:` at second to last position of device %s", reader->device[pos], reader->device);
    unsigned char savePos = reader->device[pos];
    reader->device[pos] = 0;


    uint8_t reader_config_exists = 0;
    struct s_reader *rdr;
    LL_ITER itr = ll_iter_create(configured_readers);
    while ((rdr = ll_iter_next(&itr)))
    {
        if (rdr->typ == R_SC8in1 && rdr != reader)
        {
            unsigned char save = rdr->device[pos];
            rdr->device[pos] = 0; //set to 0 so we can compare device names
            if (!strcmp(reader->device, rdr->device))   //we have a match to another slot with same device name
            {
                rdr->device[pos] = save; //restore character
                Sc8in1_SetSlotForReader(rdr);
                if (rdr->crdr_data)
                {
                    reader->crdr_data = rdr->crdr_data;
                    reader_config_exists = 1;
                    rdr_debug_mask(reader, D_DEVICE, "Sc8in1_InitLocks: Found config for %s", reader->device);
                }
            }
            else
            {
                rdr->device[pos] = save; //restore character
            }
            if (reader_config_exists)
            {
                break;
            }
        }
    }

    if (!reader_config_exists)
    {
        rdr_debug_mask(reader, D_DEVICE, "Sc8in1_InitLocks: Creating new config for %s", reader->device);
        // Create SC8in1_Config for reader
        if (cs_malloc(&reader->crdr_data, sizeof(struct sc8in1_data)))
        {
            struct sc8in1_data *crdr_data = reader->crdr_data;
            char *buff = NULL, *buff2 = NULL;
            if (cs_malloc(&buff, 128))
                snprintf(buff, 128, "sc8in1_lock_%s", reader->device);
            if (cs_malloc(&buff2, 128))
                snprintf(buff2, 128, "display_sc8in1_lock_%s", reader->device);
            cs_lock_create(&crdr_data->sc8in1_lock, 40, ESTR(buff));
            cs_lock_create(&crdr_data->sc8in1_display_lock, 10, ESTR(buff2));
        }
        else
        {
            reader->device[pos] = savePos;
            rdr_log(reader, "sc8in1: Out of memory.");
            return ERROR;
        }
    }

    reader->device[pos] = savePos;

    return OK;
}

static void sc8in1_lock(struct s_reader *reader)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    cs_writelock(&crdr_data->sc8in1_lock);
    rdr_debug_mask(reader, D_ATR, "Locked for access of slot %i", reader->slot);
    Sc8in1_Selectslot(reader, reader->slot);
}

static void sc8in1_unlock(struct s_reader *reader)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    cs_writeunlock(&crdr_data->sc8in1_lock);
    rdr_debug_mask(reader, D_ATR, "Unlocked for access of slot %i", reader->slot);
}

static void sc8in1_display(struct s_reader *reader, char *message)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    if (!crdr_data->mcr_type)
        return;
    char msg[4] = "   ";
    if (strlen(message) >= 3)
    {
        msg[0] = message[0];
        msg[1] = message[1];
        msg[2] = message[2];
    }
    char text[5] = { 'S', (char)reader->slot + 0x30, msg[0], msg[1], msg[2] };
    MCR_DisplayText(reader, text, sizeof(text), 400, 0);
}

static int32_t sc8in1_init(struct s_reader *reader)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    cs_writelock(&crdr_data->sc8in1_lock);
    if (reader->handle != 0)  //this reader is already initialized
    {
        rdr_debug_mask(reader, D_DEVICE, "%s Sc8in1 already open", __func__);
        cs_writeunlock(&crdr_data->sc8in1_lock);
        return OK;
    }
    //get physical device name
    int32_t pos = strlen(reader->device) - 2; //this is where : should be located; is also valid length of physical device name
    if (pos <= 0 || reader->device[pos] != 0x3a) //0x3a = ":"
        rdr_log(reader, "ERROR: '%c' detected instead of slot separator `:` at second to last position of device %s", reader->device[pos], reader->device);
    // Check if serial port is open already
    reader->handle = Sc8in1_GetActiveHandle(reader, 0);
    if (!reader->handle)
    {
        rdr_debug_mask(reader, D_DEVICE, "%s opening SC8in1", __func__);
        //open physical device
        char deviceName[128];
        strncpy(deviceName, reader->device, 128);
        deviceName[pos] = 0;
        reader->handle = open (deviceName,  O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (reader->handle < 0)
        {
            rdr_log(reader, "ERROR: Opening device %s with real device %s (errno=%d %s)", reader->device, deviceName, errno, strerror(errno));
            reader->handle = 0;
            cs_writeunlock(&crdr_data->sc8in1_lock);
            return ERROR;
        }
    }
    else
    {
        // serial port already initialized
        rdr_debug_mask(reader, D_DEVICE, "%s another Sc8in1 already open", __func__);
        cs_writeunlock(&crdr_data->sc8in1_lock);
        return OK;
    }
    if (Phoenix_Init(reader))
    {
        rdr_log(reader, "ERROR: Phoenix_Init returns error");
        Phoenix_Close (reader);
        cs_writeunlock(&crdr_data->sc8in1_lock);
        return ERROR;
    }
    int32_t ret = Sc8in1_Init(reader);
    cs_writeunlock(&crdr_data->sc8in1_lock);
    if (ret)
    {
        rdr_log(reader, "ERROR: Sc8in1_Init returns error");
        return ERROR;
    }
    return OK;
}

static int32_t sc8in1_close(struct s_reader *reader)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    cs_writelock(&crdr_data->sc8in1_lock);
    int32_t retval = Sc8in1_Close(reader);
    cs_writeunlock(&crdr_data->sc8in1_lock);
    if (retval == ERROR)
        return ERROR;
    return OK;
}

static int32_t sc8in1_get_status(struct s_reader *reader, int32_t *in)
{
    struct sc8in1_data *crdr_data = reader->crdr_data;
    cs_writelock(&crdr_data->sc8in1_lock);
    int32_t ret = Sc8in1_GetStatus(reader, in);
    cs_writeunlock(&crdr_data->sc8in1_lock);
    return ret;
}

static int32_t sc8in1_activate(struct s_reader *reader, struct s_ATR *atr)
{
    reader->crdr.lock(reader);
    int32_t retval = Phoenix_Reset(reader, atr);
    reader->crdr.unlock(reader);
    if (retval == ERROR)
    {
        rdr_debug_mask(reader, D_TRACE, "ERROR: Phoenix_Reset returns error");
        return ERROR;
    }
    return OK;
}

static int32_t sc8in1_set_baudrate(struct s_reader *reader, uint32_t baudrate)
{
    call(Sc8in1_SetBaudrate(reader, baudrate, NULL, 0));
    return OK;
}

void cardreader_sc8in1(struct s_cardreader *crdr)
{
    crdr->desc         = "sc8in1";
    crdr->typ          = R_SC8in1;
    crdr->flush        = 1;
    crdr->read_written = 1;
    crdr->need_inverse = 1;
    crdr->skip_t1_command_retries = 1;
    crdr->lock_init    = Sc8in1_InitLocks;
    crdr->lock         = sc8in1_lock;
    crdr->unlock       = sc8in1_unlock;
    crdr->display_msg  = sc8in1_display;
    crdr->reader_init  = sc8in1_init;
    crdr->close        = sc8in1_close;
    crdr->get_status   = sc8in1_get_status;
    crdr->activate     = sc8in1_activate;
    crdr->transmit     = IO_Serial_Transmit;
    crdr->receive      = IO_Serial_Receive;
    crdr->set_parity   = IO_Serial_SetParity;
    crdr->set_baudrate = sc8in1_set_baudrate;
}

#endif
