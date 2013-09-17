//
// Common videoguard functions.
//
#include "globals.h"
#ifdef READER_VIDEOGUARD
#include "reader-common.h"
#include "reader-videoguard-common.h"

#define VG_EMMTYPE_MASK 0xC0
#define VG_EMMTYPE_G 0
#define VG_EMMTYPE_U 1
#define VG_EMMTYPE_S 2

typedef struct mailmsg_s
{
   uint16_t caid;
   uint32_t serial;
   uint16_t date;
   uint16_t id;
   uint8_t nsubs;
   uint16_t len;
   uint8_t mask;
   uint8_t written;
   char *message;
   char *subject;
} MAILMSG;

static LLIST *vg_msgs;

void set_known_card_info(struct s_reader * reader, const unsigned char * atr, const uint32_t *atr_size)
{
  struct videoguard_data *csystem_data = reader->csystem_data;
  /* Set to sensible default values */
  csystem_data->card_baseyear = 1997;
  csystem_data->card_tierstart = 0;
  csystem_data->card_system_version = NDSUNKNOWN;
  csystem_data->card_desc = "VideoGuard Unknown Card";

  NDS_ATR_ENTRY nds_atr_table[]={ // {atr}, atr len, base year, tier start, nds version, description
    /* known NDS1 atrs */
    {{ 0x3F, 0x78, 0x13, 0x25, 0x04, 0x40, 0xB0, 0x09, 0x4A, 0x50, 0x01, 0x4E, 0x5A },
       13, 1992, 0, NDS1, "VideoGuard Sky New Zealand (0969)"}, //160E
    {{ 0x3F, 0x78, 0x12, 0x25, 0x01, 0x40, 0xB0, 0x14, 0x4A, 0x50, 0x01, 0x53, 0x44 },
       13, 1997, 0, NDS1, "VideoGuard StarTV India (caid unknown)"}, //105.5E
    /* known NDS1+ atrs */
    {{ 0x3F, 0x7F, 0x13, 0x25, 0x04, 0x33, 0xB0, 0x02, 0x69, 0xFF, 0x4A, 0x50, 0xE0, 0x00, 0x00, 0x54,
       0x42, 0x00, 0x00, 0x00 },
       20, 1997, 0, NDS12, "VideoGuard China (0988)"},
    {{ 0x3F, 0x78, 0x13, 0x25, 0x03, 0x40, 0xB0, 0x20, 0xFF, 0xFF, 0x4A, 0x50, 0x00 },
       13, 1997, 0, NDS12, "VideoGuard DirecTV"},
    /* known NDS2 atrs */
    {{ 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x33, 0xB0, 0x08, 0xFF, 0xFF, 0x4A, 0x50, 0x90,
       0x00, 0x00, 0x47, 0x4C, 0x01 },
       21, 2004, 0, NDS2, "VideoGuard Sky Brasil GL39 (0907)"},
    {{ 0x3F, 0x7F, 0x11, 0x25, 0x03, 0x33, 0xB0, 0x09, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00, 0x00, 0x46,
       0x44, 0x01, 0x00, 0x00 },
       20, 2000, 0, NDS2, "VideoGuard Foxtel Australia (090B)"}, //156E
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x0E, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x49, 0x54, 0x02, 0x00, 0x00 },
       22, 1997, 0, NDS2, "VideoGuard Sky Italia (0919)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x01, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x4A, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard Dolce Romania (092F)"},
	{{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x01, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x4B, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard Viasat Ukraine (0931)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x54, 0xB0, 0x01, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x41, 0x55, 0x01, 0x00, 0x00 },
       22, 1997, 0, NDS2, "VideoGuard OnoCable Espana (093A)"},
    {{ 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x33, 0xB0, 0x13, 0x69, 0xFF, 0x4A, 0x50, 0xD0,
       0x80, 0x00, 0x49, 0x54, 0x03 },
       21, 1997, 0, NDS2, "VideoGuard Sky Italia (093B)"},
    {{ 0x3F, 0x7D, 0x11, 0x25, 0x02, 0x41, 0xB0, 0x03, 0x69, 0xFF, 0x4A, 0x50, 0xF0, 0x80, 0x00, 0x56,
       0x54, 0x03 },
       18, 2000, 0, NDS2, "VideoGuard Viasat (093E)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x54, 0xB0, 0x03, 0xFF, 0xFF, 0x4A, 0x50, 0x80,
       0x00, 0x00, 0x00, 0x00, 0x47, 0x4C, 0x05 },
       23, 2009, 0, NDS2, "VideoGuard Sky Brasil GL54 (0943)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x54, 0xB0, 0x03, 0xFF, 0xFF, 0x3F, 0xFF, 0x13,
       0x25, 0x02, 0x50, 0x80, 0x0F, 0x54, 0xB0 },
       23, 2004, 0, NDS2, "VideoGuard Sky Mexico (095B)"},
    {{ 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x00, 0x0F, 0x33, 0xB0, 0x0F, 0x69, 0xFF, 0x4A, 0x50, 0xD0,
       0x00, 0x00, 0x53, 0x59, 0x02 },
       21, 1997, 0, NDS2, "VideoGuard BSkyB (0963)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x10, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x4E, 0x5A, 0x01, 0x00, 0x00 },
       22, 1992, 0, NDS2, "VideoGuard Sky New Zealand (096A)"}, //160E
    {{ 0x3F, 0xFD, 0x11, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x41, 0xB0, 0x03, 0x69, 0xFF, 0x4A, 0x50, 0xF0,
       0x80, 0x00, 0x46, 0x44, 0x03 },
       21, 2000, 0, NDS2, "VideoGuard Foxtel Australia (096C)"}, //156E
    {{ 0x3F, 0xFF, 0x11, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x06, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x41, 0x5A, 0x01, 0x00, 0x11 },
       22, 2004, 50, NDS2, "VideoGuard Astro Malaysia (09AC)"},
    {{ 0x3F, 0xFF, 0x12, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x06, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x41, 0x5A, 0x01, 0x00, 0x12 },
       22, 2004, 50, NDS2, "VideoGuard Astro Malaysia (09AC) FastMode"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x06, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x41, 0x5A, 0x01, 0x00, 0x13 },
       22, 2004, 50, NDS2, "VideoGuard Astro Malaysia (09AC) FastMode"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x06, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x41, 0x5A, 0x01, 0x00, 0x14 },
       22, 2004, 50, NDS2, "VideoGuard Astro Malaysia (09AC) FastMode"},
    {{ 0x3F, 0xFF, 0x15, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x06, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x41, 0x5A, 0x01, 0x00, 0x15 },
       22, 2004, 50, NDS2, "VideoGuard Astro Malaysia (09AC) FastMode"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x80,
       0x00, 0x58, 0x34, 0x01, 0x00, 0x14 },
       22, 1997, 0, NDS2, "VideoGuard Cingal Philippines (09B4)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x02, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x80,
       0x00, 0x58, 0x38, 0x01, 0x00, 0x14 },
       22, 1997, 0, NDS2, "VideoGuard TopTV (09B8)"},
    {{ 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x54, 0xB0, 0x04, 0x69, 0xFF, 0x4A, 0x50, 0xD0,
       0x80, 0x00, 0x49, 0x54, 0x03 },
       21, 1997, 0, NDS2, "VideoGuard Sky Italia (09CD)"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x11, 0x69, 0xFF, 0x4A, 0x50, 0x50, 0x00,
       0x00, 0x47, 0x54, 0x01, 0x00, 0x00 },
       22, 1997, 0, NDS2, "VideoGuard YES DBS Israel"},
    {{ 0x3F, 0x7F, 0x11, 0x25, 0x03, 0x33, 0xB0, 0x09, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00, 0x00, 0x56,
       0x54, 0x01, 0x00, 0x00 },
       20, 2000, 0, NDS2, "VideoGuard Viasat Scandinavia"},
    {{ 0x3F, 0xFF, 0x11, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x50, 0x31, 0x01, 0x00, 0x11 },
       22, 2004, 0, NDS2, "VideoGuard Sky Germany (09C4)"},
    {{ 0x3F, 0xFF, 0x12, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x50, 0x31, 0x01, 0x00, 0x12 },
       22, 2004, 0, NDS2, "VideoGuard Sky Germany (09C4) FastMode"},
    {{ 0x3F, 0xFF, 0x13, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x50, 0x31, 0x01, 0x00, 0x13 },
       22, 2004, 0, NDS2, "VideoGuard Sky Germany (09C4) FastMode"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x50, 0x31, 0x01, 0x00, 0x14 },
       22, 2004, 0, NDS2, "VideoGuard Sky Germany (09C4) FastMode"},
    {{ 0x3F, 0xFF, 0x15, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x50, 0x31, 0x01, 0x00, 0x15 },
       22, 2004, 0, NDS2, "VideoGuard Sky Germany (09C4) FastMode"},
    {{ 0x3F, 0xFD, 0x13, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x41, 0xB0, 0x0A, 0x69, 0xFF, 0x4A, 0x50, 0xF0,
       0x00, 0x00, 0x50, 0x31, 0x03 },
       21, 2004, 0, NDS2, "VideoGuard Sky Germany (098C)"},
    {{ 0x3F, 0xFD, 0x14, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x41, 0xB0, 0x0A, 0x69, 0xFF, 0x4A, 0x50, 0xF0,
       0x00, 0x00, 0x50, 0x31, 0x03 },
       21, 2004, 0, NDS2, "VideoGuard Sky Germany (098C) FastMode"},
    {{ 0x3F, 0xFD, 0x15, 0x25, 0x02, 0x50, 0x80, 0x0F, 0x41, 0xB0, 0x0A, 0x69, 0xFF, 0x4A, 0x50, 0xF0,
       0x00, 0x00, 0x50, 0x31, 0x03 },
       21, 2004, 0, NDS2, "VideoGuard Sky Germany (098C) FastMode"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x01, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x48, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard DSMART Turkey"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x54, 0xB0, 0x01, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x4B, 0x57, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard Kabel BW (098E)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x10, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x43, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard totalTV Serbia (091F)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x10, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x45, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard Get Kabel Norway"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x80,
       0x00, 0x58, 0x36, 0x01, 0x00, 0x14 },
       22, 2004, 0, NDS2, "VideoGuard Teleclub (09B6)"},
    {{ 0x3F, 0xFD, 0x11, 0x25, 0x02, 0x50, 0x00, 0x03, 0x33, 0xB0, 0x15, 0x69, 0xFF, 0x4A, 0x50, 0xF0,
       0x80, 0x03, 0x4B, 0x4C, 0x03 },
       21, 2004, 0, NDS2, "VideoGuard Kabel Deutschland G02/G09 (09C7)"},
    {{ 0x3F, 0xFD, 0x15, 0x25, 0x02, 0x50, 0x00, 0x03, 0x33, 0xB0, 0x15, 0x69, 0xFF, 0x4A, 0x50, 0xF0,
       0x80, 0x03, 0x4B, 0x4C, 0x03 },
       21, 2004, 0, NDS2, "VideoGuard Kabel Deutschland G02/G09 (09C7) FastMode"},
    {{ 0x3F, 0x7D, 0x13, 0x25, 0x02, 0x41, 0xB0, 0x03, 0x69, 0xFF, 0x4A, 0x50, 0xF0, 0x80, 0x00, 0x54,
       0x37, 0x03 },
       18, 2004, 0, NDS2, "VideoGuard Telecolumbus (09AF)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x33, 0xB0, 0x10, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x00,
       0x00, 0x5A, 0x49, 0x01, 0x00, 0x00 },
       22, 2004, 0, NDS2, "VideoGuard Cyprus (092E)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x80,
       0x00, 0x58, 0x45, 0x01, 0x00, 0x14 },
       22, 2004, 0, NDS2, "VideoGuard OTE TV Sat (09BE)"},
    // NDS Version Unknown as Yet
    {{ 0x3F, 0x7F, 0x13, 0x25, 0x02, 0x40, 0xB0, 0x12, 0x69, 0xFF, 0x4A, 0x50, 0x90, 0x41, 0x55, 0x00,
       0x00, 0x00, 0x00, 0x00 },
       20, 1997, 0, NDSUNKNOWN, "VideoGuard OnoCable Espana (0915)"},
    {{ 0x3F, 0xFF, 0x14, 0x25, 0x03, 0x10, 0x80, 0x41, 0xB0, 0x07, 0x69, 0xFF, 0x4A, 0x50, 0x70, 0x80,
       0x00, 0x58, 0x44, 0x01, 0x00, 0x14 },
       22, 1997, 0, NDSUNKNOWN, "VideoGuard Sky Vivacom (09BD)"}, //45E
    {{ 0x3F, 0x7F, 0x13, 0x25, 0x05, 0x40, 0xB0, 0x11, 0x69, 0xFF, 0x4A, 0x50, 0x00, 0x00, 0x00, 0x48,
       0x4B, 0x00, 0x01, 0x00 },
       20, 1997, 0, NDSUNKNOWN, "VideoGuard StarTV India (caid unknown)"}, //105.5E
    {{ 0x3F, 0x7F, 0x13, 0x25, 0x03, 0x33, 0xB0, 0x11, 0x69, 0xFF, 0x4A, 0x50, 0x50, 0x00, 0x00, 0x49,
       0x56, 0x01, 0x00, 0x00 },
       22, 2004, 50, NDS2, "VideoGuard Indovision (09C1)" },
    {{ 0 }, 0, 0, 0, 0, NULL}
  };

  int32_t i=0;
  ATR atrdata;
  ATR *newatr = &atrdata;
  ATR_InitFromArray(newatr, atr, *atr_size);
  get_hist;

  ATR tableatr;
  unsigned char table_hist[ATR_MAX_HISTORICAL];
  uint32_t table_hist_size;

  while(nds_atr_table[i].desc) {
    ATR_InitFromArray(&tableatr, nds_atr_table[i].atr, nds_atr_table[i].atr_len);
    ATR_GetHistoricalBytes(&tableatr, table_hist, &table_hist_size);

    if ((hist_size == table_hist_size)
          && (memcmp (hist, table_hist, hist_size) == 0)) {
        csystem_data->card_baseyear=nds_atr_table[i].base_year;
        csystem_data->card_tierstart=nds_atr_table[i].tier_start;
        csystem_data->card_system_version = nds_atr_table[i].nds_version;
        csystem_data->card_desc = nds_atr_table[i].desc;
        break;
    }
    i++;
  }
}

static void cCamCryptVG_LongMult(uint16_t *pData, uint16_t *pLen, uint32_t mult, uint32_t carry);
static void cCamCryptVG_PartialMod(uint16_t val, uint32_t count, uint16_t *outkey, const uint16_t *inkey);
static void cCamCryptVG_RotateRightAndHash(unsigned char *p);
static void cCamCryptVG_Reorder16A(unsigned char *dest, const unsigned char *src);
static void cCamCryptVG_ReorderAndEncrypt(struct s_reader * reader, unsigned char *p);
static void cCamCryptVG_Process_D0(struct s_reader * reader, const unsigned char *ins, unsigned char *data);
static void cCamCryptVG_Process_D1(struct s_reader * reader, const unsigned char *ins, unsigned char *data, const unsigned char *status);
static void cCamCryptVG_Decrypt_D3(struct s_reader * reader, unsigned char *ins, unsigned char *data, const unsigned char *status);
static void cCamCryptVG_PostProcess_Decrypt(struct s_reader * reader, unsigned char *rxbuff);
static int32_t cAES_Encrypt(struct s_reader * reader, const unsigned char *data, int32_t len, unsigned char *crypted);
static void swap_lb (const unsigned char *buff, int32_t len);

int32_t cw_is_valid(unsigned char *cw) // returns 1 if cw_is_valid, returns 0 if cw is all zeros
{
  int32_t i;
  for (i = 0; i < 8; i++)
    if (cw[i] != 0) {		//test if cw = 00
      return OK;
    }
  return ERROR;
}

void cAES_SetKey(struct s_reader * reader, const unsigned char *key)
{
  struct videoguard_data *csystem_data = reader->csystem_data;
  AES_set_encrypt_key(key,128,&(csystem_data->ekey));
}

int32_t cAES_Encrypt(struct s_reader * reader, const unsigned char *data, int32_t len, unsigned char *crypted)
{
    struct videoguard_data *csystem_data = reader->csystem_data;
    len=(len+15)&(~15); // pad up to a multiple of 16
    int32_t i;
    for(i=0; i<len; i+=16) AES_encrypt(data+i,crypted+i,&(csystem_data->ekey));
    return len;
}

static void swap_lb (const unsigned char *buff, int32_t len)
{

#if __BYTE_ORDER != __BIG_ENDIAN
  return;

#endif /*  */
  int32_t i;
  uint16_t *tmp;
  for (i = 0; i < len / 2; i++) {
    tmp = (uint16_t *) buff + i;
    *tmp = ((*tmp << 8) & 0xff00) | ((*tmp >> 8) & 0x00ff);
  }
}

inline void __xxor(unsigned char *data, int32_t len, const unsigned char *v1, const unsigned char *v2)
{
  uint32_t i;
  switch(len) { // looks ugly but the cpu don't crash!
    case 16:
      for(i = 8; i < 16; ++i ) {
        data[i] = v1[i] ^ v2[i];
      }
    case 8:
      for(i = 4; i < 8; ++i) {
        data[i] = v1[i] ^ v2[i];
      }
    case 4:
      for(i = 0; i < 4; ++i ) {
        data[i] = v1[i] ^ v2[i];
      }
      break;
    default:
      while(len--) *data++ = *v1++ ^ *v2++;
      break;
    }
}


void cCamCryptVG_SetSeed(struct s_reader * reader)
{
#if __BYTE_ORDER != __BIG_ENDIAN
  static const unsigned char key1[] = {
    0xb9, 0xd5, 0xef, 0xd5, 0xf5, 0xd5, 0xfb, 0xd5, 0x31, 0xd6, 0x43, 0xd6, 0x55, 0xd6, 0x61, 0xd6,
    0x85, 0xd6, 0x9d, 0xd6, 0xaf, 0xd6, 0xc7, 0xd6, 0xd9, 0xd6, 0x09, 0xd7, 0x15, 0xd7, 0x21, 0xd7,
    0x27, 0xd7, 0x3f, 0xd7, 0x45, 0xd7, 0xb1, 0xd7, 0xbd, 0xd7, 0xdb, 0xd7, 0x11, 0xd8, 0x23, 0xd8,
    0x29, 0xd8, 0x2f, 0xd8, 0x4d, 0xd8, 0x8f, 0xd8, 0xa1, 0xd8, 0xad, 0xd8, 0xbf, 0xd8, 0xd7, 0xd8
    };
  static const unsigned char key2[] = {
    0x01, 0x00, 0xcf, 0x13, 0xe0, 0x60, 0x54, 0xac, 0xab, 0x99, 0xe6, 0x0c, 0x9f, 0x5b, 0x91, 0xb9,
    0x72, 0x72, 0x4d, 0x5b, 0x5f, 0xd3, 0xb7, 0x5b, 0x01, 0x4d, 0xef, 0x9e, 0x6b, 0x8a, 0xb9, 0xd1,
    0xc9, 0x9f, 0xa1, 0x2a, 0x8d, 0x86, 0xb6, 0xd6, 0x39, 0xb4, 0x64, 0x65, 0x13, 0x77, 0xa1, 0x0a,
    0x0c, 0xcf, 0xb4, 0x2b, 0x3a, 0x2f, 0xd2, 0x09, 0x92, 0x15, 0x40, 0x47, 0x66, 0x5c, 0xda, 0xc9
    };
#else
  static const unsigned char key1[] = {
    0xd5, 0xb9, 0xd5, 0xef, 0xd5, 0xf5, 0xd5, 0xfb, 0xd6, 0x31, 0xd6, 0x43, 0xd6, 0x55, 0xd6, 0x61,
    0xd6, 0x85, 0xd6, 0x9d, 0xd6, 0xaf, 0xd6, 0xc7, 0xd6, 0xd9, 0xd7, 0x09, 0xd7, 0x15, 0xd7, 0x21,
    0xd7, 0x27, 0xd7, 0x3f, 0xd7, 0x45, 0xd7, 0xb1, 0xd7, 0xbd, 0xd7, 0xdb, 0xd8, 0x11, 0xd8, 0x23,
    0xd8, 0x29, 0xd8, 0x2f, 0xd8, 0x4d, 0xd8, 0x8f, 0xd8, 0xa1, 0xd8, 0xad, 0xd8, 0xbf, 0xd8, 0xd7
    };
  static const unsigned char key2[] = {
    0x00, 0x01, 0x13, 0xcf, 0x60, 0xe0, 0xac, 0x54, 0x99, 0xab, 0x0c, 0xe6, 0x5b, 0x9f, 0xb9, 0x91,
    0x72, 0x72, 0x5b, 0x4d, 0xd3, 0x5f, 0x5b, 0xb7, 0x4d, 0x01, 0x9e, 0xef, 0x8a, 0x6b, 0xd1, 0xb9,
    0x9f, 0xc9, 0x2a, 0xa1, 0x86, 0x8d, 0xd6, 0xb6, 0xb4, 0x39, 0x65, 0x64, 0x77, 0x13, 0x0a, 0xa1,
    0xcf, 0x0c, 0x2b, 0xb4, 0x2f, 0x3a, 0x09, 0xd2, 0x15, 0x92, 0x47, 0x40, 0x5c, 0x66, 0xc9, 0xda
  };
#endif
  struct videoguard_data *csystem_data = reader->csystem_data;
  memcpy(csystem_data->cardkeys[1],key1,sizeof(csystem_data->cardkeys[1]));
  memcpy(csystem_data->cardkeys[2],key2,sizeof(csystem_data->cardkeys[2]));
}

void cCamCryptVG_GetCamKey(struct s_reader * reader, unsigned char *buff)
{
  struct videoguard_data *csystem_data = reader->csystem_data;
  uint16_t *tb2=(uint16_t *)buff, c=1;
  memset(tb2,0,64);
  tb2[0]=1;
  int32_t i;
  for(i=0; i<32; i++) cCamCryptVG_LongMult(tb2,&c,csystem_data->cardkeys[1][i],0);
  swap_lb (buff, 64);
}

static void cCamCryptVG_PostProcess_Decrypt(struct s_reader * reader, unsigned char *rxbuff)
{
  switch(rxbuff[0]) {
    case 0xD0:
      cCamCryptVG_Process_D0(reader,rxbuff,rxbuff+5);
      break;
    case 0xD1:
      cCamCryptVG_Process_D1(reader,rxbuff,rxbuff+5,rxbuff+rxbuff[4]+5);
      break;
    case 0xD3:
      cCamCryptVG_Decrypt_D3(reader,rxbuff,rxbuff+5,rxbuff+rxbuff[4]+5);
      break;
  }
}

static void cCamCryptVG_Process_D0(struct s_reader * reader, const unsigned char *ins, unsigned char *data)
{
  struct videoguard_data *csystem_data = reader->csystem_data;
  switch(ins[1]) {
    case 0xb4:
      swap_lb (data, 64);
      memcpy(csystem_data->cardkeys[0],data,sizeof(csystem_data->cardkeys[0]));
      break;
    case 0xbc:
    {
      swap_lb (data, 64);
      const uint16_t *key1=(const uint16_t *)csystem_data->cardkeys[1];
      uint16_t key2[32];
      memcpy(key2,csystem_data->cardkeys[2],sizeof(key2));
      int32_t count2;
      uint16_t iidata[32];
      memcpy( (unsigned char*)&iidata, data, 64 );
      for(count2=0; count2<32; count2++) {
        uint32_t rem=0, divisor=key1[count2];
        int8_t i;
        for(i=31; i>=0; i--) {
          uint32_t x=iidata[i] | (rem<<16);
          rem=(x%divisor)&0xffff;
          }
        uint32_t carry=1, t=val_by2on3(divisor) | 1;
        while(t) {
          if(t&1) carry=((carry*rem)%divisor)&0xffff;
          rem=((rem*rem)%divisor)&0xffff;
          t>>=1;
          }
        cCamCryptVG_PartialMod(carry,count2,key2,key1);
        }
      uint16_t idatacount=0;
      int32_t i;
      for(i=31; i>=0; i--) cCamCryptVG_LongMult(iidata,&idatacount,key1[i],key2[i]);
      memcpy( data, iidata, 64 );
      swap_lb (data, 64);
      unsigned char stateD1[16];
      cCamCryptVG_Reorder16A(stateD1,data);
      cAES_SetKey(reader,stateD1);
      break;
    }
  }
}

static void cCamCryptVG_Process_D1(struct s_reader * reader, const unsigned char *ins, unsigned char *data, const unsigned char *status)
{
  struct videoguard_data *csystem_data = reader->csystem_data;
  unsigned char iter[16], tmp[16];
  memset(iter,0,sizeof(iter));
  memcpy(iter,ins,5);
  xor16(iter,csystem_data->stateD3A,iter);
  memcpy(csystem_data->stateD3A,iter,sizeof(iter));

  int32_t datalen=status-data;
  int32_t datalen1=datalen;
  if(datalen<0) datalen1+=15;
  int32_t blocklen=datalen1>>4;
  int32_t i;
  int32_t iblock;
  for(i=0,iblock=0; i<blocklen+2; i++,iblock+=16) {
    unsigned char in[16];
    int32_t docalc=1;
    if(blocklen==i && (docalc=datalen&0xf)) {
      memset(in,0,sizeof(in));
      memcpy(in,&data[iblock],datalen-(datalen1&~0xf));
      }
    else if(blocklen+1==i) {
      memset(in,0,sizeof(in));
      memcpy(&in[5],status,2);
      }
    else
      memcpy(in,&data[iblock],sizeof(in));

    if(docalc) {
      xor16(iter,in,tmp);
      cCamCryptVG_ReorderAndEncrypt(reader,tmp);
      xor16(tmp,csystem_data->stateD3A,iter);
      }
    }
  memcpy(csystem_data->stateD3A,tmp,16);
}

static void cCamCryptVG_Decrypt_D3(struct s_reader * reader, unsigned char *ins, unsigned char *data, const unsigned char *status)
{
  struct videoguard_data *csystem_data = reader->csystem_data;
  if(ins[4]>16) ins[4]-=16;
  if(ins[1]==0xbe) memset(csystem_data->stateD3A,0,sizeof(csystem_data->stateD3A));

  unsigned char tmp[16];
  memset(tmp,0,sizeof(tmp));
  memcpy(tmp,ins,5);
  xor16(tmp,csystem_data->stateD3A,csystem_data->stateD3A);

  int32_t len1=ins[4];
  int32_t blocklen=len1>>4;
  if(ins[1]!=0xbe) blocklen++;

  unsigned char iter[16], states[16][16];
  memset(iter,0,sizeof(iter));
  int32_t blockindex;
  for(blockindex=0; blockindex<blocklen; blockindex++) {
    iter[0]+=blockindex;
    xor16(iter,csystem_data->stateD3A,iter);
    cCamCryptVG_ReorderAndEncrypt(reader,iter);
    xor16(iter,&data[blockindex*16],states[blockindex]);
    if(blockindex==(len1>>4)) {
      int32_t c=len1-(blockindex*16);
      if(c<16) memset(&states[blockindex][c],0,16-c);
      }
    xor16(states[blockindex],csystem_data->stateD3A,csystem_data->stateD3A);
    cCamCryptVG_RotateRightAndHash(csystem_data->stateD3A);
    }
  memset(tmp,0,sizeof(tmp));
  memcpy(tmp+5,status,2);
  xor16(tmp,csystem_data->stateD3A,csystem_data->stateD3A);
  cCamCryptVG_ReorderAndEncrypt(reader,csystem_data->stateD3A);

  memcpy(csystem_data->stateD3A,status-16,sizeof(csystem_data->stateD3A));
  cCamCryptVG_ReorderAndEncrypt(reader,csystem_data->stateD3A);

  memcpy(data,states[0],len1);
  if(ins[1]==0xbe) {
    cCamCryptVG_Reorder16A(tmp,states[0]);
    cAES_SetKey(reader,tmp);
    }
}

static void cCamCryptVG_ReorderAndEncrypt(struct s_reader * reader, unsigned char *p)
{
  unsigned char tmp[16];
  cCamCryptVG_Reorder16A(tmp,p);
  cAES_Encrypt(reader,tmp,16,tmp);
  cCamCryptVG_Reorder16A(p,tmp);
}

// reorder AAAABBBBCCCCDDDD to ABCDABCDABCDABCD
static void cCamCryptVG_Reorder16A(unsigned char *dest, const unsigned char *src)
{
  int32_t i;
  int32_t j;
  int32_t k;
  for(i=0,k=0; i<4; i++)
    for(j=i; j<16; j+=4,k++)
      dest[k]=src[j];
}

static void cCamCryptVG_LongMult(uint16_t *pData, uint16_t *pLen, uint32_t mult, uint32_t carry)
{
  int32_t i;
  for(i=0; i<*pLen; i++) {
    carry+=pData[i]*mult;
    pData[i]=(uint16_t)carry;
    carry>>=16;
    }
  if(carry) pData[(*pLen)++]=carry;
}

static void cCamCryptVG_PartialMod(uint16_t val, uint32_t count, uint16_t *outkey, const uint16_t *inkey)
{
  if(count) {
    uint32_t mod=inkey[count];
    uint16_t mult=(inkey[count]-outkey[count-1])&0xffff;
    uint32_t i;
    uint32_t ib1;
    for(i=0,ib1=count-2; i<count-1; i++,ib1--) {
      uint32_t t=(inkey[ib1]*mult)%mod;
      mult=t-outkey[ib1];
      if(mult>t) mult+=mod;
      }
    mult+=val;
    if((val>mult) || (mod<mult)) mult-=mod;
    outkey[count]=(outkey[count]*mult)%mod;
    }
  else
    outkey[0]=val;
}

static void cCamCryptVG_RotateRightAndHash(unsigned char *p)
{
  static const unsigned char table1[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5, 0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0, 0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc, 0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a, 0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0, 0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b, 0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85, 0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5, 0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17, 0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88, 0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c, 0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9, 0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6, 0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e, 0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94, 0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68, 0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    };
  unsigned char t1=p[15];
  int32_t i;
  for(i=0; i<16; i++) {
    unsigned char t2=t1;
    t1=p[i]; p[i]=table1[(t1>>1)|((t2&1)<<7)];
    }
}

int32_t status_ok(const unsigned char *status)
{
    //rdr_log(reader, "check status %02x%02x", status[0],status[1]);
    return (status[0] == 0x90 || status[0] == 0x91)
           && (status[1] == 0x00 || status[1] == 0x01
               || status[1] == 0x20 || status[1] == 0x21
               || status[1] == 0x80 || status[1] == 0x81
               || status[1] == 0xa0 || status[1] == 0xa1);
}

void memorize_cmd_table (struct s_reader * reader, const unsigned char *mem, int32_t size){
  struct videoguard_data *csystem_data = reader->csystem_data;
  if (cs_malloc(&csystem_data->cmd_table, size))
    memcpy(csystem_data->cmd_table,mem,size);
}

int32_t cmd_table_get_info(struct s_reader * reader, const unsigned char *cmd, unsigned char *rlen, unsigned char *rmode)
{
  struct videoguard_data *csystem_data = reader->csystem_data;
  struct s_CmdTabEntry *pcte=csystem_data->cmd_table->e;
  int32_t i;
  for(i=0; i< csystem_data->cmd_table->Nentries; i++,pcte++)
    if(cmd[1]==pcte->cmd) {
      *rlen=pcte->len;
      *rmode=pcte->mode;
      return 1;
    }
  return 0;
}

int32_t cmd_exists(struct s_reader * reader, const unsigned char *cmd)
{
  struct videoguard_data *csystem_data = reader->csystem_data;
  struct s_CmdTabEntry *pcte=csystem_data->cmd_table->e;
  int32_t i;
  for(i=0; i< csystem_data->cmd_table->Nentries; i++,pcte++)
    if(cmd[1]==pcte->cmd) {
      return 1;
    }
  return 0;
}

int32_t read_cmd_len(struct s_reader * reader, const unsigned char *cmd)
{
  def_resp;
  unsigned char cmd2[5];
  memcpy(cmd2,cmd,5);
  if (cmd2[0] == 0xD3){
     cmd2[0] = 0xD0;
  }
  cmd2[3]=0x80;
  cmd2[4]=1;
  // some card reply with L 91 00 (L being the command length).
  if(!write_cmd_vg(cmd2,NULL) || !status_ok(cta_res+1)|| cta_res[0]==0) {
    if (cta_res[0]==0) {        //some cards reply len=0x00 for not supported ins
      rdr_debug_mask(reader, D_READER, "failed to read %02x%02x cmd length (%02x %02x)",cmd[1],cmd[2],cta_res[1],cta_res[2]);
    } else {                    //others reply only status byte
      rdr_debug_mask(reader, D_READER, "failed to read %02x%02x cmd length (%02x %02x)",cmd[1],cmd[2],cta_res[0],cta_res[1]);
    }
    return -1;
  }
  return cta_res[0];
}

int32_t do_cmd(struct s_reader * reader, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff,
           unsigned char * cta_res)
{
  uint16_t cta_lr;
  unsigned char ins2[5];
  memcpy(ins2,ins,5);
  unsigned char len=0, mode=0;
  if(cmd_table_get_info(reader,ins2,&len,&mode)) {
    if(len==0xFF && mode==2) {
      if(ins2[4]==0) ins2[4]=len=read_cmd_len(reader,ins2);
    }
    else if(mode!=0) ins2[4]=len;
  }
  if(ins2[0]==0xd3) {
    if (ins2[4] == 0) return 0;
    ins2[4]+=16;
  }
  len=ins2[4];
  unsigned char tmp[264];
  if(rxbuff == NULL) rxbuff=tmp;
  if(mode>1) {
    if(!write_cmd_vg(ins2,NULL) || !status_ok(cta_res+len)) return -1;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,cta_res,len);
    memcpy(rxbuff+5+len,cta_res+len,2);
  }
  else {
    if(!write_cmd_vg(ins2,txbuff) || !status_ok(cta_res)) return -2;
    memcpy(rxbuff,ins2,5);
    memcpy(rxbuff+5,txbuff,len);
    memcpy(rxbuff+5+len,cta_res,2);
  }
  cCamCryptVG_PostProcess_Decrypt(reader,rxbuff);

  return len;
}

void rev_date_calc_tm(const unsigned char *Date, struct tm *timeinfo , int32_t base_year)
{
	timeinfo->tm_year = Date[0] / 12 + base_year - 1900; //tm year starts at 1900
	timeinfo->tm_mon  = Date[0] % 12; //tm month starts with 0
	timeinfo->tm_mday = Date[1] & 0x1f;
	timeinfo->tm_hour = Date[2] / 8;
	timeinfo->tm_min = (0x100 * (Date[2] - timeinfo->tm_hour * 8) + Date[3]) / 32;
	timeinfo->tm_sec = (Date[3] - timeinfo->tm_min * 32) * 2;
}

int32_t videoguard_get_emm_type(EMM_PACKET *ep, struct s_reader * rdr)
{

/*
Unique:
82 30 ad 70 00 XX XX XX 00 XX XX XX 00 XX XX XX 00 XX XX XX 00 00
d3 02 00 22 90 20 44 02 4a 50 1d 88 ab 02 ac 79 16 6c df a1 b1 b7 77 00 ba eb 63 b5 c9 a9 30 2b 43 e9 16 a9 d5 14 00
d3 02 00 22 90 20 44 02 13 e3 40 bd 29 e4 90 97 c3 aa 93 db 8d f5 6b e4 92 dd 00 9b 51 03 c9 3d d0 e2 37 44 d3 bf 00
d3 02 00 22 90 20 44 02 97 79 5d 18 96 5f 3a 67 70 55 bb b9 d2 49 31 bd 18 17 2a e9 6f eb d8 76 ec c3 c9 cc 53 39 00
d2 02 00 21 90 1f 44 02 99 6d df 36 54 9c 7c 78 1b 21 54 d9 d4 9f c1 80 3c 46 10 76 aa 75 ef d6 82 27 2e 44 7b 00

Unknown:
82 00 1C 81 02 00 18 90 16 42 01 xx xx xx xx xx
xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
*/

	int32_t i;
	int32_t serial_count = ((ep->emm[3] >> 4) & 3) + 1;
	int32_t serial_len = (ep->emm[3] & 0x80) ? 3 : 4;
	uchar emmtype = (ep->emm[3] & VG_EMMTYPE_MASK) >> 6;

	switch(emmtype) {
		case VG_EMMTYPE_G:
			rdr_debug_mask(rdr, D_EMM, "GLOBAL");
			ep->type=GLOBAL;
			return 1;

		case VG_EMMTYPE_U:
		case VG_EMMTYPE_S:
			rdr_debug_mask(rdr, D_EMM, "%s", (emmtype == VG_EMMTYPE_U) ? "UNIQUE" : "SHARED");
			ep->type=emmtype;
			if (ep->emm[1] == 0) // detected UNIQUE EMM from cccam (there is no serial)
				return 1;

			for (i = 0; i < serial_count; i++) {
				if (!memcmp(&ep->emm[i * 4 + 4], rdr->hexserial + 2, serial_len)) {
					memcpy(ep->hexserial, &ep->emm[i * 4 + 4], serial_len);
					return 1;
				}
			}
			return 0; // if UNIQUE or SHARED but no serial match return FALSE

		default:
			//remote emm without serial
			rdr_debug_mask(rdr, D_EMM, "UNKNOWN");
			ep->type=UNKNOWN;
			return 1;
	}
}

int32_t videoguard_do_emm(struct s_reader * reader, EMM_PACKET *ep, unsigned char CLA,
	void (*read_tiers)(struct s_reader *),
	int32_t (*docmd)(struct s_reader *, const unsigned char *ins, const unsigned char *txbuff, unsigned char *rxbuff, unsigned char *cta_res))
{
   unsigned char cta_res[CTA_RES_LEN];
   unsigned char ins42[5] = { CLA, 0x42, 0x00, 0x00, 0xFF };
   int32_t rc = SKIPPED;
   int32_t nsubs = ((ep->emm[3] & 0x30) >> 4) + 1;
   int32_t offs = 4;
   int32_t emmv2 = 0;
   int32_t position, ua_position = -1;
   int32_t serial_len = (ep->type == SHARED) ? 3: 4;
   int32_t vdrsc_fix = 0;

   if (ep->type == UNIQUE || ep->type == SHARED)
   {
      if (ep->emm[1] == 0x00)  // cccam sends emm-u without UA
      {
         nsubs = 1;
         ua_position = 0;
      }
      else
      {
         int32_t i;
         for (i = 0; i < nsubs; ++i)
         {
            if (memcmp(&ep->emm[4+i*4], &reader->hexserial[2], serial_len) == 0)
            {
               ua_position = i;
               break;
            }
         }
         offs += nsubs * 4;
      }
      if (ua_position == -1)
         return ERROR;
   }
   // if (ep->type == GLOBAL && memcmp(&ep->emm[4], &reader->hexserial[2], 4) == 0)  // workaround for vdr-sc client
   // {
   //    ep->type = UNIQUE;
   //    vdrsc_fix = 1;
   //    offs += 4;
   // }
   if (ep->emm[offs] == 0x00 && (ep->emm[offs+1] == 0x00 || ep->emm[offs+1] == 0x01))  // unmodified emm from dvbapi
   {
      emmv2 = ep->emm[offs+1];
      offs += 2 + 1 + emmv2;  // skip sub-emm len (2 bytes sub-emm len if 0x01);
   }
   for (position = 0; position < nsubs && offs+2 < ep->emmlen; ++position)
   {
      if (ep->emm[offs] > 0x07)  // workaround for mgcamd and emmv2
         ++offs;
      if (ep->emm[offs] == 0x02 || ep->emm[offs] == 0x03 || ep->emm[offs] == 0x07)
      {
         if (ep->emm[offs] == 0x03)
         {
            if (position == ua_position || vdrsc_fix)
            {
               videoguard_mail_msg(reader, &ep->emm[offs+2]);
               return rc;
            }
            else
            {
               offs += ep->emm[offs+1] + 2;
               if (!(offs+1 < ep->emmlen)) return rc;
               if (ep->emm[offs] == 0x00 && (ep->emm[offs+1] == 0x00 || ep->emm[offs+1] == 0x01))
                  offs += 2 + 1 + emmv2;
               continue;
            }
         }
         offs += ep->emm[offs+1] + 2;
         if (!(offs+1 < ep->emmlen)) return rc;
         if (ep->emm[offs] != 0)
         {
            if (ep->type == GLOBAL || vdrsc_fix || position == ua_position)
            {
               ins42[4] = ep->emm[offs];
               int32_t l = (*docmd)(reader, ins42, &ep->emm[offs+1], NULL, cta_res);
               rc = (l > 0 && status_ok(cta_res)) ? OK : ERROR;
               rdr_debug_mask(reader, D_EMM, "request return code : %02X%02X", cta_res[0], cta_res[1]);
               if (status_ok(cta_res) && (cta_res[1] & 0x01))
                  (*read_tiers)(reader);
            }
            offs += ep->emm[offs] + 1;
            if (offs < ep->emmlen && ep->emm[offs] == 0x00) ++offs;
         }
         offs += 1 + emmv2;
         if (vdrsc_fix) --position;
      }
      else
         return rc;
   }
   return rc;
}

int32_t videoguard_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter** emm_filters, unsigned int* filter_count)
{
  if (*emm_filters == NULL) {
    const unsigned int max_filter_count = 7;
    if (!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
      return ERROR;

    struct s_csystem_emm_filter* filters = *emm_filters;
    *filter_count = 0;

    int32_t idx = 0;
    unsigned int n;

    for (n = 0; n < 3; ++n)
    {
      filters[idx].type = EMM_UNIQUE;
      filters[idx].enabled  = 1;
      filters[idx].filter[0] = 0x82;
      filters[idx].mask[0]   = 0xFF;
      filters[idx].filter[1] = 0x40;
      filters[idx].mask[1]   = 0xC0;
      memcpy(&filters[idx].filter[2 + 4 * n], rdr->hexserial + 2, 4);
      memset(&filters[idx].mask[2 + 4 * n], 0xFF, 4);
      idx++;
    }
    // fourth serial position does not fit within the 16bytes demux filter

    for (n = 0; n < 3; ++n)
    {
      filters[idx].type = EMM_SHARED;
      filters[idx].enabled  = 1;
      filters[idx].filter[0] = 0x82;
      filters[idx].mask[0]   = 0xFF;
      filters[idx].filter[1] = 0x80;
      filters[idx].mask[1]   = 0xC0;
      memcpy(&filters[idx].filter[2 + 4 * n], rdr->hexserial + 2, 3);
      memset(&filters[idx].mask[2 + 4 * n], 0xFF, 3);
      idx++;
    }
    // fourth serial position does not fit within the 16bytes demux filter

    filters[idx].type = EMM_GLOBAL;
    filters[idx].enabled  = 1;
    filters[idx].filter[0] = 0x82;
    filters[idx].mask[0]   = 0xFF;
    filters[idx].filter[1] = 0x00;
    filters[idx].mask[1]   = 0xC0;
    idx++;

    *filter_count = idx;
  }

  return OK;
}

static MAILMSG *find_msg(uint16_t caid, uint32_t serial, uint16_t date, uint16_t msg_id)
{
   MAILMSG *msg;
   LL_ITER it = ll_iter_create(vg_msgs);
   while ((msg = (MAILMSG *)ll_iter_next(&it)))
   {
      if (msg->caid == caid && msg->serial == serial && msg->date == date && msg->id == msg_id)
         return msg;
   }
   return 0;
}

static void write_msg(struct s_reader *reader, MAILMSG *msg, uint32_t baseyear)
{
   FILE *fp = fopen(cfg.mailfile, "a");
   if (fp == 0)
   {
      rdr_log(reader, "Cannot open mailfile %s", cfg.mailfile);
      return;
   }

   uint16_t i;
   for (i = 0; i < msg->len - 1; ++i)
   {
      if (msg->message[i] == 0x00 && msg->message[i+1] == 0x32)
      {
         msg->subject = &msg->message[i+3];
         break;
      }
   }
   int32_t year = (msg->date >> 8) / 12 + baseyear;
   int32_t mon = (msg->date >> 8) % 12 + 1;
   int32_t day = msg->date & 0x1f;

   fprintf(fp, "%04X:%08X:%02d/%02d/%04d:%04X:\"%s\":\"%s\"\n", msg->caid, msg->serial, day, mon, year,
                                                                msg->id, msg->subject, msg->message);
   fclose(fp);
   free(msg->message);
   msg->message = msg->subject = 0;
   msg->written = 1;
}

static void msgs_init(uint32_t baseyear)
{
   vg_msgs = ll_create("vg_msgs");
   FILE *fp = fopen(cfg.mailfile, "r");
   if (fp == 0)
      return;
   int32_t year, mon, day;
   char buffer[2048];
   while (fgets(buffer, sizeof(buffer), fp))
   {
      MAILMSG *msg;
      if (!cs_malloc(&msg, sizeof(MAILMSG)))
      {
         fclose(fp);
         return;
      }
      sscanf(buffer, "%04hX:%08X:%02d/%02d/%04d:%04hX", &msg->caid, &msg->serial, &day, &mon, &year, &msg->id);
      year -= baseyear;
      msg->date = ((year * 12) + mon - 1) << 8 | day;
      msg->message = msg->subject = 0;
      msg->written = 1;
      ll_append(vg_msgs, msg);
   }
   fclose(fp);
}

void videoguard_mail_msg(struct s_reader *rdr, uint8_t *data)
{
   if (cfg.disablemail)
      return;

   struct videoguard_data *csystem_data = rdr->csystem_data;
   if (vg_msgs == 0)
      msgs_init(csystem_data->card_baseyear);

   if (data[0] != 0xFF || data[1] != 0xFF)
      return;

   uint16_t msg_id = (data[2] << 8) | data[3];
   uint8_t idx = data[4] & 0x0F;
   int32_t msg_size = data[5] * 10 + 2;
   uint16_t date = (data[9] << 8) | data[10];
   int32_t submsg_len = data[12] - 2;
   uint16_t submsg_idx = (data[13] << 8) | data[14];
   uint32_t serial = (rdr->hexserial[2]<<24) | (rdr->hexserial[3]<<16) | (rdr->hexserial[4]<<8) | rdr->hexserial[5];

   MAILMSG *msg = find_msg(rdr->caid, serial, date, msg_id);

   if (msg == 0)
   {
      if (!cs_malloc(&msg, sizeof(MAILMSG)))
         return;
      msg->caid = rdr->caid;
      msg->serial = serial;
      msg->date = date;
      msg->id = msg_id;
      msg->nsubs = (data[4] & 0xF0) >> 4;
      msg->mask = 1 << idx;
      msg->written = 0;
      msg->len = submsg_len;
      if (!cs_malloc(&msg->message, msg_size))
      {
         free(msg);
         return;
      }
      memset(msg->message, 0, msg_size);
      memcpy(&msg->message[submsg_idx], &data[15], submsg_len);
      msg->subject = 0;
      ll_append(vg_msgs, msg);
   }
   else
   {
      if (msg->written == 1 || msg->mask & (1 << idx))
         return;
      msg->mask |= 1 << idx;
      msg->len += submsg_len;
      memcpy(&msg->message[submsg_idx], &data[15], submsg_len);
   }
   if (msg->mask == (1 << msg->nsubs) - 1)
      write_msg(rdr, msg, csystem_data->card_baseyear);
}
#endif
