#include "globals.h"
#ifdef READER_VIDEOGUARD
#include "cscrypt/md5.h"
#include "oscam-work.h"
#include "reader-common.h"
#include "reader-videoguard-common.h"

static void dimeno_PostProcess_Decrypt(struct s_reader * reader, unsigned char *rxbuff, unsigned char *cw)
{
  struct videoguard_data *csystem_data = reader->csystem_data;
  unsigned char tag,len,len2;
  bool valid_0x55=0;
  unsigned char *body;
  unsigned char buffer[0x10];
  int32_t a=0x13;
  len2=rxbuff[4];
  while(a<len2+5-9)  //  +5 for 5 ins bytes, -9 (body=8 len=1) to prevent memcpy(buffer+8,body,8) from reading past rxbuff
  {
    tag=rxbuff[a];
    len=rxbuff[a+1];
    body=rxbuff+a+2;
    switch(tag)
    {
      case 0x55:{
        if(body[0]==0x84){      //Tag 0x56 has valid data...
          valid_0x55=1;
        }
      }break;
      case 0x56:{
        memcpy(buffer+8,body,8);
      }break;
    }
    a+=len+2;
  }
  if(valid_0x55){
    memcpy(buffer,rxbuff+5,8);
    AES_decrypt(buffer,buffer,&(csystem_data->astrokey));
    memcpy(cw+0,buffer,8);      // copy calculated CW in right place
  }
}

static void do_post_dw_hash(struct s_reader *reader, unsigned char *cw, const unsigned char *ecm_header_data)
{
  int32_t i, ecmi, ecm_header_count;
  unsigned char buffer[0x85]; //original 0x80 but with 0x7D mask applied +8 bytes cw it was still to small
  unsigned char md5tmp[MD5_DIGEST_LENGTH];
  static const uint16_t Hash3[] = {0x0123,0x4567,0x89AB,0xCDEF,0xF861,0xCB52};
  static const unsigned char Hash4[] = {0x0B,0x04,0x07,0x08,0x05,0x09,0x0B,0x0A,0x07,0x02,0x0A,0x05,0x04,0x08,0x0D,0x0F};
  static const uint16_t NdTabB001[0x15][0x20] = {
    {0xEAF1, 0x0237, 0x29D0, 0xBAD2, 0xE9D3, 0x8BAE, 0x2D6D, 0xCD1B,
     0x538D, 0xDE6B, 0xA634, 0xF81A, 0x18B5, 0x5087, 0x14EA, 0x672E,
     0xF0FC, 0x055E, 0x62E5, 0xB78F, 0x5D09, 0x0003, 0xE4E8, 0x2DCE,
     0x6BE0, 0xAC4E, 0xF485, 0x6967, 0xF28C, 0x97A0, 0x01EF, 0x0100},
    {0xC539, 0xF5B9, 0x9099, 0x013A, 0xD4B9, 0x6AB5, 0xEA67, 0x7EB4,
     0x6C30, 0x4BF0, 0xB810, 0xB0B5, 0xB76D, 0xA751, 0x1AE7, 0x14CA,
     0x4F4F, 0x1586, 0x2608, 0x10B1, 0xE7E1, 0x48BE, 0x7DDD, 0x5ECB,
     0xCFBF, 0x323B, 0x8B31, 0xB131, 0x0F1A, 0x664B, 0x0140, 0x0100},
    {0x3C7D, 0xBDC4, 0xFEC7, 0x26A6, 0xB0A0, 0x6E55, 0xF710, 0xF9BF,
     0x0023, 0xE81F, 0x41CA, 0xBE32, 0xB461, 0xE92D, 0xF1AF, 0x409F,
     0xFC85, 0xFE5B, 0x7FCE, 0x17F5, 0x01AB, 0x4A46, 0xEB05, 0xA251,
     0xDC6F, 0xF0C0, 0x10F0, 0x1D51, 0xEFAA, 0xE9BF, 0x0100, 0x0100},
    {0x1819, 0x0CAA, 0x9067, 0x607A, 0x7576, 0x1CBC, 0xE51D, 0xBF77,
     0x7EC6, 0x839E, 0xB695, 0xF096, 0xDC10, 0xCB69, 0x4654, 0x8E68,
     0xD62D, 0x4F1A, 0x4227, 0x92AC, 0x9064, 0x6BD1, 0x1E75, 0x2747,
     0x00DA, 0xA6A6, 0x6CF1, 0xD151, 0xBE56, 0x3E33, 0x0128, 0x0100},
    {0x4091, 0x09ED, 0xD494, 0x6054, 0x1869, 0x71D5, 0xB572, 0x7BF1,
     0xE925, 0xEE2D, 0xEEDE, 0xA13C, 0x6613, 0x9BAB, 0x122D, 0x7AE4,
     0x5268, 0xE6C9, 0x50CB, 0x79A1, 0xF212, 0xA062, 0x6B48, 0x70B3,
     0xF6B0, 0x06D5, 0xF8AB, 0xECF5, 0x6255, 0xEDD8, 0x79D2, 0x290A},
    {0xD3CF, 0x014E, 0xACB3, 0x8F6B, 0x0F2C, 0xA5D8, 0xE8E0, 0x863D,
     0x80D5, 0x5705, 0x658A, 0x8BC2, 0xEE46, 0xD3AE, 0x0199, 0x0100,
     0x4A35, 0xABE4, 0xF976, 0x935A, 0xA8A5, 0xBAE9, 0x24D0, 0x71AA,
     0xB3FE, 0x095E, 0xAB06, 0x4CD5, 0x2F0D, 0x1ACB, 0x59F3, 0x4C50},
    {0xFD27, 0x0F8E, 0x191A, 0xEEE7, 0x2F49, 0x3A05, 0x3267, 0x4F88,
     0x38AE, 0xFCE9, 0x9476, 0x18C6, 0xF961, 0x4EF0, 0x39D0, 0x42E6,
     0xB747, 0xE625, 0xB68E, 0x5100, 0xF92A, 0x86FE, 0xE79B, 0xEE91,
     0x21D5, 0x4C3C, 0x683D, 0x5AD1, 0x1B49, 0xF407, 0x0194, 0x0100},
    {0x4BF9, 0xDC0D, 0x9478, 0x5174, 0xCB4A, 0x8A89, 0x4D6A, 0xFED8,
     0xF123, 0xA8CD, 0xEEE7, 0xA6D1, 0xB763, 0xF5E2, 0xE085, 0x01EF,
     0xE466, 0x9FA3, 0x2F68, 0x2190, 0x423F, 0x287F, 0x7F3F, 0x09F6,
     0x2111, 0xA963, 0xD0BB, 0x674A, 0xBA72, 0x45F9, 0xF186, 0xB8F5},
    {0x0010, 0xD1B9, 0xB164, 0x9E87, 0x1F49, 0x6950, 0x2DBF, 0x38D3,
     0x2EB0, 0x3E8E, 0x91E6, 0xF688, 0x7E41, 0x566E, 0x01B0, 0x0100,
     0x24A1, 0x73D8, 0xA0C3, 0xF71B, 0xA0A5, 0x2A06, 0xBA46, 0xFEC3,
     0xDD4C, 0x52CC, 0xF9BC, 0x3B7E, 0x3812, 0x0666, 0xB74B, 0x40F8},
    {0x28F2, 0x7C81, 0xFC92, 0x6FBD, 0x53D6, 0x72A3, 0xBBDF, 0xB6FC,
     0x9CE5, 0x2331, 0xD4F6, 0xC5BB, 0xE8BB, 0x6676, 0x02D9, 0x2F0E,
     0xD009, 0xD136, 0xCD09, 0x7551, 0x1826, 0x9D9B, 0x63EA, 0xFC63,
     0x68CD, 0x3672, 0xCB95, 0xD28E, 0xF1CD, 0x20CA, 0x014C, 0x0100},
    {0xE539, 0x55B7, 0x989D, 0x21C4, 0x463A, 0xE68F, 0xF8B5, 0xE5C5,
     0x662B, 0x35BF, 0x3C50, 0x0131, 0xF4BF, 0x38B2, 0x41BC, 0xB829,
     0x02B7, 0x6B8F, 0xA25C, 0xAFD2, 0xD84A, 0x2243, 0x53EB, 0xC6C9,
     0x2E14, 0x181F, 0x8F96, 0xDF0E, 0x0D4C, 0x30F6, 0xFFE1, 0x9DDA},
    {0x30B6, 0x777E, 0xDA3D, 0xAF77, 0x205E, 0xC90B, 0x856B, 0xB451,
     0x3BCC, 0x76C2, 0x8ACF, 0xDCB1, 0xA5E5, 0xDD64, 0x0197, 0x0100,
     0xE751, 0xB661, 0x0404, 0xDB4A, 0xE9DD, 0xA400, 0xAF26, 0x3F5E,
     0x904B, 0xA924, 0x09E0, 0xE72B, 0x825B, 0x2C50, 0x6FD0, 0x0D52},
    {0x2730, 0xC2BA, 0x9E44, 0x5815, 0xFC47, 0xB21D, 0x67B8, 0xF8B9,
     0x047D, 0xB0AF, 0x9F14, 0x741B, 0x4668, 0xBE54, 0xDE16, 0xDB14,
     0x7CB7, 0xF2B8, 0x0683, 0x762C, 0x09A0, 0x9507, 0x7F92, 0x022C,
     0xBA6A, 0x7D52, 0x0AF4, 0x1BC3, 0xB46A, 0xC4FD, 0x01C2, 0x0100},
    {0x7611, 0x66F3, 0xEE87, 0xEDD3, 0xC559, 0xEFD4, 0xDC59, 0xF86B,
     0x6D1C, 0x1C85, 0x9BB1, 0x3373, 0x763F, 0x4EBE, 0x1BF3, 0x99B5,
     0xD721, 0x978F, 0xCF5C, 0xAC51, 0x0984, 0x7462, 0x8F0C, 0x2817,
     0x4AD9, 0xFD41, 0x6678, 0x7C85, 0xD330, 0xC9F8, 0x1D9A, 0xC622},
    {0x5AE4, 0xE16A, 0x60F6, 0xFD45, 0x668C, 0x29D6, 0x0285, 0x6B92,
     0x92C2, 0x21DE, 0x45E0, 0xEF3D, 0x8B0D, 0x02CD, 0x0198, 0x0100,
     0x9E6D, 0x4D38, 0xDEF9, 0xE6F2, 0xF72E, 0xB313, 0x14F2, 0x390A,
     0x2D67, 0xC71E, 0xCB69, 0x7F66, 0xD3CF, 0x7F8A, 0x81D9, 0x9DDE},
    {0x85E3, 0x8F29, 0x36EB, 0xC968, 0x3696, 0x59F6, 0x7832, 0xA78B,
     0xA1D8, 0xF5CF, 0xAB64, 0x646D, 0x7A2A, 0xBAF8, 0xAA87, 0x41C7,
     0x5120, 0xDE78, 0x738D, 0xDC1A, 0x268D, 0x5DF8, 0xED69, 0x1C8A,
     0xBC85, 0x3DCD, 0xAE30, 0x0F8D, 0xEC89, 0x3ABD, 0x0166, 0x0100},
    {0xB8BD, 0x643B, 0x748E, 0xBD63, 0xEC6F, 0xE23A, 0x9493, 0xDD76,
     0x0A62, 0x774F, 0xCD68, 0xA67A, 0x9A23, 0xC8A8, 0xBDE5, 0x9D1B,
     0x2B86, 0x8B36, 0x5428, 0x1DFB, 0xCD1D, 0x0713, 0x29C2, 0x8E8E,
     0x5207, 0xA13F, 0x6005, 0x4F5E, 0x52E0, 0xE7C8, 0x6D1C, 0x3E34},
    {0x581D, 0x2BFA, 0x5E1D, 0xA891, 0x1069, 0x1DA4, 0x39A0, 0xBE45,
     0x5B9A, 0x7333, 0x6F3E, 0x8637, 0xA550, 0xC9E9, 0x5C6C, 0x42BA,
     0xA712, 0xC3EA, 0x3808, 0x0910, 0xAA4D, 0x5B25, 0xABCD, 0xE680,
     0x96AD, 0x2CEC, 0x8EBB, 0xA47D, 0x1690, 0xE8FB, 0x01C8, 0x0100},
    {0x73B9, 0x82BC, 0x9EBC, 0xB130, 0x0DA5, 0x8617, 0x9F7B, 0x9766,
     0x205D, 0x752D, 0xB05C, 0x2A17, 0xA75C, 0x18EF, 0x8339, 0xFD34,
     0x8DA2, 0x7970, 0xD0B4, 0x70F1, 0x3765, 0x7380, 0x7CAF, 0x570E,
     0x6440, 0xBC44, 0x0743, 0x2D02, 0x0419, 0xA240, 0x2113, 0x1AD4},
    {0x1EB5, 0xBBFF, 0x39B1, 0x3209, 0x705F, 0x15F4, 0xD7AD, 0x340B,
     0xC2A6, 0x25CA, 0xF412, 0x9570, 0x0F4F, 0xE4D5, 0x1614, 0xE464,
     0x911A, 0x0F0E, 0x07DA, 0xA929, 0x2379, 0xD988, 0x0AA6, 0x3B57,
     0xBF63, 0x71FB, 0x72D5, 0x26CE, 0xB0AF, 0xCF45, 0x011B, 0x0100},
    {0x9999, 0x98FE, 0xA108, 0x6588, 0xF90B, 0x4554, 0xFF38, 0x4642,
     0x8F5F, 0x6CC3, 0x4E8E, 0xFF7E, 0x64C2, 0x50CA, 0x0E7F, 0xAD7D,
     0x6AAB, 0x33C1, 0xE1F4, 0x6165, 0x7894, 0x83B9, 0x0A0C, 0x38AF,
     0x5803, 0x18C0, 0xFA36, 0x592C, 0x4548, 0xABB8, 0x1527, 0xAEE9}
  };


  //ecm_header_data = 01 03 b0 01 01
  if (!cw_is_valid(cw))         //if cw is all zero, keep it that way
  {
    return;
  }
  ecm_header_count = ecm_header_data[0];
  for (i = 0, ecmi = 1; i < ecm_header_count; i++)
  {
    if (ecm_header_data[ecmi + 1] != 0xb0)
    {
      ecmi += ecm_header_data[ecmi] + 1;
    }
    else
    {
      switch (ecm_header_data[ecmi + 2])
      {                         //b0 01
      case 1:
        {
          uint16_t hk[8], r, j, m = 0;
          for (r = 0; r < 6; r++)
            hk[2 + r] = Hash3[r];
          for (r = 0; r < 2; r++)
          {
            for (j = 0; j < 0x48; j += 2)
            {
              if (r)
              {
                hk[0] = ((hk[3] & hk[5]) | ((~hk[5]) & hk[4]));
              }
              else
              {
                hk[0] = ((hk[3] & hk[4]) | ((~hk[3]) & hk[5]));
              }
              if (j < 8)
              {
                hk[0] = (hk[0] + ((cw[j + 1] << 8) | cw[j]));
              }
              if (j == 8)
              {
                hk[0] = (hk[0] + 0x80);
              }
              hk[0] = (hk[0] + hk[2] + (0xFF & NdTabB001[ecm_header_data[ecmi + 3]][m >> 1] >> ((m & 1) << 3)));
              hk[1] = hk[2];
              hk[2] = hk[3];
              hk[3] = hk[4];
              hk[4] = hk[5];
              hk[5] = hk[6];
              hk[6] = hk[7];
              hk[7] = hk[2] + (((hk[0] << Hash4[m & 0xF]) | (hk[0] >> (0x10 - Hash4[m & 0xF]))));
              m = (m + 1) & 0x3F;
            }
          }
          for (r = 0; r < 6; r++)
          {
            hk[2 + r] += Hash3[r];
          }
          for (r = 0; r < 7; r++)
          {
            cw[r] = hk[2 + (r >> 1)] >> ((r & 1) << 3);
          }
          cw[3] = (cw[0] + cw[1] + cw[2]) & 0xFF;
          cw[7] = (cw[4] + cw[5] + cw[6]) & 0xFF;
          rdr_ddump_mask(reader, D_READER, cw, 8, "Postprocessed Case 1 DW:");
          break;
        }
      case 3:
        {
          memset(buffer, 0, sizeof(buffer));
          memcpy(buffer, cw, 8);
          memcpy(buffer + 8, &ecm_header_data[ecmi + 3], ecm_header_data[ecmi]&0x7D);
          MD5(buffer, 8 + (ecm_header_data[ecmi]&0x7D), md5tmp);
          memcpy(cw, md5tmp, 8);
          rdr_ddump_mask(reader, D_READER, cw, 8, "Postprocessed Case 3 DW:");
          break;
        }
      case 2:
        {
          /* Method 2 left out */
          //memcpy(DW_OUTPUT, DW_INPUT, 8);
          break;
        }
      }
    }
  }
}


static void vg2_read_tiers(struct s_reader * reader)
{
  def_resp;
  int32_t l;

  /* ins2a is not needed and causes an error on some cards eg Sky Italy 09CD
     check if ins2a is in command table before running it
  */
  static const unsigned char ins2a[5] = { 0xD0,0x2a,0x00,0x00,0x00 };
  if(cmd_exists(reader,ins2a)) {
    l=do_cmd(reader,ins2a,NULL,NULL,cta_res);
    if(l<0 || !status_ok(cta_res+l)){
      rdr_log(reader, "classD0 ins2a: failed");
      return;
    }
  }

  static const unsigned char ins76007f[5] = { 0xD0,0x76,0x00,0x7f,0x02 };
  if(!write_cmd_vg(ins76007f,NULL) || !status_ok(cta_res+2)){
    rdr_log(reader, "classD0 ins76007f: failed");
    return;
  }
  int32_t num=cta_res[1];

  int32_t i;
  unsigned char ins76[5] = { 0xD0,0x76,0x00,0x00,0x00 };
  struct videoguard_data *csystem_data = reader->csystem_data;

  // some cards start real tiers info in middle of tier info
  // and have blank tiers between old tiers and real tiers eg 09AC
  int32_t starttier = csystem_data->card_tierstart;
  bool stopemptytier = 1;
  if (!starttier)
    stopemptytier = 0;

  // check to see if specified start tier is blank and if blank, start at 0 and ignore blank tiers
  ins76[2]=starttier;
  l=do_cmd(reader,ins76,NULL,NULL,cta_res);
  if(l<0 || !status_ok(cta_res+l)) return;
  if(cta_res[2]==0 && cta_res[3]==0 ){
    stopemptytier = 0;
    starttier = 0;
  }

  cs_clear_entitlement(reader); // reset the entitlements

  for(i=starttier; i<num; i++) {
    ins76[2]=i;
    l=do_cmd(reader,ins76,NULL,NULL,cta_res);
    if(l<0 || !status_ok(cta_res+l)) return;
    if(cta_res[2]==0 && cta_res[3]==0 && stopemptytier) return;
    if(cta_res[2]!=0 || cta_res[3]!=0) {
      char tiername[83];
      uint16_t tier_id = (cta_res[2] << 8) | cta_res[3];
      // add entitlements to list
      struct tm timeinfo;
      memset(&timeinfo, 0, sizeof(struct tm));
      rev_date_calc_tm(&cta_res[4],&timeinfo,csystem_data->card_baseyear);
      cs_add_entitlement(reader, reader->caid, b2ll(4, reader->prid[0]), tier_id, 0, 0, mktime(&timeinfo), 4);

      if(!stopemptytier){
        rdr_debug_mask(reader, D_READER, "tier: %04x, tier-number: 0x%02x",tier_id,i);
      }
      rdr_log(reader, "tier: %04x, expiry date: %04d/%02d/%02d-%02d:%02d:%02d %s",tier_id,timeinfo.tm_year+1900,timeinfo.tm_mon+1,timeinfo.tm_mday,timeinfo.tm_hour,timeinfo.tm_min,timeinfo.tm_sec,get_tiername(tier_id, reader->caid, tiername));
    }
  }
}

static int32_t videoguard2_card_init(struct s_reader * reader, ATR *newatr)
{
  get_hist;
  if ((hist_size < 7) || (hist[1] != 0xB0) || (hist[4] != 0xFF) || (hist[5] != 0x4A) || (hist[6] != 0x50)){
    rdr_debug_mask(reader, D_READER, "failed history check");
    return ERROR;
  }
  rdr_debug_mask(reader, D_READER, "passed history check");

  get_atr;
  def_resp;

  if (!cs_malloc(&reader->csystem_data, sizeof(struct videoguard_data)))
    return ERROR;
  struct videoguard_data *csystem_data = reader->csystem_data;

 /* set information on the card stored in reader-videoguard-common.c */
  set_known_card_info(reader,atr,&atr_size);

  if((reader->ndsversion != NDS2) &&
     (((csystem_data->card_system_version != NDS2) && (csystem_data->card_system_version != NDSUNKNOWN)) ||
      (reader->ndsversion != NDSAUTO))) {
    /* known ATR and not NDS2
       or known NDS2 ATR and forced to another NDS version */
    return ERROR;
  }

  rdr_debug_mask(reader, D_READER, "type: %s, baseyear: %i", csystem_data->card_desc, csystem_data->card_baseyear);
  if(reader->ndsversion == NDS2){
    rdr_debug_mask(reader, D_READER, "forced to NDS2");
  }

  //a non videoguard2/NDS2 card will fail on read_cmd_len(ins7401)
  //this way unknown videoguard2/NDS2 cards will also pass this check

  unsigned char ins7401[5] = { 0xD0,0x74,0x01,0x00,0x00 };
  int32_t l;
  if((l=read_cmd_len(reader,ins7401))<0){ //not a videoguard2/NDS card or communication error
   return ERROR;
  }
  ins7401[4]=l;
  if(!write_cmd_vg(ins7401,NULL) || !status_ok(cta_res+l)) {
    rdr_log(reader, "classD0 ins7401: failed - cmd list not read");
    return ERROR;
  }

  memorize_cmd_table (reader,cta_res,l);

  unsigned char buff[256];

  static const unsigned char ins7416[5] = { 0xD0,0x74,0x16,0x00,0x00 };
  if(do_cmd(reader,ins7416,NULL,NULL,cta_res)<0) {
    rdr_log(reader, "classD0 ins7416: failed");
    return ERROR;
  }

  static const unsigned char ins02[5] = { 0xD0,0x02,0x00,0x00,0x08 };
  // D0 02 command is not always present in command table but should be supported
  // on most cards so do not use do_cmd()
  if(!write_cmd_vg(ins02,NULL) || !status_ok(cta_res+8)){
    rdr_log(reader, "Unable to get NDS ROM version.");
  } else {
    int i;
    for (i = 0; i < 8; i++) {
      if (cta_res[i] <= 0x09) {
        cta_res[i] = cta_res[i] + 0x30;
      } else if (!isalnum(cta_res[i])) {
        cta_res[i] = '*';
      }
    }
    memset(reader->rom, 0, sizeof(reader->rom));
    memcpy(reader->rom, cta_res, 4);
    reader->rom[4] = '-';
    memcpy(reader->rom + 5, cta_res + 4, 4);

    rdr_log(reader, "Card type:   %c%c%c%c", reader->rom[0], reader->rom[1], reader->rom[2],reader->rom[3]);
    rdr_log(reader, "Rom version: %c%c%c%c", reader->rom[5], reader->rom[6], reader->rom[7], reader->rom[8]);
  }


  unsigned char boxID [4];

  if (reader->boxid > 0) {
    /* the boxid is specified in the config */
    int32_t i;
    for (i=0; i < 4; i++) {
        boxID[i] = (reader->boxid >> (8 * (3 - i))) % 0x100;
    }
  } else {
    unsigned char ins36[5] = { 0xD0,0x36,0x00,0x00,0x00 };
    static const unsigned char ins5e[5] = { 0xD0,0x5E,0x00,0x0C,0x02 };

    /* we can try to get the boxid from the card */
    int32_t boxidOK=0;
    l=read_cmd_len(reader,ins36);
    if(l > 0) {
      ins36[4] = l;
    }
    else if(cmd_exists(reader,ins5e)) {
        if(!write_cmd_vg(ins5e,NULL) || !status_ok(cta_res+2)){
          rdr_log(reader, "classD0 ins5e: failed");
        } else {
          ins36[3] = cta_res[0];
          ins36[4] = cta_res[1];
        }
    }
    l=ins36[4];
    if(!write_cmd_vg(ins36,NULL) || !status_ok(cta_res+l)){
       rdr_log(reader, "classD0 ins36: failed");
       return ERROR;
    }
    memcpy(buff,ins36,5);
    memcpy(buff+5,cta_res,l);
    memcpy(buff+5+l,cta_res+l,2);
    if(l<13)
      rdr_log(reader, "classD0 ins36: answer too int16");
    else if (buff[7] > 0x0F)
      rdr_log(reader, "classD0 ins36: encrypted - can't parse");
    else {
      /* skipping the initial fixed fields: cmdecho (4) + length (1) + encr/rev++ (4) */
      int32_t i=9;
      int32_t gotUA=0;
      while (i<l) {
        if (!gotUA && buff[i]<0xF0) { /* then we guess that the next 4 bytes is the UA */
          gotUA=1;
          i+=4;
        } else switch (buff[i]) { /* object length vary depending on type */
            case 0x00: /* padding */
              i+=1;
              break;
            case 0xEF: /* card status */
              i+=3;
              break;
            case 0xD1:
              i+=4;
              break;
            case 0xDF: /* next server contact */
              i+=5;
              break;
            case 0xF3: /* boxID */
              memcpy(boxID,buff+i+1,sizeof(boxID));
              boxidOK=1;
              i+=5;
              break;
            case 0xF6:
              i+=6;
              break;
            case 0x01: /* date & time */
              i+=7;
              break;
            case 0xFA:
              i+=9;
              break;
            case 0x5E:
            case 0x67: /* signature */
            case 0xDE:
            case 0xE2:
            case 0xE9: /* tier dates */
            case 0xF8: /* Old PPV Event Record */
            case 0xFD:
              i+=buff[i+1]+2; /* skip length + 2 bytes (type and length) */
              break;
            default: /* default to assume a length byte */
              rdr_log(reader, "classD0 ins36: returned unknown type=0x%02X - parsing may fail", buff[i]);
              i+=buff[i+1]+2;
        }
      }
    }

    if(!boxidOK) {
      rdr_log(reader, "no boxID available");
      return ERROR;
      }
  }

  static const unsigned char ins4C[5] = { 0xD0,0x4C,0x00,0x00,0x09 };
  unsigned char payload4C[9] = { 0,0,0,0, 3,0,0,0,4 };
  memcpy(payload4C,boxID,4);
  if(!write_cmd_vg(ins4C,payload4C) || !status_ok(cta_res+l)) {
    rdr_log(reader, "classD0 ins4C: failed - sending boxid failed");
    return ERROR;
    }

  //int16_t int32_t SWIRDstatus = cta_res[1];
  static const unsigned char ins58[5] = { 0xD0,0x58,0x00,0x00,0x00 };
  l=do_cmd(reader,ins58,NULL,NULL,cta_res);
  if(l<0) {
    rdr_log(reader, "classD0 ins58: failed");
    return ERROR;
    }
  memset(reader->hexserial, 0, 8);
  memcpy(reader->hexserial+2, cta_res+3, 4);
  memcpy(reader->sa, cta_res+3, 3);
  reader->caid = cta_res[24]*0x100+cta_res[25];

  /* we have one provider, 0x0000 */
  reader->nprov = 1;
  memset(reader->prid, 0x00, sizeof(reader->prid));

  /*
  rdr_log(reader, "INS58 : Fuse byte=0x%02X, IRDStatus=0x%02X", cta_res[2],SWIRDstatus);
  if (SWIRDstatus==4)  {
  // If swMarriage=4, not married then exchange for BC Key
  rdr_log(reader, "Card not married, exchange for BC Keys");
   */

  cCamCryptVG_SetSeed(reader);

  static const unsigned char insB4[5] = { 0xD0,0xB4,0x00,0x00,0x40 };
  unsigned char tbuff[64];
  cCamCryptVG_GetCamKey(reader,tbuff);
  l=do_cmd(reader,insB4,tbuff,NULL,cta_res);
  if(l<0 || !status_ok(cta_res)) {
    rdr_log(reader, "classD0 insB4: failed");
    return ERROR;
    }

  static const unsigned char insBC[5] = { 0xD0,0xBC,0x00,0x00,0x00 };
  l=do_cmd(reader,insBC,NULL,NULL,cta_res);
  if(l<0) {
    rdr_log(reader, "classD0 insBC: failed");
    return ERROR;
    }

  // Class D1/D3 instructions only work after this point

  static const unsigned char insBE[5] = { 0xD3,0xBE,0x00,0x00,0x00 };
  l=do_cmd(reader,insBE,NULL,NULL,cta_res);
  if(l<0) {
    rdr_log(reader, "classD3 insBE: failed");
    return ERROR;
    }

  static const unsigned char ins58a[5] = { 0xD1,0x58,0x00,0x00,0x00 };
  l=do_cmd(reader,ins58a,NULL,NULL,cta_res);
  if(l<0) {
    rdr_log(reader, "classD1 ins58: failed");
    return ERROR;
    }

  static const unsigned char ins4Ca[5] = { 0xD1,0x4C,0x00,0x00,0x00 };
  l=do_cmd(reader,ins4Ca,payload4C,NULL,cta_res);
  if(l<0 || !status_ok(cta_res)) {
    rdr_log(reader, "classD1 ins4Ca: failed");
    return ERROR;
    }

  if (reader->ins7E[0x1A])
  {
    static const uint8_t ins7E[5] = { 0xD1,0x7E,0x10,0x00,0x1A };
    l=do_cmd(reader,ins7E,reader->ins7E,NULL,cta_res);
    if(l<0 || !status_ok(cta_res)) {
      rdr_log(reader, "classD1 ins7E: failed");
      return ERROR;
    }
  }

  if (reader->ins7E11[0x01]) {
    unsigned char ins742b[5] = { 0xD0,0x74,0x2b,0x00,0x00 };
  
    l=read_cmd_len(reader,ins742b);     //get command len for ins742b
  
    if(l<2){
      rdr_log(reader, "No TA1 change for this card is possible by ins7E11");
    } else {
      ins742b[4]=l;
      bool ta1ok=0;

      if(!write_cmd_vg(ins742b,NULL) || !status_ok(cta_res+ins742b[4])) {  //get supported TA1 bytes
        rdr_log(reader, "classD0 ins742b: failed");
        return ERROR;
      } else {
        int32_t i;
  
        for (i=2; i < l; i++) {
          if (cta_res[i]==reader->ins7E11[0x00]) {
            ta1ok=1;
            break;
          }
        }
      }
      if(ta1ok==0) {
        rdr_log(reader, "The value %02X of ins7E11 is not supported,try one between %02X and %02X",reader->ins7E11[0x00],cta_res[2],cta_res[ins742b[4]-1]);
      } else {
        static const uint8_t ins7E11[5] = { 0xD0,0x7E,0x11,0x00,0x01 };
    
        reader->ins7e11_fast_reset = 0;
    
        l=do_cmd(reader,ins7E11,reader->ins7E11,NULL,cta_res);
    
        if(l<0 || !status_ok(cta_res)) {
          rdr_log(reader, "classD0 ins7E11: failed");
          return ERROR;
        }
        else {
          unsigned char TA1;
    
          if (ATR_GetInterfaceByte (newatr, 1, ATR_INTERFACE_BYTE_TA, &TA1) == ATR_OK) {
            if (TA1 != reader->ins7E11[0x00]) {
              rdr_log(reader, "classD0 ins7E11: Scheduling card reset for TA1 change from %02X to %02X", TA1, reader->ins7E11[0x00]);
              reader->ins7e11_fast_reset = 1;
    #ifdef WITH_COOLAPI
              if (reader->typ == R_MOUSE || reader->typ == R_SC8in1 || reader->typ == R_SMART || reader->typ == R_INTERNAL) {
    #else
              if (reader->typ == R_MOUSE || reader->typ == R_SC8in1 || reader->typ == R_SMART) {
    #endif
                add_job(reader->client, ACTION_READER_RESET_FAST, NULL, 0);
              }
              else {
                add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
              }
              return OK; // Skip the rest of the init since the card will be reset anyway
            }
          }
        }
      }
    }
  }

  /* get parental lock settings */
  static const unsigned char ins74e[5] = {0xD0,0x74,0x0E,0x00,0x00};
  if(cmd_exists(reader,ins74e)) {
    l=do_cmd(reader,ins74e,NULL,NULL,cta_res);
    if (l<0 || !status_ok(cta_res+l)) {
      rdr_log(reader, "classD0 ins74e: failed to get parental lock settings");
    } else {
      char tmp[l>0?l*3:1];
      rdr_log(reader, "parental lock setting: %s",cs_hexdump(1, cta_res+2, l-2, tmp, sizeof(tmp)));
    }
  }

  /* disable parental lock */
  static const uchar ins2e[5] = {0xD0, 0x2E, 0x00, 0x00, 0x04};
  static const uchar payload2e[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  if(cfg.ulparent) {
    if(cmd_exists(reader,ins74e) && write_cmd_vg(ins2e,payload2e) && status_ok(cta_res+l)) {
      rdr_log(reader, "parental lock disabled");
    }else{
      rdr_log(reader, "cannot disable parental lock");
    }
    if(cmd_exists(reader,ins74e)) {
      l=do_cmd(reader,ins74e,NULL,NULL,cta_res);
      if (l<0 || !status_ok(cta_res+l)) {
        rdr_log(reader, "classD0 ins74e: failed to get parental lock settings");
      } else {
        char tmp[l>0?l*3:1];
        rdr_log(reader, "parental lock setting after disabling: %s",cs_hexdump(1, cta_res+2, l-2, tmp, sizeof(tmp)));
      }
    }
  }

  // fix for 09ac cards
  unsigned char dimeno_magic[0x10]={0xF9,0xFB,0xCD,0x5A,0x76,0xB5,0xC4,0x5C,0xC8,0x2E,0x1D,0xE1,0xCC,0x5B,0x6B,0x02};
  int32_t a;
  for(a=0; a<4; a++)
    dimeno_magic[a]=dimeno_magic[a]^boxID[a];
  AES_set_decrypt_key(dimeno_magic,128,&(csystem_data->astrokey));

  rdr_log(reader, "type: %s, caid: %04X",
         csystem_data->card_desc,
         reader->caid);
  rdr_log_sensitive(reader, "serial: {%02X%02X%02X%02X}, BoxID: {%02X%02X%02X%02X}, baseyear: %i",
         reader->hexserial[2],reader->hexserial[3],reader->hexserial[4],reader->hexserial[5],
         boxID[0],boxID[1],boxID[2],boxID[3],
         csystem_data->card_baseyear);
  rdr_log(reader, "ready for requests");

  return OK;
}

static int32_t videoguard2_do_ecm(struct s_reader * reader, const ECM_REQUEST *er, struct s_ecm_answer *ea)
{
  unsigned char cta_res[CTA_RES_LEN];
  static const char valid_ecm[] = { 0x00, 0x00, 0x01 };
  unsigned char ins40[5] = { 0xD1,0x40,0x00,0x80,0xFF };
  static const unsigned char ins54[5] = { 0xD3,0x54,0x00,0x00,0x00};
  int32_t posECMpart2=er->ecm[6]+7;
  int32_t lenECMpart2=er->ecm[posECMpart2]+1;
  unsigned char tbuff[264], rbuff[264];
  tbuff[0]=0;

  memset(ea->cw+0,0,16); //set cw to 0 so client will know it is invalid unless it is overwritten with a valid cw

  if (memcmp(&(er->ecm[3]), valid_ecm, sizeof(valid_ecm) != 0))
  {
    rdr_log(reader, "Not a valid ecm");
    return ERROR;
  }

  memcpy(tbuff+1,er->ecm+posECMpart2+1,lenECMpart2-1);

/*
  //log parental lock byte
  int32_t j;
  for (j = posECMpart2+1; j < lenECMpart2+posECMpart2+1-4; j++){
    if (er->ecm[j] == 0x02 && er->ecm[j+3] == 0x02) {
      rdr_log(reader, "channel parental lock mask: %02X%02X, channel parental lock byte: %02X",er->ecm[j+1],er->ecm[j+2],er->ecm[j+4]);
      break;
    }
  }

  //log tiers
  int32_t k;
  char tiername[83];
  for (k = posECMpart2+1; k < lenECMpart2+posECMpart2+1-4; k++){
    if (er->ecm[k] == 0x03 && er->ecm[k+3] == 0x80) {
      uint16_t vtier_id = (er->ecm[k+1] << 8) | er->ecm[k+2];
      get_tiername(vtier_id, reader->caid, tiername);
      rdr_log(reader, "valid tier: %04x %s",vtier_id, tiername);
    }
  }
*/

  int32_t new_len = lenECMpart2;
  if (reader->fix_9993 && reader->caid == 0x919 && tbuff[1] == 0x7F)
  {
     tbuff[1] = 0x47; tbuff[2] = 0x08;
     memmove(tbuff+11, tbuff+13, new_len-11);
     new_len -= 2;
  }
  ins40[4]=new_len;
  int32_t l;

  l = do_cmd(reader,ins40,tbuff,NULL,cta_res);
  if(l<0 || !status_ok(cta_res)) {
    rdr_log(reader, "classD0 ins40: (%d) status not ok %02x %02x",l,cta_res[0],cta_res[1]);
    rdr_log(reader, "The card is not answering correctly! Restarting reader for safety");
    add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
    return ERROR;
  } else {
    l = do_cmd(reader,ins54,NULL,rbuff,cta_res);
    if(l<0 || !status_ok(cta_res+l)) {
      rdr_log(reader, "classD3 ins54: (%d) status not ok %02x %02x",l,cta_res[0],cta_res[1]);
      rdr_log(reader, "The card is not answering correctly! Restarting reader for safety");
      add_job(reader->client, ACTION_READER_RESTART, NULL, 0);
      return ERROR;
    } else {

      // Log decrypted INS54
      rdr_ddump_mask(reader, D_READER, rbuff, 5, "INS54:");
      rdr_ddump_mask(reader, D_READER, rbuff + 5, rbuff[4], "Decrypted payload");

      if (!cw_is_valid(rbuff+5)){ //sky cards report 90 00 = ok but send cw = 00 when channel not subscribed
        rdr_log(reader, "classD3 ins54: status 90 00 = ok but cw=00 -> channel not subscribed " );
        return ERROR;
      }

      // copy cw1 in place
      memcpy(ea->cw+0,rbuff+5,8);

      // process cw2
      unsigned char *payload = rbuff+5;
      int32_t payloadLen = rbuff[4];
      int32_t ind=8+6;   // +8 for CW1, +6 for counter(?)

      while(ind<payloadLen) {
        switch(payload[ind])
        {
          case 0x25:  // CW2
            //cs_dump (payload + ind, payload[ind+1]+2, "INS54 - CW2");
            memcpy(ea->cw+8,&payload[ind+3],8);
            ind += payload[ind+1]+2;
            break;

          default:
            //cs_dump (payload + ind, payload[ind+1]+2, "INS54");
            ind += payload[ind+1]+2;
            break;
        }
      }

      if (new_len != lenECMpart2)
      {
         memcpy(ea->cw, ea->cw+8, 8);
         memset(ea->cw+8, 0, 8);
      }
      // fix for 09ac cards
      dimeno_PostProcess_Decrypt(reader, rbuff, ea->cw);

      //test for postprocessing marker
      int32_t posB0 = -1;
      int32_t i;
      for (i = 6; i < posECMpart2; i++){
        if (er->ecm[i-3] == 0x80 && er->ecm[i] == 0xB0 && ((er->ecm[i+1] == 0x01) ||(er->ecm[i+1] == 0x02)||(er->ecm[i+1] == 0x03) ) ) {
          posB0 = i;
          break;
        }
      }
      if (posB0 != -1) {
        do_post_dw_hash(reader, ea->cw+0, &er->ecm[posB0-2]);
        do_post_dw_hash(reader, ea->cw+8, &er->ecm[posB0-2]);
      }

      if (reader->caid == 0x0907) { //quickfix: cw2 is not a valid cw, something went wrong before
        memset(ea->cw+8, 0, 8);
        if (er->ecm[0] & 1) {
          memcpy(ea->cw+8, ea->cw, 8);
          memset(ea->cw, 0, 8);
        }
      } else {
        if(er->ecm[0]&1) {
          unsigned char tmpcw[8];
          memcpy(tmpcw,ea->cw+8,8);
          memcpy(ea->cw+8,ea->cw+0,8);
          memcpy(ea->cw+0,tmpcw,8);
        }
      }

      return OK;
    }
  }
}

static int32_t videoguard2_do_emm(struct s_reader * reader, EMM_PACKET *ep)
{
   return videoguard_do_emm(reader, ep, 0xD1, vg2_read_tiers, do_cmd);
}

static int32_t videoguard2_card_info(struct s_reader * reader)
{
  /* info is displayed in init, or when processing info */
  struct videoguard_data *csystem_data = reader->csystem_data;
  rdr_log(reader, "card detected");
  rdr_log(reader, "type: %s", csystem_data->card_desc);
  if (reader->ins7e11_fast_reset != 1) {
	  vg2_read_tiers(reader);
  }
  return OK;
}

void reader_videoguard2(struct s_cardsystem *ph)
{
  ph->do_emm=videoguard2_do_emm;
  ph->do_ecm=videoguard2_do_ecm;
  ph->card_info=videoguard2_card_info;
  ph->card_init=videoguard2_card_init;
  ph->get_emm_type=videoguard_get_emm_type;
  ph->get_emm_filter=videoguard_get_emm_filter;
  ph->caids[0]=0x09;
  ph->desc="videoguard2";
}
#endif

