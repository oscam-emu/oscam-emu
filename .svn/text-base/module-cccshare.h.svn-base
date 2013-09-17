/*
* module-cccshare.h
*
*  Created on: 26.02.2011
*      Author: schlocke
*/
#ifndef MODULE_CCCSHARE_H_
#define MODULE_CCCSHARE_H_

// In this file put functions that are shared between module-cccam.c and module-cccshare.c

int32_t chk_ident(FTAB *ftab, struct cc_card *card);
int32_t cc_srv_report_cards(struct s_client *cl);
LLIST *get_cardlist(uint16_t caid, LLIST **list);

void cc_free_card(struct cc_card *card);
void cc_free_cardlist(LLIST *card_list, int32_t destroy_list);
int32_t cc_cmd_send(struct s_client *cl, uint8_t *buf, int32_t len, cc_msg_type_t cmd);
int32_t sid_eq(struct cc_srvid *srvid1, struct cc_srvid *srvid2);
int32_t same_card(struct cc_card *card1, struct cc_card *card2);
int32_t same_card2(struct cc_card *card1, struct cc_card *card2, int8_t compare_grp);
void cc_UA_oscam2cccam(uint8_t *in, uint8_t *out, uint16_t caid);
void cc_SA_oscam2cccam(uint8_t *in, uint8_t *out);
void set_card_timeout(struct cc_card *card);

#endif
