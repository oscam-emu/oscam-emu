#ifndef CSCTAPI_CARDREADERS_H_
#define CSCTAPI_CARDREADERS_H_

void cardreader_db2com(struct s_cardreader *crdr);
void cardreader_internal_sci(struct s_cardreader *crdr);
void cardreader_internal_cool(struct s_cardreader *crdr);
void cardreader_internal_azbox(struct s_cardreader *crdr);
void cardreader_mp35(struct s_cardreader *crdr);
void cardreader_mouse(struct s_cardreader *crdr);
void cardreader_pcsc(struct s_cardreader *crdr);
void cardreader_sc8in1(struct s_cardreader *crdr);
void cardreader_smargo(struct s_cardreader *crdr);
void cardreader_smartreader(struct s_cardreader *crdr);
void cardreader_stapi(struct s_cardreader *crdr);

#endif
