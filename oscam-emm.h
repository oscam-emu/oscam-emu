#ifndef OSCAM_EMM_H_
#define OSCAM_EMM_H_

int32_t emm_reader_match(struct s_reader *reader, uint16_t caid, uint32_t provid);
void do_emm(struct s_client *client, EMM_PACKET *ep);
int32_t reader_do_emm(struct s_reader *reader, EMM_PACKET *ep);
void do_emm_from_file(struct s_reader *reader);
void emm_sort_nanos(unsigned char *dest, const unsigned char *src, int32_t len);

#endif
