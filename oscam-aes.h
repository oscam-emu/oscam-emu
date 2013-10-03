#ifndef OSCAM_AES_H_
#define OSCAM_AES_H_

void aes_set_key(struct aes_keys *aes, char *key);
void aes_decrypt(struct aes_keys *aes, uchar *buf, int32_t n);
void aes_encrypt_idx(struct aes_keys *aes, uchar *buf, int32_t n);

void add_aes_entry(AES_ENTRY **list, uint16_t caid, uint32_t ident, int32_t keyid, uchar *aesKey);
void parse_aes_entry(AES_ENTRY **list, char *label, char *value);
void aes_clear_entries(AES_ENTRY **list);
void parse_aes_keys(struct s_reader *rdr, char *value);
int32_t aes_decrypt_from_list(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid, uchar *buf, int32_t n);
int32_t aes_present(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid);

#endif
