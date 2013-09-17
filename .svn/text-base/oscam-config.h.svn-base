#ifndef OSCAM_CONFIG_H_
#define OSCAM_CONFIG_H_

char *get_config_filename(char *dest, size_t destlen, const char *filename);

int32_t init_config(void);
void    config_set(char *section, const char *token, char *value);
void    config_free(void);
int32_t write_config(void);

void    chk_account(const char *token, char *value, struct s_auth *account);
void    account_set_defaults(struct s_auth *auth);
int32_t init_free_userdb(struct s_auth *auth);
struct s_auth *init_userdb(void);
int32_t write_userdb(void);
void    cs_accounts_chk(void);

void    chk_reader(char *token, char *value, struct s_reader *rdr);
void    reader_set_defaults(struct s_reader *rdr);
int32_t init_readerdb(void);
void    free_reader(struct s_reader *rdr);
int32_t free_readerdb(void);
int32_t write_server(void);

void    chk_sidtab(char *token, char *value, struct s_sidtab *sidtab);
int32_t init_sidtab(void);
void    init_free_sidtab(void);
void    free_sidtab(struct s_sidtab *sidtab);
int32_t write_services(void);

int32_t chk_global_whitelist(ECM_REQUEST *er, uint32_t *line);
void    global_whitelist_read(void);
struct ecmrl get_ratelimit(ECM_REQUEST *er); // get ratelimits for ecm request (if available)
void ratelimit_read(void);
int32_t init_provid(void);
int32_t init_srvid(void);
int32_t init_tierid(void);
void    init_len4caid(void);

/* Shared parser functions */
void check_caidtab_fn(const char *token, char *value, void *setting, FILE *f);
void cacheex_valuetab_fn(const char *token, char *value, void *setting, FILE *f);
void cacheex_hitvaluetab_fn(const char *token, char *value, void *setting, FILE *f);
void class_fn(const char *token, char *value, void *setting, FILE *f);
void group_fn(const char *token, char *value, void *setting, FILE *f);
void services_fn(const char *token, char *value, void *setting, FILE *f);

enum ftab_fn {
	FTAB_ACCOUNT = 0x01,
	FTAB_READER  = 0x02,
	FTAB_PROVID  = 0x04,
	FTAB_CHID    = 0x08,
	FTAB_FBPCAID = 0x10,
};

void ftab_fn(const char *token, char *value, void *setting, long ftab_type, FILE *f);

#endif
