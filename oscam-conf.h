#ifndef OSCAM_CONF_H
#define OSCAM_CONF_H

#define MAXLINESIZE 16384

enum opt_types
{
	OPT_UNKNOWN = 0,
	OPT_INT8,
	OPT_UINT8,
	OPT_INT32,
	OPT_UINT32,
	OPT_STRING,
	OPT_SSTRING,
	OPT_HEX_ARRAY,
	OPT_FUNC,
	OPT_FUNC_EXTRA,
	OPT_SAVE_FUNC,
	OPT_FIXUP_FUNC,
};

struct config_list
{
	enum opt_types  opt_type;
	char            *config_name;
	size_t          var_offset;
	unsigned int    str_size;
	union
	{
		int8_t          d_int8;
		uint8_t         d_uint8;
		int32_t         d_int32;
		uint32_t        d_uint32;
		char            *d_char;
		long            d_extra;
		uint32_t        array_size;
	} def;
	union
	{
		void (*process_fn)(const char *token, char *value, void *setting, FILE *config_file);
		void (*process_fn_extra)(const char *token, char *value, void *setting, long extra, FILE *config_file);
		bool (*should_save_fn)(void *var);
		void (*fixup_fn)(void *var);
	} ops;
	void (*free_value)(void *setting);
};

#define DEF_OPT_INT8(__name, __var_ofs, __default) \
    { \
        .opt_type       = OPT_INT8, \
                          .config_name    = __name, \
                                            .var_offset     = __var_ofs, \
                                                    .def.d_int8     = __default \
    }

#define DEF_OPT_UINT8(__name, __var_ofs, __default) \
    { \
        .opt_type       = OPT_UINT8, \
                          .config_name    = __name, \
                                            .var_offset     = __var_ofs, \
                                                    .def.d_uint8    = __default \
    }

#define DEF_OPT_INT32(__name, __var_ofs, __default) \
    { \
        .opt_type       = OPT_INT32, \
                          .config_name    = __name, \
                                            .var_offset     = __var_ofs, \
                                                    .def.d_int32    = __default \
    }

#define DEF_OPT_UINT32(__name, __var_ofs, __default) \
    { \
        .opt_type       = OPT_UINT32, \
                          .config_name    = __name, \
                                            .var_offset     = __var_ofs, \
                                                    .def.d_uint32   = __default \
    }

#define DEF_OPT_STR(__name, __var_ofs, __default) \
    { \
        .opt_type       = OPT_STRING, \
                          .config_name    = __name, \
                                            .var_offset     = __var_ofs, \
                                                    .def.d_char     = __default \
    }

#define DEF_OPT_SSTR(__name, __var_ofs, __default, __str_size) \
    { \
        .opt_type       = OPT_SSTRING, \
                          .config_name    = __name, \
                                            .var_offset     = __var_ofs, \
                                                    .str_size       = __str_size, \
                                                            .def.d_char     = __default \
    }

#define DEF_OPT_HEX(__name, __var_ofs, __array_size) \
    { \
        .opt_type       = OPT_HEX_ARRAY, \
                          .config_name    = __name, \
                                            .var_offset     = __var_ofs, \
                                                    .def.array_size = __array_size \
    }

#define DEF_OPT_FUNC(__name, __var_ofs, __process_fn, ...) \
    { \
        .opt_type       = OPT_FUNC, \
                          .config_name    = __name, \
                                            .var_offset     = __var_ofs, \
                                                    .ops.process_fn = __process_fn, \
                                                            ##__VA_ARGS__ \
    }

#define DEF_OPT_FUNC_X(__name, __var_ofs, __process_fn_extra, __extra, ...) \
    { \
        .opt_type       = OPT_FUNC_EXTRA, \
                          .config_name    = __name, \
                                            .var_offset     = __var_ofs, \
                                                    .ops.process_fn_extra   = __process_fn_extra, \
                                                            .def.d_extra    = __extra, \
                                                                    ##__VA_ARGS__ \
    }

#define DEF_OPT_SAVE_FUNC(__fn) \
    { \
        .opt_type           = OPT_SAVE_FUNC, \
                              .ops.should_save_fn = __fn \
    }

#define DEF_OPT_FIXUP_FUNC(__fn) \
    { \
        .opt_type       = OPT_FIXUP_FUNC, \
                          .ops.fixup_fn   = __fn \
    }

#define DEF_LAST_OPT \
    { \
        .opt_type       = OPT_UNKNOWN \
    }

struct config_sections
{
	const char                  *section;
	const struct config_list    *config;
};

int32_t  strToIntVal(char *value, int32_t defaultvalue);
uint32_t strToUIntVal(char *value, uint32_t defaultvalue);

void fprintf_conf(FILE *f, const char *varname, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

int  config_list_parse(const struct config_list *clist, const char *token, char *value, void *config_data);
void config_list_save_ex(FILE *f, const struct config_list *clist, void *config_data, int save_all,
						 bool (*check_func)(const struct config_list *clist, void *config_data, const char *setting)
						);
static inline void config_list_save(FILE *f, const struct config_list *clist, void *config_data, int save_all)
{
	config_list_save_ex(f, clist, config_data, save_all, NULL);
}
void config_list_apply_fixups(const struct config_list *clist, void *var);
bool config_list_should_be_saved(const struct config_list *clist, void *var);
void config_list_set_defaults(const struct config_list *clist, void *config_data);
void config_list_free_values(const struct config_list *clist, void *config_data);
void config_list_gc_values(const struct config_list *clist, void *config_data);

int config_section_is_active(const struct config_sections *sec);
const struct config_sections *config_find_section(const struct config_sections *conf, char *section_name);
void config_sections_save(const struct config_sections *conf, FILE *f, void *var);
void config_sections_set_defaults(const struct config_sections *conf, void *var);
void config_sections_free(const struct config_sections *conf, void *var);

void config_set_value(const struct config_sections *conf, char *section, const char *token, char *value, void *var);

FILE *open_config_file(const char *conf_filename);
FILE *open_config_file_or_die(const char *conf_filename);
FILE *create_config_file(const char *conf_filename);
bool flush_config_file(FILE *f, const char *conf_filename);

#endif
