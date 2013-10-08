#include "globals.h"
#include "oscam-conf.h"
#include "oscam-config.h"
#include "oscam-files.h"
#include "oscam-garbage.h"
#include "oscam-string.h"

#define CONFVARWIDTH 30

/* Returns the default value if string length is zero, otherwise atoi is called*/
int32_t strToIntVal(char *value, int32_t defaultvalue)
{
	if(strlen(value) == 0) { return defaultvalue; }
	errno = 0; // errno should be set to 0 before calling strtol
	int32_t i = strtol(value, NULL, 10);
	return (errno == 0) ? i : defaultvalue;
}

/* Returns the default value if string length is zero, otherwise strtoul is called*/
uint32_t strToUIntVal(char *value, uint32_t defaultvalue)
{
	if(strlen(value) == 0) { return defaultvalue; }
	errno = 0; // errno should be set to 0 before calling strtoul
	uint32_t i = strtoul(value, NULL, 10);
	return (errno == 0) ? i : defaultvalue;
}

/* Replacement of fprintf which adds necessary whitespace to fill up the varname to a fixed width.
  If varname is longer than CONFVARWIDTH, no whitespace is added*/
void fprintf_conf(FILE *f, const char *varname, const char *fmtstring, ...)
{
	int32_t varlen = strlen(varname);
	int32_t max = (varlen > CONFVARWIDTH) ? varlen : CONFVARWIDTH;
	char varnamebuf[max + 3];
	char *ptr = varnamebuf + varlen;
	va_list argptr;

	cs_strncpy(varnamebuf, varname, sizeof(varnamebuf));
	while(varlen < CONFVARWIDTH)
	{
		ptr[0] = ' ';
		++ptr;
		++varlen;
	}
	cs_strncpy(ptr, "= ", sizeof(varnamebuf) - (ptr - varnamebuf));
	if(fwrite(varnamebuf, sizeof(char), strlen(varnamebuf), f))
	{
		if(strlen(fmtstring) > 0)
		{
			va_start(argptr, fmtstring);
			vfprintf(f, fmtstring, argptr);
			va_end(argptr);
		}
	}
}

int config_list_parse(const struct config_list *clist, const char *token, char *value, void *config_data)
{
	const struct config_list *c;
	for(c = clist; c->opt_type != OPT_UNKNOWN; c++)
	{
		if(c->opt_type == OPT_SAVE_FUNC || c->opt_type == OPT_FIXUP_FUNC)
			{ continue; }
		if(strcasecmp(token, c->config_name) != 0)
			{ continue; }
		void *var = config_data + c->var_offset;
		switch(c->opt_type)
		{
		case OPT_INT8:
		{
			*(int8_t *)var = (int8_t)strToIntVal(value, c->def.d_int8);
			return 1;
		}
		case OPT_UINT8:
		{
			uint32_t tmp = strToUIntVal(value, c->def.d_uint8);
			*(uint8_t *)var = (uint8_t)(tmp <= 0xff ? tmp : 0xff);
			return 1;
		}
		case OPT_INT32:
		{
			*(int32_t *)var = strToIntVal(value, c->def.d_int32);
			return 1;
		}
		case OPT_UINT32:
		{
			*(uint32_t *)var = strToUIntVal(value, c->def.d_uint32);
			return 1;
		}
		case OPT_STRING:
		{
			char **scfg = var;
			if(c->def.d_char && strlen(value) == 0)  // Set default
				{ value = c->def.d_char; }
			NULLFREE(*scfg);
			if(strlen(value))
				{ *scfg = cs_strdup(value); }
			return 1;
		}
		case OPT_SSTRING:
		{
			char *scfg = var;
			if(c->def.d_char && strlen(value) == 0)  // Set default
				{ value = c->def.d_char; }
			scfg[0] = '\0';
			unsigned int len = strlen(value);
			if(len)
			{
				strncpy(scfg, value, c->str_size - 1);
				if(len > c->str_size)
				{
					fprintf(stderr, "WARNING: Config value for '%s' (%s, len=%u) exceeds max length: %d (%s)\n",
							token, value, len, c->str_size - 1, scfg);
				}
			}
			return 1;
		}
		case OPT_HEX_ARRAY:
		{
			uint8_t *hex_array = var;
			if(!strlen(value))
				{ memset(hex_array, 0, c->def.array_size); }
			else if(key_atob_l(value, hex_array, c->def.array_size * 2))
			{
				memset(hex_array, 0, c->def.array_size);
				fprintf(stderr, "WARNING: Config value for '%s' (%s, len=%zu) requires %d chars.\n",
						token, value, strlen(value), c->def.array_size * 2);
			}
			return 1;
		}
		case OPT_FUNC:
		{
			c->ops.process_fn(token, value, var, NULL);
			return 1;
		}
		case OPT_FUNC_EXTRA:
		{
			c->ops.process_fn_extra(token, value, var, c->def.d_extra, NULL);
			return 1;
		}
		case OPT_FIXUP_FUNC:
		case OPT_SAVE_FUNC:
			return 1;
		case OPT_UNKNOWN:
		{
			fprintf(stderr, "Unknown config type (%s = %s).", token, value);
			break;
		}
		}
	}
	return 0;
}

void config_list_save_ex(FILE *f, const struct config_list *clist, void *config_data, int save_all,
						 bool (*check_func)(const struct config_list *clist, void *config_data, const char *setting))
{
	const struct config_list *c;
	for(c = clist; c->opt_type != OPT_UNKNOWN; c++)
	{
		void *var = config_data + c->var_offset;
		if(check_func && c->opt_type != OPT_UNKNOWN)
		{
			if(!check_func(clist, config_data, c->config_name))
				{ continue; }
		}
		switch(c->opt_type)
		{
		case OPT_INT8:
		{
			int8_t val = *(int8_t *)var;
			if(save_all || val != c->def.d_int8)
				{ fprintf_conf(f, c->config_name, "%d\n", val); }
			continue;
		}
		case OPT_UINT8:
		{
			uint8_t val = *(uint8_t *)var;
			if(save_all || val != c->def.d_uint8)
				{ fprintf_conf(f, c->config_name, "%u\n", val); }
			continue;
		}
		case OPT_INT32:
		{
			int32_t val = *(int32_t *)var;
			if(save_all || val != c->def.d_int32)
				{ fprintf_conf(f, c->config_name, "%d\n", val); }
			continue;
		}
		case OPT_UINT32:
		{
			uint32_t val = *(uint32_t *)var;
			if(save_all || val != c->def.d_uint32)
				{ fprintf_conf(f, c->config_name, "%u\n", val); }
			continue;
		}
		case OPT_STRING:
		{
			char **val = var;
			if(save_all || !streq(*val, c->def.d_char))
			{
				fprintf_conf(f, c->config_name, "%s\n", *val ? *val : "");
			}
			continue;
		}
		case OPT_SSTRING:
		{
			char *val = var;
			if(save_all || !streq(val, c->def.d_char))
			{
				fprintf_conf(f, c->config_name, "%s\n", val[0] ? val : "");
			}
			continue;
		}
		case OPT_HEX_ARRAY:
		{
			uint8_t *hex_array = var;
			uint32_t ok = check_filled(hex_array, c->def.array_size);
			if(save_all || ok)
			{
				fprintf_conf(f, c->config_name, "%s", ""); // it should not have \n at the end
				if(ok)
				{
					for(ok = 0; ok < c->def.array_size; ok++)
					{
						fprintf(f, "%02X", hex_array[ok]);
					}
				}
				fprintf(f, "\n");
			}
			continue;
		}
		case OPT_FUNC:
		{
			c->ops.process_fn((const char *)c->config_name, NULL, var, f);
			continue;
		}
		case OPT_FUNC_EXTRA:
		{
			c->ops.process_fn_extra((const char *)c->config_name, NULL, var, c->def.d_extra, f);
			continue;
		}
		case OPT_FIXUP_FUNC:
		case OPT_SAVE_FUNC:
			continue;
		case OPT_UNKNOWN:
			break;
		}
	}
}

bool config_list_should_be_saved(const struct config_list *clist, void *var)
{
	const struct config_list *c;
	for(c = clist; c->opt_type != OPT_UNKNOWN; c++)
	{
		if(c->opt_type == OPT_SAVE_FUNC)
		{
			return c->ops.should_save_fn(var);
		}
	}
	return true;
}

void config_list_apply_fixups(const struct config_list *clist, void *var)
{
	const struct config_list *c;
	for(c = clist; c->opt_type != OPT_UNKNOWN; c++)
	{
		if(c->opt_type == OPT_FIXUP_FUNC)
		{
			c->ops.fixup_fn(var);
			break;
		}
	}
}

void config_list_set_defaults(const struct config_list *clist, void *config_data)
{
	const struct config_list *c;
	for(c = clist; c->opt_type != OPT_UNKNOWN; c++)
	{
		void *var = config_data + c->var_offset;
		switch(c->opt_type)
		{
		case OPT_INT8:
		{
			*(int8_t *)var = c->def.d_int8;
			break;
		}
		case OPT_UINT8:
		{
			*(uint8_t *)var = c->def.d_uint8;
			break;
		}
		case OPT_INT32:
		{
			*(int32_t *)var = c->def.d_int32;
			break;
		}
		case OPT_UINT32:
		{
			*(uint32_t *)var = c->def.d_uint32;
			break;
		}
		case OPT_STRING:
		{
			char **scfg = var;
			NULLFREE(*scfg);
			if(c->def.d_char)
				{ *scfg = cs_strdup(c->def.d_char); }
			break;
		}
		case OPT_SSTRING:
		{
			char *scfg = var;
			scfg[0] = '\0';
			if(c->def.d_char && strlen(c->def.d_char))
				{ cs_strncpy(scfg, c->def.d_char, c->str_size); }
			break;
		}
		case OPT_HEX_ARRAY:
		{
			uint8_t *hex_array = var;
			memset(hex_array, 0, c->def.array_size);
			break;
		}
		case OPT_FUNC:
		{
			c->ops.process_fn((const char *)c->config_name, "", var, NULL);
			break;
		}
		case OPT_FUNC_EXTRA:
		{
			c->ops.process_fn_extra((const char *)c->config_name, "", var, c->def.d_extra, NULL);
			break;
		}
		case OPT_SAVE_FUNC:
		case OPT_FIXUP_FUNC:
		case OPT_UNKNOWN:
			continue;
		}
	}
	return;
}

void config_list_free_values(const struct config_list *clist, void *config_data)
{
	const struct config_list *c;
	for(c = clist; c->opt_type != OPT_UNKNOWN; c++)
	{
		void *var = config_data + c->var_offset;
		if(c->opt_type == OPT_STRING)
		{
			char **scfg = var;
			NULLFREE(*scfg);
		}
		if(c->free_value && (c->opt_type == OPT_FUNC || c->opt_type == OPT_FUNC_EXTRA))
		{
			c->free_value(var);
		}
	}
	return;
}

void config_list_gc_values(const struct config_list *clist, void *config_data)
{
	const struct config_list *c;
	for(c = clist; c->opt_type != OPT_UNKNOWN; c++)
	{
		void *var = config_data + c->var_offset;
		if(c->opt_type == OPT_STRING)
		{
			char **scfg = var;
			add_garbage(*scfg);
		}
	}
	return;
}

int config_section_is_active(const struct config_sections *sec)
{
	if(!sec)
		{ return 0; }
	if(sec->config[0].opt_type == OPT_UNKNOWN)
		{ return 0; }
	return 1;
}

const struct config_sections *config_find_section(const struct config_sections *conf, char *section_name)
{
	const struct config_sections *sec;
	for(sec = conf; sec && sec->section; sec++)
	{
		if(streq(section_name, sec->section))
		{
			return sec;
		}
	}
	return NULL;
}

void config_sections_save(const struct config_sections *conf, FILE *f, void *var)
{
	const struct config_sections *sec;
	for(sec = conf; sec && sec->section; sec++)
	{
		if(config_section_is_active(sec) && config_list_should_be_saved(sec->config, var))
		{
			fprintf(f, "[%s]\n", sec->section);
			config_list_apply_fixups(sec->config, var);
			config_list_save(f, sec->config, var, cfg.http_full_cfg);
			fprintf(f, "\n");
		}
	}
}

void config_sections_set_defaults(const struct config_sections *conf, void *var)
{
	const struct config_sections *sec;
	for(sec = conf; sec && sec->section; sec++)
	{
		if(config_section_is_active(sec))
			{ config_list_set_defaults(sec->config, var); }
	}
}

void config_sections_free(const struct config_sections *conf, void *var)
{
	const struct config_sections *sec;
	for(sec = conf; sec && sec->section; sec++)
	{
		if(config_section_is_active(sec))
		{
			config_list_free_values(sec->config, var);
		}
	}
}

void config_set_value(const struct config_sections *conf, char *section, const char *token, char *value, void *var)
{
	const struct config_sections *sec = config_find_section(conf, section);
	if(!sec)
	{
		fprintf(stderr, "WARNING: Unknown section '%s'.\n", section);
		return;
	}
	if(config_section_is_active(sec))
	{
		if(!config_list_parse(sec->config, token, value, var))
		{
			fprintf(stderr, "WARNING: In section [%s] unknown setting '%s=%s' tried.\n",
					section, token, value);
		}
	}
	else
	{
		fprintf(stderr, "WARNING: Section is not active '%s'.\n", section);
	}
}

static FILE *__open_config_file(const char *conf_filename, bool die_on_err)
{
	char filename[256];
	FILE *f = fopen(get_config_filename(filename, sizeof(filename), conf_filename), "r");
	if(!f)
	{
		if(die_on_err)
		{
			fprintf(stderr, "ERROR: Cannot open file \"%s\" (errno=%d %s)", filename, errno, strerror(errno));
			fprintf(stderr, "\n");
			exit(1);
		}
		else
		{
			cs_debug_mask(D_TRACE, "INFO: Cannot open file \"%s\" (errno=%d %s)", filename, errno, strerror(errno));
		}
		return NULL;
	}
	return f;
}

FILE *open_config_file(const char *conf_filename)
{
	return __open_config_file(conf_filename, false);
}

FILE *open_config_file_or_die(const char *conf_filename)
{
	return __open_config_file(conf_filename, true);
}


FILE *create_config_file(const char *conf_filename)
{
	char temp_file[256];
	get_config_filename(temp_file, sizeof(temp_file), conf_filename);
	strncat(temp_file, ".tmp", sizeof(temp_file) - strlen(temp_file) - 1);
	FILE *f = fopen(temp_file, "w");
	if(!f)
	{
		cs_log("ERROR: Cannot create file \"%s\" (errno=%d %s)", temp_file, errno, strerror(errno));
		return NULL;
	}
	setvbuf(f, NULL, _IOFBF, 16 * 1024);
	fprintf(f, "# %s generated automatically by Streamboard OSCAM %s SVN r%s\n",
			conf_filename, CS_VERSION, CS_SVN_VERSION);
	fprintf(f, "# Read more: http://www.streamboard.tv/svn/oscam/trunk/Distribution/doc/txt/%s.txt\n\n",
			conf_filename);
	return f;
}

bool flush_config_file(FILE *f, const char *conf_filename)
{
	char dst_file[256], tmp_file[256], bak_file[256];
	get_config_filename(dst_file, sizeof(dst_file), conf_filename);
	memcpy(tmp_file, dst_file, sizeof(tmp_file));
	memcpy(bak_file, dst_file, sizeof(bak_file));
	strncat(tmp_file, ".tmp", sizeof(tmp_file) - strlen(tmp_file) - 1);
	strncat(bak_file, ".bak", sizeof(bak_file) - strlen(bak_file) - 1);
	fclose(f);
	return safe_overwrite_with_bak(dst_file, tmp_file, bak_file, 0);
}
