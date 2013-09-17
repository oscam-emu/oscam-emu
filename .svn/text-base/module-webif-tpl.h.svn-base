#ifndef MODULE_WEBIF_TPL_H_
#define MODULE_WEBIF_TPL_H_

#ifdef WEBIF

/* Templates: Adds a variable. The variable can be used as often as wanted. */
#define TPLADD 0
/* Templates: Appends a variable or adds it if doesn't exist yet. The variable can be used as often as wanted. */
#define TPLAPPEND 1
/* Templates: Adds a variable which will be reset to "" after being used once, either through tpl_getVar or when used in a template.
   tpl_addVar/tpl_printf don't do a reset and will overwrite the appendmode with a new value. */
#define TPLADDONCE 2
/* Templates: Appends a variable or adds it if doesn't exist yet. The variable will be reset to "" after being used once. See TPLADDONCE for details. */
#define TPLAPPENDONCE 3

#define TOUCH_SUBDIR "touch/"

struct templatevars {
	uint32_t varscnt;
	uint32_t varsalloc;
	uint32_t tmpcnt;
	uint32_t tmpalloc;
	char **names;
	char **values;
	uint8_t *vartypes;
	char **tmp;
	uint8_t messages;
};

void    webif_tpls_prepare(void);
void    webif_tpls_free(void);

struct templatevars *tpl_create(void);
void                 tpl_clear(struct templatevars *vars);

char    *tpl_addVar(struct templatevars *vars, uint8_t addmode, char *name, char *value);
char    *tpl_addMsg(struct templatevars *vars, char *value);
char    *tpl_addTmp(struct templatevars *vars, char *value);
char    *tpl_printf(struct templatevars *vars, uint8_t addmode, char *varname, char *fmtstring, ...) __attribute__ ((format (printf, 4, 5)));

char    *tpl_getVar(struct templatevars *vars, char *name);
char    *tpl_getFilePathInSubdir(const char *path, const char* subdir, const char *name, const char* ext, char *result, uint32_t resultsize);
char    *tpl_getTplPath(const char *name, const char *path, char *result, uint32_t resultsize);
char    *tpl_getTpl(struct templatevars *vars, const char* name);
char    *tpl_getUnparsedTpl(const char* name, int8_t removeHeader, const char* subdir);

int32_t tpl_saveIncludedTpls(const char *path);

void    tpl_checkOneDirDiskRevisions(const char* subdir);
void    tpl_checkDiskRevisions(void);

char    *urlencode(struct templatevars *vars, char *str);
char    *xml_encode(struct templatevars *vars, char *chartoencode);
char    *sec2timeformat(struct templatevars *vars, int32_t seconds);

#else
static inline void webif_tpls_free(void) { return; }
#endif

#endif
