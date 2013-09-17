#include "globals.h"

#ifdef WEBIF
#include "webif/pages.h"
#include "module-webif-tpl.h"
#include "oscam-files.h"
#include "oscam-string.h"
#ifdef COMPRESSED_TEMPLATES
#include "minilzo/minilzo.h"
#endif

extern uint8_t cs_http_use_utf8;

/* struct template templates[] that comes from webif/pages.c is recreated as
   struct tpl tpls[] because we need to add additional fields such as tpl_name_hash
   and possibly preprocess templates[] struct before using it. */

struct tpl {
	uint32_t tpl_name_hash;
	const char *tpl_name;
	const char *tpl_data;
	const char *tpl_deps;
	char *extra_data;
	uint32_t tpl_data_len;
	uint8_t tpl_type;
};

static struct tpl *tpls;
static char *tpls_data;
static int tpls_count;

static void tpl_init_base64(struct tpl *tpl) {
	// The rest of OSCam expects images to be base64 encoded and contain mime type.
	if (!template_is_image(tpl->tpl_type))
		return;
	size_t b64_buf_len = 32 + BASE64_LENGTH(tpl->tpl_data_len); // Enough for base64 and 32 for header (data:XXX;base64,)
	char *b64_buf;
	if (!cs_malloc(&b64_buf, b64_buf_len)) {
		tpl->tpl_data = "";
		tpl->tpl_data_len = 0;
		return;
	}
	int hdr_len = snprintf(b64_buf, b64_buf_len, "data:%s;base64,", template_get_mimetype(tpl->tpl_type));
	base64_encode(tpl->tpl_data, tpl->tpl_data_len, b64_buf + hdr_len, b64_buf_len - hdr_len);
	tpl->tpl_data = tpl->extra_data = b64_buf;
	tpl->tpl_data_len = strlen(b64_buf);
}

void webif_tpls_prepare(void) {
	int i;
	const struct template *templates = templates_get();
	tpls_count = templates_count();
	if (!cs_malloc(&tpls, tpls_count * sizeof(struct tpl))) {
		tpls_count = 0;
		return;
	}
#ifdef COMPRESSED_TEMPLATES
	const char *templates_cdata;
	size_t tpls_data_len, tpls_data_olen;
	templates_get_data(&templates_cdata, &tpls_data_len, &tpls_data_olen);
	if (!cs_malloc(&tpls_data, tpls_data_olen)) {
		tpls_count = 0;
		return;
	}

	lzo_uint new_len = tpls_data_olen;
	int r = lzo1x_decompress_safe((uint8_t *)templates_cdata, tpls_data_len, (uint8_t *)tpls_data, &new_len, NULL);
	if (r == LZO_E_OK && new_len == tpls_data_olen) {
		cs_log("webif: decompressed %zu bytes back into %zu bytes", tpls_data_len, tpls_data_olen);
	} else {
		/* this should NEVER happen */
		cs_log("internal error - decompression failed: %d\n", r);
		free(tpls);
		tpls_count = 0;
	}

	for(i = 0; i < tpls_count; ++i) {
		tpls[i].tpl_name      = tpls_data + templates[i].tpl_name_ofs;
		tpls[i].tpl_data      = tpls_data + templates[i].tpl_data_ofs;
		tpls[i].tpl_deps      = tpls_data + templates[i].tpl_deps_ofs;
		tpls[i].tpl_data_len  = templates[i].tpl_data_len;
		tpls[i].tpl_type      = templates[i].tpl_type;
		tpls[i].tpl_name_hash = jhash(tpls[i].tpl_name, strlen(tpls[i].tpl_name));
		tpl_init_base64(&tpls[i]);
	}
#else
	for(i = 0; i < tpls_count; ++i) {
		tpls[i].tpl_name_hash = jhash(templates[i].tpl_name, strlen(templates[i].tpl_name));
		tpls[i].tpl_name      = templates[i].tpl_name;
		tpls[i].tpl_data      = templates[i].tpl_data;
		tpls[i].tpl_deps      = templates[i].tpl_deps;
		tpls[i].tpl_data_len  = templates[i].tpl_data_len;
		tpls[i].tpl_type      = templates[i].tpl_type;
		tpl_init_base64(&tpls[i]);
	}
#endif
}

void webif_tpls_free(void) {
	int32_t i;
	for(i = 0; i < tpls_count; ++i) {
		free(tpls[i].extra_data);
	}
	free(tpls_data);
	free(tpls);
}

/* Adds a name->value-mapping or appends to it. You will get a reference back which you may freely
   use (but you should not call free/realloc on this!)*/
char *tpl_addVar(struct templatevars *vars, uint8_t addmode, char *name, char *value){
	if (name == NULL) return "";
	if (value == NULL) value = "";
	int32_t i;
	char *tmp = NULL, *result = NULL;
	for(i = (*vars).varscnt-1; i >= 0; --i) {
		if (strcmp((*vars).names[i], name) == 0) {
			result = (*vars).values[i];
			break;
		}
	}
	if (result == NULL) {
		if ((*vars).varsalloc <= (*vars).varscnt) {
			if (!cs_realloc(&(*vars).names, (*vars).varsalloc * 2 * sizeof(char**))) return "";
			if (!cs_realloc(&(*vars).values, (*vars).varsalloc * 2 * sizeof(char**))) return "";
			if (!cs_realloc(&(*vars).vartypes, (*vars).varsalloc * 2 * sizeof(uint8_t*))) return "";
			(*vars).varsalloc = (*vars).varscnt * 2;
		}
		int32_t len = strlen(name) + 1;
		if (!cs_malloc(&tmp, len)) return "";
		memcpy(tmp, name, len);
		(*vars).names[(*vars).varscnt] = tmp;
		len = strlen(value) + 1;
		if (!cs_malloc(&tmp, len)) {
			free((*vars).names[(*vars).varscnt]);
			return "";
		}
		memcpy(tmp, value, len);
		(*vars).values[(*vars).varscnt] = tmp;
		(*vars).vartypes[(*vars).varscnt] = addmode;
		(*vars).varscnt++;
	} else {
		int32_t oldlen = 0, newlen = strlen(value);
		if (addmode == TPLAPPEND || addmode == TPLAPPENDONCE) oldlen = strlen((*vars).values[i]);
		if (!cs_realloc(&((*vars).values[i]), oldlen + newlen + 1)) return value;
		memcpy((*vars).values[i] + oldlen, value, newlen + 1);
		(*vars).vartypes[i] = addmode;
	}
	return tmp;
}

/* Adds a message to be output on the page using the TPLMESSAGE template. */
char *tpl_addMsg(struct templatevars *vars, char *value) {
	tpl_addVar(vars, TPLADDONCE, "MESSAGE", value);
	(*vars).messages++;
	return tpl_addVar(vars, TPLAPPEND, "MESSAGES", tpl_getTpl(vars, "MESSAGEBIT"));
}

/* Allows to add a char array which has been allocated by malloc. It will automatically get
  freed when calling tpl_clear(). Please do NOT free the memory yourself or realloc
  it after having added the array here! */
char *tpl_addTmp(struct templatevars *vars, char *value) {
	if (value == NULL) return "";
	if ((*vars).tmpalloc <= (*vars).tmpcnt) {
		if (!cs_realloc(&(*vars).tmp, (*vars).tmpalloc * 2 * sizeof(char**))) return value;
		(*vars).tmpalloc = (*vars).tmpcnt * 2;
	}
	(*vars).tmp[(*vars).tmpcnt] = value;
	(*vars).tmpcnt++;
	return value;
}

/* Allows to do a dynamic printf without knowing and defining the needed memory size. If you specify
   varname, the printf-result will be added/appended to the varlist, if varname=NULL it will only be returned.
   In either case you will always get a reference back which you may freely use (but you should not call
   free/realloc on this as it will be automatically cleaned!)*/
char *tpl_printf(struct templatevars *vars, uint8_t addmode, char *varname, char *fmtstring, ...) {
	uint32_t needed;
	char test[1];
	va_list argptr;

	va_start(argptr,fmtstring);
	needed = vsnprintf(test, 1, fmtstring, argptr);
	va_end(argptr);

	char *result;
	if (!cs_malloc(&result, needed + 1)) return "";
	va_start(argptr,fmtstring);
	vsnprintf(result, needed + 1, fmtstring, argptr);
	va_end(argptr);

	if (varname == NULL) tpl_addTmp(vars, result);
	else {
		char *tmp = tpl_addVar(vars, addmode, varname, result);
		free(result);
		result = tmp;
	}
	return result;
}

/* Returns the value for a name or an empty string if nothing was found. */
char *tpl_getVar(struct templatevars *vars, char *name) {
	int32_t i;
	char *result = NULL;
	for(i = (*vars).varscnt-1; i >= 0; --i) {
		if (strcmp((*vars).names[i], name) == 0) {
			result = (*vars).values[i];
			break;
		}
	}
	if (result == NULL) return "";
	else {
		if ((*vars).vartypes[i] == TPLADDONCE || (*vars).vartypes[i] == TPLAPPENDONCE) {
			// This is a one-time-use variable which gets cleaned up automatically after retrieving it
			if (!cs_malloc(&(*vars).values[i], 1)) {
				(*vars).values[i] = result;
				result[0] = '\0';
				return result;
			} else {
				(*vars).values[i][0] = '\0';
				return tpl_addTmp(vars, result);
			}
		} else return result;
	}
}

/* Initializes all variables for a templatevar-structure and returns a pointer to it. Make
   sure to call tpl_clear() when you are finished or you'll run into a memory leak! */
struct templatevars *tpl_create(void) {
	struct templatevars *vars;
	if (!cs_malloc(&vars, sizeof(struct templatevars))) return NULL;
	(*vars).varsalloc = 64;
	(*vars).varscnt = 0;
	(*vars).tmpalloc = 64;
	(*vars).tmpcnt = 0;
	if (!cs_malloc(&(*vars).names, (*vars).varsalloc * sizeof(char**))) {
		free(vars);
		return NULL;
	}
	if (!cs_malloc(&(*vars).values, (*vars).varsalloc * sizeof(char**))) {
		free((*vars).names);
		free(vars);
		return NULL;
	}
	if (!cs_malloc(&(*vars).vartypes, (*vars).varsalloc * sizeof(uint8_t*))) {
		free((*vars).names);
		free((*vars).values);
		free(vars);
		return NULL;
	}
	if (!cs_malloc(&(*vars).tmp, (*vars).tmpalloc * sizeof(char**))) {
		free((*vars).names);
		free((*vars).values);
		free((*vars).vartypes);
		free(vars);
		return NULL;
	}
	return vars;
}

/* Clears all allocated memory for the specified templatevar-structure. */
void tpl_clear(struct templatevars *vars) {
	int32_t i;
	for(i = (*vars).varscnt-1; i >= 0; --i) {
		free((*vars).names[i]);
		free((*vars).values[i]);
	}
	free((*vars).names);
	free((*vars).values);
	free((*vars).vartypes);
	for(i = (*vars).tmpcnt-1; i >= 0; --i) {
		free((*vars).tmp[i]);
	}
	free((*vars).tmp);
	free(vars);
}

/* Creates a path to a template file. You need to set the resultsize to the correct size of result. */
char *tpl_getFilePathInSubdir(const char *path, const char* subdir, const char *name, const char* ext, char *result, uint32_t resultsize) {
	int path_len = strlen(path);
	const char *path_fixup = "";
	if (path_len && path[path_len - 1] != '/')
		path_fixup = "/";
	if (path_len + strlen(path_fixup) + strlen(name) + strlen(subdir) + strlen(ext) < resultsize) {
		snprintf(result, resultsize, "%s%s%s%s%s", path, path_fixup, subdir, name, ext);
	} else result[0] = '\0';
	return result;
}

char *tpl_getTplPath(const char *name, const char *path, char *result, uint32_t resultsize) {
	return tpl_getFilePathInSubdir(path, "", name, ".tpl", result,  resultsize);
}

#define check_conf(CONFIG_VAR, text) \
	if (config_enabled(CONFIG_VAR) && strncmp(#CONFIG_VAR, text, len) == 0) { ok = 1; break; }

/* Returns an unparsed template either from disk or from internal templates.
   Note: You must free() the result after using it and you may get NULL if an error occured!*/
char *tpl_getUnparsedTpl(const char* name, int8_t removeHeader, const char* subdir) {
	int32_t i;
	char *result;

	if (cfg.http_tpl) {
		char path[255];
		if ((strlen(tpl_getFilePathInSubdir(cfg.http_tpl, subdir, name, ".tpl", path, 255)) > 0 && file_exists(path))
		     || (strlen(subdir) > 0
#ifdef TOUCH
		     && strcmp(subdir, TOUCH_SUBDIR)
#endif
		     && strlen(tpl_getFilePathInSubdir(cfg.http_tpl, ""    , name, ".tpl", path, 255)) > 0 && file_exists(path)))
		{
			FILE *fp;
			char buffer[1025];
			memset(buffer, 0, sizeof(buffer));
			int32_t readen, allocated = 1025, offset, size = 0;
			if (!cs_malloc(&result, allocated)) return NULL;
			if ((fp = fopen(path,"r"))!=NULL) {
			// Use as read size sizeof(buffer) - 1 to ensure that buffer is
			// zero terminated otherwise strstr can segfault!
			while((readen = fread(buffer, 1, sizeof(buffer) - 1, fp)) > 0) {
				offset = 0;
				if (size == 0 && removeHeader) {
					/* Remove version string from output and check if it is valid for output */
					char *pch1 = strstr(buffer,"<!--OSCam");
					if (pch1 != NULL) {
						char *pch2 = strstr(pch1,"-->");
						if (pch2 != NULL) {
							offset = pch2 - buffer + 4;
							readen -= offset;
							pch2[0] = '\0';
							char *ptr1, *ptr2, *saveptr1 = NULL, *saveptr2 = NULL;
							for (i = 0, ptr1 = strtok_r(pch1 + 10, ";", &saveptr1); (ptr1) && i < 4 ; ptr1 = strtok_r(NULL, ";", &saveptr1), i++)
							{
								if (i == 3 && strlen(ptr1) > 2) {
									int8_t ok = 0;
									for (ptr2 = strtok_r(ptr1, ",", &saveptr2); (ptr2) && ok == 0 ; ptr2 = strtok_r(NULL, ",", &saveptr2))
									{
										size_t len = strlen(ptr2);
										check_conf(WITH_CARDREADER, ptr2);
										check_conf(CARDREADER_PHOENIX, ptr2);
										check_conf(CARDREADER_INTERNAL_AZBOX, ptr2);
										check_conf(CARDREADER_INTERNAL_COOLAPI, ptr2);
										check_conf(CARDREADER_INTERNAL_SCI, ptr2);
										check_conf(CARDREADER_SC8IN1, ptr2);
										check_conf(CARDREADER_MP35, ptr2);
										check_conf(CARDREADER_SMARGO, ptr2);
										check_conf(CARDREADER_PCSC, ptr2);
										check_conf(CARDREADER_SMART, ptr2);
										check_conf(CARDREADER_DB2COM, ptr2);
										check_conf(CARDREADER_STAPI, ptr2);
										check_conf(TOUCH, ptr2);
										check_conf(CS_ANTICASC, ptr2);
										check_conf(CS_CACHEEX, ptr2);
										check_conf(HAVE_DVBAPI, ptr2);
										check_conf(IPV6SUPPORT, ptr2);
										check_conf(IRDETO_GUESSING, ptr2);
										check_conf(LCDSUPPORT, ptr2);
										check_conf(LEDSUPPORT, ptr2);
										check_conf(MODULE_CAMD33, ptr2);
										check_conf(MODULE_CAMD35, ptr2);
										check_conf(MODULE_CAMD35_TCP, ptr2);
										check_conf(MODULE_CCCAM, ptr2);
										check_conf(MODULE_CCCSHARE, ptr2);
										check_conf(MODULE_CONSTCW, ptr2);
										check_conf(MODULE_GBOX, ptr2);
										check_conf(MODULE_GHTTP, ptr2);
										check_conf(MODULE_MONITOR, ptr2);
										check_conf(MODULE_NEWCAMD, ptr2);
										check_conf(MODULE_PANDORA, ptr2);
										check_conf(MODULE_RADEGAST, ptr2);
										check_conf(MODULE_SERIAL, ptr2);
										check_conf(READER_BULCRYPT, ptr2);
										check_conf(READER_CONAX, ptr2);
										check_conf(READER_CRYPTOWORKS, ptr2);
										check_conf(READER_GRIFFIN, ptr2);
										check_conf(READER_DGCRYPT, ptr2);
										check_conf(READER_DRE, ptr2);
										check_conf(READER_IRDETO, ptr2);
										check_conf(READER_NAGRA, ptr2);
										check_conf(READER_SECA, ptr2);
										check_conf(READER_TONGFANG, ptr2);
										check_conf(READER_VIACCESS, ptr2);
										check_conf(READER_VIDEOGUARD, ptr2);
										check_conf(WITH_CARDREADER, ptr2);
										check_conf(WITH_DEBUG, ptr2);
										check_conf(WITH_LB, ptr2);
										check_conf(WITH_LIBCRYPTO, ptr2);
										check_conf(WITH_SSL, ptr2);
										check_conf(WITH_STAPI, ptr2);
									} // for
									if (ok == 0){
										fclose (fp);
										return result;
									}
									break;
								} // if
							} // for
						} // if
					} // if
				} // if
				if (allocated < size + readen + 1) {
					allocated += size + 1024;
					if (!cs_realloc(&result, allocated)) {
						fclose (fp);
						return NULL;
					}
				}
				memcpy(result + size, buffer + offset, readen);
				size += readen;
			} // while
			result[size] = '\0';
			fclose (fp);
			return result;
			} // if
		} // if
	} // if

	bool found = 0;
	uint32_t name_hash = jhash(name, strlen(name));
	for(i = 0; i < tpls_count; i++) {
		if (tpls[i].tpl_name_hash == name_hash) {
			found = 1;
			break;
		}
	}

	if (found) {
		const struct tpl *tpl = &tpls[i];
		if (!cs_malloc(&result, tpl->tpl_data_len + 1)) return NULL; // +1 to accomodate \0 at the end
		memcpy(result, tpl->tpl_data, tpl->tpl_data_len);
	} else {
		if (!cs_malloc(&result, 1)) return NULL; // Return empty string
	}
	return result;
}

/* Returns the specified template with all variables/other templates replaced or an
   empty string if the template doesn't exist. Do not free the result yourself, it
   will get automatically cleaned up! */
char *tpl_getTpl(struct templatevars *vars, const char* name) {
	char *tplorg = tpl_getUnparsedTpl(name, 1, tpl_getVar(vars, "SUBDIR"));
	if (!tplorg) return "";
	char *tplend = tplorg + strlen(tplorg);
	char *pch, *pch2, *tpl=tplorg;
	char varname[33];

	int32_t tmp,respos = 0;
	int32_t allocated = 2 * strlen(tpl) + 1;
	char *result;
	if (!cs_malloc(&result, allocated)) return "";

	while(tpl < tplend) {
		if (tpl[0] == '#' && tpl[1] == '#' && tpl[2] != '#') {
			pch2 = tpl;
			pch = tpl + 2;
			while(pch[0] != '\0' && (pch[0] != '#' || pch[1] != '#')) ++pch;
			if (pch - pch2 < 32 && pch[0] == '#' && pch[1] == '#') {
				memcpy(varname, pch2 + 2, pch - pch2 - 2);
				varname[pch - pch2 - 2] = '\0';
				if (strncmp(varname, "TPL", 3) == 0) {
					if ((*vars).messages > 0 || strncmp(varname, "TPLMESSAGE", 10) != 0)
						pch2 = tpl_getTpl(vars, varname + 3);
					else pch2 = "";
				} else {
					pch2 = tpl_getVar(vars, varname);
				}
				tmp = strlen(pch2);
				if (tmp + respos + 2 >= allocated) {
					allocated = tmp + respos + 256;
					if (!cs_realloc(&result, allocated)) return "";
				}
				memcpy(result + respos, pch2, tmp);
				respos += tmp;
				tpl = pch + 2;
			}
		} else {
			if (respos + 2 >= allocated) {
				allocated = respos + 256;
				if (!cs_realloc(&result, allocated)) return "";
			}
			result[respos] = tpl[0];
			++respos;
			++tpl;
		}
	}
	free(tplorg);
	result[respos] = '\0';
	tpl_addTmp(vars, result);
	return result;
}

/* Saves all templates to the specified paths. Existing files will be overwritten! */
int32_t tpl_saveIncludedTpls(const char *path) {
	int32_t i, cnt = 0;
	char tmp[256];
	FILE *fp;
	for (i = 0; i < tpls_count; ++i) {
		const struct tpl *tpl = &tpls[i];
		if (strlen(tpl_getTplPath(tpl->tpl_name, path, tmp, 256)) > 0 && (fp = fopen(tmp,"w")) != NULL) {
			if (strncmp(tpl->tpl_name, "IC", 2) != 0) {
				fprintf(fp, "<!--OSCam;%lu;%s;%s;%s-->\n", crc32(0L, (unsigned char *)tpl->tpl_data, tpl->tpl_data_len), CS_VERSION, CS_SVN_VERSION, tpl->tpl_deps);
			}
			fwrite(tpl->tpl_data, tpl->tpl_data_len, 1, fp);
			fclose (fp);
			++cnt;
		}
	}
	return cnt;
}

/* Checks all disk templates in a directory if they are still current or may need upgrade! */
void tpl_checkOneDirDiskRevisions(const char* subdir) {
	char dirpath[255] = "\0";
	snprintf(dirpath, 255, "%s%s", cfg.http_tpl ? cfg.http_tpl : "", subdir);
	int32_t i;
	char path[255];
	for(i = 0; i < tpls_count; ++i) {
		const struct tpl *tpl = &tpls[i];
		if (strncmp(tpl->tpl_name, "IC", 2) != 0 && strlen(tpl_getTplPath(tpl->tpl_name, dirpath, path, 255)) > 0 && file_exists(path)) {
			int8_t error = 1;
			char *tplorg = tpl_getUnparsedTpl(tpl->tpl_name, 0, subdir);
			unsigned long checksum = 0, curchecksum = crc32(0L, (unsigned char*)tpl->tpl_data, tpl->tpl_data_len);
			char *ifdefs = "", *pch1 = strstr(tplorg,"<!--OSCam");
			if (pch1 != NULL) {
				char *version = "?", *revision = "?";
				char *pch2 = strstr(pch1,"-->");
				if (pch2 != NULL) {
					pch2[0] = '\0';
					int32_t j;
					char *ptr1, *saveptr1 = NULL;
					for (j = 0, ptr1 = strtok_r(pch1 + 10, ";", &saveptr1); (ptr1) && j < 4 ; ptr1 = strtok_r(NULL, ";", &saveptr1), j++) {
						if (j == 0) checksum = strtoul(ptr1, NULL, 10);
						else if (j == 1) version = ptr1;
						else if (j == 2) revision = ptr1;
						else if (j == 3) ifdefs = ptr1;
					}
				}
				if (checksum != curchecksum) {
					cs_log("WARNING: Your http disk template %s was created for an older revision of OSCam and was changed in original OSCam (%s,r%s). Please consider upgrading it!", path, version, revision);
				} else error = 0;
			} else cs_log("WARNING: Your http disk template %s is in the old template format without revision info. Please consider upgrading it!", path);
			if (error) cs_log("If you are sure that it is current, add the following line at the beginning of the template to suppress this warning: <!--OSCam;%lu;%s;%s;%s-->", curchecksum, CS_VERSION, CS_SVN_VERSION, ifdefs);
			free(tplorg);
		}
	}
}

/* Checks whether disk templates need upgrade - including sub-directories */
void tpl_checkDiskRevisions(void) {
	char subdir[255];
	char dirpath[255];
	if (cfg.http_tpl) {
		tpl_checkOneDirDiskRevisions("");
		DIR *hdir;
		struct dirent entry;
		struct dirent *result;
		struct stat s;
		if ((hdir = opendir(cfg.http_tpl)) != NULL) {
			while(cs_readdir_r(hdir, &entry, &result) == 0 && result != NULL) {
				if (strcmp(".", entry.d_name) == 0 || strcmp("..", entry.d_name) == 0) {
					continue;
				}
				snprintf(dirpath, 255, "%s%s", cfg.http_tpl, entry.d_name);
				if (stat(dirpath, &s) == 0) {
					if (s.st_mode & S_IFDIR) {
						snprintf(subdir, 255,
						#ifdef WIN32
									"%s\\"
						#else
									"%s/"
						#endif
								, entry.d_name);
						tpl_checkOneDirDiskRevisions(subdir);
					}
				}
			}
			closedir(hdir);
		}
	}
}

/* Helper function for urldecode.*/
static int32_t x2i(int32_t i) {
	i = toupper(i);
	i = i - '0';
	if (i > 9) i = i - 'A' + '9' + 1;
	return i;
}

/* Decodes values in a http url. Note: The original value is modified! */
void urldecode(char *s) {
	int32_t c, c1, n;
	char *t;
	t = s;
	n = strlen(s);
	while(n >0) {
		c = *s++;
		if (c == '+') c = ' ';
		else if (c == '%' && n > 2) {
			c = *s++;
			c1 = c;
			c = *s++;
			c = 16*x2i(c1) + x2i(c);
			n -= 2;
		}
		*t++ = c;
		n--;
	}
	*t = 0;
}

/* Encode values in a http url. Do not call free() or realloc on the returned reference or you will get memory corruption! */
char *urlencode(struct templatevars *vars, char *str) {
	char *buf;
	if (!cs_malloc(&buf, strlen(str) * 3 + 1)) return "";
	char *pstr = str, *pbuf = buf;
	while (*pstr) {
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') *pbuf++ = *pstr;
		else if (*pstr == ' ') *pbuf++ = '+';
		else {
			*pbuf++ = '%';
			*pbuf++ = to_hex(*pstr >> 4);
			*pbuf++ = to_hex(*pstr & 15);
		}
		++pstr;
	}
	*pbuf = '\0';
	/* Allocate the needed memory size and store it in the templatevars */
	if (!cs_realloc(&buf, strlen(buf) + 1)) return "";
	return tpl_addTmp(vars, buf);
}

/* XML-Escapes a char array. The returned reference will be automatically cleaned through the templatevars-mechanism tpl_clear().
   Do not call free() or realloc on the returned reference or you will get memory corruption! */
char *xml_encode(struct templatevars *vars, char *chartoencode) {
	if (!chartoencode) return "";
	int32_t i, pos = 0, len = strlen(chartoencode);
	char *encoded;
	char buffer[7];
	/* In worst case, every character could get converted to 6 chars (we only support ASCII, for Unicode it would be 7)*/
	if (!cs_malloc(&encoded, len * 6 + 1)) return "";
	for (i = 0; i < len; ++i) {
		unsigned char tmp = chartoencode[i];
		switch(tmp) {
		case '&' : memcpy(encoded + pos, "&amp;", 5);  pos += 5; break;
		case '<' : memcpy(encoded + pos, "&lt;", 4);   pos += 4; break;
		case '>' : memcpy(encoded + pos, "&gt;", 4);   pos += 4; break;
		case '"' : memcpy(encoded + pos, "&quot;", 6); pos += 6; break;
		case '\'': memcpy(encoded + pos, "&#39;", 5);  pos += 5; break; // &apos; not supported on older IE
		case '\n': memcpy(encoded + pos, "\n", 1);     pos += 1; break;
		default:
			if (tmp < 32 || (cs_http_use_utf8 != 1 && tmp > 127)) {
				snprintf(buffer, 7, "&#%d;", tmp);
				memcpy(encoded + pos, buffer, strlen(buffer));
				pos += strlen(buffer);
			} else {
				encoded[pos] = tmp;
				++pos;
			}
		}
	}
	/* Reduce to the really needed memory size and store it in the templatevars */
	if (!cs_realloc(&encoded, pos + 1)) return "";
	encoded[pos] = '\0';
	return tpl_addTmp(vars, encoded);
}

/* Format a seconds integer to hh:mm:ss or dd hh:mm:ss depending hrs >24 */
char *sec2timeformat(struct templatevars *vars, int32_t seconds) {
	char *value;
	if (seconds <= 0)
		return "00:00:00";
	if (!cs_malloc(&value, 16))
		return "00:00:00";
	int32_t secs = 0, fullmins = 0, mins = 0, fullhours = 0, hours = 0,	days = 0;
	secs = seconds % 60;
	if (seconds >= 60) {
		fullmins = seconds / 60;
		mins = fullmins % 60;
		if (fullmins >= 60) {
			fullhours = fullmins / 60;
			hours = fullhours % 24;
			days = fullhours / 24;
		}
	}
	if (days == 0)
		snprintf(value, 16, "%02d:%02d:%02d", hours, mins, secs);
	else
		snprintf(value, 16, "%02dd %02d:%02d:%02d", days, hours, mins, secs);
	return tpl_addTmp(vars, value);
}

#endif
