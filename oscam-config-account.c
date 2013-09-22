#include "globals.h"
#include "module-anticasc.h"
#include "oscam-client.h"
#include "oscam-conf.h"
#include "oscam-conf-chk.h"
#include "oscam-conf-mk.h"
#include "oscam-config.h"
#include "oscam-garbage.h"
#include "oscam-lock.h"
#include "oscam-string.h"

#define cs_user "oscam.user"

static void account_tosleep_fn(const char *token, char *value, void *setting, FILE *f) {
	int32_t *tosleep = setting;
	if (value) {
		*tosleep = strToIntVal(value, cfg.tosleep);
		return;
	}
	if (*tosleep != cfg.tosleep || cfg.http_full_cfg)
		fprintf_conf(f, token, "%d\n", *tosleep);
}




static void account_c35_suppresscmd08_fn(const char *token, char *value, void *setting, FILE *f) {
	int8_t *c35_suppresscmd08 = setting;
	if (value) {
		*c35_suppresscmd08 = (int8_t)strToIntVal(value, cfg.c35_suppresscmd08);
		return;
	}
	if (*c35_suppresscmd08 != cfg.c35_suppresscmd08 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%d\n", *c35_suppresscmd08);
}

static void account_umaxidle_fn(const char *token, char *value, void *setting, FILE *f) {
	uint32_t *umaxidle = setting;
	if (value) {
		*umaxidle = (uint32_t)strToIntVal(value, cfg.umaxidle);
		return;
	}
	if (*umaxidle != cfg.umaxidle || cfg.http_full_cfg)
		fprintf_conf(f, token, "%u\n", *umaxidle);
}




static void account_ncd_keepalive_fn(const char *token, char *value, void *setting, FILE *f) {
	int8_t *ncd_keepalive = setting;
	int8_t def_value = 0;
#ifdef MODULE_NEWCAMD
	def_value = cfg.ncd_keepalive;
#endif
	if (value) {
		*ncd_keepalive = (int8_t)strToIntVal(value, def_value);
		return;
	}
	if (*ncd_keepalive != def_value || cfg.http_full_cfg)
		fprintf_conf(f, token, "%d\n", *ncd_keepalive);
}

static void account_allowedprotocols_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_auth *account = setting;
	if (value) {
		account->allowedprotocols = 0;
		if (strlen(value) > 3) {
			int i;
			char *ptr, *saveptr1 = NULL;
			for (i = 0, ptr = strtok_r(value, ",", &saveptr1); ptr; ptr = strtok_r(NULL, ",", &saveptr1), i++) {
				if		(streq(ptr, "camd33"))   account->allowedprotocols |= LIS_CAMD33TCP;
				else if (streq(ptr, "camd35"))   account->allowedprotocols |= LIS_CAMD35UDP;
				else if (streq(ptr, "cs357x"))   account->allowedprotocols |= LIS_CAMD35UDP;
				else if (streq(ptr, "cs378x"))   account->allowedprotocols |= LIS_CAMD35TCP;
				else if (streq(ptr, "newcamd"))  account->allowedprotocols |= LIS_NEWCAMD;
				else if (streq(ptr, "cccam"))    account->allowedprotocols |= LIS_CCCAM;
				else if (streq(ptr, "csp"))      account->allowedprotocols |= LIS_CSPUDP;
				else if (streq(ptr, "gbox"))     account->allowedprotocols |= LIS_GBOX;
				else if (streq(ptr, "radegast")) account->allowedprotocols |= LIS_RADEGAST;
				// these have no listener ports so it doesn't make sense
				else if (streq(ptr, "dvbapi"))   account->allowedprotocols |= LIS_DVBAPI;
				else if (streq(ptr, "constcw"))  account->allowedprotocols |= LIS_CONSTCW;
				else if (streq(ptr, "serial"))   account->allowedprotocols |= LIS_SERIAL;
			}
		}
		return;
	}
	if (account->allowedprotocols || cfg.http_full_cfg ){
		value = mk_t_allowedprotocols(account);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

#ifdef WITH_LB
static void caidvaluetab_fn(const char *token, char *value, void *setting, FILE *f) {
	CAIDVALUETAB *caid_value_table = setting;
	int limit = streq(token, "lb_retrylimits") ? 50 : 1;
	if (value) {
		chk_caidvaluetab(value, caid_value_table, limit);
		return;
	}
	if (caid_value_table->n > 0 || cfg.http_full_cfg) {
		value = mk_t_caidvaluetab(caid_value_table);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}
#endif


static void account_au_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_auth *account = setting;
	if (value) {
		// set default values for usage during runtime from Webif
		account->autoau = 0;
		if (!account->aureader_list)
			account->aureader_list = ll_create("aureader_list");
		if (streq(value, "1"))
			account->autoau = 1;
		ll_clear(account->aureader_list);
		LL_ITER itr = ll_iter_create(configured_readers);
		struct s_reader *rdr;
		char *pch, *saveptr1 = NULL;
		for (pch = strtok_r(value, ",", &saveptr1); pch != NULL; pch = strtok_r(NULL, ",", &saveptr1)) {
			ll_iter_reset(&itr);
			while ((rdr = ll_iter_next(&itr))) {
				if (streq(rdr->label, pch) || account->autoau) {
					ll_append(account->aureader_list, rdr);
				}
			}
		}
		return;
	}
	if (account->autoau == 1) {
		fprintf_conf(f, token, "%d\n", account->autoau);
	} else if (account->aureader_list) {
		value = mk_t_aureader(account);
		if (strlen(value) > 0)
			fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	} else if (cfg.http_full_cfg) {
		fprintf_conf(f, token, "%s\n", "");
	}
}

static void account_expdate_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_auth *account = setting;
	if (value) {
		if (!value[0]) {
			account->expirationdate = (time_t)NULL;
			return;
		}
		int i;
		struct tm cstime;
		char *ptr1, *saveptr1 = NULL;
		memset(&cstime,0,sizeof(cstime));
		for (i = 0, ptr1 = strtok_r(value, "-/", &saveptr1); i < 3 && ptr1; ptr1 = strtok_r(NULL, "-/", &saveptr1), i++) {
			switch(i) {
				case 0: cstime.tm_year = atoi(ptr1) - 1900; break;
				case 1: cstime.tm_mon  = atoi(ptr1) - 1;    break;
				case 2: cstime.tm_mday = atoi(ptr1);        break;
			}
		}
		cstime.tm_hour  = 23;
		cstime.tm_min   = 59;
		cstime.tm_sec   = 59;
		cstime.tm_isdst = -1;
		account->expirationdate = mktime(&cstime);
		return;
	}
	if (account->expirationdate || cfg.http_full_cfg) {
		char buf[16];
		struct tm timeinfo;
		localtime_r(&account->expirationdate, &timeinfo);
		strftime(buf, 16, "%Y-%m-%d", &timeinfo);
		fprintf_conf(f, token, "%s\n", streq(buf, "1970-01-01") ? "" : buf);
	}
}

static void account_allowedtimeframe_fn(const char *token, char *value, void *setting, FILE *f) {
	struct s_auth *account = setting;
	if (value) {
		account->allowedtimeframe[0] = 0;
		account->allowedtimeframe[1] = 0;
		if (strlen(value)) {
			int32_t allowed[4];
			if (sscanf(value, "%2d:%2d-%2d:%2d", &allowed[0], &allowed[1], &allowed[2], &allowed[3]) == 4) {
				account->allowedtimeframe[0] = allowed[0] * 60 + allowed[1];
				account->allowedtimeframe[1] = allowed[2] * 60 + allowed[3];
			} else {
				fprintf(stderr, "WARNING: Value '%s' is not valid for allowedtimeframe (hh:mm-hh:mm)\n", value);
			}
		}
		return;
	}
	if (account->allowedtimeframe[0] && account->allowedtimeframe[1]) {
		fprintf_conf(f, token, "%02d:%02d-%02d:%02d\n",
			account->allowedtimeframe[0] / 60, account->allowedtimeframe[0] % 60,
			account->allowedtimeframe[1] / 60, account->allowedtimeframe[1] % 60 );
	} else if (cfg.http_full_cfg) {
		fprintf_conf(f, token, "%s\n", "");
	}
}

static void account_tuntab_fn(const char *token, char *value, void *setting, FILE *f) {
	TUNTAB *ttab = setting;
	if (value) {
		if (strlen(value) == 0) {
			clear_tuntab(ttab);
		} else {
			chk_tuntab(value, ttab);
		}
		return;
	}
	if (ttab->bt_caidfrom[0] || cfg.http_full_cfg) {
		value = mk_t_tuntab(ttab);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

void group_fn(const char *token, char *value, void *setting, FILE *f) {
	uint64_t *grp = setting;
	if (value) {
		char *ptr1, *saveptr1 = NULL;
		*grp = 0;
		for (ptr1 = strtok_r(value, ",", &saveptr1); ptr1; ptr1 = strtok_r(NULL, ",", &saveptr1)) {
			int32_t g;
			g = atoi(ptr1);
			if (g > 0 && g < 65)
				*grp |= (((uint64_t)1) << (g-1));
		}
		return;
	}
	if (*grp || cfg.http_full_cfg) {
		value = mk_t_group(*grp);
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

void services_fn(const char *token, char *value, void *setting, FILE *f) {
	SIDTABS *sidtabs = setting;
	if (value) {
		strtolower(value);
		chk_services(value, sidtabs);
		return;
	}
	value = mk_t_service(sidtabs);
	if (strlen(value) > 0 || cfg.http_full_cfg)
		fprintf_conf(f, token, "%s\n", value);
	free_mk_t(value);
}

void class_fn(const char *token, char *value, void *setting, FILE *f) {
	CLASSTAB *cltab = setting;
	if (value) {
		strtolower(value);
		chk_cltab(value, cltab);
		return;
	}
	value = mk_t_cltab(cltab);
	if (strlen(value) > 0 || cfg.http_full_cfg) {
		fprintf_conf(f, token, "%s\n", value);
		free_mk_t(value);
	}
}

#ifdef CS_ANTICASC
static void account_fixups_fn(void *var) {
	struct s_auth *account = var;
	if (account->ac_users < -1) account->ac_users = DEFAULT_AC_USERS;
	if (account->ac_penalty < -1) account->ac_penalty = DEFAULT_AC_PENALTY;
}
#endif

#define OFS(X) offsetof(struct s_auth, X)
#define SIZEOF(X) sizeof(((struct s_auth *)0)->X)

static const struct config_list account_opts[] = {
#ifdef CS_ANTICASC
	DEF_OPT_FIXUP_FUNC(account_fixups_fn),
#endif
	DEF_OPT_INT8("disabled"				, OFS(disabled),				0 ),
	DEF_OPT_SSTR("user"					, OFS(usr),						"", SIZEOF(usr) ),
	DEF_OPT_STR("pwd"					, OFS(pwd),						NULL ),
#ifdef WEBIF
	DEF_OPT_STR("description"			, OFS(description),				NULL ),
#endif
	DEF_OPT_STR("hostname"				, OFS(dyndns),					NULL ),
	DEF_OPT_FUNC("caid"					, OFS(ctab),					check_caidtab_fn ),
	DEF_OPT_INT8("uniq"					, OFS(uniq),					0 ),
	DEF_OPT_UINT8("sleepsend"			, OFS(c35_sleepsend),			0 ),
	DEF_OPT_INT32("failban"				, OFS(failban),					0 ),
	DEF_OPT_INT8("monlevel"				, OFS(monlvl),					0 ),
	DEF_OPT_FUNC("sleep"				, OFS(tosleep),					account_tosleep_fn ),
	DEF_OPT_FUNC("suppresscmd08"		, OFS(c35_suppresscmd08),		account_c35_suppresscmd08_fn ),
        DEF_OPT_FUNC("umaxidle"                   , OFS(umaxidle),                          account_umaxidle_fn ),
	DEF_OPT_FUNC("keepalive"			, OFS(ncd_keepalive),			account_ncd_keepalive_fn ),
	DEF_OPT_FUNC("au"					, 0,							account_au_fn ),
	DEF_OPT_UINT8("emmreassembly"		, OFS(emm_reassembly), 			2 ),
	DEF_OPT_FUNC("expdate"				, 0,							account_expdate_fn ),
	DEF_OPT_FUNC("allowedprotocols"		, 0,							account_allowedprotocols_fn ),
	DEF_OPT_FUNC("allowedtimeframe"		, 0,							account_allowedtimeframe_fn ),
	DEF_OPT_FUNC("betatunnel"			, OFS(ttab),					account_tuntab_fn ),
	DEF_OPT_FUNC("group"				, OFS(grp),						group_fn ),
	DEF_OPT_FUNC("services"				, OFS(sidtabs),					services_fn ),
	DEF_OPT_FUNC_X("ident"				, OFS(ftab),					ftab_fn, FTAB_ACCOUNT | FTAB_PROVID ),
	DEF_OPT_FUNC_X("chid"				, OFS(fchid),					ftab_fn, FTAB_ACCOUNT | FTAB_CHID ),
	DEF_OPT_FUNC("class"				, OFS(cltab),					class_fn ),
#ifdef CS_CACHEEX
	DEF_OPT_INT8("cacheex"				, OFS(cacheex.mode),			0 ),
	DEF_OPT_INT8("cacheex_maxhop"		, OFS(cacheex.maxhop),			0 ),
	DEF_OPT_FUNC("cacheex_ecm_filter"	, OFS(cacheex.filter_caidtab),	cacheex_hitvaluetab_fn ),
	DEF_OPT_UINT8("cacheex_drop_csp"	, OFS(cacheex.drop_csp),		0 ),
	DEF_OPT_UINT8("cacheex_allow_request"	, OFS(cacheex.allow_request),	1 ),
#endif
#ifdef MODULE_CCCAM
	DEF_OPT_INT32("cccmaxhops"			, OFS(cccmaxhops),				DEFAULT_CC_MAXHOPS ),
	DEF_OPT_INT8("cccreshare"			, OFS(cccreshare),				DEFAULT_CC_RESHARE ),
	DEF_OPT_INT8("cccignorereshare"		, OFS(cccignorereshare),		DEFAULT_CC_IGNRSHR ),
	DEF_OPT_INT8("cccstealth"			, OFS(cccstealth),				DEFAULT_CC_STEALTH ),
#endif
#ifdef CS_ANTICASC
	DEF_OPT_INT32("fakedelay"			, OFS(ac_fakedelay),			-1 ),
	DEF_OPT_INT32("numusers"			, OFS(ac_users),				DEFAULT_AC_USERS ),
	DEF_OPT_INT8("penalty"				, OFS(ac_penalty),				DEFAULT_AC_PENALTY ),
#endif
#ifdef WITH_LB
	DEF_OPT_INT32("lb_nbest_readers"	, OFS(lb_nbest_readers),		-1),
	DEF_OPT_INT32("lb_nfb_readers"	    , OFS(lb_nfb_readers),		    -1),
	DEF_OPT_FUNC("lb_nbest_percaid"		, OFS(lb_nbest_readers_tab),    caidvaluetab_fn),
#endif
	DEF_LAST_OPT
};

void chk_account(const char *token, char *value, struct s_auth *account)
{
	if (config_list_parse(account_opts, token, value, account))
		return;
	else if (token[0] != '#')
		fprintf(stderr, "Warning: keyword '%s' in account section not recognized\n", token);
}

void account_set_defaults(struct s_auth *account) {
	config_list_set_defaults(account_opts, account);
}

struct s_auth *init_userdb(void)
{
	FILE *fp = open_config_file(cs_user);
	if (!fp)
		return NULL;

	struct s_auth *authptr = NULL;
	int32_t tag = 0, nr = 0, expired = 0, disabled = 0;
	char *token;
	struct s_auth *account = NULL;
	struct s_auth *probe = NULL;
	if (!cs_malloc(&token, MAXLINESIZE))
		return NULL;

	while (fgets(token, MAXLINESIZE, fp)) {
		int32_t l;
		void *ptr;

		if ((l=strlen(trim(token))) < 3)
			continue;
		if (token[0] == '[' && token[l-1] == ']') {
			token[l - 1] = 0;
			tag = streq("account", strtolower(token + 1));
			if (!cs_malloc(&ptr, sizeof(struct s_auth)))
				break;
			if (account)
				account->next = ptr;
			else
				authptr = ptr;

			account = ptr;
			account_set_defaults(account);
			nr++;

			continue;
		}

		if (!tag)
			continue;
		char *value = strchr(token, '=');
		if (!value)
			continue;

		*value++ = '\0';

		// check for duplicate useraccounts and make the name unique
		if (streq(trim(strtolower(token)), "user")) {
			for(probe = authptr; probe; probe = probe->next){
				if (!strcmp(probe->usr, trim(value))){
					fprintf(stderr, "Warning: duplicate account '%s'\n", value);
					strncat(value, "_x", sizeof(probe->usr) - strlen(value) - 1);
				}
			}
		}
		chk_account(trim(strtolower(token)), trim(value), account);
	}
	free(token);
	fclose(fp);

	for(account = authptr; account; account = account->next){
		if(account->expirationdate && account->expirationdate < time(NULL))
			++expired;
		if(account->disabled)
			++disabled;
	}
	cs_log("userdb reloaded: %d accounts loaded, %d expired, %d disabled", nr, expired, disabled);
	return authptr;
}

int32_t init_free_userdb(struct s_auth *ptr) {
	int32_t nro;
	for (nro = 0; ptr; nro++) {
		struct s_auth *ptr_next;
		ptr_next = ptr->next;
		ll_destroy(ptr->aureader_list);
		ptr->next = NULL;
		config_list_gc_values(account_opts, ptr);
		add_garbage(ptr);
		ptr = ptr_next;
	}
	cs_log("userdb %d accounts freed", nro);
	return nro;
}

int32_t write_userdb(void)
{
	struct s_auth *account;
	FILE *f = create_config_file(cs_user);
	if (!f)
		return 1;
	for (account = cfg.account; account; account = account->next) {
		fprintf(f, "[account]\n");
		config_list_apply_fixups(account_opts, account);
		config_list_save(f, account_opts, account, cfg.http_full_cfg);
		fprintf(f, "\n");
	}
	return flush_config_file(f, cs_user);
}

void cs_accounts_chk(void)
{
	struct s_auth *account1,*account2;
	struct s_auth *new_accounts = init_userdb();
	cs_writelock(&config_lock);
	struct s_auth *old_accounts = cfg.account;
	for (account1 = cfg.account; account1; account1 = account1->next) {
		for (account2 = new_accounts; account2; account2 = account2->next) {
			if (!strcmp(account1->usr, account2->usr)) {
				account2->cwfound    = account1->cwfound;
				account2->cwcache    = account1->cwcache;
				account2->cwnot      = account1->cwnot;
				account2->cwtun      = account1->cwtun;
				account2->cwignored  = account1->cwignored;
				account2->cwtout     = account1->cwtout;
				account2->emmok      = account1->emmok;
				account2->emmnok     = account1->emmnok;
				account2->firstlogin = account1->firstlogin;
				ac_copy_vars(account1, account2);
			}
		}
	}
	cs_reinit_clients(new_accounts);
	cfg.account = new_accounts;
	init_free_userdb(old_accounts);
	ac_clear();
	cs_writeunlock(&config_lock);
}
