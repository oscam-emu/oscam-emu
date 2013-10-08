#ifndef MODULE_WEBIF_LIB_H_
#define MODULE_WEBIF_LIB_H_

#ifdef WITH_SSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "cscrypt/md5.h"

/* The server string in the http header */
#define SERVER "webserver/1.0"
/* The protocol that gets output. Currently only 1.0 is possible as 1.1 requires many features we don't have. */
#define PROTOCOL "HTTP/1.0"
/* The RFC1123 time format which is used in http headers. */
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"
/* The realm for http digest authentication. Gets displayed to browser. */
#define AUTHREALM "Forbidden"
/* How long a nonce is valid in seconds after a first request with this nonce has been received. If the nonce isn't valid anymore, the browser gets a "stale=true" message and must resubmit with the current nonce. */
#define AUTHNONCEVALIDSECS 15
/* When a nonce gets expired after it has been first given to the client. */
#define AUTHNONCEEXPIRATION 120
/* The amount of hash buckets (based on opaque string) for better performance. */
#define AUTHNONCEHASHBUCKETS 4
/* The maximum amount of GET parameters the webserver will parse. */
#define MAXGETPARAMS 100
/* The refresh delay (in seconds) when stopping OSCam via http. */
#define SHUTDOWNREFRESH 30

#define TOUCH_SUBDIR "touch/"

struct s_connection
{
	int32_t socket;
	struct s_client *cl;
	IN_ADDR_T remote;
#ifdef WITH_SSL
	SSL *ssl;
#endif
};

struct uriparams
{
	int32_t paramcount;
	char *params[MAXGETPARAMS];
	char *values[MAXGETPARAMS];
};

struct s_nonce
{
	char nonce[(MD5_DIGEST_LENGTH * 2) + 1];
	char opaque[(MD5_DIGEST_LENGTH * 2) + 1];
	time_t expirationdate;
	time_t firstuse;
	struct s_nonce *next;
};

extern time_t parse_modifiedsince(char *value);
extern void calculate_opaque(IN_ADDR_T addr, char *opaque);
extern void init_noncelocks(void);
extern void calculate_nonce(char *nonce, char *result, char *opaque);
extern int32_t check_auth(char *authstring, char *method, char *path, IN_ADDR_T addr, char *expectednonce, char *opaque);
extern int32_t webif_write_raw(char *buf, FILE *f, int32_t len);
extern int32_t webif_write(char *buf, FILE *f);
extern int32_t webif_read(char *buf, int32_t num, FILE *f);
extern void send_headers(FILE *f, int32_t status, char *title, char *extra, char *mime, int32_t cache, int32_t length, char *content, int8_t forcePlain);
extern void send_error(FILE *f, int32_t status, char *title, char *extra, char *text, int8_t forcePlain);
extern void send_error500(FILE *f);
extern void send_header304(FILE *f, char *extraheader);
extern void send_file(FILE *f, char *filename, char *subdir, time_t modifiedheader, uint32_t etagheader, char *extraheader);
extern void urldecode(char *s);
extern void parseParams(struct uriparams *params, char *pch);
extern char *getParam(struct uriparams *params, char *name);

#ifdef WITH_SSL
extern SSL *cur_ssl(void);
extern SSL_CTX *SSL_Webif_Init(void);
#endif

#endif
