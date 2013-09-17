#include "globals.h"
#ifdef MODULE_GHTTP
#include "oscam-client.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-reader.h"
#include "oscam-work.h"
#include "module-dvbapi.h"
#ifdef WITH_SSL
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

typedef struct {
	uchar* session_id;
	uchar* host_id;
	uchar* fallback_id;
	pthread_mutex_t conn_mutex;
	LLIST* post_contexts;
	LLIST* ecm_q;
#ifdef WITH_SSL
	SSL* ssl_handle;
#endif
} s_ghttp;

typedef struct {
	uint16_t onid;
	uint16_t tsid;
	uint16_t sid;
	uint16_t pid;
} s_ca_context;

static LLIST* ghttp_ignored_contexts;
#ifdef WITH_SSL
static SSL_CTX* ghttp_ssl_context;
#endif

static int32_t _ghttp_post_ecmdata(struct s_client *client, ECM_REQUEST* er);

#ifdef WITH_SSL	
static bool _ssl_connect(struct s_client *client, int32_t fd) {
	s_ghttp* context = (s_ghttp*)client->ghttp;

	if (context->ssl_handle) { // cleanup previous
		SSL_shutdown(context->ssl_handle);
		SSL_free(context->ssl_handle);
	}

	cs_debug_mask(D_CLIENT, "%s: trying ssl...", client->reader->label);
	
	context->ssl_handle = SSL_new(ghttp_ssl_context);
	if (context->ssl_handle == NULL) {
		ERR_print_errors_fp(stderr);
		return false;
	}
	if (!SSL_set_fd(context->ssl_handle, fd)) {
		ERR_print_errors_fp(stderr);
		return false;
	}
	if (SSL_connect(context->ssl_handle) != 1)
		ERR_print_errors_fp(stderr);
	
	if(context->ssl_handle) {
		cs_debug_mask(D_CLIENT, "%s: ssl established", client->reader->label);
		return true;
	} 

	return false;
}
#endif

int32_t ghttp_client_init(struct s_client *cl) {
	int32_t handle;
	char* str = NULL;
	
	if (cl->reader->r_port == 0) 
		cl->reader->r_port = cl->reader->ghttp_use_ssl ? 443 : 80;
	
	str = strstr(cl->reader->device, ".");
	if (!str) {
		char host[128];
		cs_strncpy(host, cl->reader->device, sizeof(cl->reader->device));
		snprintf(cl->reader->device, sizeof(cl->reader->device), "%s.appspot.com", host);
	}

	cs_log("%s: init google cache client %s:%d (fd=%d)", cl->reader->label, cl->reader->device, cl->reader->r_port, cl->udp_fd);

	if (cl->udp_fd) network_tcp_connection_close(cl->reader, "re-init");
	
	handle = network_tcp_connection_open(cl->reader);
	if (handle < 0) return -1;

	cl->reader->tcp_connected = 2;
	cl->reader->card_status = CARD_INSERTED;
	cl->reader->last_g = cl->reader->last_s = time((time_t *)0);

	cl->pfd = cl->udp_fd;

	if (!cl->ghttp) {
		if (!cs_malloc(&(cl->ghttp), sizeof(s_ghttp))) return -1;
		memset(cl->ghttp, 0, sizeof(s_ghttp));
		((s_ghttp*)cl->ghttp)->post_contexts = ll_create("post contexts");			
		((s_ghttp*)cl->ghttp)->ecm_q = ll_create("ecm queue");
	} else {
		ll_clear(((s_ghttp*)cl->ghttp)->ecm_q);
	}

	if (cl->reader->ghttp_use_ssl) {
#ifndef WITH_SSL		
		cs_log("%s: use_ssl set but no ssl support available, aborting...", cl->reader->label);
		return -1;
#endif
#ifdef WITH_SSL
		if (ghttp_ssl_context == NULL) return -1;

		if (_ssl_connect(cl, handle)) {
			cl->crypted = 1;
		} else {
			network_tcp_connection_close(cl->reader, "ssl failed");
			return -1;
		}
#endif
	}

	return 0;
}

static uint32_t javastring_hashcode(uchar* input, int32_t len) {
	uint32_t h = 0;
	while (/**input &&*/ len--) {
		h = 31 * h + *input++;
	}
	return h;
}

static int32_t ghttp_send_int(struct s_client *client, uchar *buf, int32_t l) {		
	cs_debug_mask(D_CLIENT, "%s: sending %d bytes", client->reader->label, l);
	if (!client->pfd) {
		// disconnected? try reinit.
		cs_debug_mask(D_CLIENT, "%s: disconnected?", client->reader->label);
		ghttp_client_init(client);
	}	

#ifdef WITH_SSL		
	s_ghttp* context = (s_ghttp*)client->ghttp;
	if (client->reader->ghttp_use_ssl) 
		return SSL_write(context->ssl_handle, buf, l);
#endif		
	return send(client->pfd, buf, l, 0);
}

static int32_t ghttp_send(struct s_client *client, uchar *buf, int32_t l) {		
	s_ghttp* context = (s_ghttp*)client->ghttp;
	pthread_mutex_lock(&context->conn_mutex);
	int32_t ret = ghttp_send_int(client, buf, l);
	pthread_mutex_unlock(&context->conn_mutex);
	return ret;
}

static int32_t ghttp_recv_int(struct s_client *client, uchar *buf, int32_t l) {
	int32_t n = -1;
	s_ghttp* context = (s_ghttp*)client->ghttp;
	
	if (!client->pfd) {
		ll_clear(context->ecm_q);
		return -1;
	}
	
	if (client->reader->ghttp_use_ssl) {
#ifdef WITH_SSL		
		n = SSL_read(context->ssl_handle, buf, l);
#endif		
	} else n = recv(client->pfd, buf, l, 0);

	if (n > 0) {
		cs_debug_mask(D_CLIENT, "%s: received %d bytes from %s", client->reader->label, n, remote_txt());
		client->last = time((time_t *)0);

		if (n > 400) {
			buf[n] = '\0';
			cs_debug_mask(D_CLIENT, "%s: unexpected reply size %d - %s", client->reader->label, n, buf);
			return -1; // assumes google error, disconnects
		}
	}
	if (n < 5) {
		cs_debug_mask(D_CLIENT, "%s: read %d bytes, disconnecting", client->reader->label, n);
		n = -1;
	}
	return n;
}

static int32_t ghttp_recv(struct s_client *client, uchar *buf, int32_t l) {
	s_ghttp* context = (s_ghttp*)client->ghttp;
	pthread_mutex_lock(&context->conn_mutex);
	int32_t ret = ghttp_recv_int(client, buf, l);
	pthread_mutex_unlock(&context->conn_mutex);
	return ret;
}

static bool _is_post_context(LLIST *ca_contexts, ECM_REQUEST *er, bool remove_data) {
	s_ca_context* ctx;
	s_ca_context* existing = NULL;
	if(cs_malloc(&ctx, sizeof(s_ca_context))) {
		ctx->onid = er->onid;
		ctx->tsid = er->tsid;
		ctx->sid = er->srvid;
		ctx->pid = 0;	
		
		existing = (s_ca_context*)ll_contains_data(ca_contexts, ctx, sizeof(s_ca_context));
		if (remove_data)
			ll_remove_data(ca_contexts, existing);
		free(ctx);
	}
	return existing != NULL;
}

static void _add_context(LLIST *ca_contexts, s_ca_context *context) {
	if(!ll_contains_data(ca_contexts, context, sizeof(s_ca_context))) {
		ll_append(ca_contexts, context);
	} else free(context);
	
	while (ll_count(ca_contexts) > 64)
		ll_remove_first_data(ca_contexts);
		
	cs_debug_mask(D_CLIENT, "ca contexts size %d", ll_count(ca_contexts));	
}

static void _set_pid_status(LLIST *ca_contexts, uint16_t onid, uint16_t tsid, uint16_t sid, uint16_t pid) {
	s_ca_context* ctx;
	if (cs_malloc(&ctx, sizeof(s_ca_context))) {
		ctx->onid = onid;
		ctx->tsid = tsid;
		ctx->sid = sid;
		ctx->pid = pid;
		_add_context(ca_contexts, ctx);
	}	
}

static void _set_pids_status(LLIST *ca_contexts, uint16_t onid, uint16_t tsid, uint16_t sid, uchar *buf, int len) {
	int8_t offs = 0;
	uint16_t pid = 0;

	while (offs < len) {
		pid = b2i(2, buf + offs);
		offs += 2;
		_set_pid_status(ca_contexts, onid, tsid, sid, pid);
	}
}

static bool _swap_hosts(s_ghttp *context) {
	if (!context->fallback_id) return false;
	uchar* tmp = context->host_id;
	context->host_id = context->fallback_id;
	context->fallback_id = tmp;
	NULLFREE(context->session_id);
	ll_clear(context->ecm_q);
	ll_clear_data(ghttp_ignored_contexts);
	return true;
}

static char* _get_header_substr(uchar *buf, const char *start, const char *end) {
	char* data = strstr((char*)buf, start);
	if(!data) return NULL;
	data += strlen(start);
	int len = strstr(data, end) - data;
	if(len <= 0) return NULL;
	char tmp = data[len];
	data[len] = '\0';
	char* value = cs_strdup(data);
	data[len] = tmp;
	return value;
}

static int _get_int_header(uchar *buf, const char *start) {
	char* data = strstr((char*)buf, start);
	if(!data) return -1;
	data += strlen(start);
	return atoi(data);
}

static char* _get_header(uchar *buf, const char *start) {
	return _get_header_substr(buf, start, "\r\n");
}

static int32_t ghttp_recv_chk(struct s_client *client, uchar *dcw, int32_t *rc, uchar *buf, int32_t n) {
	char* data;
	char* hdrstr;
	uchar* content;
	int rcode, len, clen = 0;
	s_ghttp* context = (s_ghttp*)client->ghttp;
	ECM_REQUEST *er = NULL;	

	if (n < 5) return -1;

	data = strstr((char*)buf, "HTTP/1.1 ");
	if (!data || ll_count(context->ecm_q) > 6) {
		cs_debug_mask(D_CLIENT, "%s: non http or otherwise corrupt response: %s", client->reader->label, buf);
		cs_ddump_mask(D_CLIENT, buf, n, "%s: ", client->reader->label);
		network_tcp_connection_close(client->reader, "receive error");
		NULLFREE(context->session_id);
		ll_clear(context->ecm_q);
		return -1;
	}
	
	LL_ITER itr = ll_iter_create(context->ecm_q);
	er = (ECM_REQUEST*)ll_iter_next(&itr);

	rcode = _get_int_header(buf, "HTTP/1.1 ");
	clen = _get_int_header(buf, "Content-Length: ");
	
	content = (uchar*)(strstr(data, "\r\n\r\n") + 4);
	
	hdrstr = _get_header_substr(buf, "ETag: \"", "\"\r\n");
	if (hdrstr) {
		NULLFREE(context->host_id);
		context->host_id = (uchar*)hdrstr;
		cs_debug_mask(D_CLIENT, "%s: new name: %s", client->reader->label, context->host_id);
		len = b64decode(context->host_id);
		if (len == 0 || len >= 64) {
			NULLFREE(context->host_id);			
		} else {
			cs_debug_mask(D_CLIENT, "%s: redirected...", client->reader->label);
			NULLFREE(context->session_id);
			ll_clear_data(ghttp_ignored_contexts);
			ll_clear(context->ecm_q);
			return -1;
		}		
	}
	
	hdrstr = _get_header_substr(buf, "ETag: W/\"", "\"\r\n");
	if (hdrstr) {
		NULLFREE(context->fallback_id);
		context->fallback_id = (uchar*)hdrstr;
		cs_debug_mask(D_CLIENT, "%s: new fallback name: %s", client->reader->label, context->fallback_id);
		len = b64decode(context->fallback_id);
		if (len == 0 || len >= 64) {
			NULLFREE(context->fallback_id);
		} 		
	}
	
	hdrstr = _get_header(buf, "Set-Cookie: GSSID=");
	if (hdrstr) {
		NULLFREE(context->session_id);
		context->session_id = (uchar*)hdrstr;
		cs_debug_mask(D_CLIENT, "%s: set session_id to: %s", client->reader->label, context->session_id);
	}
	
	// buf[n] = '\0';
	// cs_ddump_mask(D_TRACE, content, clen, "%s: reply\n%s", client->reader->label, buf);		
	
	if (rcode < 200 || rcode > 204) {
		cs_debug_mask(D_CLIENT, "%s: http error code %d", client->reader->label, rcode);
		data = strstr((char*)buf, "Content-Type: application/octet-stream"); // if not octet-stream, google error. need reconnect?
		if (data) { // we have error info string in the post content
			if (clen > 0) {
				content[clen] = '\0';
				cs_debug_mask(D_CLIENT, "%s: http error message: %s", client->reader->label, content);
			}
		}
		if (rcode == 503) {
			if (er && _is_post_context(context->post_contexts, er, false)) {
				if (_swap_hosts(context)) {
					cs_debug_mask(D_CLIENT, "%s: switching to fallback", client->reader->label);
				} else {
					cs_debug_mask(D_CLIENT, "%s: recv_chk got 503 despite post, trying reconnect", client->reader->label);
					network_tcp_connection_close(client->reader, "reconnect");
					ll_clear(context->ecm_q);
				}
			} else {
				// on 503 cache timeout, retry with POST immediately (and switch to POST for subsequent)			
				if (er) {
					_set_pid_status(context->post_contexts, er->onid, er->tsid, er->srvid, 0);					
					cs_debug_mask(D_CLIENT, "%s: recv_chk got 503, trying direct post", client->reader->label);
					_ghttp_post_ecmdata(client, er);					
				}
			}
		} else if (rcode == 401) {
			NULLFREE(context->session_id);
			if (er) {
				cs_debug_mask(D_CLIENT, "%s: session expired, trying direct post", client->reader->label);
				_ghttp_post_ecmdata(client, er);			
			}
		} else if (rcode == 403) {
			client->reader->enable = 0;
			network_tcp_connection_close(client->reader, "login failure");
			ll_clear(context->ecm_q);
			cs_log("%s: invalid username/password, disabling reader.", client->reader->label);
		}
		
		// not sure if this is needed on failure, copied from newcamd
		*rc = 0;
		memset(dcw, 0, 16);	
		
		return -1;
	}

	// successful http reply (200 ok or 204 no content)
	
	hdrstr = _get_header(buf,  "Pragma: context-ignore=");
	if (hdrstr) {
		if (clen > 1) {
			cs_ddump_mask(D_CLIENT, content, clen, "%s: pmt ignore reply - %s (%d pids)", client->reader->label, hdrstr, clen / 2);
			uint32_t onid = 0, tsid = 0, sid = 0;
			if (sscanf(hdrstr, "%4x-%4x-%4x", &onid, &tsid, &sid) == 3)
				_set_pids_status(ghttp_ignored_contexts, onid, tsid, sid, content, clen);
			NULLFREE(hdrstr);
			return -1;
		} 
		NULLFREE(hdrstr);
	}

	data = strstr((char*)buf, "Pragma: context-ignore-clear");
	if (data) {
		cs_debug_mask(D_CLIENT, "%s: clearing local ignore list (size %d)", client->reader->label, ll_count(ghttp_ignored_contexts));
		ll_clear_data(ghttp_ignored_contexts);
	}		

	// switch back to cache get after rapid ecm response (arbitrary atm), only effect is a slight bw save for client
	if (!er || _is_post_context(context->post_contexts, er, false)) {
		data = strstr((char*)buf, "Pragma: cached");
		if (data || (client->cwlastresptime > 0 && client->cwlastresptime < 640)) {
			cs_debug_mask(D_CLIENT, "%s: probably cached cw (%d ms), switching back to cache get for next req", client->reader->label, client->cwlastresptime);
			if (er) _is_post_context(context->post_contexts, er, true);
		}
	}

	if (clen == 16) { // cw in content
		memcpy(dcw, content, 16);
		*rc = 1;
		er = ll_remove_first(context->ecm_q);
		if (!er) return -1;
		cs_ddump_mask(D_TRACE, dcw, 16, "%s: cw recv chk for idx %d", client->reader->label, er->idx);
		return er->idx;
	} else {
		if (clen != 0) cs_ddump_mask(D_CLIENT, content, clen, "%s: recv_chk fail, clen = %d", client->reader->label, clen);
	}
	return -1;
}

static char* _ghttp_basic_auth(struct s_client *client) {
	uchar auth[64];
	char* encauth = NULL;
	int32_t ret;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	if (!context->session_id && strlen(client->reader->r_usr) > 0) {
		cs_debug_mask(D_CLIENT, "%s: username specified and no existing session, adding basic auth", client->reader->label);
		ret = snprintf((char*)auth, sizeof(auth), "%s:%s", client->reader->r_usr, client->reader->r_pwd);
		ret = b64encode((char*)auth, ret, &encauth);
	}
	return encauth;
}

static int32_t _ghttp_http_get(struct s_client *client, uint32_t hash, int odd) {
	uchar req[128];
	char* encauth = NULL;
	int32_t ret;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	encauth = _ghttp_basic_auth(client);

	if (encauth) { // basic auth login
		ret = snprintf((char*)req, sizeof(req), "GET /api/c/%d/%x HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\n\r\n", odd ? 81 : 80, hash, context->host_id, encauth);
		free(encauth);
	} else {
		if (context->session_id) { // session exists
			ret = snprintf((char*)req, sizeof(req), "GET /api/c/%s/%d/%x HTTP/1.1\r\nHost: %s\r\n\r\n", context->session_id, odd ? 81 : 80, hash, context->host_id);
		} else { // no credentials configured, assume no session required
			ret = snprintf((char*)req, sizeof(req), "GET /api/c/%d/%x HTTP/1.1\r\nHost: %s\r\n\r\n", odd ? 81 : 80, hash, context->host_id);
		}
	}

	ret = ghttp_send(client, req, ret);

	return ret;
}

static int32_t _ghttp_post_ecmdata(struct s_client *client, ECM_REQUEST* er) {
	uchar req[640];
	uchar* end;
	char* encauth = NULL;
	int32_t ret;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	encauth = _ghttp_basic_auth(client);

	if (encauth) { // basic auth login
		ret = snprintf((char*)req, sizeof(req), "POST /api/e/%x/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nContent-Length: %d\r\n\r\n", er->onid, er->tsid, er->pid, er->srvid, er->caid, er->prid, context->host_id, encauth, er->ecmlen);
		free(encauth);
	} else {
		if (context->session_id) { // session exists
			ret = snprintf((char*)req, sizeof(req), "POST /api/e/%s/%x/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", context->session_id, er->onid, er->tsid, er->pid, er->srvid, er->caid, er->prid, context->host_id, er->ecmlen);
		} else { // no credentials configured, assume no session required
			ret = snprintf((char*)req, sizeof(req), "POST /api/e/%x/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", er->onid, er->tsid, er->pid, er->srvid, er->caid, er->prid, context->host_id, er->ecmlen);
		}
	}
	end = req + ret;
	memcpy(end, er->ecm, er->ecmlen);

	cs_debug_mask(D_CLIENT, "%s: sending full ecm - /api/e/%x/%x/%x/%x/%x/%x", client->reader->label, er->onid, er->tsid, er->pid, er->srvid, er->caid, er->prid);

	ret = ghttp_send(client, req, ret + er->ecmlen);

	return ret;
}

static bool _is_pid_ignored(ECM_REQUEST *er) {
	s_ca_context* ignore;
	if (cs_malloc(&ignore, sizeof(s_ca_context))) {
		ignore->onid = er->onid;
		ignore->tsid = er->tsid;
		ignore->sid = er->srvid;
		ignore->pid = er->pid;
		if (ll_contains_data(ghttp_ignored_contexts, ignore, sizeof(s_ca_context))) {
			free(ignore);
			return true;
		} else free(ignore);
	}
	return false;
}

static int32_t ghttp_send_ecm(struct s_client *client, ECM_REQUEST *er, uchar *UNUSED(buf)) {
	uint32_t hash;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	if (_is_pid_ignored(er)) {
		cs_debug_mask(D_CLIENT, "%s: ca context found in ignore list, ecm blocked: %x-%x-%x pid %x", client->reader->label, er->onid, er->tsid, er->srvid, er->pid);
		return -1;
	}

	if (!context->host_id) context->host_id = (uchar*)cs_strdup(client->reader->device); 

	ll_append(context->ecm_q, er);
	if (ll_count(context->ecm_q) > 1)
		cs_debug_mask(D_CLIENT, "%s: %d simultaneous ecms...", client->reader->label, ll_count(context->ecm_q));

	if (_is_post_context(context->post_contexts, er, false)) {
		_ghttp_post_ecmdata(client, er);
	} else {
		hash = javastring_hashcode(er->ecm + 3, er->ecmlen - 3);
		_ghttp_http_get(client, hash, er->ecm[0] == 0x81);
	}

	return 0;
}

static void ghttp_cleanup(struct s_client *client) {
	s_ghttp* context = (s_ghttp*)client->ghttp;
	
	if (context) {
		NULLFREE(context->session_id);
		NULLFREE(context->host_id);
		NULLFREE(context->fallback_id);
		if (context->ecm_q) ll_destroy(context->ecm_q);
		if (context->post_contexts) ll_destroy_data(context->post_contexts);
#ifdef WITH_SSL
		if (context->ssl_handle) { 
			SSL_shutdown(context->ssl_handle);
			SSL_free(context->ssl_handle);
		}	
#endif		
		NULLFREE(context);
	}
}

#ifdef HAVE_DVBAPI
static int32_t ghttp_capmt_notify(struct s_client *client, struct demux_s *demux) {
	uchar req[640], lenhdr[64] = "";
	uchar* pids;
	uchar* end;
	char* encauth = NULL;
	int32_t ret;
	int8_t i, pids_len = 0, offs = 0;
	s_ghttp* context = (s_ghttp*)client->ghttp;

	if (!context) return -1;

	cs_debug_mask(D_CLIENT, "%s: capmt %x-%x-%x %d pids on adapter %d mask %x dmx index %d", client->reader->label, demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->adapter_index, demux->ca_mask, demux->demux_index);

	if (demux->ECMpidcount > 0) {
		if (cs_malloc(&pids, demux->ECMpidcount * 8)) {
			pids_len = demux->ECMpidcount * 8;
			for (i = 0; i < demux->ECMpidcount; i++) {
				i2b_buf(2, demux->ECMpids[i].ECM_PID, pids + offs);
				i2b_buf(2, demux->ECMpids[i].CAID, pids + (offs += 2));
				i2b_buf(4, demux->ECMpids[i].PROVID, pids + (offs += 2));
				offs += 4;
			}
			snprintf((char*)lenhdr, sizeof(lenhdr), "\r\nContent-Length: %d", pids_len);
		} else return -1;
	}

	if (!context->host_id) context->host_id = (uchar*)cs_strdup(client->reader->device);

	encauth = _ghttp_basic_auth(client);

	if (encauth) { // basic auth login
		ret = snprintf((char*)req, sizeof(req), "%s /api/p/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s%s\r\n\r\n", ((pids_len > 0) ? "POST" : "GET"), demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->enigma_namespace, context->host_id, encauth, lenhdr);
		free(encauth);
	} else {
		if (context->session_id) { // session exists
			ret = snprintf((char*)req, sizeof(req), "%s /api/p/%s/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s%s\r\n\r\n", ((pids_len > 0) ? "POST" : "GET"), context->session_id, demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->enigma_namespace, context->host_id, lenhdr);
		} else { // no credentials configured, assume no session required
			ret = snprintf((char*)req, sizeof(req), "%s /api/p/%x/%x/%x/%x/%x HTTP/1.1\r\nHost: %s%s\r\n\r\n", ((pids_len > 0) ? "POST" : "GET"), demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->enigma_namespace, context->host_id, lenhdr);
		}
	}
	end = req + ret;
	if (pids_len > 0) {
		memcpy(end, pids, pids_len);
		cs_debug_mask(D_CLIENT, "%s: new unscrambling detected, switching to post", client->reader->label);
		_set_pid_status(context->post_contexts, demux->onid, demux->tsid, demux->program_number, 0);
	}
	cs_ddump_mask(D_CLIENT, pids, pids_len, "%s: sending capmt ecm pids - %s /api/p/%x/%x/%x/%x/%x", client->reader->label, (pids_len > 0) ? "POST" : "GET", demux->onid, demux->tsid, demux->program_number, demux->ECMpidcount, demux->enigma_namespace);

	ret = ghttp_send(client, req, ret + pids_len);

	if (pids_len > 0) free(pids);

	return 0;
}
#endif

void module_ghttp(struct s_module *ph) {
	ph->ptab.nports = 0;
	// ph->ptab.ports[0].s_port = cfg.ghttp_port;
	ph->desc = "ghttp";
	ph->type = MOD_CONN_TCP;
	// ph->listenertype = LIS_GHTTP;
	ph->large_ecm_support = 1;
	ph->recv = ghttp_recv;
	ph->c_init = ghttp_client_init;
	ph->c_recv_chk = ghttp_recv_chk;
	ph->c_send_ecm = ghttp_send_ecm;
	ph->cleanup = ghttp_cleanup;
#ifdef HAVE_DVBAPI	
	ph->c_capmt = ghttp_capmt_notify;
#endif
	ph->num = R_GHTTP;
	ghttp_ignored_contexts = ll_create("ignored contexts");
#ifdef WITH_SSL
	SSL_load_error_strings();
	SSL_library_init();
	ghttp_ssl_context = SSL_CTX_new(SSLv23_client_method());
	if (ghttp_ssl_context == NULL) ERR_print_errors_fp(stderr);	
#endif
}
#endif
