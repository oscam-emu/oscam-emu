#include "globals.h"
#ifdef MODULE_GBOX

// The following headers are used in parsing mg-encrypted parameter
#if defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_dl.h>
#include <ifaddrs.h>
#elif defined(__SOLARIS__)
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/sockio.h>
#else
#include <net/if.h>
#endif

#include "minilzo/minilzo.h"
#include "module-gbox.h"
#include "module-cccam.h"
#include "module-cccam-data.h"
#include "oscam-failban.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-lock.h"
#include "oscam-net.h"
#include "oscam-chk.h"
#include "oscam-string.h"
#include "oscam-reader.h"
#include "oscam-garbage.h"

#define FILE_GBOX_VERSION       "/tmp/gbx.ver"
#define FILE_SHARED_CARDS_INFO  "/tmp/gbx_card.info"
#define FILE_ATTACK_INFO        "/tmp/gbx_attack.txt"

#define GBOX_STAT_HELLOL	0
#define GBOX_STAT_HELLOS	1
#define GBOX_STAT_HELLOR	2
#define GBOX_STAT_HELLO3	3
#define GBOX_STAT_HELLO4	4

enum {
  MSG_ECM = 0x445c,
  MSG_CW = 0x4844,
  MSG_HELLO = 0xddab,
  MSG_HELLO1 = 0x4849,
  MSG_CHECKCODE = 0x41c0,
  MSG_GOODBYE = 0x9091,
  MSG_GSMS_ACK = 0x9098,
  MSG_GSMS = 0xff0,
  MSG_BOXINFO = 0xa0a1,
  MSG_UNKNWN1 = 0x9099,
  MSG_UNKNWN2 = 0x48F9,
};

struct gbox_srvid {
  uint16_t sid;
  uint16_t peer_idcard;
  uint32_t provid_id;
};

struct gbox_card {
  uint16_t peer_id;
  uint16_t caid;
  uint32_t provid;
  uint32_t provid_1;
  int32_t slot;
  int32_t dist;
  int32_t lvl;
  LLIST *badsids; // sids that have failed to decode (struct cc_srvid)
  LLIST *goodsids; //sids that could be decoded (struct cc_srvid)
};

struct gbox_peer {
  uint16_t id;
  uchar key[4];
  uchar ver;
  uchar type;
  LLIST *cards;
  uchar checkcode[7];
  uchar *hostname;
  int32_t online;
  int32_t hello_stat;
  int32_t goodbye_cont;
  uchar ecm_idx;
  uchar gbox_count_ecm;
  time_t t_ecm;
  uint16_t	last_srvid;
  uint16_t	last_caid;
};

struct gbox_data {
  uint16_t id;
  uchar checkcode[7];
  uchar key[4];
  uchar ver;
  uchar type;
  uint16_t exp_seq; // hello seq
  uchar cws[16];
  struct gbox_peer peer;
  CS_MUTEX_LOCK lock;
  uchar buf[1024];
  pthread_mutex_t hello_expire_mut;
  pthread_cond_t hello_expire_cond;
  LLIST *local_cards;
};

struct gbox_ecm_info {
  uint16_t peer,
           peer_cw,
           caid,
           extra;
  uchar version,
        type,
        slot,
        unknwn1,
        unknwn2,
        ncards;
  uchar checksums[14];
  uchar ecm[512];
  int16_t l;
  uint16_t id_cl_gbox;
};

struct cwcache_data {
  uint32_t ecmcrc;
  uchar cws[16];
} cwcache[64];

void gbox_decrypt(uchar *buffer, int bufsize, uchar *localkey);
static void    gbox_send_boxinfo(struct s_client *cli);
static void    gbox_decompress(struct gbox_data *UNUSED(gbox), uchar *buf, int32_t *unpacked_len);
static void    gbox_send_hello(struct s_client *cli);
static void    gbox_send_hello_packet(struct s_client *cli, int8_t number, uchar *outbuf, uchar *ptr, int32_t nbcards); 
static void    gbox_send_checkcode(struct s_client *cli);
static void    gbox_expire_hello(struct s_client *cli);
static void    gbox_local_cards(struct s_client *cli);	
static int32_t gbox_client_init(struct s_client *cli);
static int32_t gbox_recv2(struct s_client *cli, uchar *b, int32_t l);
static int32_t gbox_recv_chk(struct s_client *cli, uchar *dcw, int32_t *rc, uchar *data, int32_t UNUSED(n));
static int32_t gbox_checkcode_recv(struct s_client *cli, uchar *checkcode);
static int32_t gbox_decode_cmd(uchar *buf);
uint32_t gbox_get_ecmchecksum(ECM_REQUEST *er);

static const uint8_t gbox_version_high_byte = 0x02;
static const uint8_t gbox_version_low_byte  = 0x25;
static const uint8_t gbox_type_dvb          = 0x40;


void gbox_write_version(void)
{
	FILE *fhandle = fopen(FILE_GBOX_VERSION, "w");
	if (!fhandle) {
		cs_log("Couldn't open %s: %s\n", FILE_GBOX_VERSION, strerror(errno));
		return;
	}
	fprintf(fhandle, "%02X.%02X\n", gbox_version_high_byte, gbox_version_low_byte);
	fclose(fhandle);
}

void gbox_write_shared_cards_info(void)
{
	int32_t card_count=0;
	int32_t i = 0;
	int8_t local_written = 0;

	FILE *fhandle;
	fhandle = fopen(FILE_SHARED_CARDS_INFO, "w");
	if (!fhandle) {
		cs_log("Couldn't open %s: %s\n", FILE_SHARED_CARDS_INFO, strerror(errno));
		return;
	}

	struct s_client *cl;
	LL_ITER it;
	for (i = 0, cl = first_client; cl; cl = cl->next, i++) {
		if (cl->gbox) {
			struct s_reader *rdr = cl->reader;
			struct gbox_data *gbox = cl->gbox;
			struct gbox_card *card;
			
			//local cards should be written once - not for every peer
			if (!local_written) {
			  it = ll_iter_create(gbox->local_cards);
                          while ((card = ll_iter_next(&it))) {
                                fprintf(fhandle, "CardID %4d at oscam Card %08X Sl:%2d Lev:%2d dist:%2d id:%04X\n",
                                        card_count, card->provid_1,
                                        card->slot, card->lvl, card->dist, card->peer_id);
                                card_count++;
                          } // end of while ll_iter_next
                          local_written = 1;
			}

			if ((rdr->card_status == CARD_INSERTED) &&  (cl->typ == 'p')) {
				it = ll_iter_create(gbox->peer.cards);
				while ((card = ll_iter_next(&it))) {
					fprintf(fhandle, "CardID %4d at %s Card %08X Sl:%2d Lev:%2d dist:%2d id:%04X\n",
						card_count, cl->reader->label, card->provid_1,
						card->slot, card->lvl, card->dist, card->peer_id);
					card_count++;
				} // end of while ll_iter_next
			} // end of if INSERTED && 'p'
		} // end of if cl->gbox
	} // end of for cl->next
	fclose(fhandle);
	return;
}

void hostname2ip(char *hostname, IN_ADDR_T* ip)
{
	cs_resolve(hostname, ip, NULL, NULL);
}

void gbox_add_good_card(struct s_client *cl, uint16_t id_card, uint16_t caid, uint32_t prov, uint16_t sid_ok)
{
	struct gbox_data *gbox = cl->gbox;
	struct gbox_card *card = NULL;
	struct gbox_srvid *srvid = NULL;
	LL_ITER it = ll_iter_create(gbox->peer.cards);
	while ((card = ll_iter_next(&it))) {
		if (card->peer_id == id_card && card->caid == caid && card->provid == prov) {
			cl->reader->currenthops = card->dist;
			LL_ITER it2 = ll_iter_create(card->goodsids);
			while ((srvid = ll_iter_next(&it2))) {
				if (srvid->sid == sid_ok) {
					return; // sid_ok is already in the list of goodsids
				}
			}

			LL_ITER it3 = ll_iter_create(card->badsids);
			while ((srvid = ll_iter_next(&it3))) {
				if (srvid->sid == sid_ok){
					ll_iter_remove_data(&it3); // remove sid_ok from badsids
					break;
				}
			}

			if (!cs_malloc(&srvid, sizeof(struct gbox_srvid)))
				return;
			srvid->sid=sid_ok;
			srvid->peer_idcard=id_card;
			srvid->provid_id=card->provid;
                        cs_debug_mask(D_READER, "GBOX Adding good SID: %04X for CAID: %04X Provider: %04X on CardID: %04X\n",sid_ok,caid,card->provid,id_card);
			ll_append(card->goodsids, srvid);
			break;
		}
	}//end of ll_iter_next
	//return dist_c;
}

void gbox_free_card(struct gbox_card *card)
{
	ll_destroy_data_NULL(card->badsids);
	ll_destroy_data_NULL(card->goodsids);
	add_garbage(card);
	return;
}

void gbox_remove_cards_without_goodsids(LLIST *card_list)
{
	if (card_list) {
		LL_ITER it = ll_iter_create(card_list);
		struct gbox_card *card;
		while ((card = ll_iter_next(&it))) {
				if (ll_count(card->goodsids)==0){
					ll_iter_remove(&it);
					gbox_free_card(card);
				} else {
					ll_destroy_data_NULL(card->badsids);
				}
		}
	}
	return;
}

void gbox_free_cardlist(LLIST *card_list)
{
	if (card_list) {
		LL_ITER it = ll_iter_create(card_list);
		struct gbox_card *card;
		while ((card = ll_iter_next_remove(&it))) {
				gbox_free_card(card);
		}
		ll_destroy_NULL(card_list);
	}
	return;
}

// if input client is typ proxy get client and vice versa
struct s_client *switch_client_proxy(struct s_client *cli)
{
        struct s_client *cl;
        int8_t typ;
        if (cli->typ == 'c')
          typ = 'p';
        else
          typ = 'c';
        for (cl = first_client; cl; cl = cl->next) {
        //needfix: only one gbox per IP. Ports?
          if (IP_EQUAL(cli->ip,cl->ip) && cl->typ == typ && cl->gbox) {
            return cl;
          }  
        }
        return cli;
}

void gbox_reconnect_client(void)
{
	struct s_client *cl;
	for (cl = first_client; cl; cl = cl->next) {
		if (cl->gbox) {
			hostname2ip(cl->reader->device, &SIN_GET_ADDR(cl->udp_sa));
			SIN_GET_FAMILY(cl->udp_sa) = AF_INET;
			SIN_GET_PORT(cl->udp_sa) = htons((uint16_t)cl->reader->r_port);
			hostname2ip(cl->reader->device, &(cl->ip));
			cl->reader->tcp_connected = 0;
			cl->reader->card_status = CARD_NEED_INIT;
			struct gbox_data *gbox = cl->gbox;
			gbox->peer.online = 0;
			gbox->peer.ecm_idx = 0;
			gbox->peer.hello_stat = GBOX_STAT_HELLOL;
			gbox->peer.t_ecm=time((time_t*)0);
			cl->reader->last_s = cl->reader->last_g = 0;
			gbox_free_cardlist(gbox->peer.cards);
			gbox->peer.cards = ll_create("peer.cards");
			gbox_send_hello(cl);
		}
	}
}

static void * gbox_server(struct s_client *cli, uchar *b, int32_t l)
{
  if (l > 0) {
	cs_log("gbox:  gbox_server %s/%d",cli->reader->label, cli->port);
	gbox_recv2(cli, b, l);
  }
  return 0;
}

char *gbox_username(struct s_client * client)
{
  if (!client) return "anonymous";
  if (client->reader)
    if (client->reader->r_usr[0]){
      return client->reader->r_usr;
    }
  return "anonymous";
}

static void gbox_auth_client(struct s_client *cli)
{
      struct s_client *cl = switch_client_proxy(cli);
      if (cl->typ == 'p' && cl->gbox && cl->reader) {
        cli->crypted = 1; //display as crypted
        cli->gbox = cl->gbox; //point to the same gbox as proxy
        cli->reader = cl->reader; //point to the same reader as proxy

        struct s_auth *account = get_account_by_name( gbox_username(cl));
        if (account) {
          cs_auth_client(cli, account, NULL);
          cli->account = account;
          cl->account = account;
          cli->grp = account->grp;
        }
      }
      return ;
} 

static void gbox_server_init(struct s_client *cl)
{
        if (!cl->init_done) {
          if (IP_ISSET(cl->ip))
	  	cs_log("gbox: new connection from %s", cs_inet_ntoa(cl->ip));
          gbox_auth_client(cl);
          if (cl->gbox) {
            gbox_local_cards(cl);
            cl->init_done=1;
          }  
        }
        return;
}
/*
static void gbox_decompress2(uchar *buf, int32_t *unpacked_len)
{
	uint8_t *tmp;
	if (!cs_malloc(&tmp,0x40000))
		return;

	int err;
	int len = *unpacked_len - 12;
	*unpacked_len = 0x40000;

	lzo_init();
	cs_debug_mask(D_READER, "decompressing %d bytes",len);
	if ((err=lzo1x_decompress_safe(buf + 12, len, tmp, (lzo_uint *)unpacked_len, NULL)) != LZO_E_OK) {
		cs_debug_mask(D_READER, "gbox: decompression failed! errno=%d", err);
	}

	memcpy(buf + 12, tmp, *unpacked_len);
	*unpacked_len += 12;
	free(tmp);
}
*/
int32_t gbox_cmd_hello(struct s_client *cli, int32_t n)
{
	struct gbox_data *gbox = cli->gbox;
	uint8_t *data = gbox->buf;
	int32_t i;
	int32_t ncards_in_msg = 0;
	int32_t payload_len = n;
	//TODO: checkcode_len can be made void
	int32_t checkcode_len = 0;
	int32_t hostname_len = 0;
	int32_t footer_len = 0;
	uint8_t *ptr = 0;

	if (!(data[0] == 0x48 && data[1]==0x49)) { // if not MSG_HELLO1
		gbox_decompress(gbox, data, &payload_len);
	}
	cs_ddump_mask(D_READER, data, payload_len, "gbox: decompressed data (%d bytes):", payload_len);

	if ((data[0x0B] == 0) | ((data[0x0A] == 1) && (data[0x0B] == 0x80))) {
		if (gbox->peer.cards)
			gbox_remove_cards_without_goodsids(gbox->peer.cards);
		else
			gbox->peer.cards = ll_create("peer.cards");
        }
        if ((data[0xB] & 0xF) == 0) {        
                checkcode_len = 7;
                hostname_len = data[payload_len - 1];
                footer_len = hostname_len + 2;
	}

	if (data[0] == 0x48 && data[1] == 0x49) // if MSG_HELLO1
		ptr = data + 11;
	else
		ptr = data + 12;

	while (ptr < data + payload_len - footer_len - checkcode_len - 1) {
		uint16_t caid;
		uint32_t provid;
		uint32_t provid1;

		switch (ptr[0]) {
		  //Viaccess
		  case 0x05:		
                      caid = ptr[0] << 8;
                      provid =  ptr[1] << 16 | ptr[2] << 8 | ptr[3];
                      break;
                  //Cryptoworks
                  case 0x0D:    	
                      caid = ptr[0] << 8 | ptr[1];
                      provid =  ptr[2];
                      break;
                  default:    
                      caid = ptr[0] << 8 | ptr[1];
                      provid =  ptr[2] << 8 | ptr[3];
                      break;
		}
		
		//caid check
		if (chk_ctab(caid, &cli->reader->ctab)){

		  provid1 =  ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
		  int32_t ncards = ptr[4];

		  ptr += 5;

		  for (i = 0; i < ncards; i++) {
			// for all n cards and current caid/provid,
			// create card info from data and add card to peer.cards
			struct gbox_card *card;
			if (!cs_malloc(&card,sizeof(struct gbox_card)))
				continue;

			card->caid = caid;
			card->provid = provid;
			card->provid_1 = provid1;
			card->slot = ptr[0];
			card->dist = ptr[1] & 0xf;
			card->lvl = ptr[1] >> 4;
			card->peer_id = ptr[2] << 8 | ptr[3];
			ptr += 4;

			if ((cli->reader->gbox_maxdist >= card->dist) && (card->peer_id != gbox->id)) {

				LL_ITER it = ll_iter_create(gbox->peer.cards);
				struct gbox_card *card_s;
				uint8_t v_card=0;
				while ((card_s = ll_iter_next(&it))) { // don't add card if already in peer.cards list
					if (card_s->peer_id == card->peer_id && card_s->provid_1 == card->provid_1) {
						gbox_free_card(card);
						card=NULL;
						v_card=1;
						break;
					}
				}

				if (v_card != 1) { // new card - not in list
					card->badsids = ll_create("badsids");
					card->goodsids = ll_create("goodsids");
					ll_append(gbox->peer.cards, card);
					ncards_in_msg++;
					cs_debug_mask(D_READER,"   card: caid=%04x, provid=%06x, slot=%d, level=%d, dist=%d, peer=%04x",
							card->caid, card->provid, card->slot, card->lvl, card->dist, card->peer_id);
				}
			} else { // don't add card
				gbox_free_card(card);
				card=NULL;
			}
			cli->reader->tcp_connected = 2; // we have card
                  } // end for ncards
                } else {
                    ptr += 5 + ptr[4] * 4; //skip cards because caid
                }  
	} // end while caid/provid

	if (!(data[0x0B]&0xF)) { // first packet. We've got peer hostname
		NULLFREE(gbox->peer.hostname);
		if (!cs_malloc(&gbox->peer.hostname,hostname_len + 1)) {
			cs_writeunlock(&gbox->lock);
			return -1;
		}
		memcpy(gbox->peer.hostname, data + payload_len - 1 - hostname_len, hostname_len);
		gbox->peer.hostname[hostname_len] = '\0';

		gbox_checkcode_recv(cli, data + payload_len - footer_len - checkcode_len - 1);  
		gbox->peer.ver = data[payload_len - footer_len - 1];
		gbox->peer.type = data[payload_len - footer_len];              
	} // end if first hello packet

	if (data[0x0B]&0x80) {	//last packet
		gbox->peer.online = 1;
	        if (!data[0xA]) {
                  cs_log("<-HelloS from %s (%s:%d)",cli->reader->label,cs_inet_ntoa(cli->ip), cli->reader->r_port);
		  gbox->peer.hello_stat = GBOX_STAT_HELLOR;
                  gbox_send_hello(cli);                 
                } else {
                  cs_log("<-HelloR from %s (%s:%d)",cli->reader->label,cs_inet_ntoa(cli->ip), cli->reader->r_port);
                  gbox_send_checkcode(cli);
                }  
                if (gbox->peer.hello_stat == GBOX_STAT_HELLOS) {
                  gbox_send_hello(cli);                 
                }                    		
		cli->reader->tcp_connected = 2; //we have card
		cli->reader->card_status = CARD_INSERTED;
		if (ll_count(gbox->peer.cards)==0)
			cli->reader->card_status = NO_CARD;

		gbox_write_shared_cards_info();
		gbox_write_version();
	}
	return 0;
}

int32_t gbox_cmd_switch(struct s_client *cli, int32_t n)
{
	struct gbox_data *gbox = cli->gbox;
	uchar *data = gbox->buf;
	int32_t n1=0, rc1=0, i1, idx, diffcheck=0;
	uchar dcw[16];
	struct s_client *cl;

	switch (gbox_decode_cmd(data)) {
	case MSG_BOXINFO:
	        // Keep alive message
                pthread_mutex_lock (&gbox->hello_expire_mut);
                pthread_cond_signal(&gbox->hello_expire_cond);
                pthread_mutex_unlock (&gbox->hello_expire_mut);
		gbox_send_hello(cli);
		break;
	case MSG_GOODBYE:
	        //needfix what to do after Goodbye?
	        //suspect: we get goodbye as signal of SID not found
		break;
	case MSG_HELLO1:
	case MSG_HELLO:
		if (gbox_cmd_hello(cli, n) < 0)
			return -1;
                pthread_mutex_lock (&gbox->hello_expire_mut);
                pthread_cond_signal(&gbox->hello_expire_cond);
                pthread_mutex_unlock (&gbox->hello_expire_mut);
		break;
	case MSG_CW:
		memcpy(gbox->cws, data + 14, 16);
		cli->last=time((time_t*)0);
		idx=gbox_recv_chk(cli, dcw, &rc1, data, rc1);
		if (idx<0) break;  // no dcw received
		if (!idx) idx=cli->last_idx;
		cli->reader->last_g= time((time_t*)0); // for reconnect timeout
		for (i1=0, n1=0; i1< cfg.max_pending && n1 == 0; i1++) {
			if (cli->ecmtask[i1].idx==idx) {
				cli->pending--;
				casc_check_dcw(cli->reader, i1, rc1, dcw);
				n1++;
			}
		}
		pthread_mutex_lock (&gbox->hello_expire_mut);
		pthread_cond_signal(&gbox->hello_expire_cond);
		pthread_mutex_unlock (&gbox->hello_expire_mut);
		break;
	case MSG_CHECKCODE:
	        gbox_checkcode_recv(cli, data + 10);
		pthread_mutex_lock (&gbox->hello_expire_mut);
		pthread_cond_signal(&gbox->hello_expire_cond);
		pthread_mutex_unlock (&gbox->hello_expire_mut);
		break;
	case MSG_ECM: {
	        cl = switch_client_proxy(cli);
	        gbox = cl->gbox;

	        gbox->peer.t_ecm = time((time_t*)0);

		ECM_REQUEST *er;
		if (!(er=get_ecmtask())) break;

		struct gbox_ecm_info *ei;
		if (!cs_malloc(&ei,sizeof(struct gbox_ecm_info))){
			cs_writeunlock(&gbox->lock);
			return -1;
		}
		
		// No ECMs with length < 8 expected
		if (data[20] < 8)
		  return -1;
		
		er->src_data = ei;
		uchar *ecm = data + 18;

		gbox->peer.gbox_count_ecm++;
		er->gbox_ecm_id = gbox->peer.id;

		if (gbox->peer.ecm_idx == 100)gbox->peer.ecm_idx=0;

		er->idx = gbox->peer.ecm_idx++;
		er->ecmlen = ecm[2] + 3;

		er->pid = data[10] << 8 | data[11];
		er->srvid = data[12] << 8 | data[13];

		int32_t adr_caid_1 = data[20] + 26;
		if (data[adr_caid_1] == 0x05)
			er->caid = (data[adr_caid_1]<<8);
		else
			er->caid = (data[adr_caid_1]<<8 | data[adr_caid_1+1]);

		ei->caid = (data[adr_caid_1]<<8 | data[adr_caid_1+1]);

		gbox->peer.last_caid=er->caid;
		gbox->peer.last_srvid=er->srvid;
		ei->extra = data[14] << 8 | data[15];
		memcpy(er->ecm, data + 18, er->ecmlen);
		//ei->ecm = gbox ecm without checksums
		memcpy(ei->ecm, data, (-14 +n));
		ei->l=(-14+n);

		ei->id_cl_gbox=gbox->peer.id;

		ei->ncards = data[16];
		ei->peer_cw = data[data[0x14]+0x1F] << 8 | data[data[0x14]+0x20];
		ei->peer = ecm[er->ecmlen] << 8 | ecm[er->ecmlen + 1];
		ei->version = ecm[er->ecmlen + 2];
		ei->type = ecm[er->ecmlen + 4];
		ei->slot = ecm[er->ecmlen + 12];
		diffcheck = gbox_checkcode_recv(cl, data + n - 14);
		//TODO: What do we do with our own checkcode @-7?
		memcpy(ei->checksums, data + n - 14, 14);
		er->gbox_crc = gbox_get_ecmchecksum(er);
		er->gbox_hops = data[-15 + n] + 1;
		er->gbox_peer = ei->peer;

		er->prid = chk_provid(er->ecm, er->caid);
		cs_debug_mask(D_READER, "<- ECM (%d<-) from server (%s:%d) to cardserver (%04X) SID %02X%02X", er->gbox_hops, gbox->peer.hostname,cli->port,ei->peer,data[0x0C],data[0x0D]);
		get_cw(cl, er);
		//TODO:gbox_cw_cache(cli,er);

		//checkcode did not match gbox->peer checkcode
		if (diffcheck) {
//		  TODO: Send HelloS here?		
//		  gbox->peer.hello_stat = GBOX_STAT_HELLOS;
//                gbox_send_hello(cli);                 		
		}
		break;
	}
	default:
		cs_ddump_mask(D_READER, data, n, "gbox: unknown data received (%d bytes):", n);
	} // end switch
	return 0;
}
/*
int32_t gbox_peer_ip_unverified(IN_ADDR_T recv_ip, in_port_t recv_port, uchar *b, int32_t l)
{
	uchar attc_key[4];
	char no_hostname[64];
	int32_t payload_len;
	int32_t hostname_len;
	uint32_t key = a2i("AF14E35C", 4);
	int32_t i;

	for (i = 3; i >= 0; i--) {
		attc_key[3 - i] = (key >> (8 * i)) & 0xff;
	}
	gbox_decrypt(b, l, attc_key);

	switch (gbox_decode_cmd(b)) {
	case MSG_HELLO:
	case MSG_HELLO1:
		payload_len = l;
		hostname_len = b[payload_len - 1];
		gbox_decompress2(b, &payload_len);
		if ((b[0x0B] == 0) | (b[0x0B] == 0x80)) { // we've got peer hostname
			memcpy(no_hostname, b + payload_len - 1 - hostname_len, hostname_len);
			no_hostname[hostname_len] = '\0';
		}
		break;

	case MSG_BOXINFO:
		if (l>11) {
			memcpy(no_hostname, b + 12, l-11);		no_hostname[l-12] = '\0';
			break;
		}
		memcpy(no_hostname, "No peer gbox 0", 14);	no_hostname[14] = '\0';
		break;

	default:
		memcpy(no_hostname, "No peer gbox", 12);	no_hostname[12] = '\0';
		break;
	}

	if (cs_add_violation_by_ip(recv_ip,recv_port,no_hostname)==0) {
		FILE *fhandle = fopen(FILE_ATTACK_INFO, "a");
		if (!fhandle) {
			memcpy(no_hostname, "No peer gbox_3", 14); no_hostname[14] = '\0';
			cs_add_violation_by_ip(recv_ip, recv_port, no_hostname);
			return -1;
		}
		fprintf(fhandle,"gbox: ATACK ALERT: %s proxy %s:%d MSG_TYP %02X%02X my pass %02X%02X%02X%02X peer pass  %02X%02X%02X%02X\n", no_hostname,cs_inet_ntoa(recv_ip), recv_port,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9]);
		fclose(fhandle);
	}

	return 0;
}
*/
static int32_t gbox_recv2(struct s_client *cli, uchar *b, int32_t l)
{
        struct gbox_data *gbox = cli->gbox;
	uchar *data = gbox->buf;
	char tmp[0x50];

	if (!gbox)
          return -1;

	int32_t n=l;
	memcpy(data ,b, l);

	cs_writelock(&gbox->lock);

	cs_ddump_mask(D_READER, data, n, "gbox: encrypted data received (%d bytes):", n);

	if ((data[0]==0x48)&&(data[1]==0x49)) // if MSG_HELLO1
          cs_log("test cs2gbox");
	else
	  gbox_decrypt(data, n, gbox->key);

	// if my pass ok verify CW | pass to peer
	if (data[0]==0x48 && data[1]==0x44){ // if MSG_CW
          if (data[39] != cli->gbox_cw_id[0] && data[40] != cli->gbox_cw_id[1]){
            cs_writeunlock(&gbox->lock);
            //continue; // next client
	  }
	}

	cs_ddump_mask(D_READER, data, n, "gbox: decrypted received data (%d bytes):", n);

	//verify my pass received
	if (data[2]==gbox->key[0] && data[3]==gbox->key[1] && data[4]==gbox->key[2] && data[5]==gbox->key[3]) {
  	  cs_debug_mask(D_READER,"received data, peer : %04x   data: %s",gbox->peer.id,cs_hexdump(0, data, l, tmp, sizeof(tmp)));

  	  if (data[0]!=0x48 && data[1]!=0x44) { // if MSG_CW
	    if (data[6]!=gbox->peer.key[0] && data[7]!=gbox->peer.key[1] && data[8]!=gbox->peer.key[2] && data[9]!=gbox->peer.key[3]) {
	      cs_writeunlock(&gbox->lock);
	      //continue; // next client
            }
          }
	}  // error my pass
	else {
	  cs_log("gbox: ATTACK ALERT: proxy %s:%d",cs_inet_ntoa(cli->ip), cli->reader->r_port);
	  cs_log("received data, peer : %04x   data: %s",gbox->peer.id,cs_hexdump(0, data, n, tmp, sizeof(tmp)));
	  cs_writeunlock(&gbox->lock);
	  //continue; // next client
	}
	if (gbox_cmd_switch(cli, n) < 0)
  	  return -1;

	cs_writeunlock(&gbox->lock);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
// GBOX BUFFER ENCRYPTION/DECRYPTION (thanks to dvbcrypt@gmail.com)
////////////////////////////////////////////////////////////////////////////////

static unsigned char Lookup_Table[0x40] = {
  0x25,0x38,0xD4,0xCD,0x17,0x7A,0x5E,0x6C,0x52,0x42,0xFE,0x68,0xAB,0x3F,0xF7,0xBE,
  0x47,0x57,0x71,0xB0,0x23,0xC1,0x26,0x6C,0x41,0xCE,0x94,0x37,0x45,0x04,0xA2,0xEA,
  0x07,0x58,0x35,0x55,0x08,0x2A,0x0F,0xE7,0xAC,0x76,0xF0,0xC1,0xE6,0x09,0x10,0xDD,
  0xC5,0x8D,0x2E,0xD9,0x03,0x9C,0x3D,0x2C,0x4D,0x41,0x0C,0x5E,0xDE,0xE4,0x90,0xAE
  };


void gbox_encrypt8(unsigned char *buffer, unsigned char *pass)
{
  int passcounter;
  int bufcounter;
  unsigned char temp;

  for(passcounter=0; passcounter<4; passcounter++)
    for(bufcounter=7; bufcounter>=0; bufcounter--)
    {
      temp = ( buffer[bufcounter]>>2);
      temp = pass[3];
      pass[3] = (pass[3]/2)+(pass[2]&1)*0x80;
      pass[2] = (pass[2]/2)+(pass[1]&1)*0x80;
      pass[1] = (pass[1]/2)+(pass[0]&1)*0x80;
      pass[0] = (pass[0]/2)+(temp   &1)*0x80;
      buffer[(bufcounter+1) & 7] = buffer[ (bufcounter+1) & 7 ] - Lookup_Table[ (buffer[bufcounter]>>2) & 0x3F ];
      buffer[(bufcounter+1) & 7] = Lookup_Table[ ( buffer[bufcounter] - pass[(bufcounter+1) & 3] ) & 0x3F ] ^ buffer[ (bufcounter+1) & 7 ];
      buffer[(bufcounter+1) & 7] = buffer[ (bufcounter+1) & 7 ] - pass[(bufcounter & 3)];
    }
}

void gbox_decrypt8(unsigned char *buffer,unsigned char *pass)
{
 unsigned char temp;
 int bufcounter;
 int passcounter;
  for( passcounter=3; passcounter>=0; passcounter--)
  for( bufcounter=0; bufcounter<=7; bufcounter++) {
    buffer[(bufcounter+1)&7] = pass[bufcounter&3] + buffer[(bufcounter+1)&7];
    temp = buffer[bufcounter] -  pass[(bufcounter+1)&3];
    buffer[(bufcounter+1)&7] = Lookup_Table[temp &0x3F] ^ buffer[(bufcounter+1)&7];
    temp = buffer[bufcounter] >> 2;
    buffer[(bufcounter+1)&7] =  Lookup_Table[temp & 0x3F] + buffer[(bufcounter+1)&7];

    temp = pass[0] & 0x80;
    pass[0] = ( (pass[1]&0x80)>>7 ) + (pass[0]<<1);
    pass[1] = ( (pass[2]&0x80)>>7 ) + (pass[1]<<1);
    pass[2] = ( (pass[3]&0x80)>>7 ) + (pass[2]<<1);
    pass[3] = ( temp>>7 ) + (pass[3]<<1);
  }

}

void gbox_decryptB(unsigned char *buffer, int bufsize, uchar *localkey)
{
  int counter;
  gbox_encrypt8(&buffer[bufsize-9], localkey);
  gbox_decrypt8(buffer, localkey);
  for (counter=bufsize-2; counter>=0; counter--)
    buffer[counter] = buffer[counter+1] ^ buffer[counter];
}

void gbox_encryptB(unsigned char *buffer, int bufsize, uchar *key)
{
 int counter;
  for (counter=0; counter<(bufsize-1); counter++)
    buffer[counter] = buffer[counter+1] ^ buffer[counter];
  gbox_encrypt8(buffer, key);
  gbox_decrypt8(&buffer[bufsize-9], key);
}

void gbox_encryptA(unsigned char *buffer, unsigned char *pass)
{
  int counter;
  unsigned char temp;
  for (counter=0x1F; counter>=0; counter--) {
    temp = pass[3]&1;
    pass[3] = ((pass[2]&1)<<7) + (pass[3]>>1);
    pass[2] = ((pass[1]&1)<<7) + (pass[2]>>1);
    pass[1] = ((pass[0]&1)<<7) + (pass[1]>>1);
    pass[0] = (temp<<7) + (pass[0]>>1);
    temp = ( pass[(counter+1)&3] ^ buffer[counter&7] ) >> 2;
    buffer[(counter+1)&7] = Lookup_Table[temp & 0x3F]*2  +  buffer[  (counter+1) & 7 ];
    temp = buffer[counter&7] - pass[(counter+1) & 3];
    buffer[(counter+1)&7] = Lookup_Table[temp & 0x3F] ^ buffer[(counter+1)&7];
    buffer[(counter+1)&7] = pass[counter&3] + buffer[(counter+1)&7];
  }
}

void gbox_decryptA(unsigned char *buffer, unsigned char *pass)
{
  int counter;
  unsigned char temp;
  for (counter=0; counter<=0x1F; counter++) {
    buffer[(counter+1)&7] = buffer[(counter+1)&7] - pass[counter&3];
    temp = buffer[counter&7] - pass[(counter+1)&3];
    buffer[(counter+1)&7] = Lookup_Table[temp&0x3F] ^ buffer[(counter+1)&7];
    temp = ( pass[ (counter+1) & 3] ^ buffer[counter & 7] ) >> 2;
    buffer[(counter+1) & 7] = buffer[(counter+1)&7] - Lookup_Table[temp & 0x3F]*2;
    temp = pass[0]&0x80;
    pass[0] = ((pass[1]&0x80)>>7) + (pass[0]<<1);
    pass[1] = ((pass[2]&0x80)>>7) + (pass[1]<<1);
    pass[2] = ((pass[3]&0x80)>>7) + (pass[2]<<1);
    pass[3] = (temp>>7) + (pass[3]<<1);
  }
}

void gbox_encrypt(uchar *buffer, int bufsize, uchar *key)
{
	gbox_encryptA(buffer, key);
	gbox_encryptB(buffer, bufsize, key);
}

void gbox_decrypt(uchar *buffer, int bufsize, uchar *localkey)
{
	gbox_decryptB(buffer, bufsize, localkey);
	gbox_decryptA(buffer, localkey);
}

static void gbox_compress(struct gbox_data *UNUSED(gbox), uchar *buf, int32_t unpacked_len, int32_t *packed_len)
{
  unsigned char *tmp, *tmp2;
  lzo_voidp wrkmem;

  if (!cs_malloc(&tmp, 0x40000)) {
    return;
  }
  if (!cs_malloc(&tmp2,0x40000)) {
    free(tmp);
    return;
  }

  if (!cs_malloc(&wrkmem, unpacked_len * 0x1000)) {
    free(tmp);
    free(tmp2);
    return;
  }

  unpacked_len -= 12;
  memcpy(tmp2, buf + 12, unpacked_len);

  lzo_init();

  lzo_uint pl = 0;
  if (lzo1x_1_compress(tmp2, unpacked_len, tmp, &pl, wrkmem) != LZO_E_OK)
    cs_log("gbox: compression failed!");

  memcpy(buf + 12, tmp, pl);
  pl += 12;

  free(tmp);
  free(tmp2);
  free(wrkmem);

  *packed_len = pl;
}

static void gbox_decompress(struct gbox_data *UNUSED(gbox), uchar *buf, int32_t *unpacked_len)
{
  uchar *tmp;

  if (!cs_malloc(&tmp, 0x40000))
    return;
  int err;
  int len = *unpacked_len - 12;
  *unpacked_len = 0x40000;

  lzo_init();
  cs_debug_mask(D_READER, "decompressing %d bytes",len);
  if ((err=lzo1x_decompress_safe(buf + 12, len, tmp, (lzo_uint *)unpacked_len, NULL)) != LZO_E_OK)
    cs_debug_mask(D_READER, "gbox: decompression failed! errno=%d", err);

  memcpy(buf + 12, tmp, *unpacked_len);
  *unpacked_len += 12;
  free(tmp);
}

static int32_t gbox_decode_cmd(uchar *buf)
{
  return buf[0] << 8 | buf[1];
}

void gbox_code_cmd(uchar *buf, int16_t cmd)
{
  buf[0] = cmd >> 8;
  buf[1] = cmd & 0xff;
}

static void gbox_calc_checkcode(struct gbox_data *gbox)
{
  if (gbox->peer.hello_stat != GBOX_STAT_HELLOL)
  {
    gbox->checkcode[0] = 0x15;
    gbox->checkcode[1] = 0x30;
    gbox->checkcode[2] = 0x02;
    gbox->checkcode[3] = 0x04;
    gbox->checkcode[4] = 0x19; 
    gbox->checkcode[5] = 0x19;
    gbox->checkcode[6] = 0x66;

    LL_ITER it = ll_iter_create(gbox->local_cards);
    struct gbox_card *card;
    while ((card = ll_iter_next(&it))) {
      gbox->checkcode[0] ^= (0xFF & (card->provid_1 >> 24));
      gbox->checkcode[1] ^= (0xFF & (card->provid_1 >> 16));
      gbox->checkcode[2] ^= (0xFF & (card->provid_1 >> 8));
      gbox->checkcode[3] ^= (0xFF & (card->provid_1));
      gbox->checkcode[4] ^= (0xFF & (card->slot));
      gbox->checkcode[5] ^= (0xFF & (card->peer_id >> 8));
      gbox->checkcode[6] ^= (0xFF & (card->peer_id));
    }
    it = ll_iter_create(gbox->peer.cards);
    while ((card = ll_iter_next(&it))) {
      gbox->checkcode[0] ^= (0xFF & (card->provid_1 >> 24));
      gbox->checkcode[1] ^= (0xFF & (card->provid_1 >> 16));
      gbox->checkcode[2] ^= (0xFF & (card->provid_1 >> 8));
      gbox->checkcode[3] ^= (0xFF & (card->provid_1));
      gbox->checkcode[4] ^= (0xFF & (card->slot));
      gbox->checkcode[5] ^= (0xFF & (card->peer_id >> 8));
      gbox->checkcode[6] ^= (0xFF & (card->peer_id));
    }
  }
  else {
    gbox->checkcode[0] = 0;
    gbox->checkcode[1] = 0;
    gbox->checkcode[2] = 0;
    gbox->checkcode[3] = 0;
    gbox->checkcode[4] = 0; 
    gbox->checkcode[5] = 0;
    gbox->checkcode[6] = 0;  
  }    
}

//returns 1 if checkcode changed / 0 if not
static int32_t gbox_checkcode_recv(struct s_client *cli, uchar *checkcode)
{
  struct gbox_data *gbox = cli->gbox;
  char tmp[0x50];

  if (memcmp(gbox->peer.checkcode, checkcode, 7)) {
    memcpy(gbox->peer.checkcode, checkcode, 7);
    cs_debug_mask(D_READER, "gbox: received new checkcode=%s",  cs_hexdump(0, gbox->peer.checkcode, 7, tmp, sizeof(tmp)));
    return 1;
  }
  return 0;
}

uint32_t gbox_get_ecmchecksum(ECM_REQUEST *er)
{

  uint8_t checksum[4];
  int32_t counter;

  uchar ecm[255];
  memcpy(ecm, er->ecm, er->ecmlen);

  checksum[3] = ecm[0];
  checksum[2] = ecm[1];
  checksum[1] = ecm[2];
  checksum[0] = ecm[3];

  for (counter=1; counter < (er->ecmlen/4) - 4; counter++) {
    checksum[3] ^= ecm[counter*4];
    checksum[2] ^= ecm[counter*4+1];
    checksum[1] ^= ecm[counter*4+2];
    checksum[0] ^= ecm[counter*4+3];
  }

  return checksum[3] << 24 | checksum[2] << 16 | checksum[1] << 8 | checksum[0];
}

/*
static void gbox_handle_gsms(uint16_t peerid, char *gsms)
{
	cs_log("gbox: gsms received from peer %04x: %s", peerid, gsms);

	if (cfg.gbox_gsms_path) {
		FILE *f = fopen(cfg.gbox_gsms_path, "a");
		if (f) {
			f//printf(f, "FROM %04X: %s\n", peerid, gsms);
			fclose(f);
		}
		else
			cs_log("gbox: error writing to file! (path=%s)", cfg.gbox_gsms_path);
	}
}
*/

static void gbox_expire_hello(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;

  int32_t callback = 60;

  set_thread_name(__func__);

  struct timespec ts;
  struct timeval tv;
  
  pthread_mutex_init(&gbox->hello_expire_mut, NULL);
  pthread_cond_init(&gbox->hello_expire_cond, NULL);

  while (1) {
    gettimeofday(&tv, NULL);
    ts.tv_sec = tv.tv_sec + callback;
    ts.tv_nsec = tv.tv_usec * 1000;

    pthread_mutex_lock (&gbox->hello_expire_mut);
    if (pthread_cond_timedwait(&gbox->hello_expire_cond, &gbox->hello_expire_mut, &ts) == ETIMEDOUT) {
      switch (gbox->peer.hello_stat) {
        case GBOX_STAT_HELLOS:
          gbox->peer.hello_stat = GBOX_STAT_HELLOL;
          gbox_send_hello(cli);
          callback = 180;          
          break;      
        
        case GBOX_STAT_HELLOR:
          callback = 300;
          break;                
                  
        case GBOX_STAT_HELLO3:
          gbox->peer.hello_stat = GBOX_STAT_HELLOS;         
//          gbox_send_boxinfo(cli);
//          gbox_send_hello(cli);
          callback = 900;
          gbox->peer.hello_stat = GBOX_STAT_HELLO3;
          break;      

        case GBOX_STAT_HELLO4:
          gbox_send_boxinfo(cli);                            
          break;               
      }
    }
    pthread_mutex_unlock (&gbox->hello_expire_mut);
  }    
}

/* static void gbox_wait_for_response(struct s_client *cli)
{
	//printf("gbox: enter gbox_wait_for_response()\n");
	//cs_debug_mask(D_READER, "gbox: enter gbox_wait_for_response()");
	struct gbox_data *gbox = cli->gbox;
	struct timespec ts;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;
	ts.tv_sec += 5;

	pthread_mutex_lock (&gbox->peer_online_mutex);
	if (pthread_cond_timedwait(&gbox->peer_online_cond, &gbox->peer_online_mutex, &ts) == ETIMEDOUT) {
		gbox->peer.fail_count++;
		//printf("gbox: wait timed-out, fail_count=%d\n", gbox->peer.fail_count);
#define GBOX_FAIL_COUNT 1
		if (gbox->peer.fail_count >= GBOX_FAIL_COUNT) {
			gbox->peer.online = 0;
			//printf("gbox: fail_count >= %d, peer is offline\n", GBOX_FAIL_COUNT);
		}
		//cs_debug_mask(D_READER, "gbox: wait timed-out, fail_count=%d\n", gbox->peer.fail_count);
	} else {
		gbox->peer.fail_count = 0;
		//printf("gbox: cond posted, peer is online\n");
	}
	pthread_mutex_unlock (&gbox->peer_online_mutex);

	//cs_debug_mask(D_READER, "gbox: exit gbox_wait_for_response()");
	//printf("gbox: exit gbox_wait_for_response()\n");
} */

static void gbox_send(struct s_client *cli, uchar *buf, int32_t l)
{
  struct gbox_data *gbox = cli->gbox;
  uchar key_v[4] = {buf[2], buf[3], buf[4], buf[5]};
  if (key_v[0]!=gbox->peer.key[0] && key_v[1]!=gbox->peer.key[1] && key_v[2]!=gbox->peer.key[2] && key_v[3]!=gbox->peer.key[3]) {
    cs_log("gbox: VERIFY send proxy ,gbox->peer.key: %02x%02x%02x%02x",gbox->peer.key[0],gbox->peer.key[1],gbox->peer.key[2],gbox->peer.key[3]);
    cs_log("gbox: VERIFY send proxy ,key_v         : %02x%02x%02x%02x",key_v[0],key_v[1],key_v[2],key_v[3]);
  }

  cs_ddump_mask(D_READER, buf, l, "gbox: decrypted data send (%d bytes):", l);

  hostname2ip(cli->reader->device, &SIN_GET_ADDR(cli->udp_sa));
  SIN_GET_FAMILY(cli->udp_sa) = AF_INET;
  SIN_GET_PORT(cli->udp_sa) = htons((uint16_t)cli->reader->r_port);

  gbox_encrypt(buf, l, gbox->peer.key);
  sendto(cli->udp_fd, buf, l, 0, (struct sockaddr *)&cli->udp_sa, cli->udp_sa_len);
  cs_ddump_mask(D_READER, buf, l, "gbox: encrypted data send (%d bytes):", l);
}
/*
static void gbox_send_goodbye(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;

 uchar buf[20];

 gbox_code_cmd(buf, MSG_GOODBYE);
 memcpy(buf + 2, gbox->peer.key, 4);
 memcpy(buf + 6, gbox->key, 4);

 gbox_send(cli, buf, 11);
}
*/
static void gbox_send_hello_packet(struct s_client *cli, int8_t number, uchar *outbuf, uchar *ptr, int32_t nbcards)
{
    struct gbox_data *gbox = cli->gbox;
    int32_t hostname_len = strlen(cfg.gbox_hostname);
    int32_t len;

    gbox_code_cmd(outbuf, MSG_HELLO);
    memcpy(outbuf + 2, gbox->peer.key, 4);
    memcpy(outbuf + 6, gbox->key, 4);
    // initial HELLO = 0, subsequent = 1
    if (gbox->peer.hello_stat > GBOX_STAT_HELLOS)
      outbuf[10] = 1;
    else
      outbuf[10] = 0;   
    outbuf[11] = number;    // 0x80 (if last packet) else 0x00 | packet number

    if ((number & 0x0F) == 0) {
      gbox_calc_checkcode(gbox);
      memcpy(++ptr, gbox->checkcode, 7);
      ptr += 7;
      *ptr = gbox_version_low_byte;
      *(++ptr) = gbox_type_dvb;
      memcpy(++ptr, cfg.gbox_hostname, hostname_len);
      ptr += hostname_len;
      *ptr = hostname_len;
    }
    len = ptr - outbuf + 1;
    switch (gbox->peer.hello_stat) {
      case GBOX_STAT_HELLOL:
        cs_log("gbox: send HELLOL to %s",cli->reader->label);
        if ((number & 0x80) == 0x80)
          gbox->peer.hello_stat = GBOX_STAT_HELLOS;      
        break;
      case GBOX_STAT_HELLOS:
        cs_log("gbox: send HELLOS total cards  %d to %s",nbcards,cli->reader->label);
        if ((number & 0x80) == 0x80)
          gbox->peer.hello_stat = GBOX_STAT_HELLO3;
        break;
      case GBOX_STAT_HELLOR:
        cs_log("gbox: send HELLOR total cards  %d to %s",nbcards,cli->reader->label);
        if ((number & 0x80) == 0x80)
          gbox->peer.hello_stat = GBOX_STAT_HELLO3;
        break;
      default:
        cs_log("gbox: send hello total cards  %d to %s",nbcards,cli->reader->label);
        break;  
    }
    cs_ddump_mask(D_READER, outbuf, len, "send hello, (len=%d):", len);

    gbox_compress(gbox, outbuf, len, &len);

    gbox_send(cli, outbuf, len);
}

static void gbox_send_hello(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;

  int32_t nbcards = 0;
  int32_t packet;
  uchar buf[2048];
/*
  int32_t ok = 0;
#ifdef WEBIF
  ok = check_ip(cfg.http_allowed, cli->ip) ? 1 : 0;
#endif
*/
  packet=0;
  uchar *ptr = buf + 11;
  if (ll_count(gbox->local_cards) != 0 && gbox->peer.hello_stat > GBOX_STAT_HELLOL) {
    memset(buf, 0, sizeof(buf));

    LL_ITER it = ll_iter_create(gbox->local_cards);
    struct gbox_card *card;
    while ((card = ll_iter_next(&it))) {      
      //send to user only cards which matching CAID from account
      if (chk_ctab(card->caid, &cli->account->ctab)) {
        *(++ptr) = card->provid_1 >> 24;
        *(++ptr) = card->provid_1 >> 16;
        *(++ptr) = card->provid_1 >> 8;
        *(++ptr) = card->provid_1 & 0xff;
        *(++ptr) = 1;		//note: original gbx is more efficient and sends all cards of one caid as package
        *(++ptr) = card->slot;
        //If you modify the next line you are going to destroy the community
        //It will be recognized by original gbx and you will get banned
        *(++ptr) = ((card->lvl-1) << 4) + card->dist + 1;
        *(++ptr) = card->peer_id >> 8;
        *(++ptr) = card->peer_id & 0xff;
        nbcards++;  
        if (nbcards == 100) { //check if 100 is good or we need more sophisticated algorithm
          gbox_send_hello_packet(cli,packet,buf,ptr,nbcards);
          packet++;
          nbcards = 0;
          ptr = buf + 11;
          memset(buf, 0, sizeof(buf));
        }
      }  
    }
  } // end if local card exists

  //last packet has bit 0x80 set
  gbox_send_hello_packet(cli,0x80 | packet,buf,ptr,nbcards);  
}

static void gbox_send_checkcode(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;
  uchar outbuf[20];
  
  gbox_calc_checkcode(gbox);  
  gbox_code_cmd(outbuf, MSG_CHECKCODE);
  memcpy(outbuf + 2, gbox->peer.key, 4);
  memcpy(outbuf + 6, gbox->key, 4);
  memcpy(outbuf + 10, gbox->checkcode, 7);

  gbox_send(cli, outbuf, 17);    
}

static void gbox_send_boxinfo(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;
  uchar outbuf[256];
  int32_t hostname_len = strlen(cfg.gbox_hostname);

  gbox_code_cmd(outbuf, MSG_BOXINFO);
  memcpy(outbuf + 2, gbox->peer.key, 4);
  memcpy(outbuf + 6, gbox->key, 4);
  outbuf[0xA] = gbox_version_low_byte;
  outbuf[0xB] = gbox_type_dvb;
  memcpy(&outbuf[0xC], cfg.gbox_hostname, hostname_len);
  gbox_send(cli, outbuf, hostname_len+0xC);      
}

static int32_t gbox_recv(struct s_client *cli, uchar *buf, int32_t l)
{

  uchar *data;  
  int32_t n=l;

  if (!cli->udp_fd) return -1;
  if (cli->is_udp && cli->typ == 'c' ) {
    data = buf;
    n = recv_from_udpipe(data);
    struct s_client *cl = switch_client_proxy(cli);
    
    //clients may timeout - attach to peer's gbox/reader
    cli->gbox = cl->gbox; //point to the same gbox as proxy
    cli->reader = cl->reader; //point to the same reader as proxy

    gbox_recv2(cl, data, n);

    //clients may timeout - dettach from peer's gbox/reader
    cli->gbox = NULL; 
    cli->reader = NULL;
  } 
  return 0;
}

static void gbox_send_dcw(struct s_client *cl, ECM_REQUEST *er)
{
  struct s_client *cli = switch_client_proxy(cl);
  struct gbox_data *gbox = cli->gbox;

  gbox->peer.gbox_count_ecm--;
  if( er->rc >= E_NOTFOUND ) {
      cs_debug_mask(D_READER,"gbox: unable to decode!");
    return;
  }

  uchar buf[50];
 
  struct gbox_ecm_info *ei =  er->src_data;

  memset(buf, 0, sizeof(buf));

  gbox_code_cmd(buf, MSG_CW);
  buf[2] = ei->ecm[6];			//Peer key
  buf[3] = ei->ecm[7];			//Peer key
  buf[4] = ei->ecm[8];			//Peer key
  buf[5] = ei->ecm[9];			//Peer key
  buf[6] = ei->ecm[10];			//PID
  buf[7] = ei->ecm[11];			//PID
  buf[8] = ei->ecm[12];			//SrvID
  buf[9] = ei->ecm[13];			//SrvID
  buf[10] = ei->ecm[ei->ecm[20] + 31];	//From peer
  buf[11] = ei->ecm[ei->ecm[20] + 32];	//From peer
  buf[12] = ((ei->ecm[ei->ecm[20] + 33]) << 4) | (ei->ecm[18] & 0xF); //slot << 4 | even/odd
  buf[13] = ei->ecm[ei->ecm[20] + 26];	//CAID first byte
  memcpy(buf + 14, er->cw, 16);		//CW
  buf[30] = er->gbox_crc >> 24;		//CRC
  buf[31] = er->gbox_crc >> 16;		//CRC
  buf[32] = er->gbox_crc >> 8;		//CRC
  buf[33] = er->gbox_crc & 0xff;	//CRC
  buf[34] = ei->ecm[ei->ecm[20] + 26];	//CAID
  buf[35] = ei->ecm[ei->ecm[20] + 27];	//CAID
//  buf[36] = ei->ecm[16];		//nbcards???
  buf[36] = ei->ecm[ei->ecm[20] + 33];	//Slot
  buf[37] = ei->ecm[ei->ecm[20] + 28];	//ProvID
  buf[38] = ei->ecm[ei->ecm[20] + 29];	//ProvID
  buf[39] = ei->ecm[ei->ecm[20] + 21];	//Target peer
  buf[40] = ei->ecm[ei->ecm[20] + 22];	//Target peer
  buf[41] = 0x04;			//don't know what this is
  buf[42] = 0x33;			//don't know what this is
  buf[43] = ei->ecm[ei->ecm[20] + 24];

  //This copies the routing info from ECM to answer. 
  //Each hop adds one byte and number of hops is in ecm[ei->l - 1].
  memcpy(&buf[44], &ei->ecm[ei->l - ei->ecm[ei->l - 1] - 1], ei->ecm[ei->l - 1] + 1);
  gbox_send(cli, buf, ei->ecm[ei->l - 1] + 45);

  cs_debug_mask(D_READER, "-> CW  (->%d) from %s/%d (%04X) ",ei->ecm[ei->l - 1] + 1,cli->reader->label, cli->port, ei->peer);
	if (er->src_data) {
		free(er->src_data);
		er->src_data = NULL;
	}
}

static uint8_t gbox_next_free_slot(struct gbox_data *gbox, uint16_t id)
{
  LL_ITER it = ll_iter_create(gbox->local_cards);
  struct gbox_card *c;
  uint8_t lastslot = 0;

  while ((c = ll_iter_next(&it))) {
    if (id == c->peer_id && c->slot > lastslot)
      lastslot = c->slot;
  }
  return ++lastslot;
}

static void gbox_add_local_card(struct gbox_data *gbox, uint16_t id, uint16_t caid, uint32_t prid, uint8_t slot, uint8_t card_reshare, uint8_t dist)
{
      struct gbox_card *c;

      //don't insert 0100:000000
      if ((caid >> 8 == 0x01) && (!prid)) {
        return;
      }
      //skip CAID 18XX providers
      if ((caid >> 8 == 0x18) && (prid)) {
        return;
      }      
      if (!cs_malloc(&c,sizeof(struct gbox_card))) {
        return;
      }
      c->caid = caid;
      switch (caid >> 8) {
        // Viaccess
        case 0x05:
          c->provid_1 = (caid >> 8) << 24 | (prid & 0xFFFFFF);		
          break;          
        // Cryptoworks
        case 0x0D:
          c->provid_1 = (caid >> 8) << 24 | (caid & 0xFF) << 16 |
                        ((prid << 8) & 0xFF00);	
          break;          
        default:
          c->provid_1 = (caid >> 8) << 24 | (caid & 0xFF) << 16 |
                       (prid & 0xFFFF);                      
          break;
      }
      c->provid = prid;
      c->peer_id = id;
      c->slot = slot;
      c->lvl = card_reshare;
      c->dist = dist;
      ll_append(gbox->local_cards, c); 
}

static void gbox_local_cards(struct s_client *cli)
{
  struct gbox_data *gbox = cli->gbox;
  int32_t i;
  uint32_t prid = 0;
  int8_t slot = 0;
  char card_reshare;
#ifdef MODULE_CCCAM
  LL_ITER it,it2;
  struct cc_card *card = NULL;
  struct cc_data *cc;
  uint32_t checksum = 0;
  uint16_t cc_peer_id = 0;
  struct cc_provider *provider;
  uint8_t * node1 = NULL;
#endif

  if (!gbox->local_cards) {
    gbox_free_cardlist(gbox->local_cards);
  }
  gbox->local_cards = ll_create("local_cards");

  //value >5 not allowed in gbox network 
  if(cli->reader->gbox_reshare > 5)
    card_reshare = 5;
  else
    card_reshare = cli->reader->gbox_reshare;

  struct s_client *cl;
  for (cl = first_client; cl; cl = cl->next) { 
    if (cl->typ == 'r' && cl->reader && cl->reader->card_status == 2) {
      slot = gbox_next_free_slot(gbox,gbox->id);
      //SECA, Viaccess and Cryptoworks have multiple providers
      if ((cl->reader->caid >> 8 == 0x01) || (cl->reader->caid >> 8 == 0x05) ||
          (cl->reader->caid >> 8 == 0x0D)) {
        for (i = 0; i < cl->reader->nprov; i++) {
          prid = cl->reader->prid[i][1] << 16 |
                  cl->reader->prid[i][2] << 8 | cl->reader->prid[i][3];
          gbox_add_local_card(gbox, gbox->id, cl->reader->caid, prid, slot, card_reshare, 0);
        }  
      } else 
        gbox_add_local_card(gbox, gbox->id, cl->reader->caid, 0, slot, card_reshare, 0);               
    }	//end local readers
#ifdef MODULE_CCCAM
    if (cl->typ == 'p' && cl->reader 
          && cl->reader->typ == R_CCCAM && cl->cc) {
      cc = cl->cc;      
      it = ll_iter_create(cc->cards);
      while ((card = ll_iter_next(&it))) {
        //calculate gbox id from cc node
        //1st node is orgin, shorten to 32Bit by CRC, the GBX-ID like from PW
        node1 = ll_has_elements(card->remote_nodes);
        checksum = (uint32_t)crc32(0L, node1, 8);
        cc_peer_id = ((((checksum >> 24) & 0xFF) ^ ((checksum >> 8) & 0xFF)) << 8 | 
                      (((checksum >> 16) & 0xFF) ^ (checksum & 0xFF)));
        slot = gbox_next_free_slot(gbox,cc_peer_id);              
        if ((card->caid >> 8 == 0x01) || (card->caid >> 8 == 0x05) ||
            (card->caid >> 8 == 0x0D)) {
          it2 = ll_iter_create(card->providers);
          while ((provider = ll_iter_next(&it2))) {  
            gbox_add_local_card(gbox, cc_peer_id, card->caid, provider->prov, slot, card->reshare, card->hop);
          }  
        } else
            gbox_add_local_card(gbox, cc_peer_id, card->caid, 0, slot, card->reshare, card->hop);                       
      }  
    }	//end cccam
#endif    
  } //end for clients
}

static int32_t gbox_client_init(struct s_client *cli)
{
	if (!cfg.gbox_hostname || strlen(cfg.gbox_hostname) > 128) {
		cs_log("gbox: error, no/invalid hostname '%s' configured in oscam.conf!",
			cfg.gbox_hostname ? cfg.gbox_hostname : "");
		return -1;
	}

	if (!cli->reader->gbox_my_password || strlen(cli->reader->gbox_my_password) != 8) {
		cs_log("gbox: error, no/invalid password '%s' configured in oscam.conf!",
			cli->reader->gbox_my_password ? cli->reader->gbox_my_password : "");
		return -1;
	} 	

  if (!cs_malloc(&cli->gbox, sizeof(struct gbox_data)))
    return -1;

  struct gbox_data *gbox = cli->gbox;
  struct s_reader *rdr = cli->reader;

  rdr->card_status = CARD_NEED_INIT;
  rdr->tcp_connected = 0;

  memset(gbox, 0, sizeof(struct gbox_data));
  memset(&gbox->peer, 0, sizeof(struct gbox_peer));

  uint32_t r_pwd = a2i(rdr->r_pwd, 4);
  uint32_t key = a2i(cli->reader->gbox_my_password, 4);
  int32_t i;
  for (i = 3; i >= 0; i--) {
	  gbox->peer.key[3 - i] = (r_pwd >> (8 * i)) & 0xff;
	  gbox->key[3 - i] = (key >> (8 * i)) & 0xff;
  }

  cs_ddump_mask(D_READER, gbox->peer.key, 4, "Peer password: %s:", rdr->r_pwd);
  cs_ddump_mask(D_READER, gbox->key,      4, " My  password: %s:", cli->reader->gbox_my_password);

  gbox->peer.id = (gbox->peer.key[0] ^ gbox->peer.key[2]) << 8 | (gbox->peer.key[1] ^ gbox->peer.key[3]);

  cli->gbox_peer_id[0] = gbox->peer.id >> 8;
  cli->gbox_peer_id[1] = gbox->peer.id & 0xff;

  gbox->id = (gbox->key[0] ^ gbox->key[2]) << 8 | (gbox->key[1] ^ gbox->key[3]);
  gbox->ver = gbox_version_low_byte;
  gbox->type = gbox_type_dvb;
  rdr->gbox_peer_id= gbox->peer.id;

  cli->gbox_cw_id[0] = gbox->peer.id >> 8;
  cli->gbox_cw_id[1] = (gbox->id >> 8) + (gbox->peer.id & 0xff);

  cli->pfd=0;
  cli->crypted=1;

  set_null_ip(&cli->ip);

  if ((cli->udp_fd=socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP))<0)
   {
        cs_log("socket creation failed (errno=%d %s)", errno, strerror(errno));
        cs_disconnect_client(cli);
  }

  int32_t opt = 1;
  setsockopt(cli->udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));
  
#ifdef SO_REUSEPORT
	setsockopt(cli->udp_fd, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(opt));
#endif

#ifdef SO_REUSEPORT 
  setsockopt(cli->udp_fd, SOL_SOCKET, SO_REUSEPORT, (void *)&opt, sizeof(opt)); 
#endif 

  set_socket_priority(cli->udp_fd, cfg.netprio);

  memset((char *)&cli->udp_sa, 0, sizeof(cli->udp_sa));
  
  if (!hostResolve(rdr))
  	return 0;

  cli->port=rdr->r_port;
  SIN_GET_FAMILY(cli->udp_sa) = AF_INET;
  SIN_GET_PORT(cli->udp_sa) = htons((uint16_t)rdr->r_port);
  hostname2ip(cli->reader->device, &SIN_GET_ADDR(cli->udp_sa));

  cs_log("proxy %s:%d (fd=%d, peer id=%04x, my id=%04x, my hostname=%s, listen port=%d)",
    rdr->device, rdr->r_port, cli->udp_fd, gbox->peer.id, gbox->id, cfg.gbox_hostname, rdr->r_port);

    cli->pfd=cli->udp_fd;

  cs_lock_create(&gbox->lock, 5, "gbox_lock");

  gbox->peer.online     = 0;
  gbox->peer.ecm_idx    = 0;
  gbox->peer.hello_stat	= GBOX_STAT_HELLOL;
  gbox->peer.t_ecm      = time(NULL);

  cli->reader->card_status = CARD_NEED_INIT;
  gbox_send_hello(cli);

  if (!cli->reader->gbox_maxecmsend)
    cli->reader->gbox_maxecmsend = DEFAULT_GBOX_MAX_ECM_SEND;

  if (!cli->reader->gbox_maxdist)
    cli->reader->gbox_maxdist=DEFAULT_GBOX_MAX_DIST;
    
  // create expire thread
  pthread_t t;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
  int32_t ret = pthread_create(&t, &attr, (void *)gbox_expire_hello, cli);

  if (ret) {
    cs_log("ERROR: can't create gbox expire thread (errno=%d %s)", ret, strerror(ret));
    pthread_attr_destroy(&attr);
    return -1;
  } else
    pthread_detach(t);

  pthread_attr_destroy(&attr);

  return 0;
}

static int32_t gbox_recv_chk(struct s_client *cli, uchar *dcw, int32_t *rc, uchar *data, int32_t UNUSED(n))
{
uint16_t id_card = 0;

struct s_client *cl;
  if (cli->typ !='p') {
   cl = switch_client_proxy(cli);
  } else {
  cl = cli;
  }
  char tmp[512];
  if (gbox_decode_cmd(data) == MSG_CW) {
	int i, n;
	*rc = 1;
	memcpy(dcw, data + 14, 16);
	uint32_t crc = data[30] << 24 | data[31] << 16 | data[32] << 8 | data[33];
		//TODO:gbox_add_cwcache(crc, dcw);
		cs_debug_mask(D_READER, "gbox: received cws=%s, peer=%04x, ecm_pid=%04x, sid=%04x, crc=%08x",
		cs_hexdump(0, dcw, 16, tmp, sizeof(tmp)), data[10] << 8 | data[11], data[6] << 8 | data[7], data[8] << 8 | data[9], crc);
		for (i = 0, n = 0; i < cfg.max_pending && n == 0; i++) {
			if (cl->ecmtask[i].gbox_crc==crc) {
				id_card = data[10] << 8 | data[11];
				gbox_add_good_card(cl,id_card,cl->ecmtask[i].caid,cl->ecmtask[i].prid,cl->ecmtask[i].srvid);
				if(cl->ecmtask[i].gbox_ecm_ok==0 || cl->ecmtask[i].gbox_ecm_ok==2)
					return -1;
				struct s_ecm_answer ea;
				memset(&ea, 0, sizeof(struct s_ecm_answer));
				cl->ecmtask[i].gbox_ecm_ok=2;
				memcpy(ea.cw, dcw, 16);
				*rc = 1;
				return cl->ecmtask[i].idx;
			}
		}
		cs_debug_mask(D_READER, "gbox: no task found for crc=%08x",crc);
	}
	return -1;
}

static int32_t gbox_send_ecm(struct s_client *cli, ECM_REQUEST *er, uchar *UNUSED(buf))
{
  struct gbox_data *gbox = cli->gbox;
	int32_t cont_1;
	uint32_t sid_verified=0;

	if (!gbox || !cli->reader->tcp_connected) {
		cs_debug_mask(D_READER, "gbox: %s server not init!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);

		return 0;
	}

	if (!ll_count(gbox->peer.cards)) {
		cs_debug_mask(D_READER, "gbox: %s NO CARDS!", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		return 0;
	}

	if (!gbox->peer.online) {
		cs_debug_mask(D_READER, "gbox: peer is OFFLINE!");
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
//		gbox_send_hello(cli,0);
		return 0;
	}

	if(er->gbox_ecm_ok==2) {
		cs_debug_mask(D_READER, "gbox: %s replied to this ecm already", cli->reader->label);
	}

	if(er->gbox_ecm_id == gbox->peer.id) {
		cs_debug_mask(D_READER, "gbox: %s provided ecm", cli->reader->label);
		write_ecm_answer(cli->reader, er, E_NOTFOUND, 0x27, NULL, NULL);
		return 0;
	}

        uint16_t ercaid = er->caid;
        uint32_t erprid = er->prid;

	if(cli->reader->gbox_maxecmsend == 0) {
		cli->reader->gbox_maxecmsend=DEFAULT_GBOX_MAX_ECM_SEND;
	}
        
	switch (ercaid >> 8) {
          //Viaccess
          case 0x05:
            ercaid = (ercaid & 0xFF00) | ((erprid >> 16) & 0xFF);
            erprid = erprid & 0xFFFF;
            break;
          //Cryptoworks
          case 0x0D:
            erprid = erprid << 8;
            break;
          //Nagra  
          case 0x18:
            erprid = 0;
            break;
        }  

	uchar send_buf_1[0x1024];
	int32_t len2;

	if (!er->ecmlen) return 0;

	len2 = er->ecmlen + 18;
	er->gbox_crc = gbox_get_ecmchecksum(er);

	memset(send_buf_1, 0, sizeof(send_buf_1));

	LL_ITER it = ll_iter_create(gbox->peer.cards);
	struct gbox_card *card;

	int32_t cont_send = 0;
	int32_t cont_card_1 = 0;

	send_buf_1[0] = MSG_ECM >> 8;
	send_buf_1[1] = MSG_ECM & 0xff;
	memcpy(send_buf_1 + 2, gbox->peer.key, 4);
	memcpy(send_buf_1 + 6, gbox->key, 4);

        send_buf_1[10] = (er->pid >> 8) & 0xFF;
        send_buf_1[11] = er->pid & 0xFF;

	send_buf_1[12] = (er->srvid >> 8) & 0xFF;
	send_buf_1[13] = er->srvid & 0xFF;
	send_buf_1[14] = 0x00;
	send_buf_1[15] = 0x00;

	send_buf_1[16] = cont_card_1;
	send_buf_1[17] = 0x00;

	memcpy(send_buf_1 + 18, er->ecm, er->ecmlen);

//	send_buf_1[len2]   = cli->gbox_cw_id[0];
//	send_buf_1[len2+1] = cli->gbox_cw_id[1];
	send_buf_1[len2]   = (gbox->id >> 8) & 0xff;
	send_buf_1[len2+1] = gbox->id & 0xff;
	send_buf_1[len2+2] = gbox_version_low_byte;
	send_buf_1[len2+3] = 0x00;
	send_buf_1[len2+4] = gbox_type_dvb;

	send_buf_1[len2+5] = ercaid >> 8;
        send_buf_1[len2+6] = ercaid & 0xFF;

	send_buf_1[len2+7] = (erprid >> 8) & 0xFF;
	send_buf_1[len2+8] = erprid & 0xFF;
	send_buf_1[len2+9] = 0x00;
	cont_1 =len2+10;

	struct gbox_srvid *srvid1=NULL;
	while ((card = ll_iter_next(&it))) {
		if (card->caid == er->caid && card->provid == er->prid) {
			sid_verified = 0;

			LL_ITER it2 = ll_iter_create(card->goodsids);
			while ((srvid1 = ll_iter_next(&it2))) {
				if (srvid1->provid_id == er->prid && srvid1->sid == er->srvid) {
					send_buf_1[cont_1] = card->peer_id >> 8;
					send_buf_1[cont_1+1] = card->peer_id;
					send_buf_1[cont_1+2] = card->slot;
					cont_1=cont_1+3;cont_card_1++;
					cont_send++;
					sid_verified=1;
					break;
				}
			}

			if (cont_send == cli->reader->gbox_maxecmsend)
				break;

			if (sid_verified == 0) {
				LL_ITER itt = ll_iter_create(card->badsids);
				while ((srvid1 = ll_iter_next(&itt))) {
					if (srvid1->provid_id == er->prid && srvid1->sid == er->srvid) {
						sid_verified = 1;
						break;
					}
				}

				if (sid_verified != 1) {
					send_buf_1[cont_1] = card->peer_id >> 8;
					send_buf_1[cont_1+1] = card->peer_id;
					send_buf_1[cont_1+2] = card->slot;
					cont_1=cont_1+3;
					cont_card_1++;
					cont_send++;
					sid_verified=0;

					if (!cs_malloc(&srvid1, sizeof(struct gbox_srvid)))
						return 0;

					srvid1->sid=er->srvid;
					srvid1->peer_idcard=card->peer_id;
					srvid1->provid_id=card->provid;
					ll_append(card->badsids, srvid1);

					if(cont_send == cli->reader->gbox_maxecmsend)
						break;
				}
			}

			if (cont_send == cli->reader->gbox_maxecmsend)
				break;
		}
	}

	if (!cont_card_1) {
	        cs_debug_mask(D_READER, "GBOX: no valid card found for CAID: %04X PROVID: %04X",er->caid, er->prid);
		return 0;
	}	

	send_buf_1[16] = cont_card_1;
	
	//Hops
	send_buf_1[cont_1] = 0;
	cont_1++;

	memcpy(&send_buf_1[cont_1], gbox->checkcode, 7);
	cont_1 = cont_1 + 7;
	memcpy(&send_buf_1[cont_1], gbox->peer.checkcode, 7);
	cont_1 = cont_1 + 7;

	cs_debug_mask(D_READER,"Gbox sending ecm for %06x : %s",er->prid ,cli->reader->label);
	
	er->gbox_ecm_ok = 1;
	gbox_send(cli, send_buf_1, cont_1);
	cli->pending++;
	cli->reader->last_s = time((time_t *) 0);

	return 0;
}

static int32_t gbox_send_emm(EMM_PACKET *UNUSED(ep))
{
  // emms not yet supported

  return 0;
}

// Parsing of mg-encrypted option in [reader]
void mgencrypted_fn(const char *UNUSED(token), char *value, void *setting, FILE *UNUSED(f)) {
	struct s_reader *rdr = setting;

	if (value) {
		uchar key[16];
		uchar mac[6];
		char tmp_dbg[13];
		uchar *buf = NULL;
		int32_t i, len = 0;
		char *ptr, *saveptr1 = NULL;

		memset(&key, 0, 16);
		memset(&mac, 0, 6);

		for (i = 0, ptr = strtok_r(value, ",", &saveptr1); (i < 2) && (ptr); ptr = strtok_r(NULL, ",", &saveptr1), i++) {
			trim(ptr);
			switch(i) {
			case 0:
				len = strlen(ptr) / 2 + (16 - (strlen(ptr) / 2) % 16);
				if (!cs_malloc(&buf, len)) return;
				key_atob_l(ptr, buf, strlen(ptr));
				cs_log("enc %d: %s", len, ptr);
				break;

			case 1:
				key_atob_l(ptr, mac, 12);
				cs_log("mac: %s", ptr);
				break;
			}
		}
		if (!buf)
			return;

		if (!memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6)) {
#if defined(__APPLE__) || defined(__FreeBSD__)
			// no mac address specified so use mac of en0 on local box
			struct ifaddrs *ifs, *current;

			if (getifaddrs(&ifs) == 0)
			{
				for (current = ifs; current != 0; current = current->ifa_next)
				{
					if (current->ifa_addr->sa_family == AF_LINK && strcmp(current->ifa_name, "en0") == 0)
					{
						struct sockaddr_dl *sdl = (struct sockaddr_dl *)current->ifa_addr;
						memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
						break;
					}
				}
				freeifaddrs(ifs);
			}
#elif defined(__SOLARIS__)
			// no mac address specified so use first filled mac
			int32_t j, sock, niccount;
			struct ifreq nicnumber[16];
			struct ifconf ifconf;
			struct arpreq arpreq;

			if ((sock=socket(AF_INET,SOCK_DGRAM,0)) > -1){
				ifconf.ifc_buf = (caddr_t)nicnumber;
				ifconf.ifc_len = sizeof(nicnumber);
				if (!ioctl(sock,SIOCGIFCONF,(char*)&ifconf)){
					niccount = ifconf.ifc_len/(sizeof(struct ifreq));
					for(i = 0; i < niccount, ++i){
						memset(&arpreq, 0, sizeof(arpreq));
						((struct sockaddr_in*)&arpreq.arp_pa)->sin_addr.s_addr = ((struct sockaddr_in*)&nicnumber[i].ifr_addr)->sin_addr.s_addr;
						if (!(ioctl(sock,SIOCGARP,(char*)&arpreq))){
							for (j = 0; j < 6; ++j)
								mac[j] = (unsigned char)arpreq.arp_ha.sa_data[j];
							if(check_filled(mac, 6) > 0) break;
						}
					}
				}
				close(sock);
			}
#else
			// no mac address specified so use mac of eth0 on local box
			int32_t fd = socket(PF_INET, SOCK_STREAM, 0);

			struct ifreq ifreq;
			memset(&ifreq, 0, sizeof(ifreq));
			snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "eth0");

			ioctl(fd, SIOCGIFHWADDR, &ifreq);
			memcpy(mac, ifreq.ifr_ifru.ifru_hwaddr.sa_data, 6);

			close(fd);
#endif
			cs_debug_mask(D_TRACE, "Determined local mac address for mg-encrypted as %s", cs_hexdump(1, mac, 6, tmp_dbg, sizeof(tmp_dbg)));
		}

		// decrypt encrypted mgcamd gbox line
		for (i = 0; i < 6; i++)
			key[i * 2] = mac[i];

		AES_KEY aeskey;
		AES_set_decrypt_key(key, 128, &aeskey);
		for (i = 0; i < len; i+=16)
			AES_decrypt(buf + i,buf + i, &aeskey);

		// parse d-line
		for (i = 0, ptr = strtok_r((char *)buf, " {", &saveptr1); (i < 5) && (ptr); ptr = strtok_r(NULL, " {", &saveptr1), i++) {
			trim(ptr);
			switch (i) {
			case 1:    // hostname
				cs_strncpy(rdr->device, ptr, sizeof(rdr->device));
				break;
			case 2:   // local port
				rdr->l_port = atoi(ptr);
				break;
			case 3:   // remote port
				rdr->r_port = atoi(ptr);
				break;
			case 4:   // password
				cs_strncpy(rdr->r_pwd, ptr, sizeof(rdr->r_pwd));
				break;
			}
		}

		free(buf);
		return;
	}
}


void module_gbox(struct s_module *ph)
{
  ph->ptab.nports = 1;
  ph->ptab.ports[0].s_port = cfg.gbox_port;

  ph->desc="gbox";
  ph->num=R_GBOX;
  ph->type=MOD_CONN_UDP;
  ph->listenertype = LIS_GBOX;

  ph->s_handler=gbox_server;
  ph->s_init=gbox_server_init;

  ph->send_dcw=gbox_send_dcw;

  ph->recv=gbox_recv;
  ph->c_init=gbox_client_init;
  ph->c_recv_chk=gbox_recv_chk;
  ph->c_send_ecm=gbox_send_ecm;
  ph->c_send_emm=gbox_send_emm;
}
#endif

