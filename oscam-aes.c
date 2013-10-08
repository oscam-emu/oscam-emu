#include "globals.h"
#include "oscam-aes.h"
#include "oscam-garbage.h"
#include "oscam-string.h"

void aes_set_key(struct aes_keys *aes, char *key)
{
	AES_set_decrypt_key((const unsigned char *)key, 128, &aes->aeskey_decrypt);
	AES_set_encrypt_key((const unsigned char *)key, 128, &aes->aeskey_encrypt);
}

void aes_decrypt(struct aes_keys *aes, uchar *buf, int32_t n)
{
	int32_t i;
	for(i = 0; i < n; i += 16)
	{
		AES_decrypt(buf + i, buf + i, &aes->aeskey_decrypt);
	}
}

void aes_encrypt_idx(struct aes_keys *aes, uchar *buf, int32_t n)
{
	int32_t i;
	for(i = 0; i < n; i += 16)
	{
		AES_encrypt(buf + i, buf + i, &aes->aeskey_encrypt);
	}
}

/* Creates an AES_ENTRY and adds it to the given linked list. */
void add_aes_entry(AES_ENTRY **list, uint16_t caid, uint32_t ident, int32_t keyid, uchar *aesKey)
{
	AES_ENTRY *new_entry, *next, *current;

	// create the AES key entry for the linked list
	if(!cs_malloc(&new_entry, sizeof(AES_ENTRY)))
		{ return; }

	memcpy(new_entry->plainkey, aesKey, 16);
	new_entry->caid = caid;
	new_entry->ident = ident;
	new_entry->keyid = keyid;
	if(memcmp(aesKey, "\xFF\xFF", 2))
	{
		AES_set_decrypt_key((const unsigned char *)aesKey, 128, &(new_entry->key));
		// cs_log("adding key : %s",cs_hexdump(1,aesKey,16, tmp, sizeof(tmp)));
	}
	else
	{
		memset(&new_entry->key, 0, sizeof(AES_KEY));
		// cs_log("adding fake key");
	}
	new_entry->next = NULL;

	//if list is empty, new_entry is the new head
	if(!*list)
	{
		*list = new_entry;
		return;
	}

	//append it to the list
	current = *list;
	next = current->next;
	while(next)
	{
		current = next;
		next = current->next;
	}
	current->next = new_entry;
}

/* Parses a single AES_KEYS entry and assigns it to the given list.
   The expected format for value is caid1@ident1:key0,key1 */
void parse_aes_entry(AES_ENTRY **list, char *label, char *value)
{
	uint16_t caid, dummy;
	uint32_t ident;
	int32_t len;
	char *tmp;
	int32_t nb_keys, key_id;
	uchar aes_key[16];
	char *save = NULL;

	tmp = strtok_r(value, "@", &save);

	//if we got error caid
	len = strlen(tmp);
	if(len == 0 || len > 4) { return; }

	//if there is not value after @
	len = strlen(save);
	if(len == 0) { return; }

	caid = a2i(tmp, 2);
	tmp = strtok_r(NULL, ":", &save);

	//if we got error ident
	len = strlen(tmp);
	if(len == 0 || len > 6) { return; }

	ident = a2i(tmp, 3);

	// now we need to split the key and add the entry to the reader.
	nb_keys = 0;
	key_id = 0;
	while((tmp = strtok_r(NULL, ",", &save)))
	{
		dummy = 0;
		len = strlen(tmp);
		if(len != 32)
		{
			dummy = a2i(tmp, 1);
			// FF means the card will do the AES decrypt
			// 00 means we don't have the aes.
			if((dummy != 0xFF && dummy != 0x00) || len > 2)
			{
				key_id++;
				cs_log("AES key length error .. not adding");
				continue;
			}
			if(dummy == 0x00)
			{
				key_id++;
				continue;
			}
		}
		nb_keys++;
		if(dummy)
			{ memset(aes_key, 0xFF, 16); }
		else
			{ key_atob_l(tmp, aes_key, 32); }
		// now add the key to the reader... TBD
		add_aes_entry(list, caid, ident, key_id, aes_key);
		key_id++;
	}

	cs_log("%d AES key(s) added on reader %s for %04x:%06x", nb_keys, label, caid, ident);
}

/* Clears all entries from an AES list*/
void aes_clear_entries(AES_ENTRY **list)
{
	AES_ENTRY *current, *next;
	current = NULL;
	next = *list;
	while(next)
	{
		current = next;
		next = current->next;
		add_garbage(current);
	}
	*list = NULL;
}

/* Parses multiple AES_KEYS entrys in a reader section and assigns them to the reader.
   The expected format for value is caid1@ident1:key0,key1;caid2@ident2:key0,key1 */
void parse_aes_keys(struct s_reader *rdr, char *value)
{
	char *entry;
	char *save = NULL;
	AES_ENTRY *newlist = NULL, *savelist = rdr->aes_list;

	for(entry = strtok_r(value, ";", &save); entry; entry = strtok_r(NULL, ";", &save))
	{
		parse_aes_entry(&newlist, rdr->label, entry);
	}
	rdr->aes_list = newlist;
	aes_clear_entries(&savelist);

	/*
	AES_ENTRY *current;
	current=rdr->aes_list;
	while(current) {
	    cs_log("**************************");
	    cs_log("current = %p",current);
	    cs_log("CAID = %04x",current->caid);
	    cs_log("IDENT = %06x",current->ident);
	    cs_log("keyID = %d",current->keyid);
	    cs_log("next = %p",current->next);
	    cs_log("**************************");
	    current=current->next;
	}
	*/
}

static AES_ENTRY *aes_list_find(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid)
{
	AES_ENTRY *current = list;
	while(current)
	{
		if(current->caid == caid && current->ident == provid && current->keyid == keyid)
			{ break; }
		current = current->next;
	}
	if(!current)
	{
		cs_log("AES Decrypt : key id %d not found for CAID %04X , provider %06x", keyid, caid, provid);
		return NULL;
	}
	return current;
}


int32_t aes_decrypt_from_list(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid, uchar *buf, int32_t n)
{
	AES_ENTRY *current = aes_list_find(list, caid, provid, keyid);
	if(!current)
		{ return 0; }
	AES_KEY dummy;
	int32_t i;
	// hack for card that do the AES decrypt themsleves
	memset(&dummy, 0, sizeof(AES_KEY));
	if(!memcmp(&current->key, &dummy, sizeof(AES_KEY)))
	{
		return 1;
	}
	// decode the key
	for(i = 0; i < n; i += 16)
		{ AES_decrypt(buf + i, buf + i, &(current->key)); }
	return 1; // all ok, key decoded.
}

int32_t aes_present(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid)
{
	return aes_list_find(list, caid, provid, keyid) != NULL;
}
