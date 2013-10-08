#include "globals.h"

#ifdef IRDETO_GUESSING
#include "module-ird-guess.h"
#include "oscam-string.h"
#include "oscam-conf.h"

struct s_irdeto_quess
{
	int32_t         b47;
	uint16_t        caid;
	uint16_t        sid;
	struct s_irdeto_quess *next;
};

static struct s_irdeto_quess **itab;

int32_t init_irdeto_guess_tab(void)
{
	FILE *fp = open_config_file("oscam.ird");
	if(!fp)
		{ return 1; }

	int32_t i, j, skip;
	int32_t b47;
	char token[128], *ptr, *saveptr1 = NULL;
	char zSid[5];
	uchar b3;
	uint16_t caid, sid;
	struct s_irdeto_quess *ird_row, *head;

	if(!cs_malloc(&itab, sizeof(struct s_irdeto_quess *) * 0xff))
	{
		fclose(fp);
		return 0;
	}

	while(fgets(token, sizeof(token), fp))
	{
		if(strlen(token) < 20) { continue; }
		for(i = b3 = b47 = caid = sid = skip = 0, ptr = strtok_r(token, ":", &saveptr1); (i < 4) && (ptr); ptr = strtok_r(NULL, ":", &saveptr1), i++)
		{
			trim(ptr);
			if(*ptr == ';' || *ptr == '#' || *ptr == '-')
			{
				skip = 1;
				break;
			}
			switch(i)
			{
			case 0:
				b3   = a2i(ptr, 2);
				break;
			case 1:
				b47  = a2i(ptr, 8);
				break;
			case 2:
				caid = a2i(ptr, 4);
				break;
			case 3:
				for(j = 0; j < 4; j++)
					{ zSid[j] = ptr[j]; }
				zSid[4] = 0;
				sid  = a2i(zSid, 4);
				break;
			}
		}
		if(!skip)
		{
			if(!cs_malloc(&ird_row, sizeof(struct s_irdeto_quess)))
			{
				fclose(fp);
				return (1);
			}
			ird_row->b47  = b47;
			ird_row->caid = caid;
			ird_row->sid  = sid;

			head = itab[b3];
			if(head)
			{
				while(head->next)
					{ head = head->next; }
				head->next = ird_row;
			}
			else
				{ itab[b3] = ird_row; }
			//cs_debug_mask(D_CLIENT, "%02X:%08X:%04X:%04X", b3, b47, caid, sid);
		}
	}
	fclose(fp);

	for(i = 0; i < 0xff; i++)
	{
		head = itab[i];
		while(head)
		{
			cs_debug_mask(D_CLIENT, "itab[%02X]: b47=%08X, caid=%04X, sid=%04X",
						  i, head->b47, head->caid, head->sid);
			head = head->next;
		}
	}
	return (0);
}

void free_irdeto_guess_tab(void)
{
	uint8_t i;
	if(!itab)
		{ return; }
	for(i = 0; i < 0xff; i++)
	{
		struct s_irdeto_quess *head = itab[i];
		while(head)
		{
			void *next = head->next;
			free(head);
			head = next;
		}
	}
	free(itab);
}

void guess_irdeto(ECM_REQUEST *er)
{
	uchar  b3;
	int32_t    b47;
	//uint16_t chid;
	struct s_irdeto_quess *ptr;

	if(!itab)
		{ return; }
	b3  = er->ecm[3];
	ptr = itab[b3];
	if(!ptr)
	{
		cs_debug_mask(D_TRACE, "unknown irdeto byte 3: %02X", b3);
		return;
	}
	b47  = b2i(4, er->ecm + 4);
	//chid = b2i(2, er->ecm+6);
	//cs_debug_mask(D_TRACE, "ecm: b47=%08X, ptr->b47=%08X, ptr->caid=%04X", b47, ptr->b47, ptr->caid);
	while(ptr)
	{
		if(b47 == ptr->b47)
		{
			if(er->srvid && (er->srvid != ptr->sid))
			{
				cs_debug_mask(D_TRACE, "sid mismatched (ecm: %04X, guess: %04X), wrong oscam.ird file?",
							  er->srvid, ptr->sid);
				return;
			}
			er->caid = ptr->caid;
			er->srvid = ptr->sid;
			er->chid = (uint16_t)ptr->b47;
			//      cs_debug_mask(D_TRACE, "quess_irdeto() found caid=%04X, sid=%04X, chid=%04X",
			//               er->caid, er->srvid, er->chid);
			return;
		}
		ptr = ptr->next;
	}
}

#endif
