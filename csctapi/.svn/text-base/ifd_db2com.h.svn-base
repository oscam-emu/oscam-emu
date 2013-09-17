#ifndef _CSCTAPI_IFD_DB2COM_H_
#define _CSCTAPI_IFD_DB2COM_H_

#ifdef CARDREADER_DB2COM
bool detect_db2com_reader(struct s_reader *reader);
void cardreader_db2com(struct s_cardreader *crdr);
#else
static inline bool detect_db2com_reader(struct s_reader *UNUSED(reader)) { return false; }
static inline void cardreader_db2com(struct s_cardreader *UNUSED(crdr)) { }
#endif

#endif
