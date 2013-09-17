#!/bin/sh

FILES="oscam-config-global.c oscam-config-account.c oscam-config-reader.c"

echo "** Checking config tables stored in: $FILES"

if [ ! -f globals.h ]
then
	echo "ERROR: Run this script in the oscam source directory (where globals.h file is)."
	exit 1
fi

check_int() {
	DEF=$1
	TYPE=$2
	echo "== Checking $DEF -> Var type must be $TYPE"
	for VAR in `cat $FILES | grep $DEF | grep OFS | awk '{print $3}' | sed "s|OFS(||;s|)||;s|,||"`
	do
		grep -w $VAR globals.h | grep -vw $TYPE | grep -w --color $VAR
	done
}

check_int DEF_OPT_INT8   int8_t
check_int DEF_OPT_UINT8  uint8_t
check_int DEF_OPT_INT32  int32_t
check_int DEF_OPT_UINT32 uint32_t

echo "== Checking DEF_OPT_STR (strings) -> Var type must be char *"
for VAR in `cat $FILES | grep DEF_OPT_STR | grep OFS | awk '{print $3}' | sed "s|OFS(||;s|)||;s|,||"`
do
	grep -w $VAR globals.h | grep -vwE "(\*$VAR|#include)" | grep -w --color $VAR
done

echo "== Checking DEF_OPT_SSTR (static strings) -> Var type must be char[x]"
for VAR in `cat $FILES | grep DEF_OPT_SSTR | grep OFS | awk '{print $3}' | sed "s|OFS(||;s|)||;s|,||"`
do
	grep -w $VAR globals.h | grep -vE "(\[|#define)" | grep -w --color $VAR
done

echo "== Checking DEF_OPT_HEX (arrays) -> Var type must be uint8_t[x]"
for VAR in `cat $FILES | grep DEF_OPT_HEX | grep OFS | awk '{print $3}' | sed "s|OFS(||;s|)||;s|,||"`
do
	grep -w $VAR globals.h | grep -vw uint8_t | grep -w --color $VAR
done
