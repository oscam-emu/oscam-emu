#!/bin/sh

if [ ! -f oscam.c ]
then
	echo "ERROR: Run this script in the oscam source directory (where oscam.c file is)."
	exit 1
fi

OPTS=`grep "static const char short_options" oscam.c | sed -e 's|.* \"||;s|\".*||;s|:||g;s|\(.\)|\1 |g'`
SOPTS=$((for i in $OPTS; do echo $i; done) | sort)
LOPTS=$(grep "^	{ \"" oscam.c | sed -e 's|.*{ \"||;s|".*||')
FOPTS=""

#echo opts:$OPTS
#echo sopts:$SOPTS
#echo lopts:$LOPTS
#exit

echo -en "Short options that are free to use:\n    "
for i in $(echo {A..Z}) $(echo {a..z}) $(echo {0..9})
do
	echo $OPTS | grep -q $i 2>/dev/null
	if [ $? != 0 ]
	then
		echo -n $i
		FOPTS="$FOPTS $i"
	fi
done
echo

echo -en "Options that are not processed in oscam.c (missing case 'x'):\n    "
#AOPTS="$FOPTS $SOPTS"
AOPTS="$SOPTS"
for i in $AOPTS
do
	grep -q "case '$i'" oscam.c 2>/dev/null
	[ $? != 0 ] && echo -n $i
done
echo

echo -en "Short options that are missing from 'struct long_options[]'\n    "
for i in $AOPTS
do
	grep -q "NULL, '$i' }," oscam.c 2>/dev/null
	[ $? != 0 ] && echo -n $i
done
echo

echo -en "No help entry in usage() for short options:\n    "
for i in $AOPTS
do
	grep -q "	printf(\" -$i" oscam.c 2>/dev/null
	[ $? != 0 ] && echo -n $i
done
echo

echo "No help entry in usage() long options:"
for i in $LOPTS
do
	grep -q "	printf(\" -., --$i" oscam.c 2>/dev/null
	[ $? != 0 ] && echo "    $i"
done
echo
