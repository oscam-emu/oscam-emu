#!/bin/sh

if [ "$1" = "" ]
then
	echo "Extract OSCam config from OSCam binary"
	echo
	echo "  Usage: `basename $0` oscam_binary"
	echo
	exit 1
fi

strings $1 | sed -n 's/^CFG~//p' | openssl enc -d -base64 | gzip -d 2>/dev/null
