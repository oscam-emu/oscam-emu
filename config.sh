#!/bin/sh

addons="WEBIF TOUCH HAVE_DVBAPI IRDETO_GUESSING CS_ANTICASC WITH_DEBUG MODULE_MONITOR WITH_SSL WITH_LB CS_CACHEEX CW_CYCLE_CHECK LCDSUPPORT LEDSUPPORT IPV6SUPPORT"
protocols="MODULE_CAMD33 MODULE_CAMD35 MODULE_CAMD35_TCP MODULE_NEWCAMD MODULE_CCCAM MODULE_CCCSHARE MODULE_GBOX MODULE_RADEGAST MODULE_SERIAL MODULE_CONSTCW MODULE_PANDORA MODULE_GHTTP"
readers="READER_NAGRA READER_IRDETO READER_CONAX READER_CRYPTOWORKS READER_SECA READER_VIACCESS READER_VIDEOGUARD READER_DRE READER_TONGFANG READER_BULCRYPT READER_GRIFFIN READER_DGCRYPT"
card_readers="CARDREADER_PHOENIX CARDREADER_INTERNAL CARDREADER_SC8IN1 CARDREADER_MP35 CARDREADER_SMARGO CARDREADER_DB2COM CARDREADER_STAPI"

defconfig="
CONFIG_WEBIF=y
CONFIG_TOUCH=y
CONFIG_HAVE_DVBAPI=y
CONFIG_IRDETO_GUESSING=y
CONFIG_CS_ANTICASC=y
CONFIG_WITH_DEBUG=y
CONFIG_MODULE_MONITOR=y
# CONFIG_WITH_SSL=n
CONFIG_WITH_LB=y
CONFIG_CS_CACHEEX=y
CONFIG_CW_CYCLE_CHECK=y
# CONFIG_LCDSUPPORT=n
# CONFIG_LEDSUPPORT=n
# CONFIG_IPV6SUPPORT=n
# CONFIG_MODULE_CAMD33=n
CONFIG_MODULE_CAMD35=y
CONFIG_MODULE_CAMD35_TCP=y
CONFIG_MODULE_NEWCAMD=y
CONFIG_MODULE_CCCAM=y
CONFIG_MODULE_CCCSHARE=y
CONFIG_MODULE_GBOX=y
CONFIG_MODULE_RADEGAST=y
CONFIG_MODULE_SERIAL=y
CONFIG_MODULE_CONSTCW=y
CONFIG_MODULE_PANDORA=y
CONFIG_MODULE_GHTTP=y
CONFIG_WITH_CARDREADER=y
CONFIG_READER_NAGRA=y
CONFIG_READER_IRDETO=y
CONFIG_READER_CONAX=y
CONFIG_READER_CRYPTOWORKS=y
CONFIG_READER_SECA=y
CONFIG_READER_VIACCESS=y
CONFIG_READER_VIDEOGUARD=y
CONFIG_READER_DRE=y
CONFIG_READER_TONGFANG=y
CONFIG_READER_BULCRYPT=y
CONFIG_READER_GRIFFIN=y
CONFIG_READER_DGCRYPT=y
CARDREADER_PHOENIX=y
CARDREADER_INTERNAL=y
CARDREADER_SC8IN1=y
CARDREADER_MP35=y
CARDREADER_SMARGO=y
CARDREADER_DB2COM=y
CARDREADER_STAPI=y
"

usage() {
	echo \
"OSCam config
Usage: `basename $0` [parameters]

 -g, --gui                 Start interactive configuration

 -s, --show-enabled [param] Show enabled configuration options.
 -Z, --show-disabled [param] Show disabled configuration options.
 -S, --show-valid [param]  Show valid configuration options.
                           Possible params: all, addons, protocols,
                                            readers, card_readers

 -l, --list-config         List active configuration variables.
 -e, --enabled [option]    Check if certain option is enabled.
 -d, --disabled [option]   Check if certain option is disabled.

 -E, --enable [option]     Enable config option.
 -D, --disable [option]    Disable config option.

    The following [option]s enable or disable multiple settings.
      all          - Everything.
      addons       - All addons.
      protocols    - All protocols.
      readers      - All readers.
      card_readers - All card readers.

 -R, --restore             Restore default config.

 -v, --oscam-version       Display OSCam version.
 -r, --oscam-revision      Display OSCam SVN revision.

 -O, --detect-osx-sdk-version  Find where OS X SDK is located

 -h, --help                Display this help text.

Examples:
  # Enable WEBIF and SSL
  ./config.sh --enable WEBIF WITH_SSL

  # Disable WEBIF but enable WITH_SSL
  ./config.sh --disable WEBIF --enable WITH_SSL

  # Restore defaults and disable WEBIF and READER_NAGRA
  ./config.sh --restore --disable WEBIF READER_NAGRA

  # Use default config with only one enabled reader
  ./config.sh --restore --disable readers --enable READER_BULCRYPT

  # Disable everything and enable webif one module and one card reader
  ./config.sh --disable all --enable WEBIF MODULE_NEWCAMD READER_BULCRYPT

  # Disable all card readers except INTERNAL
  ./config.sh -D card_readers -E CARDREADER_INTERNAL

Available options:
       addons: $addons
    protocols: $protocols
      readers: $readers
 card_readers: $card_readers
"
}

# Output directory for config.mak set by --objdir parameter
OBJDIR=.

# Use flags set by --use-flags parameter
USE_FLAGS=

have_flag() {
	for FLAG in $USE_FLAGS
	do
		[ $FLAG = "$1" ] && return 0
	done
	return 1
}

have_all_flags() {
	for opt ; do
		have_flag $opt || return 1
	done
	return 0
}

have_any_flags() {
	for opt ; do
		have_flag $opt && return 0
	done
	return 1
}

not_have_flag() {
	for FLAG in $USE_FLAGS
	do
		[ $FLAG = "$1" ] && return 1
	done
	return 0
}

not_have_all_flags() {
	for opt ; do
		not_have_flag $opt || return 1
	done
	return 0
}

not_have_any_flags() {
	for opt ; do
		not_have_flag $opt && return 0
	done
	return 1
}

# Config functions
enabled() {
	grep "^\#define $1 1$" config.h >/dev/null 2>/dev/null
	return $?
}

disabled() {
	grep "^\#define $1 1$" config.h >/dev/null 2>/dev/null
	test $? = 0 && return 1
	return 0
}

enabled_all() {
	for opt ; do
		enabled $opt || return 1
	done
	return 0
}

disabled_all() {
	for opt ; do
		disabled $opt || return 1
	done
	return 0
}

enabled_any() {
	for opt ; do
		enabled $opt && return 0
	done
	return 1
}

disabled_any() {
	for opt ; do
		disabled $opt && return 0
	done
	return 1
}

list_enabled() {
	for OPT in $@
	do
		enabled $OPT && echo $OPT
	done
}

list_disabled() {
	for OPT in $@
	do
		disabled $OPT && echo $OPT
	done
}

valid_opt() {
	[ "$1" = "WITH_CARDREADER" ] && return 0 # Special case
	echo $addons $protocols $readers $card_readers | grep -w "$1" >/dev/null
	return $?
}

enable_opt() {
	valid_opt $1 && disabled $1 && {
		sed -i.bak -e "s|//#define $1 1$|#define $1 1|g" config.h && rm config.h.bak
		echo "Enable $1"
	}
}

enable_opts() {
	for OPT in $@
	do
		enable_opt $OPT
	done
}

disable_opt() {
	valid_opt $1 && enabled $1 && {
		sed -i.bak -e "s|#define $1 1$|//#define $1 1|g" config.h && rm config.h.bak
		echo "Disable $1"
	}
}

disable_opts() {
	for OPT in $@
	do
		disable_opt $OPT
	done
}

get_opts() {
	OPTS=""
	case "$1" in
	'addons')       OPTS="$addons" ; ;;
	'protocols')    OPTS="$protocols" ; ;;
	'readers')      OPTS="$readers" ; ;;
	'card_readers') OPTS="$card_readers" ; ;;
	*)              OPTS="$addons $protocols $readers $card_readers" ; ;;
	esac
	echo $OPTS
}

update_deps() {
	# Calculate dependencies
	enabled_any $(get_opts readers) $(get_opts card_readers) && enable_opt WITH_CARDREADER >/dev/null
	disabled_all $(get_opts readers) $(get_opts card_readers) && disable_opt WITH_CARDREADER >/dev/null
	enabled MODULE_CCCSHARE && enable_opt MODULE_CCCAM >/dev/null
	enabled_any CARDREADER_DB2COM CARDREADER_MP35 CARDREADER_SC8IN1 && enable_opt CARDREADER_PHOENIX >/dev/null
}

list_config() {
	update_deps
	# Handle use flags
	have_flag USE_STAPI && echo "CONFIG_WITH_STAPI=y" || echo "# CONFIG_WITH_STAPI=n"
	have_flag USE_COOLAPI && echo "CONFIG_WITH_COOLAPI=y" || echo "# CONFIG_WITH_COOLAPI=n"
	have_flag USE_SU980 && echo "CONFIG_WITH_SU980=y" || echo "# CONFIG_WITH_SU980=n"
	have_flag USE_AZBOX && echo "CONFIG_WITH_AZBOX=y" || echo "# CONFIG_WITH_AZBOX=n"
	have_flag USE_MCA && echo "CONFIG_WITH_MCA=y" || echo "# CONFIG_WITH_MCA=n"
	have_flag USE_LIBCRYPTO && echo "CONFIG_WITH_LIBCRYPTO=y" || echo "# CONFIG_WITH_LIBCRYPTO=n"
	for OPT in $addons $protocols WITH_CARDREADER $readers
	do
		enabled $OPT && echo "CONFIG_$OPT=y" || echo "# CONFIG_$OPT=n"
	done
	for OPT in $card_readers
	do
		if [ $OPT = CARDREADER_INTERNAL ]
		then
			# Internal card reader is actually three different readers depending on USE flags
			enabled $OPT && have_flag USE_AZBOX && echo "CONFIG_${OPT}_AZBOX=y" || echo "# CONFIG_${OPT}_AZBOX=n"
			enabled $OPT && have_any_flags USE_COOLAPI USE_SU980 && echo "CONFIG_${OPT}_COOLAPI=y" || echo "# CONFIG_${OPT}_COOLAPI=n"
			enabled $OPT && not_have_all_flags USE_AZBOX USE_COOLAPI USE_SU980 && echo "CONFIG_${OPT}_SCI=y" || echo "# CONFIG_${OPT}_SCI=n"
			continue
		fi
		if [ $OPT = CARDREADER_STAPI ]
		then
			# Enable CARDREADER_STAPI only if USE_STAPI is set
			enabled $OPT && have_flag USE_STAPI && echo "CONFIG_$OPT=y" || echo "# CONFIG_$OPT=n"
			continue
		fi
		enabled $OPT && echo "CONFIG_$OPT=y" || echo "# CONFIG_$OPT=n"
	done
	have_flag USE_LIBUSB && echo "CONFIG_CARDREADER_SMART=y" || echo "# CONFIG_CARDREADER_SMART=n"
	have_flag USE_PCSC && echo "CONFIG_CARDREADER_PCSC=y" || echo "# CONFIG_CARDREADER_PCSC=n"
	# Extra modules/libraries
	enabled_any MODULE_GBOX WEBIF && echo "CONFIG_LIB_MINILZO=y" || echo "# CONFIG_LIB_MINILZO=n"
	not_have_flag USE_LIBCRYPTO && echo "CONFIG_LIB_AES=y" || echo "# CONFIG_LIB_AES=n"
	enabled MODULE_CCCAM && echo "CONFIG_LIB_RC6=y" || echo "# CONFIG_LIB_RC6=n"
	not_have_flag USE_LIBCRYPTO && enabled MODULE_CCCAM && echo "CONFIG_LIB_SHA1=y" || echo "# CONFIG_LIB_SHA1=n"
	enabled_any MODULE_NEWCAMD READER_DRE && echo "CONFIG_LIB_DES=y" || echo "# CONFIG_LIB_DES=n"
	enabled_any MODULE_CCCAM READER_NAGRA && echo "CONFIG_LIB_IDEA=y" || echo "# CONFIG_LIB_IDEA=n"
	not_have_flag USE_LIBCRYPTO && enabled_any READER_CONAX READER_CRYPTOWORKS READER_NAGRA && echo "CONFIG_LIB_BIGNUM=y" || echo "# CONFIG_LIB_BIGNUM=n"
}

make_config_c() {
	OPENSSL=$(which openssl 2>/dev/null)
	if [ "$OPENSSL" = "" ]
	then
		echo "// openssl not found!"
		echo "const char *config_mak = \"CFG: openssl not found in PATH!\";"
	else
		echo "// This file is generated by ./config.sh --objdir $OBJDIR --make-config.mak"
		echo "const char *config_mak ="
		printf "  \"\\\nCFG: strings FILE | sed -n 's/^CFG~//p' | openssl enc -d -base64 | gzip -d\\\n\"\n"
		gzip -9 < $OBJDIR/config.mak | $OPENSSL enc -base64 | while read LINE
		do
			printf "  \"CFG~%s\\\\n\"\n" "$LINE"
		done
		echo "  ;"
	fi
}

make_config_mak() {
	TMPFILE=$(mktemp -t config.mak.XXXXXX) || exit 1
	list_config > $TMPFILE
	[ ! -d $OBJDIR ] && mkdir -p $OBJDIR 2>/dev/null
	cmp $TMPFILE $OBJDIR/config.mak >/dev/null 2>/dev/null
	if [ $? != 0 ]
	then
		cat $TMPFILE  > $OBJDIR/config.mak
		make_config_c > $OBJDIR/config.c
	else
		make_config_c > $TMPFILE
		cmp $TMPFILE $OBJDIR/config.c >/dev/null 2>/dev/null
		[ $? != 0 ] && cat $TMPFILE > $OBJDIR/config.c
	fi
	rm -rf $TMPFILE
}

check_test() {
	if [ "$(cat $tempfileconfig | grep "^#define $1 1$")" != "" ]; then
		echo "on"
	else
		echo "off"
	fi
}

disable_all() {
	for i in $1; do
		sed -i.bak -e "s/^#define ${i} 1$/\/\/#define ${i} 1/g" $tempfileconfig
	done
}

enable_package() {
	for i in $(cat $tempfile); do
		strip=$(echo $i | sed "s/\"//g")
		sed -i.bak -e "s/\/\/#define ${strip} 1$/#define ${strip} 1/g" $tempfileconfig
	done
}

print_components() {
	clear
	echo "You have selected the following components:"
	echo
	echo "Add-ons:"
	for i in $addons; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done

	echo
	echo "Protocols:"
	for i in $protocols; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done

	echo
	echo "Readers:"
	for i in $readers; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done

	echo
	echo "Card readers:"
	for i in $card_readers; do
		printf "\t%-20s: %s\n" $i $(check_test "$i")
	done

	cp -f $tempfileconfig $configfile
}

menu_addons() {
	${DIALOG} --checklist "\nChoose add-ons:\n " $height $width $listheight \
		WEBIF				"Web Interface"				$(check_test "WEBIF") \
		TOUCH				"Touch Web Interface"				$(check_test "TOUCH") \
		HAVE_DVBAPI			"DVB API"					$(check_test "HAVE_DVBAPI") \
		IRDETO_GUESSING		"Irdeto guessing"			$(check_test "IRDETO_GUESSING") \
		CS_ANTICASC			"Anti cascading"			$(check_test "CS_ANTICASC") \
		WITH_DEBUG			"Debug messages"			$(check_test "WITH_DEBUG") \
		MODULE_MONITOR		"Monitor"					$(check_test "MODULE_MONITOR") \
		WITH_SSL			"OpenSSL support"			$(check_test "WITH_SSL") \
		WITH_LB				"Loadbalancing"				$(check_test "WITH_LB") \
		CS_CACHEEX			"Cache exchange"			$(check_test "CS_CACHEEX") \
		CW_CYCLE_CHECK			"CW Cycle Check"			$(check_test "CW_CYCLE_CHECK") \
		LCDSUPPORT			"LCD support"				$(check_test "LCDSUPPORT") \
		LEDSUPPORT			"LED support"				$(check_test "LEDSUPPORT") \
		IPV6SUPPORT			"IPv6 support (experimental)"		$(check_test "IPV6SUPPORT") \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	disable_all "$addons"
	enable_package
}

menu_protocols() {
	${DIALOG} --checklist "\nChoose protocols:\n " $height $width $listheight \
		MODULE_CAMD33		"camd 3.3"		$(check_test "MODULE_CAMD33") \
		MODULE_CAMD35		"camd 3.5 UDP"	        $(check_test "MODULE_CAMD35") \
		MODULE_CAMD35_TCP	"camd 3.5 TCP"	        $(check_test "MODULE_CAMD35_TCP") \
		MODULE_NEWCAMD		"newcamd"		$(check_test "MODULE_NEWCAMD") \
		MODULE_CCCAM		"CCcam"			$(check_test "MODULE_CCCAM") \
		MODULE_CCCSHARE		"CCcam share"	$(check_test "MODULE_CCCSHARE") \
		MODULE_GBOX		"gbox"  		$(check_test "MODULE_GBOX") \
		MODULE_RADEGAST		"radegast"		$(check_test "MODULE_RADEGAST") \
		MODULE_SERIAL		"Serial"		$(check_test "MODULE_SERIAL") \
		MODULE_CONSTCW		"constant CW"	        $(check_test "MODULE_CONSTCW") \
		MODULE_PANDORA		"Pandora"		$(check_test "MODULE_PANDORA") \
		MODULE_GHTTP		"Ghttp"			$(check_test "MODULE_GHTTP") \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	disable_all "$protocols"
	enable_package
}

menu_readers() {
	${DIALOG} --checklist "\nChoose readers (CA systems):\n " $height $width $listheight \
		READER_NAGRA		"Nagravision"		$(check_test "READER_NAGRA") \
		READER_IRDETO		"Irdeto"			$(check_test "READER_IRDETO") \
		READER_CONAX		"Conax"				$(check_test "READER_CONAX") \
		READER_CRYPTOWORKS	"Cryptoworks"		$(check_test "READER_CRYPTOWORKS") \
		READER_SECA			"Seca"				$(check_test "READER_SECA") \
		READER_VIACCESS		"Viaccess"			$(check_test "READER_VIACCESS") \
		READER_VIDEOGUARD	"NDS Videoguard"	$(check_test "READER_VIDEOGUARD") \
		READER_DRE			"DRE Crypt"			$(check_test "READER_DRE") \
		READER_TONGFANG		"Tongfang"			$(check_test "READER_TONGFANG") \
		READER_BULCRYPT		"Bulcrypt"			$(check_test "READER_BULCRYPT") \
		READER_GRIFFIN		"Griffin"			$(check_test "READER_GRIFFIN") \
		READER_DGCRYPT		"DGCrypt"			$(check_test "READER_DGCRYPT") \
		2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	disable_all "$readers"
	enable_package
}

menu_card_readers() {
	${DIALOG} --checklist "\nChoose card reader drivers:\n " $height $width $listheight \
		CARDREADER_PHOENIX	"Phoenix/mouse"				$(check_test "CARDREADER_PHOENIX") \
		CARDREADER_INTERNAL	"Internal (Sci,Azbox,Cool)"	$(check_test "CARDREADER_INTERNAL") \
		CARDREADER_SC8IN1	"SC8in1"					$(check_test "CARDREADER_SC8IN1") \
		CARDREADER_MP35		"AD-Teknik MP 3.6/USB Phoenix"						$(check_test "CARDREADER_MP35") \
		CARDREADER_SMARGO	"Argolis Smargo Smartreader"					$(check_test "CARDREADER_SMARGO") \
		CARDREADER_DB2COM	"dbox2"						$(check_test "CARDREADER_DB2COM") \
		CARDREADER_STAPI	"STAPI"						$(check_test "CARDREADER_STAPI") \
	2> ${tempfile}

	opt=${?}
	if [ $opt != 0 ]; then return; fi

	disable_all "$card_readers"
	enable_package
}


config_dialog() {
	height=30
	width=65
	listheight=16

	DIALOG=${DIALOG:-`which dialog`}
	if [ -z "${DIALOG}" ]; then
		echo "Please install dialog package." 1>&2
		exit 1
	fi

	configfile=config.h
	tempfile=$(mktemp -t oscam-config.dialog.XXXXXX) || exit 1
	tempfileconfig=$(mktemp -t oscam-config.h.XXXXXX) || exit 1
	trap 'rm -f $tempfile $tempfileconfig $tempfileconfig.bak 2>/dev/null' INT TERM EXIT
	cp -f $configfile $tempfileconfig

	while true; do
		${DIALOG} --menu "\nSelect category:\n " $height $width $listheight \
			Add-ons			"Add-ons" \
			Protocols		"Network protocols" \
			Readers			"Readers (CA systems)" \
			CardReaders		"Card reader drivers" \
			Save			"Save" \
			2> ${tempfile}

		opt=${?}
		if [ $opt != 0 ]; then clear; exit; fi

		menuitem=`cat $tempfile`
		case $menuitem in
			Add-ons) menu_addons ;;
			Protocols) menu_protocols ;;
			Readers) menu_readers ;;
			CardReaders) menu_card_readers ;;
			Save)
				print_components
				update_deps
				exit 0
			;;
		esac
	done
}

# Change working directory to the directory where the script is
cd $(dirname $0)

if [ $# = 0 ]
then
	usage
	exit 1
fi

while [ $# -gt 0 ]
do
	case "$1" in
	'-g'|'--gui'|'--config'|'--menuconfig')
		config_dialog
		break
	;;
	'-s'|'--show-enabled'|'--show')
		shift
		list_enabled $(get_opts $1)
		break
		;;
	'-Z'|'--show-disabled')
		shift
		list_disabled $(get_opts $1)
		break
		;;
	'-S'|'--show-valid')
		shift
		for OPT in $(get_opts $1)
		do
			echo $OPT
		done
		break
		;;
	'-E'|'--enable')
		shift
		while [ "$1" != "" ]
		do
			case "$1" in
			-*)
				update_deps
				continue 2
				;;
			all|addons|protocols|readers|card_readers)
				enable_opts $(get_opts $1)
				;;
			*)
				enable_opt "$1"
				;;
			esac
			shift
		done
		update_deps
		;;
	'-D'|'--disable')
		shift
		while [ "$1" != "" ]
		do
			case "$1" in
			-*)
				update_deps
				continue 2
				;;
			all|addons|protocols|readers|card_readers)
				disable_opts $(get_opts $1)
				;;
			*)
				disable_opt "$1"
				;;
			esac
			shift
		done
		update_deps
		;;
	'-R'|'--restore')
		echo $defconfig | sed -e 's|# ||g' | xargs printf "%s\n" | grep "=y$" | sed -e 's|^CONFIG_||g;s|=.*||g' |
		while read OPT
		do
			enable_opt "$OPT"
		done
		echo $defconfig | sed -e 's|# ||g' | xargs printf "%s\n" | grep "=n$" | sed -e 's|^CONFIG_||g;s|=.*||g' |
		while read OPT
		do
			disable_opt "$OPT"
		done
		update_deps
		;;
	'-e'|'--enabled')
		enabled $2 && echo "Y" && exit 0 || echo "N" && exit 1
		break
	;;
	'-d'|'--disabled')
		disabled $2 && echo "Y" && exit 0 || echo "N" && exit 1
		break
	;;
	'-v'|'--oscam-version')
		grep CS_VERSION globals.h | cut -d\" -f2
		break
	;;
	'-r'|'--oscam-revision')
		(svnversion -n . 2>/dev/null || printf 0) | sed 's/.*://; s/[^0-9]*$//; s/^$/0/'
		break
	;;
	'-O'|'--detect-osx-sdk-version')
		shift
		OSX_VER=${1:-10.8}
		for DIR in /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX{$OSX_VER,10.8,10.7}.sdk /Developer/SDKs/MacOSX{$OSX_VER,10.6,10.5}.sdk
		do
			if test -d $DIR
			then
				echo $DIR
				exit 0
			fi
		done
		echo Cant_find_OSX_SDK
		break
	;;
	'-l'|'--list-config')
		list_config
		exit 0
	;;
	'-m'|'--make-config.mak')
		make_config_mak
		exit 0
	;;
	'--use-flags')
		shift
		USE_FLAGS=$1
	;;
	'--objdir')
		shift
		OBJDIR=$1
	;;
	'-h'|'--help')
		usage
		break
	;;
	*)
		echo "[WARN] Unknown parameter: $1" >&2
	;;
	esac
	# Some shells complain when there are no more parameters to shift
	test $# -gt 0 && shift
done

exit 0
