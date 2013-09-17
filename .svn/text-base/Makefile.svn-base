SHELL = /bin/sh

.SUFFIXES:
.SUFFIXES: .o .c
.PHONY: all help README.build README.config simple default debug config menuconfig allyesconfig allnoconfig defconfig clean distclean

VER     := $(shell ./config.sh --oscam-version)
SVN_REV := $(shell ./config.sh --oscam-revision)

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

LINKER_VER_OPT:=-Wl,--version

# Find OSX SDK
ifeq ($(uname_S),Darwin)
# Setting OSX_VER allows you to choose prefered version if you have
# two SDKs installed. For example if you have 10.6 and 10.5 installed
# you can choose 10.5 by using 'make USE_PCSC=1 OSX_VER=10.5'
# './config.sh --detect-osx-sdk-version' returns the newest SDK if
# SDK_VER is not set.
OSX_SDK := $(shell ./config.sh --detect-osx-sdk-version $(OSX_VER))
LINKER_VER_OPT:=-Wl,-v
endif

ifeq "$(shell ./config.sh --enabled WITH_SSL)" "Y"
	override USE_SSL=1
	override USE_LIBCRYPTO=1
endif
ifdef USE_SSL
	override USE_LIBCRYPTO=1
endif

CONF_DIR = /usr/local/etc

LIB_PTHREAD = -lpthread
LIB_DL = -ldl
ifeq ($(uname_S),FreeBSD)
LIB_DL :=
endif

override STD_LIBS := $(LIB_PTHREAD) $(LIB_DL)
override STD_DEFS := -D'CS_SVN_VERSION="$(SVN_REV)"'
override STD_DEFS += -D'CS_CONFDIR="$(CONF_DIR)"'

# Compiler warnings
CC_WARN = -W -Wall -Wshadow -Wredundant-decls -Wstrict-prototypes -Wold-style-definition

# Compiler optimizations
CC_OPTS = -O2 -ggdb -pipe -ffunction-sections -fdata-sections

CC = $(CROSS_DIR)$(CROSS)gcc
STRIP = $(CROSS_DIR)$(CROSS)strip

LDFLAGS = -Wl,--gc-sections

# The linker for powerpc have bug that prevents --gc-sections from working
# Check for the linker version and if it matches disable --gc-sections
# For more information about the bug see:
#   http://cygwin.com/ml/binutils/2005-01/msg00103.html
# The LD output is saved into variable and then processed, because if
# the output is piped directly into another command LD creates 4 files
# in your /tmp directory and doesn't delete them.
LINKER_VER := $(shell set -e; VER="`$(CC) $(LINKER_VER_OPT) 2>&1`"; echo $$VER | head -1 | cut -d' ' -f5)

# dm500 toolchain
ifeq "$(LINKER_VER)" "20040727"
LDFLAGS :=
endif
# dm600/7000/7020 toolchain
ifeq "$(LINKER_VER)" "20041121"
LDFLAGS :=
endif
# The OS X linker do not support --gc-sections
ifeq ($(uname_S),Darwin)
LDFLAGS :=
endif

# The compiler knows for what target it compiles, so use this information
TARGET := $(shell $(CC) -dumpmachine 2>/dev/null)

# Process USE_ variables
DEFAULT_STAPI_LIB = -L./stapi -loscam_stapi
DEFAULT_COOLAPI_LIB = -lnxp -lrt
DEFAULT_SU980_LIB = -lentropic -lrt
DEFAULT_AZBOX_LIB = -Lextapi/openxcas -lOpenXCASAPI
DEFAULT_LIBCRYPTO_LIB = -lcrypto
DEFAULT_SSL_LIB = -lssl
ifeq ($(uname_S),Linux)
DEFAULT_LIBUSB_LIB = -lusb-1.0 -lrt
else
DEFAULT_LIBUSB_LIB = -lusb-1.0
endif
ifeq ($(uname_S),Darwin)
DEFAULT_PCSC_FLAGS = -isysroot $(OSX_SDK) -I/usr/local/include
DEFAULT_PCSC_LIB = -syslibroot,$(OSX_SDK) -framework IOKit -framework CoreFoundation -framework PCSC -L/usr/local/lib
else
DEFAULT_PCSC_FLAGS = -I/usr/include/PCSC
DEFAULT_PCSC_LIB = -lpcsclite
endif

# Function to initialize USE related variables
#   Usage: $(eval $(call prepare_use_flags,FLAG_NAME,PLUS_TARGET_TEXT))
define prepare_use_flags
override DEFAULT_$(1)_FLAGS:=$$(strip -DWITH_$(1)=1 $$(DEFAULT_$(1)_FLAGS))
ifdef USE_$(1)
$(1)_FLAGS:=$$(DEFAULT_$(1)_FLAGS)
$(1)_CFLAGS:=$$($(1)_FLAGS)
$(1)_LDFLAGS:=$$($(1)_FLAGS)
$(1)_LIB:=$$(DEFAULT_$(1)_LIB)
ifneq "$(2)" ""
override PLUS_TARGET:=$$(PLUS_TARGET)-$(2)
endif
override USE_CFLAGS+=$$($(1)_CFLAGS)
override USE_LDFLAGS+=$$($(1)_LDFLAGS)
override USE_LIBS+=$$($(1)_LIB)
override USE_FLAGS+=$$(if $$(USE_$(1)),USE_$(1))
endif
endef

# Initialize USE variables
$(eval $(call prepare_use_flags,STAPI,stapi))
$(eval $(call prepare_use_flags,COOLAPI,coolapi))
$(eval $(call prepare_use_flags,SU980,su980))
$(eval $(call prepare_use_flags,AZBOX,azbox))
$(eval $(call prepare_use_flags,MCA,mca))
$(eval $(call prepare_use_flags,SSL,ssl))
$(eval $(call prepare_use_flags,LIBCRYPTO,))
$(eval $(call prepare_use_flags,LIBUSB,libusb))
$(eval $(call prepare_use_flags,PCSC,pcsc))

# Add PLUS_TARGET and EXTRA_TARGET to TARGET
ifdef NO_PLUS_TARGET
override TARGET := $(TARGET)$(EXTRA_TARGET)
else
override TARGET := $(TARGET)$(PLUS_TARGET)$(EXTRA_TARGET)
endif

EXTRA_CFLAGS = $(EXTRA_FLAGS)
EXTRA_LDFLAGS = $(EXTRA_FLAGS)

# Add USE_xxx, EXTRA_xxx and STD_xxx vars
override CC_WARN += $(EXTRA_CC_WARN)
override CC_OPTS += $(EXTRA_CC_OPTS)
override CFLAGS  += $(USE_CFLAGS) $(EXTRA_CFLAGS)
override LDFLAGS += $(USE_LDFLAGS) $(EXTRA_LDFLAGS)
override LIBS    += $(USE_LIBS) $(EXTRA_LIBS) $(STD_LIBS)

override STD_DEFS += -D'CS_TARGET="$(TARGET)"'

# Setup quiet build
Q =
SAY = @true
ifndef V
Q = @
NP = --no-print-directory
SAY = @echo
endif

BINDIR := Distribution
override BUILD_DIR := build
OBJDIR := $(BUILD_DIR)/$(TARGET)

# Include config.mak which contains variables for all enabled modules
# These variables will be used to select only needed files for compilation
-include $(OBJDIR)/config.mak

OSCAM_BIN := $(BINDIR)/oscam-$(VER)$(SVN_REV)-$(subst cygwin,cygwin.exe,$(TARGET))
LIST_SMARGO_BIN := $(BINDIR)/list_smargo-$(VER)$(SVN_REV)-$(subst cygwin,cygwin.exe,$(TARGET))

# Build list_smargo-.... only when WITH_LIBUSB build is requested.
ifndef USE_LIBUSB
override LIST_SMARGO_BIN =
endif

SRC-$(CONFIG_LIB_AES) += cscrypt/aes.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_add.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_asm.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_ctx.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_div.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_exp.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_lib.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_mul.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_print.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_shift.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_sqr.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/bn_word.c
SRC-$(CONFIG_LIB_BIGNUM) += cscrypt/mem.c
SRC-$(CONFIG_LIB_DES) += cscrypt/des.c
SRC-$(CONFIG_LIB_IDEA) += cscrypt/i_cbc.c
SRC-$(CONFIG_LIB_IDEA) += cscrypt/i_ecb.c
SRC-$(CONFIG_LIB_IDEA) += cscrypt/i_skey.c
SRC-y += cscrypt/md5.c
SRC-$(CONFIG_LIB_RC6) += cscrypt/rc6.c
SRC-$(CONFIG_LIB_SHA1) += cscrypt/sha1.c

SRC-$(CONFIG_WITH_CARDREADER) += csctapi/atr.c
SRC-$(CONFIG_WITH_CARDREADER) += csctapi/icc_async.c
SRC-$(CONFIG_WITH_CARDREADER) += csctapi/io_serial.c
SRC-$(CONFIG_WITH_CARDREADER) += csctapi/protocol_t0.c
SRC-$(CONFIG_WITH_CARDREADER) += csctapi/protocol_t1.c
SRC-$(CONFIG_CARDREADER_INTERNAL_AZBOX) += csctapi/ifd_azbox.c
SRC-$(CONFIG_CARDREADER_INTERNAL_COOLAPI) += csctapi/ifd_cool.c
SRC-$(CONFIG_CARDREADER_DB2COM) += csctapi/ifd_db2com.c
SRC-$(CONFIG_CARDREADER_MP35) += csctapi/ifd_mp35.c
SRC-$(CONFIG_CARDREADER_PCSC) += csctapi/ifd_pcsc.c
SRC-$(CONFIG_CARDREADER_PHOENIX) += csctapi/ifd_phoenix.c
SRC-$(CONFIG_CARDREADER_SC8IN1) += csctapi/ifd_sc8in1.c
SRC-$(CONFIG_CARDREADER_INTERNAL_SCI) += csctapi/ifd_sci.c
SRC-$(CONFIG_CARDREADER_SMARGO) += csctapi/ifd_smargo.c
SRC-$(CONFIG_CARDREADER_SMART) += csctapi/ifd_smartreader.c
SRC-$(CONFIG_CARDREADER_STAPI) += csctapi/ifd_stapi.c

SRC-$(CONFIG_LIB_MINILZO) += minilzo/minilzo.c

SRC-$(CONFIG_CS_ANTICASC) += module-anticasc.c
SRC-$(CONFIG_CS_CACHEEX) += module-cacheex.c
SRC-$(CONFIG_MODULE_CAMD33) += module-camd33.c
SRC-$(sort $(CONFIG_MODULE_CAMD35) $(CONFIG_MODULE_CAMD35_TCP)) += module-camd35.c
SRC-$(CONFIG_MODULE_CCCAM) += module-cccam.c
SRC-$(CONFIG_MODULE_CCCSHARE) += module-cccshare.c
SRC-$(CONFIG_MODULE_CONSTCW) += module-constcw.c
SRC-$(CONFIG_CS_CACHEEX) += module-csp.c
SRC-$(CONFIG_CW_CYCLE_CHECK) += module-cw-cycle-check.c
SRC-$(CONFIG_WITH_AZBOX) += module-dvbapi-azbox.c
SRC-$(CONFIG_WITH_MCA) += module-dvbapi-mca.c
SRC-$(CONFIG_WITH_COOLAPI) += module-dvbapi-coolapi.c
SRC-$(CONFIG_WITH_SU980) += module-dvbapi-coolapi.c
SRC-$(CONFIG_WITH_STAPI) += module-dvbapi-stapi.c
SRC-$(CONFIG_HAVE_DVBAPI) += module-dvbapi.c
SRC-$(CONFIG_MODULE_GBOX) += module-gbox.c
SRC-$(CONFIG_IRDETO_GUESSING) += module-ird-guess.c
SRC-$(CONFIG_LCDSUPPORT) += module-lcd.c
SRC-$(CONFIG_LEDSUPPORT) += module-led.c
SRC-$(CONFIG_MODULE_MONITOR) += module-monitor.c
SRC-$(CONFIG_MODULE_NEWCAMD) += module-newcamd.c
SRC-$(CONFIG_MODULE_PANDORA) += module-pandora.c
SRC-$(CONFIG_MODULE_GHTTP) += module-ghttp.c
SRC-$(CONFIG_MODULE_RADEGAST) += module-radegast.c
SRC-$(CONFIG_MODULE_SERIAL) += module-serial.c
SRC-$(CONFIG_WITH_LB) += module-stat.c
SRC-$(CONFIG_WEBIF) += module-webif-lib.c
SRC-$(CONFIG_WEBIF) += module-webif-tpl.c
SRC-$(CONFIG_WEBIF) += module-webif.c
SRC-$(CONFIG_WEBIF) += webif/pages.c
SRC-$(CONFIG_WITH_CARDREADER) += reader-common.c
SRC-$(CONFIG_READER_BULCRYPT) += reader-bulcrypt.c
SRC-$(CONFIG_READER_CONAX) += reader-conax.c
SRC-$(CONFIG_READER_CRYPTOWORKS) += reader-cryptoworks.c
SRC-$(CONFIG_READER_DGCRYPT) += reader-dgcrypt.c
SRC-$(CONFIG_READER_DRE) += reader-dre.c
SRC-$(CONFIG_READER_GRIFFIN) += reader-griffin.c
SRC-$(CONFIG_READER_IRDETO) += reader-irdeto.c
SRC-$(CONFIG_READER_NAGRA) += reader-nagra.c
SRC-$(CONFIG_READER_SECA) += reader-seca.c
SRC-$(CONFIG_READER_TONGFANG) += reader-tongfang.c
SRC-$(CONFIG_READER_VIACCESS) += reader-viaccess.c
SRC-$(CONFIG_READER_VIDEOGUARD) += reader-videoguard-common.c
SRC-$(CONFIG_READER_VIDEOGUARD) += reader-videoguard1.c
SRC-$(CONFIG_READER_VIDEOGUARD) += reader-videoguard12.c
SRC-$(CONFIG_READER_VIDEOGUARD) += reader-videoguard2.c
SRC-y += oscam-aes.c
SRC-y += oscam-chk.c
SRC-y += oscam-client.c
SRC-y += oscam-conf.c
SRC-y += oscam-conf-chk.c
SRC-y += oscam-conf-mk.c
SRC-y += oscam-config-account.c
SRC-y += oscam-config-global.c
SRC-y += oscam-config-reader.c
SRC-y += oscam-config.c
SRC-y += oscam-ecm.c
SRC-y += oscam-emm.c
SRC-y += oscam-failban.c
SRC-y += oscam-files.c
SRC-y += oscam-garbage.c
SRC-y += oscam-lock.c
SRC-y += oscam-log.c
SRC-y += oscam-log-reader.c
SRC-y += oscam-net.c
SRC-y += oscam-llist.c
SRC-y += oscam-reader.c
SRC-y += oscam-simples.c
SRC-y += oscam-string.c
SRC-y += oscam-time.c
SRC-y += oscam-work.c
SRC-y += oscam.c
# config.c is automatically generated by config.sh in OBJDIR
SRC-y += config.c

SRC := $(SRC-y)
OBJ := $(addprefix $(OBJDIR)/,$(subst .c,.o,$(SRC)))
SRC := $(subst config.c,$(OBJDIR)/config.c,$(SRC))

# The default build target rebuilds the config.mak if needed and then
# starts the compilation.
all:
	@./config.sh --use-flags "$(USE_FLAGS)" --objdir "$(OBJDIR)" --make-config.mak
	@-mkdir -p $(OBJDIR)/cscrypt $(OBJDIR)/csctapi $(OBJDIR)/minilzo $(OBJDIR)/webif
	@-printf "\
+-------------------------------------------------------------------------------\n\
| OSCam ver: $(VER) rev: $(SVN_REV) target: $(TARGET)\n\
| Tools:\n\
|  CROSS    = $(CROSS_DIR)$(CROSS)\n\
|  CC       = $(CC)\n\
| Settings:\n\
|  CONF_DIR = $(CONF_DIR)\n\
|  CC_OPTS  = $(strip $(CC_OPTS))\n\
|  CC_WARN  = $(strip $(CC_WARN))\n\
|  CFLAGS   = $(strip $(CFLAGS))\n\
|  LDFLAGS  = $(strip $(LDFLAGS))\n\
|  LIBS     = $(strip $(LIBS))\n\
|  UseFlags = $(addsuffix =1,$(USE_FLAGS))\n\
| Config:\n\
|  Addons   : $(shell ./config.sh --show-enabled addons)\n\
|  Protocols: $(shell ./config.sh --show-enabled protocols | sed -e 's|MODULE_||g')\n\
|  Readers  : $(shell ./config.sh --show-enabled readers | sed -e 's|READER_||g')\n\
|  CardRdrs : $(shell ./config.sh --show-enabled card_readers | sed -e 's|CARDREADER_||g')\n\
|  Compiler : $(shell $(CC) --version 2>/dev/null | head -n 1)\n\
|  Binary   : $(OSCAM_BIN)\n\
+-------------------------------------------------------------------------------\n"
ifeq "$(shell ./config.sh --enabled WEBIF)" "Y"
	@$(MAKE) --no-print-directory --quiet -C webif
endif
	@$(MAKE) --no-print-directory $(OSCAM_BIN) $(LIST_SMARGO_BIN)

$(OSCAM_BIN).debug: $(OBJ)
	$(SAY) "LINK	$@"
	$(Q)$(CC) $(LDFLAGS) $(OBJ) $(LIBS) -o $@

$(OSCAM_BIN): $(OSCAM_BIN).debug
	$(SAY) "STRIP	$@"
	$(Q)cp $(OSCAM_BIN).debug $(OSCAM_BIN)
	$(Q)$(STRIP) $(OSCAM_BIN)

$(LIST_SMARGO_BIN): utils/list_smargo.c
	$(SAY) "BUILD	$@"
	$(Q)$(CC) $(STD_DEFS) $(CC_OPTS) $(CC_WARN) $(CFLAGS) $(LDFLAGS) utils/list_smargo.c $(LIBS) -o $@

$(OBJDIR)/config.o: $(OBJDIR)/config.c
	$(SAY) "CONF	$<"
	$(Q)$(CC) $(STD_DEFS) $(CC_OPTS) $(CC_WARN) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: %.c Makefile
	@$(CC) -MP -MM -MT $@ -o $(subst .o,.d,$@) $<
	$(SAY) "CC	$<"
	$(Q)$(CC) $(STD_DEFS) $(CC_OPTS) $(CC_WARN) $(CFLAGS) -c $< -o $@

-include $(subst .o,.d,$(OBJ))

config:
	$(SHELL) ./config.sh --gui

menuconfig: config

allyesconfig:
	@echo "Enabling all config options."
	@-$(SHELL) ./config.sh --enable all

allnoconfig:
	@echo "Disabling all config options."
	@-$(SHELL) ./config.sh --disable all

defconfig:
	@echo "Restoring default config."
	@-$(SHELL) ./config.sh --restore

clean:
	@-for FILE in $(BUILD_DIR)/*; do \
		echo "RM	$$FILE"; \
		rm -rf $$FILE; \
	done
	@-rm -rf $(BUILD_DIR) lib

distclean: clean
	@-for FILE in $(BINDIR)/list_smargo-* $(BINDIR)/oscam-$(VER)*; do \
		echo "RM	$$FILE"; \
		rm -rf $$FILE; \
	done
	@-$(MAKE) --no-print-directory --quiet -C webif clean

README.build:
	@echo "Extracting 'make help' into $@ file."
	@-printf "\
** This file is generated from 'make help' output, do not edit it. **\n\
\n\
" > $@
	@-$(MAKE) --no-print-directory help >> $@
	@echo "Done."

README.config:
	@echo "Extracting 'config.sh --help' into $@ file."
	@-printf "\
** This file is generated from 'config.sh --help' output, do not edit it. **\n\
\n\
" > $@
	@-./config.sh --help >> $@
	@echo "Done."

help:
	@-printf "\
OSCam build system documentation\n\
================================\n\
\n\
 Build variables:\n\
   The build variables are set on the make command line and control the build\n\
   process. Setting the variables lets you enable additional features, request\n\
   extra libraries and more. Currently recognized build variables are:\n\
\n\
   CROSS=prefix   - Set tools prefix. This variable is used when OScam is being\n\
                    cross compiled. For example if you want to cross compile\n\
                    for SH4 architecture you can run: 'make CROSS=sh4-linux-'\n\
                    If you don't have the directory where cross compilers are\n\
                    in your PATH you can run:\n\
                    'make CROSS=/opt/STM/STLinux-2.3/devkit/sh4/bin/sh4-linux-'\n\
\n\
   CROSS_DIR=dir  - Set tools directory. This variable is added in front of\n\
                    CROSS variable. CROSS_DIR is useful if you want to use\n\
                    predefined targets that are setting CROSS, but you don't have\n\
                    the cross compilers in your PATH. For example:\n\
                    'make sh4 CROSS_DIR=/opt/STM/STLinux-2.3/devkit/sh4/bin/'\n\
                    'make dm500 CROSS_DIR=/opt/cross/dm500/cdk/bin/'\n\
\n\
   CONF_DIR=/dir  - Set OSCam config directory. For example to change config\n\
                    directory to /etc run: 'make CONF_DIR=/etc'\n\
                    The default config directory is: '$(CONF_DIR)'\n\
\n\
   CC_OPTS=text   - This variable holds compiler optimization parameters.\n\
                    Default CC_OPTS value is:\n\
                    '$(CC_OPTS)'\n\
                    To add text to this variable set EXTRA_CC_OPTS=text.\n\
\n\
   CC_WARN=text   - This variable holds compiler warning parameters.\n\
                    Default CC_WARN value is:\n\
                    '$(CC_WARN)'\n\
                    To add text to this variable set EXTRA_CC_WARN=text.\n\
\n\
   V=1            - Request build process to print verbose messages. By\n\
                    default the only messages that are shown are simple info\n\
                    what is being compiled. To request verbose build run:\n\
                    'make V=1'\n\
\n\
 Extra build variables:\n\
   These variables add text to build variables. They are useful if you want\n\
   to add additional options to already set variables without overwriting them\n\
   Currently defined EXTRA_xxx variables are:\n\
\n\
   EXTRA_CC_OPTS  - Add text to CC_OPTS.\n\
                    Example: 'make EXTRA_CC_OPTS=-Os'\n\
\n\
   EXTRA_CC_WARN  - Add text to CC_WARN.\n\
                    Example: 'make EXTRA_CC_WARN=-Wshadow'\n\
\n\
   EXTRA_TARGET   - Add text to TARGET.\n\
                    Example: 'make EXTRA_TARGET=-private'\n\
\n\
   EXTRA_CFLAGS   - Add text to CFLAGS (affects compilation).\n\
                    Example: 'make EXTRA_CFLAGS=\"-DBLAH=1 -I/opt/local\"'\n\
\n\
   EXTRA_LDFLAGS  - Add text to LDFLAGS (affects linking).\n\
                    Example: 'make EXTRA_LDFLAGS=-Llibdir'\n\
\n\
   EXTRA_FLAGS    - Add text to both EXTRA_CFLAGS and EXTRA_LDFLAGS.\n\
                    Example: 'make EXTRA_FLAGS=-DBLAH=1'\n\
\n\
   EXTRA_LIBS     - Add text to LIBS (affects linking).\n\
                    Example: 'make EXTRA_LIBS=\"-L./stapi -loscam_stapi\"'\n\
\n\
 Use flags:\n\
   Use flags are used to request additional libraries or features to be used\n\
   by OSCam. Currently defined USE_xxx flags are:\n\
\n\
   USE_LIBUSB=1    - Request linking with libusb. The variables that control\n\
                     USE_LIBUSB=1 build are:\n\
                         LIBUSB_FLAGS='$(DEFAULT_LIBUSB_FLAGS)'\n\
                         LIBUSB_CFLAGS='$(DEFAULT_LIBUSB_FLAGS)'\n\
                         LIBUSB_LDFLAGS='$(DEFAULT_LIBUSB_FLAGS)'\n\
                         LIBUSB_LIB='$(DEFAULT_LIBUSB_LIB)'\n\
                     Using USE_LIBUSB=1 adds to '-libusb' to PLUS_TARGET.\n\
                     To build with static libusb, set the variable LIBUSB_LIB\n\
                     to contain full path of libusb library. For example:\n\
                      make USR_LIBUSB=1 LIBUSB_LIB=/usr/lib/libusb-1.0.a\n\
\n\
   USE_PCSC=1      - Request linking with PCSC. The variables that control\n\
                     USE_PCSC=1 build are:\n\
                         PCSC_FLAGS='$(DEFAULT_PCSC_FLAGS)'\n\
                         PCSC_CFLAGS='$(DEFAULT_PCSC_FLAGS)'\n\
                         PCSC_LDFLAGS='$(DEFAULT_PCSC_FLAGS)'\n\
                         PCSC_LIB='$(DEFAULT_PCSC_LIB)'\n\
                     Using USE_PCSC=1 adds to '-pcsc' to PLUS_TARGET.\n\
                     To build with static PCSC, set the variable PCSC_LIB\n\
                     to contain full path of PCSC library. For example:\n\
                      make USE_PCSC=1 PCSC_LIB=/usr/local/lib/libpcsclite.a\n\
\n\
   USE_STAPI=1    - Request linking with STAPI. The variables that control\n\
                     USE_STAPI=1 build are:\n\
                         STAPI_FLAGS='$(DEFAULT_STAPI_FLAGS)'\n\
                         STAPI_CFLAGS='$(DEFAULT_STAPI_FLAGS)'\n\
                         STAPI_LDFLAGS='$(DEFAULT_STAPI_FLAGS)'\n\
                         STAPI_LIB='$(DEFAULT_STAPI_LIB)'\n\
                     Using USE_STAPI=1 adds to '-stapi' to PLUS_TARGET.\n\
                     In order for USE_STAPI to work you have to create stapi\n\
                     directory and put liboscam_stapi.a file in it.\n\
\n\
   USE_COOLAPI=1  - Request support for Coolstream API (libnxp) aka NeutrinoHD\n\
                    box. The variables that control the build are:\n\
                         COOLAPI_FLAGS='$(DEFAULT_COOLAPI_FLAGS)'\n\
                         COOLAPI_CFLAGS='$(DEFAULT_COOLAPI_FLAGS)'\n\
                         COOLAPI_LDFLAGS='$(DEFAULT_COOLAPI_FLAGS)'\n\
                         COOLAPI_LIB='$(DEFAULT_COOLAPI_LIB)'\n\
                     Using USE_COOLAPI=1 adds to '-coolapi' to PLUS_TARGET.\n\
                     In order for USE_COOLAPI to work you have to have libnxp.so\n\
                     library in your cross compilation toolchain.\n\
\n\
   USE_SU980=1  - Request support for SU980 API (libentropic) aka Enimga2 arm\n\
                    box. The variables that control the build are:\n\
                         COOLAPI_FLAGS='$(DEFAULT_SU980_FLAGS)'\n\
                         COOLAPI_CFLAGS='$(DEFAULT_SU980_FLAGS)'\n\
                         COOLAPI_LDFLAGS='$(DEFAULT_SU980_FLAGS)'\n\
                         COOLAPI_LIB='$(DEFAULT_SU980_LIB)'\n\
                     Using USE_SU980=1 adds to '-su980' to PLUS_TARGET.\n\
                     In order for USE_SU980 to work you have to have libentropic.a\n\
                     library in your cross compilation toolchain.\n\
\n\
   USE_AZBOX=1    - Request support for AZBOX (openxcas)\n\
                    box. The variables that control the build are:\n\
                         AZBOX_FLAGS='$(DEFAULT_AZBOX_FLAGS)'\n\
                         AZBOX_CFLAGS='$(DEFAULT_AZBOX_FLAGS)'\n\
                         AZBOX_LDFLAGS='$(DEFAULT_AZBOX_FLAGS)'\n\
                         AZBOX_LIB='$(DEFAULT_AZBOX_LIB)'\n\
                     Using USE_AZBOX=1 adds to '-azbox' to PLUS_TARGET.\n\
                     extapi/openxcas/libOpenXCASAPI.a library that is shipped\n\
                     with OSCam is compiled for MIPSEL.\n\
\n\
   USE_MCA=1      - Request support for Matrix Cam Air (MCA).\n\
                    The variables that control the build are:\n\
                         MCA_FLAGS='$(DEFAULT_MCA_FLAGS)'\n\
                         MCA_CFLAGS='$(DEFAULT_MCA_FLAGS)'\n\
                         MCA_LDFLAGS='$(DEFAULT_MCA_FLAGS)'\n\
                     Using USE_MCA=1 adds to '-mca' to PLUS_TARGET.\n\
\n\
   USE_LIBCRYPTO=1 - Request linking with libcrypto instead of using OSCam\n\
                     internal crypto functions. USE_LIBCRYPTO is automatically\n\
                     enabled if the build is configured with SSL support. The\n\
                     variables that control USE_LIBCRYPTO=1 build are:\n\
                         LIBCRYPTO_FLAGS='$(DEFAULT_LIBCRYPTO_FLAGS)'\n\
                         LIBCRYPTO_CFLAGS='$(DEFAULT_LIBCRYPTO_FLAGS)'\n\
                         LIBCRYPTO_LDFLAGS='$(DEFAULT_LIBCRYPTO_FLAGS)'\n\
                         LIBCRYPTO_LIB='$(DEFAULT_LIBCRYPTO_LIB)'\n\
\n\
   USE_SSL=1       - Request linking with libssl. USE_SSL is automatically\n\
                     enabled if the build is configured with SSL support. The\n\
                     variables that control USE_SSL=1 build are:\n\
                         SSL_FLAGS='$(DEFAULT_SSL_FLAGS)'\n\
                         SSL_CFLAGS='$(DEFAULT_SSL_FLAGS)'\n\
                         SSL_LDFLAGS='$(DEFAULT_SSL_FLAGS)'\n\
                         SSL_LIB='$(DEFAULT_SSL_LIB)'\n\
                     Using USE_SSL=1 adds to '-ssl' to PLUS_TARGET.\n\
\n\
 Automatically intialized variables:\n\
\n\
   TARGET=text     - This variable is auto detected by using the compiler's\n\
                    -dumpmachine output. To see the target on your machine run:\n\
                     'gcc -dumpmachine'\n\
\n\
   PLUS_TARGET     - This variable is added to TARGET and it is set depending\n\
                     on the chosen USE_xxx flags. To disable adding\n\
                     PLUS_TARGET to TARGET, set NO_PLUS_TARGET=1\n\
\n\
   BINDIR          - The directory where final oscam binary would be put. The\n\
                     default is: $(BINDIR)\n\
\n\
   OSCAM_BIN=text  - This variable controls how the oscam binary will be named.\n\
                     Default OSCAM_BIN value is:\n\
                      'BINDIR/oscam-VERSVN_REV-TARGET'\n\
                     Once the variables (BINDIR, VER, SVN_REV and TARGET) are\n\
                     replaced, the resulting filename can look like this:\n\
                      'Distribution/oscam-1.20-unstable_svn7404-i486-slackware-linux-static'\n\
                     For example you can run: 'make OSCAM_BIN=my-oscam'\n\
\n\
 Binaries compiled and run during the OSCam build:\n\
\n\
   OSCam builds webif/pages_gen binary that is run by the build system to\n\
   generate file that holds web pages. To build this binary two variables\n\
   are used:\n\
\n\
   HOSTCC=gcc     - The compiler used for building binaries that are run on\n\
                    the build machine (the host). Default: gcc\n\
                    To use clang for example run: make CC=clang HOSTCC=clang\n\
\n\
   HOSTCFLAGS=xxx - The CFLAGS passed to HOSTCC. See webif/Makefile for the\n\
                    default host cflags.\n\
\n\
 Config targets:\n\
   make config        - Start configuration utility.\n\
   make allyesconfig  - Enable all configuration options.\n\
   make allnoconfig   - Disable all configuration options.\n\
   make defconfig     - Restore default configuration options.\n\
\n\
 Cleaning targets:\n\
   make clean     - Remove '$(BUILD_DIR)' directory which contains compiled\n\
                    object files.\n\
   make distclean - Executes clean target and also removes binary files\n\
                    located in '$(BINDIR)' directory.\n\
\n\
 Build system files:\n\
   config.sh      - OSCam configuration. Run 'config.sh --help' to see\n\
                    available parameters or 'make config' to start GUI\n\
                    configuratior.\n\
   Makefile       - Main build system file.\n\
   Makefile.extra - Contains predefined targets. You can use this file\n\
                    as example on how to use the build system.\n\
   Makefile.local - This file is included in Makefile and allows creation\n\
                    of local build system targets. See Makefile.extra for\n\
                    examples.\n\
\n\
 Here are some of the interesting predefined targets in Makefile.extra.\n\
 To use them run 'make target ...' where ... can be any extra flag. For\n\
 example if you want to compile OSCam for Dreambox (DM500) but do not\n\
 have the compilers in the path, you can run:\n\
    make dm500 CROSS_DIR=/opt/cross/dm500/cdk/bin/\n\
\n\
 Predefined targets in Makefile.extra:\n\
\n\
    make libusb        - Builds OSCam with libusb support\n\
    make pcsc          - Builds OSCam with PCSC support\n\
    make pcsc-libusb   - Builds OSCam with PCSC and libusb support\n\
    make dm500         - Builds OSCam for Dreambox (DM500)\n\
    make sh4           - Builds OSCam for SH4 boxes\n\
    make azbox         - Builds OSCam for AZBox STBs\n\
    make mca           - Builds OSCam for Matrix Cam Air (MCA)\n\
    make coolstream    - Builds OSCam for Coolstream\n\
    make dockstar      - Builds OSCam for Dockstar\n\
    make qboxhd        - Builds OSCam for QBoxHD STBs\n\
    make opensolaris   - Builds OSCam for OpenSolaris\n\
    make uclinux       - Builds OSCam for m68k uClinux\n\
\n\
 Predefined targets for static builds:\n\
    make static        - Builds OSCam statically\n\
    make static-libusb - Builds OSCam with libusb linked statically\n\
    make static-libcrypto - Builds OSCam with libcrypto linked statically\n\
    make static-ssl    - Builds OSCam with SSL support linked statically\n\
\n\
 Examples:\n\
   Build OSCam for SH4 (the compilers are in the path):\n\
     make CROSS=sh4-linux-\n\n\
   Build OSCam for SH4 (the compilers are in not in the path):\n\
     make sh4 CROSS_DIR=/opt/STM/STLinux-2.3/devkit/sh4/bin/\n\
     make CROSS_DIR=/opt/STM/STLinux-2.3/devkit/sh4/bin/ CROSS=sh4-linux-\n\
     make CROSS=/opt/STM/STLinux-2.3/devkit/sh4/bin/sh4-linux-\n\n\
   Build OSCam for SH4 with STAPI:\n\
     make CROSS=sh4-linux- USE_STAPI=1\n\n\
   Build OSCam for SH4 with STAPI and changed configuration directory:\n\
     make CROSS=sh4-linux- USE_STAPI=1 CONF_DIR=/var/tuxbox/config\n\n\
   Build OSCam for ARM with COOLAPI (coolstream aka NeutrinoHD):\n\
     make CROSS=arm-cx2450x-linux-gnueabi- USE_COOLAPI=1\n\n\
   Build OSCam for MIPSEL with AZBOX support:\n\
     make CROSS=mipsel-linux-uclibc- USE_AZBOX=1\n\n\
   Build OSCam for ARM with MCA support:\n\
     make CROSS=arm-none-linux-gnueabi- USE_MCA=1\n\n\
   Build OSCam with libusb and PCSC:\n\
     make USE_LIBUSB=1 USE_PCSC=1\n\n\
   Build OSCam with static libusb:\n\
     make USE_LIBUSB=1 LIBUSB_LIB=\"/usr/lib/libusb-1.0.a\"\n\n\
   Build OSCam with static libcrypto:\n\
     make USE_LIBCRYPTO=1 LIBCRYPTO_LIB=\"/usr/lib/libcrypto.a\"\n\n\
   Build OSCam with static libssl and libcrypto:\n\
     make USE_SSL=1 SSL_LIB=\"/usr/lib/libssl.a\" LIBCRYPTO_LIB=\"/usr/lib/libcrypto.a\"\n\n\
   Build with verbose messages and size optimizations:\n\
     make V=1 CC_OPTS=-Os\n\n\
   Build and set oscam file name:\n\
     make OSCAM_BIN=oscam\n\n\
   Build and set oscam file name depending on revision:\n\
     make OSCAM_BIN=oscam-\`./config.sh -r\`\n\n\
"

simple: all
default: all
debug: all

-include Makefile.extra
-include Makefile.local
