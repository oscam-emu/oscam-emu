HOSTCC ?= gcc
HOSTCFLAGS ?= -O2 \
 -W -Wall -Wextra -Wno-sign-compare \
 -Wshadow -Wformat-security -Wstrict-prototypes

# Setup quiet build
Q =
SAY = @true
ifndef V
Q = @
NP = --no-print-directory
SAY = @echo
endif

all: pages.c

pages.c: pages_gen
	$(SAY) "GEN	webif/$@"
	$(Q)./pages_mkdep
	$(Q)./pages_gen

-include pages.dep

pages_gen: Makefile pages_gen.c
	$(SAY) "HOSTCC	webif/$@"
	$(Q)$(HOSTCC) $(HOSTCFLAGS) ../minilzo/minilzo.c pages_gen.c -o $@

clean:
	@-for FILE in pages_gen pages.dep pages.bin pages.bin.compressed pages.h pages.c; do \
		if [ -f $$FILE ]; then echo "RM	webif/$$FILE"; fi; \
		rm -rf $$FILE; \
	done

distclean: clean
