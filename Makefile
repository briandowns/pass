CC                ?= cc
DOCKER            ?= docker

VERSION           := 0.9.0

BINDIR            := bin
BINARY            := pass
PREFIX            := /usr/local

UNAME_S           := $(shell uname -s)

INCDIR            = include
MACOS_MANPAGE_LOC = /usr/share/man
LINUX_MAPPAGE_LOC = $(PREFIX)/man/man1

override LDFLAGS += -lsodium
override CFLAGS  += -O3 \
		-Dapp_name=$(BINARY) \
		-Dgit_sha=$(shell git rev-parse HEAD) \
		-Dapp_version=$(VERSION) \
		-DSODIUM_STATIC=1

$(BINDIR)/$(BINARY): $(BINDIR) clean
ifeq ($(UNAME_S),Darwin)
	$(CC) main.c pass.c $(CFLAGS) -o $@ $(LDFLAGS)
else
	$(CC) main.c pass.c $(CFLAGS) -o $@ -static $(LDFLAGS)
endif

$(BINDIR):
	mkdir -p $@

.PHONY: install
install: $(BINDIR)/$(BINARY)
	install -s $(BINDIR)/$(BINARY) $(PREFIX)/bin

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/$(BINDIR)/$(BINARY)

.PHONY: clean
clean:
	rm -f $(BINDIR)/$(BINARY)

.PHONY: manpage
manpage:
ifeq ($(UNAME_S),Linux)
$(LINUX_MAPPAGE_LOC)/$(BINARY).1:
	cp $(INCDIR)/$(BINARY)_manpage $(LINUX_MAPPAGE_LOC)/$(BINARY).1
	gzip $(LINUX_MAPPAGE_LOC)/$(BINARY).1
endif
ifeq ($(UNAME_S),Darwin)
$(MACOS_MANPAGE_LOC)/$(BINARY).1:
	cp $(INCDIR)/$(BINARY)_manpage $(MACOS_MANPAGE_LOC)/$(BINARY).1
	gzip $(MACOS_MANPAGE_LOC)/$(BINARY).1
endif
