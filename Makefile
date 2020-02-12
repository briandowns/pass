CC                ?= cc
DOCKER            ?= docker

VERSION           := 0.5.0

BINDIR            := bin
BINARY            := pass
PREFIX            := /usr/local

UNAME_S           := $(shell uname -s)

MACOS_MANPAGE_LOC = /usr/share/man
LINUX_MAPPAGE_LOC = $(PREFIX)/man/man8

override LDFLAGS += -lsodium
override CFLAGS  += -O3 \
		-Dapp_name=$(BINARY) \
		-Dgit_sha=$(shell git rev-parse HEAD) \
		-Dapp_version=$(VERSION)

$(BINDIR)/$(BINARY): $(BINDIR) clean
	$(CC) main.c $(CFLAGS) -o $@ $(LDFLAGS)

$(BINDIR):
	mkdir -p $@

$(DEPDIR):
	mkdir -p $@

.PHONY: install
install: $(BINDIR)/$(BINARY) $(BINDIR)
	cp $(BINDIR)/$(BINARY) $(PREFIX)/bin

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/$(BINDIR)/$(BINARY)

.PHONY: deps
deps: $(DEPDIR)

.PHONY: clean
clean:
	rm -f $(BINDIR)/*

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
