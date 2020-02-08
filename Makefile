CC               ?= cc
DOCKER           ?= docker

VERSION          := 0.1.0
BINDIR           := bin
BINARY           := pass
override LDFLAGS += -lssl -lsodium
override CFLAGS  += -O3 \
					-Dapp_name=$(BINARY) \
					-Dgit_sha=$(shell git rev-parse HEAD) \
					-Dapp_version=$(VERSION) \
					-L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include \
					-L/usr/local/opt/libarchive/lib -I/usr/local/opt/libarchive/include

$(BINDIR)/$(BINARY): $(BINDIR) clean
	$(CC) main.c backup.c $(CFLAGS) -o $@ $(LDFLAGS)

$(BINDIR):
	mkdir -p $@

$(DEPDIR):
	mkdir -p $@

.PHONY: image
image:
	$(DOCKER) build -t $(BINARY):latest .

.PHONY: push
push:

.PHONY: deps
deps: $(DEPDIR)

.PHONY: clean
clean:
	rm -f $(BINDIR)/*

