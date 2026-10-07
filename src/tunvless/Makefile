# tunvless — a TUN device with a VLESS outbound.
#
#   make                    build out/tunvless (fetches and builds wolfSSL on first run)
#   make test               unit and crypto tests (no root, no network)
#   make e2e                tunnel tests in network namespaces (root, iproute2, python3)
#   make interop            against real Xray-core / sing-box (XRAY=, SINGBOX=; skipped without)
#   make install            DESTDIR, PREFIX (default /usr/local)
#
# Cross builds take the toolchain from the environment, e.g.
#   make CC=mipsel-openwrt-linux-gnu-gcc AR=mipsel-openwrt-linux-gnu-ar
# The Entware package is built this way by the Entware SDK (tools/ci/entware-package/Makefile).

VERSION     ?= dev
O           ?= out
CC          ?= cc
AR          ?= ar
CFLAGS      ?= -O2
LDFLAGS     ?=
WOLFSSL_SRC ?= third_party/wolfssl

INC      := -Isrc/lib -Isrc/tunnel -Isrc/proto/vless -Isrc/proto/transport -Isrc/proto/tls
WARN     := -Wall -Wextra
PREFIXMAP := -ffile-prefix-map=$(CURDIR)/=
ALL_CFLAGS = $(CFLAGS) $(WARN) $(INC) $(PREFIXMAP) -ffunction-sections -fdata-sections
DEFS     := -DTUNVLESS_VERSION='"$(VERSION)"'

TUNNEL_SRC    := src/tunnel/tun.c src/tunnel/stack.c src/tunnel/rtx.c src/tunnel/ifcfg.c src/tunnel/pool.c src/tunnel/nodes.c src/control.c
VLESS_SRC     := src/proto/vless/vldial.c src/proto/vless/client.c src/proto/vless/vless_proto.c src/proto/vless/vlink.c \
                 src/proto/vless/vision.c src/proto/vless/sublink.c src/proto/vless/sub.c
TRANSPORT_SRC := src/proto/transport/transport.c src/proto/transport/trdial.c \
                 src/proto/transport/trsec.c src/proto/transport/trgrpc.c src/proto/transport/trxhttp.c \
                 src/proto/transport/trupgrade.c src/proto/transport/trws.c src/proto/transport/trpath.c \
                 src/proto/transport/trvenc.c
TLS_SRC       := src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c \
                 src/proto/tls/h2.c src/proto/tls/ech.c src/proto/tls/roots.c
LIB_SRC       := src/lib/osrand.c
# The one file that sees wolfSSL headers: built with the library's own flags.
CRYPTO_SRC    := src/lib/scrypto.c
SRC           := src/main.c src/ctlnodes.c $(TUNNEL_SRC) $(VLESS_SRC) $(TRANSPORT_SRC) $(TLS_SRC) $(LIB_SRC)
HDR           := $(wildcard src/*/*.h src/proto/*/*.h)

WOLFSSL_LIB   := $(O)/wolfssl/libwolfssl.a
WOLFSSL_FLAGS  = $(shell cat $(WOLFSSL_LIB).cflags 2>/dev/null)

.PHONY: all fetch test unit-test crypto-test e2e interop install clean distclean

all: $(O)/tunvless

fetch: $(WOLFSSL_SRC)/wolfssl/wolfcrypt/settings.h

$(WOLFSSL_SRC)/wolfssl/wolfcrypt/settings.h:
	sh build/wolfssl/fetch.sh $(WOLFSSL_SRC)

# build.sh rebuilds only when the options, the compiler or the flags change.
$(WOLFSSL_LIB): $(WOLFSSL_SRC)/wolfssl/wolfcrypt/settings.h build/wolfssl/user_settings.h build/wolfssl/build.sh FORCE
	@CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS) $(PREFIXMAP) -ffunction-sections -fdata-sections" \
		sh build/wolfssl/build.sh $(WOLFSSL_SRC) $@

$(O)/scrypto.o: $(CRYPTO_SRC) src/lib/scrypto.h src/lib/blake3.h $(WOLFSSL_LIB)
	@mkdir -p $(O)
	$(CC) $(ALL_CFLAGS) $(WOLFSSL_FLAGS) -c $< -o $@

$(O)/tunvless: $(SRC) $(HDR) $(O)/scrypto.o $(WOLFSSL_LIB)
	@mkdir -p $(O)
	$(CC) $(ALL_CFLAGS) $(DEFS) -o $@ $(SRC) $(O)/scrypto.o $(WOLFSSL_LIB) \
		$(LDFLAGS) -Wl,--gc-sections -lpthread

install: $(O)/tunvless
	install -d $(DESTDIR)$(or $(PREFIX),/usr/local)/bin
	install -m 0755 $(O)/tunvless $(DESTDIR)$(or $(PREFIX),/usr/local)/bin/tunvless

# ---- tests ------------------------------------------------------------------------------
#
# Unit tests need neither the network nor wolfSSL: where a test needs TLS, it stubs it.
# Crypto tests link a wolfSSL built with the test-only options (certificate issuing and a TLS
# server for the peer side), in its own archive so the shipped one never carries them.

T        := $(O)/tests
T_CFLAGS  = -O1 -g $(WARN) -Wno-unused-function $(INC) -Itests $(if $(SANITIZE),-fsanitize=$(SANITIZE))
TW_LIB   := $(T)/wolfssl/libwolfssl.a
TW_FLAGS  = $(shell cat $(TW_LIB).cflags 2>/dev/null)

UNIT := h2match xhupmatch wsmatch b3match visionmatch submatch subpq vlinkmatch tungromatch tunnamematch tunnelmatch rtxmatch grpcmatch ctlmatch nodesmatch ctlnodesmatch
CRYPTO_TESTS := scryptomatch hellofreeze echmatch vlessmatch takematch

test: unit-test crypto-test
	@echo "all tests passed"

unit-test: $(addprefix $(T)/,$(UNIT))
	@set -e; for t in $(UNIT); do echo "== $$t"; $(T)/$$t; done

crypto-test: $(addprefix $(T)/,$(CRYPTO_TESTS))
	@set -e; for t in $(CRYPTO_TESTS); do echo "== $$t"; $(T)/$$t; done

$(T)/h2match: tests/h2match.c src/proto/tls/h2.c $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/h2match.c

XHUP_SRC := src/proto/tls/h2.c src/proto/transport/transport.c src/proto/transport/trsec.c \
            src/proto/transport/trdial.c src/proto/transport/trgrpc.c src/proto/tls/roots.c \
            src/proto/transport/trws.c src/proto/transport/trupgrade.c src/proto/transport/trpath.c \
            src/lib/osrand.c
$(T)/xhupmatch: tests/xhupmatch.c tests/trvenc-stub.c src/proto/transport/trxhttp.c $(XHUP_SRC) $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/xhupmatch.c tests/trvenc-stub.c $(XHUP_SRC) -lpthread

WS_SRC := src/proto/transport/trws.c src/proto/transport/trupgrade.c src/proto/transport/trpath.c \
          src/proto/transport/transport.c src/proto/transport/trsec.c src/proto/transport/trdial.c \
          src/proto/transport/trgrpc.c src/proto/transport/trxhttp.c src/proto/tls/h2.c \
          src/proto/tls/roots.c src/lib/osrand.c
$(T)/wsmatch: tests/wsmatch.c tests/trvenc-stub.c $(WS_SRC) $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/wsmatch.c tests/trvenc-stub.c $(WS_SRC) -lpthread

$(T)/b3match: tests/b3match.c src/lib/blake3.h
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/b3match.c

$(T)/visionmatch: tests/visionmatch.c src/proto/vless/vision.c src/lib/osrand.c $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/visionmatch.c src/proto/vless/vision.c src/lib/osrand.c -lpthread

SUB_SRC := src/proto/vless/sublink.c src/proto/transport/trpath.c
$(T)/submatch: tests/submatch.c src/proto/vless/sub.c src/proto/vless/vless_proto.c $(SUB_SRC) $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/submatch.c $(SUB_SRC)

$(T)/subpq: tests/subpq.c tests/sub-pq-samples.h src/proto/vless/sub.c src/proto/vless/vless_proto.c $(SUB_SRC) $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/subpq.c src/proto/vless/sub.c src/proto/vless/vless_proto.c $(SUB_SRC)

$(T)/vlinkmatch: tests/vlinkmatch.c tests/sub-pq-samples.h src/proto/vless/vlink.c src/proto/vless/sub.c src/proto/vless/vless_proto.c $(SUB_SRC) $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/vlinkmatch.c src/proto/vless/vlink.c src/proto/vless/sub.c src/proto/vless/vless_proto.c $(SUB_SRC)

$(T)/tungromatch: tests/tungromatch.c src/tunnel/tun.c $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/tungromatch.c

$(T)/tunnamematch: tests/tunnamematch.c src/tunnel/tun.c $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/tunnamematch.c src/tunnel/tun.c

# grpcmatch includes trgrpc.c (its framing functions are static) and links the rest for real.
GRPC_TEST_SRC := $(filter-out src/proto/transport/trgrpc.c,$(XHUP_SRC)) src/proto/transport/trxhttp.c
$(T)/grpcmatch: tests/grpcmatch.c tests/trvenc-stub.c src/proto/transport/trgrpc.c $(GRPC_TEST_SRC) $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/grpcmatch.c tests/trvenc-stub.c $(GRPC_TEST_SRC) -lpthread

$(T)/ctlmatch: tests/ctlmatch.c src/control.c src/control.h
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/ctlmatch.c src/control.c -lpthread

$(T)/nodesmatch: tests/nodesmatch.c src/tunnel/nodes.c src/proto/transport/trdial.c $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/nodesmatch.c src/tunnel/nodes.c -lpthread

CTLN_SRC := src/ctlnodes.c src/tunnel/nodes.c src/proto/vless/vlink.c src/proto/vless/sub.c \
            src/proto/vless/vless_proto.c $(SUB_SRC)
$(T)/ctlnodesmatch: tests/ctlnodesmatch.c src/proto/transport/trdial.c $(CTLN_SRC) $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/ctlnodesmatch.c $(CTLN_SRC) -lpthread

$(T)/rtxmatch: tests/rtxmatch.c src/tunnel/rtx.c src/tunnel/rtx.h
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/rtxmatch.c src/tunnel/rtx.c

TUNNEL_TEST_SRC := src/control.c src/tunnel/tun.c src/tunnel/rtx.c src/tunnel/ifcfg.c src/proto/vless/vless_proto.c \
                   src/proto/vless/vision.c src/proto/vless/vldial.c src/lib/osrand.c
$(T)/tunnelmatch: tests/tunnelmatch.c src/tunnel/stack.c src/tunnel/pool.c $(TUNNEL_TEST_SRC) $(HDR)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) -o $@ tests/tunnelmatch.c $(TUNNEL_TEST_SRC) -lpthread -ldl

# -- crypto tests: the test wolfSSL and the crypto layer built against it --

$(TW_LIB): $(WOLFSSL_SRC)/wolfssl/wolfcrypt/settings.h build/wolfssl/user_settings.h build/wolfssl/build.sh FORCE
	@CC="$(CC)" AR="$(AR)" CFLAGS="-O2 -g" \
		STEER_WOLFSSL_DEFS="-DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DSTEER_WOLFSSL_SERVER" \
		sh build/wolfssl/build.sh $(WOLFSSL_SRC) $@

$(T)/scrypto.o: $(CRYPTO_SRC) src/lib/scrypto.h src/lib/blake3.h $(TW_LIB)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) $(TW_FLAGS) -c $< -o $@

$(T)/certgen.o: tests/certgen.c tests/certgen.h $(TW_LIB)
	@mkdir -p $(T)
	$(CC) $(T_CFLAGS) $(TW_FLAGS) -c $< -o $@

T_CRYPTO = $(T)/scrypto.o src/lib/osrand.c $(TW_LIB) -lpthread
CLIENT_SRC := src/proto/vless/client.c src/proto/vless/vless_proto.c src/proto/vless/vision.c \
              src/proto/vless/sub.c src/proto/vless/sublink.c \
              src/proto/transport/transport.c src/proto/transport/trsec.c src/proto/transport/trgrpc.c \
              src/proto/transport/trxhttp.c src/proto/transport/trupgrade.c src/proto/transport/trws.c \
              src/proto/transport/trpath.c src/proto/transport/trvenc.c \
              src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c src/proto/tls/h2.c \
              src/proto/tls/ech.c

$(T)/scryptomatch: tests/scryptomatch.c tests/scrypto-pki.h tests/scrypto-pq.h $(T)/scrypto.o
	$(CC) $(T_CFLAGS) -o $@ tests/scryptomatch.c $(T_CRYPTO)

$(T)/hellofreeze: tests/hellofreeze.c tests/chello-frozen.h tests/chello-frozen-pq.h src/proto/tls/reality.c $(T)/scrypto.o
	$(CC) $(T_CFLAGS) -o $@ tests/hellofreeze.c $(T_CRYPTO)

$(T)/echmatch: tests/echmatch.c src/proto/tls/ech.c src/proto/tls/reality.c $(T)/scrypto.o $(HDR)
	$(CC) $(T_CFLAGS) -o $@ tests/echmatch.c src/proto/tls/ech.c src/proto/tls/reality.c $(T_CRYPTO)

# vlessmatch includes trdial.c and roots.c (it reaches their static seams).
$(T)/vlessmatch: tests/vlessmatch.c $(CLIENT_SRC) src/proto/transport/trdial.c src/proto/tls/roots.c \
                 $(T)/certgen.o $(T)/scrypto.o $(HDR)
	$(CC) $(T_CFLAGS) -DSTEER_HAVE_X509WRITE -o $@ tests/vlessmatch.c $(CLIENT_SRC) $(T)/certgen.o $(T_CRYPTO)

$(T)/takematch: tests/takematch.c src/proto/vless/vldial.c $(CLIENT_SRC) $(T)/scrypto.o $(HDR)
	$(CC) $(T_CFLAGS) -o $@ tests/takematch.c src/proto/vless/vldial.c $(TUNNEL_SRC) $(CLIENT_SRC) \
		src/proto/transport/trdial.c src/proto/tls/roots.c $(T_CRYPTO)

# -- probes for the interop scripts (a real server on the other side) --

$(T)/vencprobe: tests/vencprobe.c $(CLIENT_SRC) $(T)/scrypto.o $(HDR)
	$(CC) $(T_CFLAGS) -o $@ tests/vencprobe.c $(CLIENT_SRC) src/proto/transport/trdial.c \
		src/proto/tls/roots.c $(T_CRYPTO)

$(T)/xudpprobe: tests/xudpprobe.c src/proto/vless/vldial.c $(CLIENT_SRC) $(T)/scrypto.o $(HDR)
	$(CC) $(T_CFLAGS) -o $@ tests/xudpprobe.c src/proto/vless/vldial.c $(CLIENT_SRC) \
		src/proto/transport/trdial.c src/proto/tls/roots.c $(T_CRYPTO)

interop: $(T)/vencprobe $(T)/xudpprobe $(O)/tunvless
	BUILD=$(T) sh tests/venc.sh
	BUILD=$(T) sh tests/xudp.sh
	BUILD=$(T) sh tests/ech.sh
	TUNVLESS=$(O)/tunvless sh tests/run-xray.sh

e2e: $(O)/tunvless
	TUNVLESS=$(O)/tunvless sh tests/run-tunnel.sh
	TUNVLESS=$(O)/tunvless sh tests/run-tunnel.sh 3
	TUNVLESS=$(O)/tunvless sh tests/run-udp.sh
	TUNVLESS=$(O)/tunvless sh tests/run-tunnel-fin.sh
	TUNVLESS=$(O)/tunvless sh tests/rcvwnd.sh
	TUNVLESS=$(O)/tunvless sh tests/sigpipe.sh
	TUNVLESS=$(O)/tunvless sh tests/routes.sh
	TUNVLESS=$(O)/tunvless sh tests/failover.sh
	TUNVLESS=$(O)/tunvless sh tests/control.sh

clean:
	rm -rf $(O)

distclean: clean
	rm -rf $(WOLFSSL_SRC)

FORCE:
