# Targets: all (default), test, sanitize, tsan, static_analysis, fuzz, routing. Never use -march=native.

CROSS_COMPILE ?=
CC       := $(CROSS_COMPILE)gcc
BUILD    ?= $(if $(CROSS_COMPILE),cross-$(patsubst %-,%,$(CROSS_COMPILE)),host)
BUILDDIR := build/$(BUILD)
FIRC_VERSION ?= unattached

ENTWARE_KN ?=

# entware selects the /opt path defaults in paths.h; empty keeps the host defaults.
PLATFORM ?=

WARNINGS := -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 \
            -Wundef -Wstrict-prototypes -Wmissing-prototypes
CSTD     := -std=c11
OPT      ?= -O2
CFLAGS   ?=
# POSIX.1-2008 project-wide; only src/platform/ defines _GNU_SOURCE.
TUNVLESS_DIR := ../tunvless
TUNVLESS_HDR := -I$(TUNVLESS_DIR)/src/proto/vless
CFLAGS   += $(CSTD) $(OPT) $(WARNINGS) -Iinclude $(TUNVLESS_HDR) -MMD -MP \
            -D_POSIX_C_SOURCE=200809L \
            -DFIRC_VERSION=\"$(FIRC_VERSION)\" -fno-common \
            $(if $(ENTWARE_KN),-DFIRC_ENTWARE_KN) \
            $(if $(filter entware,$(PLATFORM)),-DFIRC_PLATFORM_ENTWARE)
# CI passes CFLAGS_EXTRA=-Werror.
CFLAGS_EXTRA ?=
CFLAGS   += $(CFLAGS_EXTRA)
LDFLAGS  ?=
LDFLAGS_EXTRA ?=
LDFLAGS  += $(LDFLAGS_EXTRA)
# -latomic: 32-bit targets lower 8-byte atomics to libatomic, which the linker does not pull in itself.
LDLIBS   := -lpthread -latomic
ifneq ($(SYSROOT),)
CFLAGS  += --sysroot=$(SYSROOT)
LDFLAGS += --sysroot=$(SYSROOT)
endif

# No external library dependencies.
CORE_SRCS := \
    src/util/err.c \
    src/util/atomic_write.c \
    src/util/queue.c \
    src/util/bytebuf.c \
    src/util/cancel.c \
    src/util/rand.c \
    src/util/instance_lock.c \
    src/util/spawn.c \
    src/util/listen.c \
    src/util/ifacename.c \
    src/core/lifecycle.c \
    src/logging/log.c \
    src/logging/events.c \
    src/platform/loop.c \
    src/dns/wire.c \
    src/netlink/nlattr_iter.c \
    src/dns/rewrite.c \
    src/dns/resolver_addr.c \
    src/dns/proxy.c \
    src/dns/pktinfo.c \
    src/fakeip/addr.c \
    src/fakeip/pool.c \
    src/fakeip/ula.c \
    src/iptables/rule.c \
    src/iptables/chain_patch.c \
    src/iptables/chain_override.c \
    src/iptables/chain_delete.c \
    src/iptables/engine.c \
    src/iptables/executable_real.c \
    src/crypto/md5.c \
    src/crypto/sha256.c \
    src/crypto/sha512.c \
    src/crypto/hmac.c \
    src/crypto/base64.c \
    src/crypto/crypt.c

# Needs libyaml, PCRE2 and cJSON.
CONFIG_SRCS := \
    src/config/duration.c \
    src/config/id.c \
    src/config/models.c \
    src/config/settings.c \
    src/config/resolve_check.c \
    src/config/yaml_scalar.c \
    src/config/yaml_load.c \
    src/config/yaml_save.c \
    src/rules/wildcard.c \
    src/rules/match.c \
    src/rules/snapshot.c \
    src/rules/devices.c \
    src/subscriptions/subparse.c \
    src/subscriptions/subparse_singbox.c \
    src/fakeip/from_config.c \
    src/dns/pipeline.c \
    src/dns/recall.c \
    src/dns/resolveroute.c

# Needs libmnl.
NETFILTER_SRCS := \
    src/netfilter/ipset_to_link.c \
    src/netfilter/port_remap.c \
    src/netfilter/cleaner.c \
    src/netfilter/purge.c \
    src/netfilter/conntrack.c \
    src/netfilter/stale_marks.c \
    src/netfilter/fields_file.c \
    src/netfilter/stable_fields.c \
    src/netfilter/committer.c \
    src/netfilter/ruleset.c \
    src/netfilter/pool_reject.c \
    src/netfilter/dnat.c \
    src/netlink/rtnl.c \
    src/netlink/watcher.c

# Needs cJSON (jwt.c too).
API_SRCS := \
    src/api/json.c \
    src/api/httpd.c \
    src/api/auth.c \
    src/api/app.c \
    src/api/groups.c \
    src/api/system.c \
    src/api/settings_api.c \
    src/api/capture.c \
    src/api/staticfiles.c \
    src/api/group_lists.c \
    src/api/tunnels.c \
    src/crypto/jwt.c

# Needs libyaml.
TUNNELS_SRCS := \
    src/tunnels/tconfig.c \
    src/tunnels/tunproto.c \
    src/tunnels/tunsup.c \
    src/tunnels/tunnet.c \
    src/tunnels/tunrun.c \
    src/tunnels/tunnodes.c \
    src/tunnels/tunsubs.c \
    src/tunnels/tunprobe.c

# The tunvless parser, built with tunvless's own flags; its own tests cover it.
TUNVLESS_PARSER_SRCS := \
    $(TUNVLESS_DIR)/src/proto/vless/sub.c \
    $(TUNVLESS_DIR)/src/proto/vless/sublink.c \
    $(TUNVLESS_DIR)/src/proto/vless/vless_proto.c \
    $(TUNVLESS_DIR)/src/proto/vless/vlink.c \
    $(TUNVLESS_DIR)/src/proto/transport/trpath.c
TUNVLESS_CFLAGS = -std=gnu11 $(OPT) -Wall -Wextra $(filter-out -Werror%,$(CFLAGS_EXTRA)) -MMD -MP \
    -I$(TUNVLESS_DIR)/src/lib -I$(TUNVLESS_DIR)/src/tunnel -I$(TUNVLESS_DIR)/src/proto/vless \
    -I$(TUNVLESS_DIR)/src/proto/transport -I$(TUNVLESS_DIR)/src/proto/tls \
    $(if $(SYSROOT),--sysroot=$(SYSROOT))

# Needs libcurl.
SUBSCRIPTIONS_SRCS := \
    src/subscriptions/fetch.c \
    src/subscriptions/worker.c

# The capture's readers; CI fails the build if a routing layer references a symbol from these.
TAP_SRCS := \
    src/tap/clienthello.c \
    src/tap/packet.c \
    src/tap/nflog.c \
    src/tap/nflog_sock.c \
    src/tap/report.c

# The capture rules belong to the daemon and are not part of the CI reader check.
TAP_RULES_SRCS := \
    src/tap/taprules.c

# Needs the config layer; kept apart so the parsers stay linkable and fuzzable without it.
TAP_CFG_SRCS := \
    src/tap/judge.c \
    src/tap/window.c

INTERFACES_SRCS := \
    src/interfaces/keenetic_rci.c \
    src/interfaces/keenetic_policy.c \
    src/interfaces/keenetic_resolvers.c

LIB_SRCS := $(CORE_SRCS) $(CONFIG_SRCS) $(NETFILTER_SRCS) $(API_SRCS) $(SUBSCRIPTIONS_SRCS) \
            $(TUNNELS_SRCS) $(INTERFACES_SRCS) $(TAP_RULES_SRCS) $(TAP_SRCS) $(TAP_CFG_SRCS)

MAIN_SRC := src/main/main.c
CONFIGTOOL_SRC := src/tools/configtool.c
DNSTOOL_SRC := src/tools/dnstool.c

CORE_OBJS := $(CORE_SRCS:%.c=$(BUILDDIR)/%.o)
CONFIG_OBJS := $(CONFIG_SRCS:%.c=$(BUILDDIR)/%.o)
NETFILTER_OBJS := $(NETFILTER_SRCS:%.c=$(BUILDDIR)/%.o)
API_OBJS := $(API_SRCS:%.c=$(BUILDDIR)/%.o)
SUBSCRIPTIONS_OBJS := $(SUBSCRIPTIONS_SRCS:%.c=$(BUILDDIR)/%.o)
TUNNELS_OBJS := $(TUNNELS_SRCS:%.c=$(BUILDDIR)/%.o) \
    $(TUNVLESS_PARSER_SRCS:$(TUNVLESS_DIR)/%.c=$(BUILDDIR)/tunvless/%.o)
INTERFACES_OBJS := $(INTERFACES_SRCS:%.c=$(BUILDDIR)/%.o)
TAP_RULES_OBJS := $(TAP_RULES_SRCS:%.c=$(BUILDDIR)/%.o)
TAP_OBJS := $(TAP_SRCS:%.c=$(BUILDDIR)/%.o) $(TAP_CFG_SRCS:%.c=$(BUILDDIR)/%.o)
LIB_OBJS := $(CORE_OBJS) $(CONFIG_OBJS) $(NETFILTER_OBJS) $(API_OBJS) $(SUBSCRIPTIONS_OBJS) \
            $(TUNNELS_OBJS) $(INTERFACES_OBJS) $(TAP_RULES_OBJS) $(TAP_OBJS)
MAIN_OBJ := $(MAIN_SRC:%.c=$(BUILDDIR)/%.o)
CONFIGTOOL_OBJ := $(CONFIGTOOL_SRC:%.c=$(BUILDDIR)/%.o)
DNSTOOL_OBJ := $(DNSTOOL_SRC:%.c=$(BUILDDIR)/%.o)

PCRE2_LIB ?= -lpcre2-8
CJSON_LIB ?= -lcjson
DEP_LIBS := -lyaml $(PCRE2_LIB) -lmnl $(CJSON_LIB) -lm -lcurl

TEST_SUPPORT_SRCS := tests/unit/fake_iptables.c tests/unit/fake_rtnl.c tests/unit/fake_conntrack.c tests/unit/fake_nflog.c
TEST_SUPPORT_OBJS := $(TEST_SUPPORT_SRCS:tests/unit/%.c=$(BUILDDIR)/tests/support/%.o)

TEST_SRCS := $(filter-out $(TEST_SUPPORT_SRCS), $(wildcard tests/unit/*.c))
TEST_BINS := $(TEST_SRCS:tests/unit/%.c=$(BUILDDIR)/tests/%)

FUZZ_SRCS := $(wildcard tests/fuzz/*.c)
FUZZ_BINS := $(FUZZ_SRCS:tests/fuzz/%.c=$(BUILDDIR)/fuzz/%)

.PHONY: all core tap clean test sanitize tsan static_analysis fuzz

# CI derives the reader-symbol check from `make print-TAP_OBJS`.
print-%:
	@echo '$($*)'

# A cross build with neither SYSROOT nor WITH_DEPS has no feed libs, so it builds the dependency-free subset only.
ifneq ($(and $(CROSS_COMPILE),$(if $(or $(SYSROOT),$(WITH_DEPS)),,1)),)
all: core tap $(BUILDDIR)/firc-dnstool
else
all: $(BUILDDIR)/fircd $(BUILDDIR)/firc-configtool $(BUILDDIR)/firc-dnstool
endif

core: $(CORE_OBJS)

tap: $(TAP_SRCS:%.c=$(BUILDDIR)/%.o) $(TAP_RULES_OBJS)

$(BUILDDIR)/fircd: $(LIB_OBJS) $(MAIN_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(DEP_LIBS)

$(BUILDDIR)/firc-configtool: $(LIB_OBJS) $(CONFIGTOOL_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(DEP_LIBS)

$(BUILDDIR)/firc-dnstool: $(CORE_OBJS) $(DNSTOOL_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR)/tunvless/%.o: $(TUNVLESS_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TUNVLESS_CFLAGS) -c -o $@ $<

# Keep support objects, or make deletes them as intermediates and rebuilds every test.
.PRECIOUS: $(BUILDDIR)/tests/support/%.o

$(BUILDDIR)/tests/support/%.o: tests/unit/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -c -o $@ $<

# Its own rule: sanitize passes LDFLAGS on the command line, which overrides a target-specific LDFLAGS.
OOM_WRAP := -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=strdup

$(BUILDDIR)/tests/test_oom: tests/unit/test_oom.c $(LIB_OBJS) $(TEST_SUPPORT_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/vendor -Itests/unit $(LDFLAGS) $(OOM_WRAP) -o $@ $< \
	    $(LIB_OBJS) $(TEST_SUPPORT_OBJS) $(LDLIBS) $(DEP_LIBS)

APP_WRAP := -Wl,--wrap=firc_dnsproxy_close_group_pools,--wrap=firc_dnsproxy_forget_group

$(BUILDDIR)/tests/test_app: tests/unit/test_app.c $(LIB_OBJS) $(TEST_SUPPORT_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/vendor -Itests/unit $(LDFLAGS) $(APP_WRAP) -o $@ $< \
	    $(LIB_OBJS) $(TEST_SUPPORT_OBJS) $(LDLIBS) $(DEP_LIBS)

SYSTEM_WRAP := -Wl,--wrap=firc_app_netfilter_health

$(BUILDDIR)/tests/test_system: tests/unit/test_system.c $(LIB_OBJS) $(TEST_SUPPORT_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/vendor -Itests/unit $(LDFLAGS) $(SYSTEM_WRAP) -o $@ $< \
	    $(LIB_OBJS) $(TEST_SUPPORT_OBJS) $(LDLIBS) $(DEP_LIBS)

$(BUILDDIR)/tests/%: tests/unit/%.c $(LIB_OBJS) $(TEST_SUPPORT_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/vendor -Itests/unit $(LDFLAGS) -o $@ $< $(LIB_OBJS) $(TEST_SUPPORT_OBJS) $(LDLIBS) $(DEP_LIBS)

# Run every binary even after a failure, then name the failures.
test: $(TEST_BINS)
	@failed=""; 	for t in $(TEST_BINS); do 	    echo "== $$t"; 	    $$t || failed="$$failed $$t"; 	done; 	if [ -n "$$failed" ]; then 	    echo; echo "FAILED:"; for t in $$failed; do echo "  $$t"; done; exit 1; 	fi

# float-cast-overflow is not part of -fsanitize=undefined and has to be named.
SAN := address,undefined,float-cast-overflow
# UBSan keeps going by default; halt_on_error makes the first error fail the suite.
SAN_ENV := UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
sanitize:
	$(SAN_ENV) $(MAKE) BUILD=sanitize \
	    OPT="-O1 -g -fsanitize=$(SAN) -fno-omit-frame-pointer" \
	    LDFLAGS="-fsanitize=$(SAN)" test

# Own build dir: TSan and ASan objects do not mix.
TSAN_TESTS := test_keenetic_policy test_keenetic_resolvers test_loop test_queue test_nfcommit test_sub_worker test_app
TSAN_BINS := $(TSAN_TESTS:%=build/tsan/tests/%)
tsan:
	$(MAKE) BUILD=tsan \
	    OPT="-O1 -g -fsanitize=thread" \
	    LDFLAGS="-fsanitize=thread" $(TSAN_BINS)
	@failed=""; \
	for t in $(TSAN_BINS); do \
	    echo "== $$t"; \
	    TSAN_OPTIONS=halt_on_error=1 $$t || failed="$$failed $$t"; \
	done; \
	if [ -n "$$failed" ]; then \
	    echo; echo "FAILED:"; for t in $$failed; do echo "  $$t"; done; exit 1; \
	fi

# Rootless routing checks against a real kernel; each script unshares its own namespaces.
ROUTECHECK := $(BUILDDIR)/tests/routing/firc-routecheck

$(ROUTECHECK): tests/routing/routecheck.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB_OBJS) $(LDLIBS) $(DEP_LIBS)

.PHONY: routing
routing: $(ROUTECHECK)
	FIRC_ROUTECHECK=$(abspath $(ROUTECHECK)) sh tests/routing/run_mark_routing.sh
	FIRC_ROUTECHECK=$(abspath $(ROUTECHECK)) sh tests/routing/run_selector_routing.sh

FUZZ_CC ?= clang
FUZZ_RUNS ?= 100000

$(BUILDDIR)/fuzz/fuzz_singbox: tests/fuzz/fuzz_singbox.c $(CORE_SRCS) $(CONFIG_SRCS)
	@mkdir -p $(dir $@)
	$(FUZZ_CC) -std=c11 -g -O1 -Iinclude -D_POSIX_C_SOURCE=200809L \
	    -fsanitize=fuzzer,address,undefined -o $@ $< $(CORE_SRCS) $(CONFIG_SRCS) $(DEP_LIBS)

$(BUILDDIR)/fuzz/%: tests/fuzz/%.c $(CORE_SRCS) $(TAP_SRCS)
	@mkdir -p $(dir $@)
	$(FUZZ_CC) -std=c11 -g -O1 -Iinclude -D_POSIX_C_SOURCE=200809L \
	    -fsanitize=fuzzer,address,undefined -o $@ $< $(CORE_SRCS) $(TAP_SRCS)

# The run goes to a log file: a pipe into tail would hide the fuzzer's exit status.
fuzz: $(FUZZ_BINS)
	@set -e; for f in $(FUZZ_BINS); do \
	    name=$$(basename $$f); \
	    echo "== $$f ($(FUZZ_RUNS) runs)"; \
	    mkdir -p tests/fuzz/corpus/$$name; \
	    [ -d tests/fuzz/seeds/$$name ] && \
	        cp -n tests/fuzz/seeds/$$name/* tests/fuzz/corpus/$$name/ 2>/dev/null || true; \
	    log=$$(mktemp); \
	    if $$f -runs=$(FUZZ_RUNS) -max_len=1600 \
	        tests/fuzz/corpus/$$name >"$$log" 2>&1; then \
	        tail -3 "$$log"; rm -f "$$log"; \
	    else \
	        echo "== $$f FAILED, last 20 lines:"; tail -20 "$$log"; \
	        rm -f "$$log"; exit 1; \
	    fi; \
	done

ANALYSIS_JOBS ?= $(shell nproc)
static_analysis:
	@if command -v clang-tidy >/dev/null; then \
	    printf '%s\n' $(LIB_SRCS) $(MAIN_SRC) $(CONFIGTOOL_SRC) $(DNSTOOL_SRC) $(TEST_SUPPORT_SRCS) | \
	    xargs -P $(ANALYSIS_JOBS) -n 4 sh -c 'clang-tidy --quiet "$$@" -- $(CSTD) -Iinclude $(TUNVLESS_HDR) -Itests/unit \
	        -D_POSIX_C_SOURCE=200809L -DFIRC_VERSION=\"$(FIRC_VERSION)\"' clang-tidy; \
	else echo "clang-tidy not found (skipped)"; fi
	@if command -v cppcheck >/dev/null; then \
	    cppcheck -j $(ANALYSIS_JOBS) --std=c11 --enable=warning,performance,portability \
	        --error-exitcode=1 --inline-suppr -Iinclude $(TUNVLESS_HDR) -Itests/unit \
	        -D_POSIX_C_SOURCE=200809L \
	        $(LIB_SRCS) $(MAIN_SRC) $(CONFIGTOOL_SRC) $(DNSTOOL_SRC) $(TEST_SUPPORT_SRCS); \
	else echo "cppcheck not found (skipped)"; fi

clean:
	rm -rf build

# Every built object needs its .d included, or a header change leaves it stale.
-include $(LIB_OBJS:.o=.d) $(TAP_OBJS:.o=.d) $(MAIN_OBJ:.o=.d) \
         $(CONFIGTOOL_OBJ:.o=.d) $(DNSTOOL_OBJ:.o=.d) \
         $(TEST_SUPPORT_OBJS:.o=.d) $(TEST_SRCS:tests/unit/%.c=$(BUILDDIR)/tests/%.d)
