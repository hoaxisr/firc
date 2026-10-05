include $(TOPDIR)/rules.mk

include ./version.mk

PKG_NAME:=firc
PKG_VERSION:=$(FIRC_VERSION)
PKG_RELEASE:=$(FIRC_RELEASE)
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=hoaxisr <https://github.com/hoaxisr>
PKG_SOURCE:=firc-source.tar.gz
PKG_SOURCE_URL:=file://$(CURDIR)
PKG_HASH:=skip
PKG_MIRROR_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1
PKGARCH:=$(FIRC_TARGET)

include $(INCLUDE_DIR)/package.mk

# The SDK ships without toolchain stamps; restore them so packaging does not rebuild GCC.
FIRC_TOOLCHAIN_DIR:=$(BUILD_DIR)/toolchain
FIRC_TOOLCHAIN_PREPARED:=.prepared_ad8c94d059fbcd3e4fe92dada0211bba_18f1e190c5d53547fed41a3eaa76e9e9
FIRC_TOOLCHAIN_CONFIGURED:=.configured_68b329da9893e34099c7d8ad5cb9c940
$(shell mkdir -p $(FIRC_TOOLCHAIN_DIR) && \
	touch \
		$(FIRC_TOOLCHAIN_DIR)/$(FIRC_TOOLCHAIN_PREPARED)_check \
		$(FIRC_TOOLCHAIN_DIR)/$(FIRC_TOOLCHAIN_PREPARED) \
		$(FIRC_TOOLCHAIN_DIR)/$(FIRC_TOOLCHAIN_CONFIGURED) \
		$(FIRC_TOOLCHAIN_DIR)/.built)

FIRC_DYNAMIC_LINKER:=ld.so.1
ifneq ($(findstring aarch64,$(FIRC_TARGET)),)
FIRC_DYNAMIC_LINKER:=ld-linux-aarch64.so.1
endif

define Package/firc
  SECTION:=net
  CATEGORY:=Network
  TITLE:=DNS-based routing application
  URL:=https://github.com/hoaxisr/firc
  DEPENDS:=+iptables +libyaml +libpcre2 +libmnl +libcurl +cJSON +socat
endef

define Package/firc/description
 DNS-based routing application for Entware.
endef

define Package/firc/conffiles
/opt/etc/firc/firc.conf
/opt/etc/firc/groups.yaml
endef

# Mirrors files/entware/_ipk/control/postinst with every `$` doubled; CI diffs the two.
define Package/firc/postinst
#!/bin/sh

# Strip fetched list rules from an old groups.yaml before start: a huge file OOM-kills fircd on load.
GROUPS=/opt/etc/firc/groups.yaml

# Smaller files load fine and are left to the daemon.
MIGRATE_MIN_BYTES=$${MIGRATE_MIN_BYTES:-262144}

migrate_groups() {
    f=$$1
    [ -f "$$f" ] || return 0
    if [ "$${FIRC_MIGRATE_FORCE:-0}" != 1 ]; then
        size=$$(wc -c < "$$f" 2>/dev/null) || return 0
        [ "$$size" -ge "$$MIGRATE_MIN_BYTES" ] || return 0
    fi
    # A YAML sequence may sit at its key's own indent, so the skip also runs over `-` items at that indent.
    awk -v countfile="$$f.off" '
        /^[^ \t#-]/ { in_subs = ($$0 ~ /^subscriptions:[[:space:]]*$$/); skip = 0 }
        {
            if (skip) {
                if ($$0 ~ /^[[:space:]]*$$/) { next }
                match($$0, /^[ \t]*/)
                if (RLENGTH > skip_indent) {
                    if ($$0 ~ /^[ \t]*enable:[[:space:]]*false[[:space:]]*$$/) { off++ }
                    next
                }
                if (RLENGTH == skip_indent && substr($$0, RLENGTH + 1, 1) == "-") { next }
                skip = 0
            }
            if (in_subs && $$0 ~ /^[ \t]*rules:/) {
                match($$0, /^[ \t]*/)
                skip_indent = RLENGTH
                skip = 1
                next
            }
            print
        }
        END { print off + 0 > countfile }
    ' "$$f" > "$$f.new" || return 1

    if [ ! -s "$$f.new" ]; then
        rm -f "$$f.new" "$$f.off"
        return 1
    fi
    if cmp -s "$$f" "$$f.new"; then
        rm -f "$$f.new" "$$f.off"
        return 0
    fi
    cp "$$f" "$$f.pre-0027.bak" || { rm -f "$$f.new"; return 1; }
    mv "$$f.new" "$$f" || return 1

    off=$$(cat "$$f.off" 2>/dev/null) || off=0
    rm -f "$$f.off"
    if [ "$${off:-0}" -gt 0 ]; then
        echo "firc: $$f was too large to load, so its subscriptions' rules were" >&2
        echo "firc: dropped and will be refetched. $$off rule(s) you had switched off" >&2
        echo "firc: could not be carried over; the old file is at $$f.pre-0027.bak" >&2
    fi
    return 0
}

# Used by the differential tests; opkg never passes it.
if [ "$${1:-}" = "--migrate-only" ]; then
    migrate_groups "$${2:-$$GROUPS}"
    exit $$?
fi

migrate_groups "$$GROUPS" || {
    echo "firc: could not rewrite $$GROUPS; the original is at $$GROUPS.pre-0027.bak" >&2
}

# A failed start must fail the configure step so opkg leaves the package unpacked.
/opt/etc/init.d/S99firc restart || {
    echo "firc: the daemon did not start; see logread and /opt/etc/firc/firc.conf" >&2
    exit 1
}

exit 0
endef

# Mirrors files/entware/_ipk/control/prerm with every `$` doubled.
define Package/firc/prerm
#!/bin/sh

# A daemon left running from an unlinked binary keeps its rules until reboot, so refuse if it will not stop.
ACTION="$${1:-}"
if [ -x /opt/etc/init.d/S99firc ]; then
  /opt/etc/init.d/S99firc stop || {
    if [ "$$ACTION" = upgrade ]; then
      MSG="firc: the running daemon would not stop; the upgrade is refused while it still routes. Reboot, then upgrade."
    else
      MSG="firc: the daemon would not stop; its files are not removed while it still routes. Reboot, then remove (or opkg remove --force-remove)."
    fi
    echo "$$MSG" >&2
    logger -t firc "$$MSG" 2>/dev/null
    exit 1
  }
fi

# A stop keeps the pool's barrier and reject routes for the next daemon; purge them only on "remove".
case "$$ACTION" in
  remove)
    try_purge() {
      # fircd's status goes out on fd 3: a pipeline reports logger's status, not the purge's.
      rc=`{ { /opt/bin/fircd --purge; echo $$? >&3; } | logger -t fircd 2>/dev/null; } 3>&1`
      return $${rc:-1}
    }
    if [ -x /opt/bin/fircd ]; then
      try_purge || try_purge ||
        logger -t firc "purge did not finish; some rules or routes may be left until the next reboot"
    fi
    rm -rf /tmp/firc-init
    ;;
  upgrade) ;;
  *) logger -t firc "prerm: action '$$ACTION' unknown; the pool's routes and barrier are left for the next daemon" 2>/dev/null ;;
esac

exit 0
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src/backend-c \
		BUILD=entware-$(FIRC_TARGET) \
		FIRC_VERSION="$(PKG_VERSION)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		PLATFORM=entware \
		ENTWARE_KN=1 \
		WITH_DEPS=1 \
		CFLAGS_EXTRA="$(TARGET_CFLAGS) -I$(STAGING_DIR)/opt/include" \
		LDLIBS="-lpthread -Wl,-Bstatic -latomic -Wl,-Bdynamic" \
		LDFLAGS_EXTRA="$(TARGET_LDFLAGS) \
			-Wl,--dynamic-linker=/opt/lib/$(FIRC_DYNAMIC_LINKER) \
			-Wl,-rpath,/opt/lib \
			-L$(STAGING_DIR)/opt/lib \
			-Wl,-rpath-link,$(STAGING_DIR)/opt/lib"
endef

define Package/firc/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/src/backend-c/build/entware-$(FIRC_TARGET)/fircd \
		$(1)/opt/bin/fircd

	$(INSTALL_DIR) $(1)/opt/usr/share/firc/skins/default
	$(CP) $(PKG_BUILD_DIR)/src/frontend/dist/. \
		$(1)/opt/usr/share/firc/skins/default/

	$(INSTALL_DIR) $(1)/opt/etc/firc
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/files/common/etc/firc/firc.conf \
		$(1)/opt/etc/firc/firc.conf
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/files/common/etc/firc/groups.yaml \
		$(1)/opt/etc/firc/groups.yaml

	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/entware_kn/etc/init.d/S99firc \
		$(1)/opt/etc/init.d/S99firc

	$(INSTALL_DIR) $(1)/opt/etc/ndm/netfilter.d
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/files/entware_kn/etc/ndm/netfilter.d/100-firc \
		$(1)/opt/etc/ndm/netfilter.d/100-firc
endef

$(eval $(call BuildPackage,firc))
