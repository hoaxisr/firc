-include .config

PKG_NAME := firc
PKG_DESCRIPTION := DNS-based routing application
PKG_LICENSE := GPL-3.0-or-later
PKG_URL := https://github.com/hoaxisr/firc
PKG_MAINTAINER := hoaxisr <https://github.com/hoaxisr>

ifeq ($(strip $(PKG_VERSION)),)
	TAG_REF := $(shell git describe --tags --abbrev=0 --match '[0-9]*' --match 'v[0-9]*' 2> /dev/null)
	TAG := $(patsubst v%,%,$(TAG_REF))
	COMMITS_SINCE_TAG := $(shell [ -n "$(TAG_REF)" ] && git rev-list $(TAG_REF)..HEAD --count 2>/dev/null || echo 0)

	ifneq ($(strip $(TAG)),)
		ifeq ($(strip $(COMMITS_SINCE_TAG)),0)
			PKG_VERSION := $(shell echo "$(TAG)" | sed 's/-rev[0-9]*$$//')
			TAG_REVISION := $(shell echo "$(TAG)" | grep -oE 'rev[0-9]+$$' | sed 's/rev//')
			ifneq ($(strip $(TAG_REVISION)),)
				PKG_REVISION ?= $(TAG_REVISION)
			endif
		endif
	endif

	ifeq ($(strip $(PKG_VERSION)),)
		PKG_VERSION_PRERELEASE := $(if $(TAG),$(shell echo "$(TAG)" | sed 's/-rev[0-9]*$$//' | awk -F. 'BEGIN{OFS="."} {if (NF >= 3) {$$3=$$3+1; NF=3} else {$$NF=$$NF+1}; print}'),0.0.0)
		PRERELEASE_DATE := $(shell date -u +%Y%m%d%H%M%S)
		COMMIT := $(shell git rev-parse --short HEAD)
		PKG_VERSION := $(PKG_VERSION_PRERELEASE)~git$(PRERELEASE_DATE).$(COMMIT)
	endif
endif
ifeq ($(strip $(PKG_VERSION_DISPLAY)),)
	ifeq ($(strip $(PKG_VERSION_PRERELEASE)),)
		PKG_VERSION_DISPLAY := $(PKG_VERSION)
	else
		PKG_VERSION_DISPLAY := $(PKG_VERSION_PRERELEASE) ($(COMMIT))
	endif
endif
PKG_REVISION ?= 1

export PKG_VERSION
export PKG_REVISION
export PKG_VERSION_DISPLAY
export PKG_VERSION_PRERELEASE

BUILDS_DIR := ./.build
STAMPS_DIR := $(BUILDS_DIR)/.stamps

UNIQUE_NAME := $(PLATFORM)_$(TARGET)
BUILD_DIR := $(BUILDS_DIR)/$(UNIQUE_NAME)
COMPILE_DIR := $(BUILD_DIR)/compile

ROOT_DIR := $(BUILD_DIR)/root
BIN_DIR := $(ROOT_DIR)/bin
ETC_DIR := $(ROOT_DIR)/etc
LIB_DIR := $(ROOT_DIR)/lib
USRSHARE_DIR := $(ROOT_DIR)/usr/share

ifeq ($(PLATFORM),entware)
	BIN_DIR := $(ROOT_DIR)/opt/bin
	ETC_DIR := $(ROOT_DIR)/opt/etc
	LIB_DIR := $(ROOT_DIR)/opt/lib
	USRSHARE_DIR := $(ROOT_DIR)/opt/usr/share

	ifeq ($(filter %_kn,$(TARGET)),$(TARGET))
		ENTWARE_KN := 1
	endif
endif

IPK_DIR := $(BUILD_DIR)/ipk
IPK_CONTROL_DIR := $(IPK_DIR)/control

# Empty CROSS_COMPILE and SYSROOT build host-native, which is right only when TARGET matches the host.
CROSS_COMPILE ?=
SYSROOT ?=

# Entware's cJSON package is named `cJSON`, not `libcjson`.
DEPS_IPK := libatomic, libyaml, libpcre2, libmnl, libcurl, ca-bundle

BACKEND_DEPENDENCIES :=
BACKEND_SOURCES := $(shell find ./src/backend-c/src ./src/backend-c/include ./src/tunvless/src ./src/tunvless/build -type f \( -name '*.c' -o -name '*.h' -o -name '*.sh' -o -name Makefile \) 2>/dev/null)
BACKEND_BUILD_PROPERTIES := PLATFORM=\"$(PLATFORM)\" TARGET=\"$(TARGET)\" PKG_VERSION=\"$(PKG_VERSION)\" CROSS_COMPILE=\"$(CROSS_COMPILE)\" SYSROOT=\"$(SYSROOT)\" ENTWARE_KN=\"$(ENTWARE_KN)\"

FRONTEND_DEPENDENCIES := ./src/frontend/package.json ./src/frontend/package-lock.json
FRONTEND_SOURCES := $(shell find ./src/frontend/src -type f 2>/dev/null)
FRONTEND_SOURCES += ./src/frontend/vite.config.ts ./src/frontend/tsconfig.json
FRONTEND_SOURCES += $(FRONTEND_DEPENDENCIES)
FRONTEND_BUILD_PROPERTIES := PKG_VERSION_DISPLAY=\"$(PKG_VERSION_DISPLAY)\" PKG_VERSION_PRERELEASE=\"$(PKG_VERSION_PRERELEASE)\"

.PHONY: _return_export_dynamic_env all clear clean download download_backend download_frontend redownload redownload_backend redownload_frontend build build_backend build_frontend rebuild rebuild_backend rebuild_frontend prepare_files package package_ipk FORCE

all: download build package

_return_export_dynamic_env:
	@bash -c 'printf "COMMIT=%q\n" "$(COMMIT)"'
	@bash -c 'printf "COMMITS_SINCE_TAG=%q\n" "$(COMMITS_SINCE_TAG)"'
	@bash -c 'printf "PKG_REVISION=%q\n" "$(PKG_REVISION)"'
	@bash -c 'printf "PKG_VERSION=%q\n" "$(PKG_VERSION)"'
	@bash -c 'printf "PKG_VERSION_DISPLAY=%q\n" "$(PKG_VERSION_DISPLAY)"'
	@bash -c 'printf "PKG_VERSION_PRERELEASE=%q\n" "$(PKG_VERSION_PRERELEASE)"'
	@bash -c 'printf "PRERELEASE_DATE=%q\n" "$(PRERELEASE_DATE)"'
	@bash -c 'printf "TAG=%q\n" "$(TAG)"'

clear:
	rm -rf ./src/frontend/dist
	rm -rf "$(BUILD_DIR)"

clean:
	rm -rf "$(BUILDS_DIR)"

redownload: redownload_backend redownload_frontend

download: download_backend download_frontend

rebuild: rebuild_backend rebuild_frontend

build: build_backend build_frontend

$(STAMPS_DIR)/download-backend: $(BACKEND_DEPENDENCIES)
	@mkdir -p $(STAMPS_DIR)
	@touch "$(STAMPS_DIR)/download-backend"

download_backend: $(STAMPS_DIR)/download-backend

redownload_backend:
	@rm -f "$(STAMPS_DIR)/download-backend"
	$(MAKE) download_backend

$(STAMPS_DIR)/build-properties-backend-$(UNIQUE_NAME): FORCE
	@mkdir -p $(STAMPS_DIR)
	@echo "$(BACKEND_BUILD_PROPERTIES)" | cmp -s - $@ || echo "$(BACKEND_BUILD_PROPERTIES)" > $@

# Makefile is a prerequisite: it decides which binaries reach prepare_files.
$(STAMPS_DIR)/build-backend-$(UNIQUE_NAME): $(STAMPS_DIR)/download-backend $(BACKEND_SOURCES) $(STAMPS_DIR)/build-properties-backend-$(UNIQUE_NAME) Makefile
	mkdir -p "$(COMPILE_DIR)"
	$(MAKE) -C ./src/backend-c BUILD="$(UNIQUE_NAME)" FIRC_VERSION="$(PKG_VERSION)" \
	    $(if $(PLATFORM),PLATFORM="$(PLATFORM)") \
	    $(if $(CROSS_COMPILE),CROSS_COMPILE="$(CROSS_COMPILE)") \
	    $(if $(SYSROOT),SYSROOT="$(SYSROOT)") \
	    $(if $(ENTWARE_KN),ENTWARE_KN=1)
	cp "./src/backend-c/build/$(UNIQUE_NAME)/fircd" "$(COMPILE_DIR)/fircd"
	$(MAKE) -C ./src/tunvless fetch
	$(MAKE) -C ./src/tunvless CC="$(CROSS_COMPILE)gcc" AR="$(CROSS_COMPILE)ar" \
		CFLAGS="$(if $(SYSROOT),--sysroot=$(SYSROOT) )-O2" LDFLAGS="$(if $(SYSROOT),--sysroot=$(SYSROOT))" \
		VERSION="$(PKG_VERSION)" O=$(abspath $(COMPILE_DIR))/tunvless
	cp "$(COMPILE_DIR)/tunvless/tunvless" "$(COMPILE_DIR)/tunvless-bin"

	@mkdir -p $(STAMPS_DIR)
	@touch "$(STAMPS_DIR)/build-backend-$(UNIQUE_NAME)"

build_backend: $(STAMPS_DIR)/build-backend-$(UNIQUE_NAME)

rebuild_backend:
	@rm -f "$(STAMPS_DIR)/build-backend"
	$(MAKE) build_backend

$(STAMPS_DIR)/download-frontend: $(FRONTEND_DEPENDENCIES)
	cd ./src/frontend && npm install

	@mkdir -p $(STAMPS_DIR)
	@touch "$(STAMPS_DIR)/download-frontend"

download_frontend: $(STAMPS_DIR)/download-frontend

redownload_frontend:
	@rm -f "$(STAMPS_DIR)/download-frontend"
	$(MAKE) download_frontend

$(STAMPS_DIR)/build-properties-frontend: FORCE
	@mkdir -p $(STAMPS_DIR)
	@echo "$(FRONTEND_BUILD_PROPERTIES)" | cmp -s - $@ || echo "$(FRONTEND_BUILD_PROPERTIES)" > $@

$(STAMPS_DIR)/build-frontend: $(STAMPS_DIR)/download-frontend $(FRONTEND_SOURCES) $(STAMPS_DIR)/build-properties-frontend
	cd ./src/frontend && VITE_PKG_VERSION="$(PKG_VERSION_DISPLAY)" VITE_PKG_VERSION_IS_DEV=$(if $(PKG_VERSION_PRERELEASE),true,false) npm run build

	@mkdir -p $(STAMPS_DIR)
	@touch "$(STAMPS_DIR)/build-frontend"

build_frontend: $(STAMPS_DIR)/build-frontend

rebuild_frontend:
	@rm -f "$(STAMPS_DIR)/build-frontend"
	$(MAKE) build_frontend

define _copy_files
	if [ -d $(1)/_ipk/control ]; then mkdir -p $(IPK_CONTROL_DIR); cp -r $(1)/_ipk/control/* $(IPK_CONTROL_DIR); fi
	if [ -d $(1)/bin ]; then mkdir -p $(BIN_DIR); cp -r $(1)/bin/* $(BIN_DIR); fi
	if [ -d $(1)/etc ]; then mkdir -p $(ETC_DIR); cp -r $(1)/etc/* $(ETC_DIR); fi
	if [ -d $(1)/lib ]; then mkdir -p $(LIB_DIR); cp -r $(1)/lib/* $(LIB_DIR); fi
	if [ -d $(1)/usr/share ]; then mkdir -p $(USRSHARE_DIR); cp -r $(1)/usr/share/* $(USRSHARE_DIR); fi
endef

prepare_files: build
	rm -rf "$(ROOT_DIR)"
	mkdir -p "$(BIN_DIR)"
	cp "$(COMPILE_DIR)/fircd" "$(BIN_DIR)/fircd"
	install -m 0755 "$(COMPILE_DIR)/tunvless-bin" "$(BIN_DIR)/tunvless"
	mkdir -p "$(USRSHARE_DIR)/firc/skins/default"
	cp -r ./src/frontend/dist/* "$(USRSHARE_DIR)/firc/skins/default"
	$(call _copy_files,./files/common)
	$(if $(filter entware,$(PLATFORM)), $(call _copy_files,./files/entware))
	$(if $(filter entware,$(PLATFORM)), $(if $(filter %_kn,$(TARGET)), $(call _copy_files,./files/entware_kn)))

package:
	$(MAKE) package_ipk

package_ipk: prepare_files
	mkdir -p "$(IPK_DIR)"
	echo '2.0' > $(IPK_DIR)/debian-binary

	mkdir -p $(IPK_CONTROL_DIR)
	echo 'Package: $(PKG_NAME)' > $(IPK_CONTROL_DIR)/control
	echo 'Version: $(PKG_VERSION)-$(PKG_REVISION)' >> $(IPK_CONTROL_DIR)/control
	echo 'Architecture: $(TARGET)' >> $(IPK_CONTROL_DIR)/control
	echo 'License: $(PKG_LICENSE)' >> $(IPK_CONTROL_DIR)/control
	echo 'URL: $(PKG_URL)' >> $(IPK_CONTROL_DIR)/control
	echo 'Maintainer: $(PKG_MAINTAINER)' >> $(IPK_CONTROL_DIR)/control
	echo 'Description: $(PKG_DESCRIPTION)' >> $(IPK_CONTROL_DIR)/control
	echo 'Section: net' >> $(IPK_CONTROL_DIR)/control
	echo 'Priority: optional' >> $(IPK_CONTROL_DIR)/control
	@DEPS="libc, iptables, $(DEPS_IPK), cJSON"; \
	if echo "$(TARGET)" | grep -q '_kn$$'; then \
		DEPS="$$DEPS, socat"; \
	fi; \
	echo "Depends: $$DEPS" >> $(IPK_CONTROL_DIR)/control
	echo 'Conflicts: tunvless' >> $(IPK_CONTROL_DIR)/control

	tar -C "$(IPK_CONTROL_DIR)" -czvf "$(IPK_DIR)/control.tar.gz" --owner=0 --group=0 .
	tar -C "$(ROOT_DIR)" -czvf "$(IPK_DIR)/data.tar.gz" --owner=0 --group=0 .
	tar -C "$(IPK_DIR)" -czvf "$(BUILDS_DIR)/$(PKG_NAME)_$(PKG_VERSION)-$(PKG_REVISION)_$(UNIQUE_NAME).ipk" --owner=0 --group=0 ./debian-binary ./control.tar.gz ./data.tar.gz

FORCE:
