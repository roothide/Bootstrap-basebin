ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

TOOL_NAME = appatch

appatch_FILES = $(wildcard *.c *.m *.mm *.cpp)
appatch_CFLAGS = -fobjc-arc -I../common $(shell pkg-config --cflags libcrypto) $(shell pkg-config --cflags libplist-2.0)  -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function -Wno-unneeded-internal-declaration
appatch_CCFLAGS = -std=c++11
appatch_LDFLAGS = -L../common/lib -lcommon -lchoma -lcrypto -lplist-2.0
appatch_CODESIGN_FLAGS = -Sentitlements.plist
appatch_INSTALL_PATH = /basebin/

include $(THEOS_MAKE_PATH)/tool.mk

after-all::
	mkdir -p ../.build/
	cp $(THEOS_OBJ_DIR)/appatch ../.build/

clean::
	rm -rf ./packages/*
	
before-package::
	cp -a ../entitlements $(THEOS_STAGING_DIR)/basebin/appatch.entitlements
# 	cp -a ../rebuildApps.sh $(THEOS_STAGING_DIR)/DEBIAN/postinst
	
after-install::
	install.exec "rm -rf /basebin/entitlements; mv /basebin/appatch.entitlements /basebin/entitlements"
