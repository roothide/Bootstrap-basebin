ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

TOOL_NAME = rebuildapp

rebuildapp_FILES = $(wildcard *.c *.m *.mm *.cpp)
rebuildapp_CFLAGS = -fobjc-arc -I./ $(shell pkg-config --cflags libcrypto) $(shell pkg-config --cflags libplist-2.0)  -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function -Wno-unneeded-internal-declaration
rebuildapp_CCFLAGS = -std=c++11
rebuildapp_LDFLAGS = -L./ -lchoma -lcrypto -lplist-2.0
rebuildapp_CODESIGN_FLAGS = -Sentitlements.plist
rebuildapp_INSTALL_PATH = /basebin/

include $(THEOS_MAKE_PATH)/tool.mk

clean::
	rm -rf ./packages/*
	
before-package::
	cp -a ../entitlements ./.theos/_/basebin/
	
# after-install::
# 	install.exec '$(THEOS_PACKAGE_INSTALL_PREFIX)/basebin/$(TOOL_NAME)' /Applications/MobileSafari.app
