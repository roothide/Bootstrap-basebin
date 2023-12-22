TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME = roothide

THEOS_DEVICE_IP = iphone.local

include $(THEOS)/makefiles/common.mk

TOOL_NAME = bootstrapd

#-fvisibility=hidden 

bootstrapd_FILES = $(wildcard *.c *.m *.cpp)
bootstrapd_CFLAGS = -DBOOTSTRAPD -fobjc-arc -Wno-unused-variable -Wno-unused-function -Wno-unneeded-internal-declaration -I./ $(shell pkg-config --cflags libcrypto) $(shell pkg-config --cflags libplist-2.0)
bootstrapd_CCFLAGS = -std=c++11
bootstrapd_LDFLAGS = -lbsm -L./ -lchoma -lcrypto -lplist-2.0
bootstrapd_CODESIGN_FLAGS = -Sentitlements.plist
bootstrapd_INSTALL_PATH = /basebin/

include $(THEOS_MAKE_PATH)/tool.mk

after-install::
	install.exec '$(THEOS_PACKAGE_INSTALL_PREFIX)/basebin/$(TOOL_NAME)' server -f
