TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME = roothide

FINALPACKAGE ?= 1
DEBUG ?= 0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = bootstrapd

#-fvisibility=hidden 

bootstrapd_FILES = $(wildcard *.c *.m *.mm *.cpp)
bootstrapd_CFLAGS = -I../common -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function -Wno-unneeded-internal-declaration
bootstrapd_LDFLAGS = -L../common/lib -lcommon -lbsm
bootstrapd_CODESIGN_FLAGS = -Sentitlements.plist
bootstrapd_INSTALL_PATH = /basebin/

include $(THEOS_MAKE_PATH)/tool.mk

after-all::
	mkdir -p ../.build/
	cp $(THEOS_OBJ_DIR)/bootstrapd ../.build/
	cp -a ./layout/basebin/LaunchDaemons ../.build/

after-install::
	install.exec '$(THEOS_PACKAGE_INSTALL_PREFIX)/basebin/$(TOOL_NAME)' server -f

clean::
	rm -rf ./packages/*
	