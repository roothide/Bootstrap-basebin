TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME = roothide

FINALPACKAGE ?= 1
DEBUG ?= 0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = bsctl

bsctl_FILES = $(wildcard *.c *.m *.mm *.cpp)
bsctl_CFLAGS = -I../common -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function -Wno-unneeded-internal-declaration
bsctl_LDFLAGS = -L../common/lib -lcommon -lbsm
bsctl_CODESIGN_FLAGS = -Sentitlements.plist
bsctl_INSTALL_PATH = /basebin/

include $(THEOS_MAKE_PATH)/tool.mk

after-all::
	mkdir -p ../.build/
	cp $(THEOS_OBJ_DIR)/bsctl ../.build/
	cp -a ./layout/basebin/LaunchDaemons ../.build/

clean::
	rm -rf ./packages/*
