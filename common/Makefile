ARCHS = arm64 arm64e

TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME = roothide

# FINALPACKAGE ?= 1
# DEBUG ?= 0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = libcommon
libcommon_FILES = $(wildcard *.c *.m *.mm *.cpp)
libcommon_CFLAGS = -I. -DFISHHOOK_EXPORT -fobjc-arc -Wno-unused-variable -Wno-unused-but-set-variable
libcommon_LFGLAGS = -L.
libcommon_LINKAGE_TYPE = static
libcommon_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/library.mk

after-all::
	mkdir -p ./lib
	cp $(THEOS_OBJ_DIR)/libcommon.a ./lib/

clean::
	rm -rf ./packages/*
	