ARCHS = arm64 arm64e

TARGET := iphone:clang:latest:7.0

THEOS_PACKAGE_SCHEME = roothide

THEOS_DEVICE_IP = iphone13.local

include $(THEOS)/makefiles/common.mk

TOOL_NAME = preload

preload_FILES = preload.m ../bootstrapd/ipc.m ../bootstrapd/libbsd.m
preload_CFLAGS = -fobjc-arc
preload_CODESIGN_FLAGS = -Sentitlements.plist
preload_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/tool.mk

LIBRARY_NAME = prelib
prelib_FILES = prelib.m
prelib_CFLAGS = -fobjc-arc -Wno-unused-variable -Wno-unused-but-set-variable
prelib_LFGLAGS = 
prelib_CODESIGN_FLAGS =
prelib_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/library.mk

before-package::
	mv ./.theos/_/basebin/prelib.dylib ./.theos/_/basebin/preload.dylib 