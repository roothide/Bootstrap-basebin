TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME = roothide

THEOS_DEVICE_IP = iphone13.local

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = bootstrap

bootstrap_FILES = $(wildcard *.c *.m) ../bootstrapd/ipc.m ../bootstrapd/libbsd.m
bootstrap_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable
bootstrap_LDFLAGS = -L./ -ldobby -framework MobileCoreServices -lbsm
bootstrap_INSTALL_PATH = /basebin/

include $(THEOS_MAKE_PATH)/library.mk
