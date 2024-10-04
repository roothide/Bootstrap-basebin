TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME = roothide

FINALPACKAGE ?= 1
DEBUG ?= 0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = bootstrap

bootstrap_FILES = $(wildcard *.c *.m *.S) ../bootstrapd/ipc.m ../bootstrapd/libbsd.m
bootstrap_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-value
bootstrap_LDFLAGS = -L./ -ldobby -lc++
bootstrap_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/library.mk

clean::
	rm -rf ./packages/*
	
ifneq ($(DEBUG), 1)
before-package::
	strip -N ./.theos/_/basebin/bootstrap.dylib
	ldid -S ./.theos/_/basebin/bootstrap.dylib
endif
