TARGET := iphone:clang:latest:7.0

include $(THEOS)/makefiles/common.mk

TOOL_NAME = devtest

devtest_FILES = main.m
devtest_CFLAGS = -fobjc-arc
devtest_CODESIGN_FLAGS = -Sentitlements.plist
devtest_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/tool.mk

clean::
	rm -rf ./packages/*
	