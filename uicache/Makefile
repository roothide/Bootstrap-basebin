ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = roothide
THEOS_DEVICE_IP = iphone13.local
include $(THEOS)/makefiles/common.mk

TOOL_NAME = uicache

uicache_FILES = main.m  ../bootstrapd/ipc.m ../bootstrapd/libbsd.m
uicache_CFLAGS = -fobjc-arc
uicache_LDFLAGS = -framework MobileCoreServices -framework Security -framework MobileContainerManager -framework CoreTelephony
uicache_CODESIGN_FLAGS = -Sentitlements.plist
uicache_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/tool.mk
