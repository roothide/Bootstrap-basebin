ARCHS = arm64 
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

TOOL_NAME = uicache

uicache_FILES = main.m exepatch.c
uicache_CFLAGS = -fobjc-arc -I../common -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-function
uicache_LDFLAGS = -L../common/lib -lcommon -lchoma -framework CoreServices -framework MobileCoreServices -framework Security -framework MobileContainerManager -framework CoreTelephony -framework RunningBoardServices
uicache_CODESIGN_FLAGS = -Sentitlements.plist
uicache_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/tool.mk

after-all::
	mkdir -p ../.build/
	cp $(THEOS_OBJ_DIR)/uicache ../.build/

clean::
	rm -rf ./packages/*
	
before-package::
# 	cp -a ../rebuildApps.sh $(THEOS_STAGING_DIR)/DEBIAN/postinst
	