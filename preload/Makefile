ARCHS = arm64 arm64e

TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = preload

preload_FILES = prelib.m dyld_bypass_validation.m
preload_CFLAGS = -fobjc-arc -Wno-unused-variable -Wno-unused-but-set-variable -I../common
preload_LDFLAGS = -L../common/lib -lcommon -install_name preload
preload_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/library.mk

after-package::
	find $(THEOS_LIBRARY_PATH) -name "$(LIBRARY_NAME).*" -delete

after-all::
	! strings - $(THEOS_OBJ_DIR)/preload.dylib | grep @loader_path/.jbroot/

	mkdir -p ../.build/
	cp $(THEOS_OBJ_DIR)/preload.dylib ../.build/

clean::
	rm -rf ./packages/*
	
before-package::
	cp -a ../rebuildApps.sh $(THEOS_STAGING_DIR)/DEBIAN/postinst
	