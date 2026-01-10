TARGET := iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = lsd cfprefsd
FINALPACKAGE = 1
THEOS_PACKAGE_SCHEME = roothide
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = roothidehooks

roothidehooks_FILES = $(wildcard *.x) $(wildcard *.c) $(wildcard *.m)
roothidehooks_CFLAGS = -Werror -fobjc-arc -I../common
roothidehooks_LDFLAGS = -rpath @loader_path/.jbroot/Library/Frameworks -rpath @loader_path/fallback -L../common/lib -lcommon
roothidehooks_INSTALL_PATH = /basebin

lsd.x_CFLAGS = -fno-objc-arc #lsd using mrc

include $(THEOS_MAKE_PATH)/tweak.mk

after-all::
	install_name_tool -change @loader_path/.jbroot/usr/lib/libsubstrate.dylib @rpath/CydiaSubstrate.framework/CydiaSubstrate $(THEOS_OBJ_DIR)/roothidehooks.dylib
	ldid -S $(THEOS_OBJ_DIR)/roothidehooks.dylib

	mkdir -p ../.build/
	cp $(THEOS_OBJ_DIR)/roothidehooks.dylib ../.build/
