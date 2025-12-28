ARCHS = arm64
TARGET := iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

TOOL_NAME = TaskPortHaxx

TaskPortHaxx_FILES = \
	TaskPortHaxxApp/main.m \
	TaskPortHaxxApp/launch.m \
	TaskPortHaxxApp/unarchive.m \
	TaskPortHaxxApp/TaskPortHaxx.m \
	TaskPortHaxxApp/ProcessContext.m \
	TaskPortHaxxApp/fake_bootstrap_server.m \
	TaskPortHaxxApp/NSUserDefaults+Pref.m
TaskPortHaxx_FRAMEWORKS = UIKit CoreGraphics CoreServices IOKit
TaskPortHaxx_LIBRARIES = archive
TaskPortHaxx_CFLAGS = -fobjc-arc -I./TaskPortHaxxApp/ -I../common -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-local-typedef -Wno-unused-but-set-variable -Wno-\#warnings
TaskPortHaxx_LDFLAGS = -L../common/lib -lcommon
TaskPortHaxx_CODESIGN_FLAGS = -S./TaskPortHaxxApp/TaskPortHaxxApp.ent
TaskPortHaxx_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/tool.mk

LIBRARY_NAME = prepare
prepare_FILES = \
	TaskPortHaxxApp/launch.m \
	TaskPortHaxxApp/unarchive.m \
	TaskPortHaxxApp/TaskPortHaxx.m \
	TaskPortHaxxApp/ProcessContext.m \
	TaskPortHaxxApp/fake_bootstrap_server.m \
	TaskPortHaxxApp/NSUserDefaults+Pref.m
prepare_FRAMEWORKS = UIKit CoreGraphics CoreServices IOKit
prepare_CFLAGS = -fobjc-arc -I./TaskPortHaxxApp/ -I../common -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-local-typedef -Wno-unused-but-set-variable -Wno-\#warnings
prepare_LDFLAGS = -L../common/lib -lcommon
prepare_LINKAGE_TYPE = static
include $(THEOS_MAKE_PATH)/library.mk


# after-install::
# 	install.exec '/basebin/TaskPortHaxx'

after-all::
	ldid -M -S./roothide.entitlements $(THEOS_OBJ_DIR)/TaskPortHaxx
	ldid -M -S./launchd.entitlements $(THEOS_OBJ_DIR)/TaskPortHaxx

	mkdir -p ../.build/
	cp $(THEOS_OBJ_DIR)/TaskPortHaxx ../.build/
	cp $(THEOS_OBJ_DIR)/prepare.a ../common/lib/

clean::
	rm -rf ./packages/*


