TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME = roothide

FINALPACKAGE ?= 1
DEBUG ?= 0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = launchdhook

launchdhook_FILES = $(wildcard *.c *.m *.mm *.cpp)
launchdhook_CFLAGS = -I../common -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function -Wno-unneeded-internal-declaration -Wno-incompatible-function-pointer-types -Wno-incompatible-pointer-types-discards-qualifiers
launchdhook_CCFLAGS = -std=c++11
launchdhook_LDFLAGS = -L../common/lib -lcommon -lbsm -ldobby
launchdhook_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/library.mk

after-package::
	find $(THEOS_LIBRARY_PATH) -name "$(LIBRARY_NAME).*" -delete

after-all::
	mkdir -p ../.build/
	cp $(THEOS_OBJ_DIR)/launchdhook.dylib ../.build/

clean::
	rm -rf ./packages/*
	
after-install::
	install.exec '/basebin/bsctl usreboot'
	