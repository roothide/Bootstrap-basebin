TARGET := iphone:clang:latest:15.0

THEOS_PACKAGE_SCHEME = roothide

FINALPACKAGE ?= 1
DEBUG ?= 0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = bootstrap

bootstrap_FILES = $(wildcard *.c *.x *.m *.S)
bootstrap_CFLAGS = -I../common -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-unused-value -Wno-format-invalid-specifier
bootstrap_LDFLAGS = -L../common/lib -lcommon -ldobby -lc++ -lbsm
bootstrap_INSTALL_PATH = /basebin

include $(THEOS_MAKE_PATH)/library.mk

after-package::
	find $(THEOS_LIBRARY_PATH) -name "$(LIBRARY_NAME).*" -delete

after-all::
ifneq ($(DEBUG), 1)
	strip -N $(THEOS_OBJ_DIR)/bootstrap.dylib
	ldid -S $(THEOS_OBJ_DIR)/bootstrap.dylib
endif
	mkdir -p ../.build/
	cp $(THEOS_OBJ_DIR)/bootstrap.dylib ../.build/

clean::
	rm -rf ./packages/*

