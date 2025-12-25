GO_EASY_ON_ME = 1

TARGET := iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = TaskPortHaxxApp
ARCHS = arm64
PACKAGE_FORMAT = ipa

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = TaskPortHaxxApp

TaskPortHaxxApp_FILES = \
	TaskPortHaxxApp/AppDelegate.m \
	TaskPortHaxxApp/SceneDelegate.m \
	TaskPortHaxxApp/ViewController.m \
	TaskPortHaxxApp/ProcessContext.m \
	TaskPortHaxxApp/main.m \
	TaskPortHaxxApp/fake_bootstrap_server.m \
	TaskPortHaxxApp/launch.m \
	TaskPortHaxxApp/troller.m \
	TaskPortHaxxApp/unarchive.m \
	TaskPortHaxxApp/NSUserDefaults+Pref.m
TaskPortHaxxApp_FRAMEWORKS = UIKit CoreGraphics CoreServices IOKit
TaskPortHaxxApp_LIBRARIES = archive
TaskPortHaxxApp_CFLAGS = -fobjc-arc
TaskPortHaxxApp_CODESIGN_FLAGS = -S./TaskPortHaxxApp/TaskPortHaxxApp.ent

include $(THEOS_MAKE_PATH)/application.mk

#SUBPROJECTS += opainject
#include $(THEOS_MAKE_PATH)/aggregate.mk
