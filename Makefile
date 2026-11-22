# Theos project - NON-jailbreak (inject the built .dylib into the IPA)
TARGET := iphone:clang:latest:15.0
ARCHS = arm64
THEOS_PACKAGE_SCHEME =

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HuskJITKick
HuskJITKick_FILES = Tweak.m
HuskJITKick_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
HuskJITKick_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
