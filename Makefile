export THEOS=/var/theos
export ARCHS = armv6 armv7 arm64
export SDKVERSION = 8.1
export TARGET = iphone:clang:$(SDKVERSION):$(SDKVERSION)


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = DecryptMe
DecryptMe_FILES = Tweak.c

include $(THEOS_MAKE_PATH)/tweak.mk
