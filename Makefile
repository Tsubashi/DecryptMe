ARCHS = armv7 arm64

include theos/makefiles/common.mk

TWEAK_NAME = DecryptMe
DecryptMe_FILES = Tweak.c

include $(THEOS_MAKE_PATH)/tweak.mk
