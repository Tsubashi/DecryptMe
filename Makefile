include theos/makefiles/common.mk

TWEAK_NAME = UnsandboxMe
UnsandboxMe_FILES = sha1.c Tweak.x
UnsandboxMe_FRAMEWORKS = MobileCoreServices

include $(THEOS_MAKE_PATH)/tweak.mk
