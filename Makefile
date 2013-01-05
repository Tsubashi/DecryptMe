include theos/makefiles/common.mk

TWEAK_NAME = UnsandboxMe
UnsandboxMe_FILES = Tweak.x
UnsandboxMe_FRAMEWORKS = MobileCoreServices

include $(THEOS_MAKE_PATH)/tweak.mk
