
LOCAL_PATH := $(call my-dir)

TARGET_ARCH_ABI_MACRO :=$(shell echo ${TARGET_ARCH_ABI} | tr \- _ | tr [:lower:] [:upper:])

APK_FILE_PATH = ../bins/com.ketchapp.knifehit/

include $(CLEAR_VARS)
LOCAL_MODULE:= MyGame
LOCAL_SRC_FILES := ${APK_FILE_PATH}/lib/$(TARGET_ARCH_ABI)/libMyGame.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE:= fridafuns
LOCAL_SRC_FILES := frida_funs.c
LOCAL_C_INCLUDES := 
LOCAL_LDLIBS :=  
LOCAL_CXXFLAGS= 
LOCAL_SHARED_LIBRARIES =  
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE:= patch
LOCAL_SRC_FILES := main.cpp utils.cpp  

LOCAL_C_INCLUDES := 
LOCAL_LDLIBS :=  -lGLESv2  -landroid
LOCAL_CXXFLAGS= -fno-rtti                                           \
                -fno-exceptions                                     \
                -fno-stack-protector                                \
                -z execstack                                        \
                -DLOG_OUTPUT=2                                      \
                -DIMGUI_IMPL_OPENGL_ES2                             \
                -DTARGET_ARCH_ABI="${TARGET_ARCH_ABI}"              \
                -D${TARGET_ARCH_ABI_MACRO}                          \
                -DANDROID_CPP_DISABLE_FEATURES="rtti exceptions"    \
                -I imgui                                            \
                -std=c++14

LOCAL_SHARED_LIBRARIES = MyGame fridafuns
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE:= shadowhook
ifeq ("${TARGET_ARCH_ABI_MACRO}","ARM64_V8A")
    LOCAL_SRC_FILES := shadowhook/src/main/cpp/arch/arm64/sh_a64.c  \
                       shadowhook/src/main/cpp/arch/arm64/sh_inst.c 
else ifeq ("${TARGET_ARCH_ABI_MACRO}","ARMEABI_V7A")
    LOCAL_SRC_FILES := shadowhook/src/main/cpp/arch/arm/sh_t32.c \
                       shadowhook/src/main/cpp/common/sh_util.c  \
                       shadowhook/src/main/cpp/arch/arm/sh_t16.c \
                       shadowhook/src/main/cpp/arch/arm/sh_txx.c \
                       shadowhook/src/main/cpp/arch/arm/sh_inst.c \
                       shadowhook/src/main/cpp/arch/arm/sh_a32.c
else
    $(error please chck architecture ${TARGET_ARCH_ABI_MACRO})
endif




LOCAL_C_INCLUDES :=     shadowhook/src/main/cpp/common              \
                        shadowhook/src/main/cpp/third_party/xdl     \
                        shadowhook/src/main/cpp/arch/arm64          \
                        shadowhook/src/main/cpp/                    \
                        shadowhook/src/main/cpp/include  

LOCAL_LDLIBS    :=  
LOCAL_CXXFLAGS  :=
LOCAL_CFLAGS    :=   -std=c11                                       \
                     -fno-rtti                                      \
                     -fno-exceptions                                \
                     -DLOG_OUTPUT=2                                 \
                     -fno-stack-protector                           

LOCAL_SHARED_LIBRARIES =  fridafuns
include $(BUILD_SHARED_LIBRARY)


