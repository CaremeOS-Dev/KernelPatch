ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

ifndef KP_DIR
    KP_DIR = ../..
endif

CC = $(TARGET_COMPILE)gcc

ifeq ($(TARGET_COMPILE),arm-linux-gnueabi-)
    # ---- XTC Z9 / MSM8937 AArch32 target -------------------------------
    include $(KP_DIR)/kpms/kpm-arm32.mk
    CFLAGS_LOCAL := $(KPM_ARM32_CFLAGS)
    INCLUDE_FLAGS := $(KPM_ARM32_INCLUDE_FLAGS)
else
    CFLAGS_LOCAL :=
    INCLUDE_FLAGS := $(foreach dir,. include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include,-I$(KP_DIR)/kernel/$(dir))
endif

objs := inlinehook.o

all: inlinehook.kpm

inlinehook.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(CFLAGS_LOCAL) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f