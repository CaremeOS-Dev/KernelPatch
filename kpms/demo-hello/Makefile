ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

ifndef KP_DIR
    KP_DIR = ../..
endif

CC = $(TARGET_COMPILE)gcc

ifeq ($(TARGET_COMPILE),arm-linux-gnueabi-)
    # ---- XTC Z9 / MSM8937 AArch32 target -------------------------------
    # See kpms/kpm-arm32.mk for why -mlong-calls is mandatory here.
    include $(KP_DIR)/kpms/kpm-arm32.mk
    CFLAGS_LOCAL := $(KPM_ARM32_CFLAGS)
    INCLUDE_FLAGS := $(KPM_ARM32_INCLUDE_FLAGS)
    # The listed empty .plt sections make no sense for ARM and would trip
    # nothing, so the plain ARM linker script is used instead.
    LDSCRIPT :=
else
    # ---- upstream AArch64 target ---------------------------------------
    CFLAGS_LOCAL :=
    INCLUDE_FLAGS := $(foreach dir,. include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include,-I$(KP_DIR)/kernel/$(dir))
    LDSCRIPT := -Thello.lds
endif

objs := hello.o

all: hello.kpm

hello.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(CFLAGS_LOCAL) $(INCLUDE_FLAGS) $(LDSCRIPT) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f