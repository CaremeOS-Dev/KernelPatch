# kpms/kpm-arm32.mk -- AArch32 (ARMv7-A) KPM build settings.
#
# Include this from a KPM Makefile to target the XTC Z9 / MSM8937 port:
#
#     TARGET_COMPILE = arm-linux-gnueabi-
#     include ../../kpm-arm32.mk
#
# Why every flag here exists
# --------------------------
# -marm -march=armv7-a
#     The device kernel is ARMv7-A in ARM (A32) state; Thumb-2 would need the
#     R_ARM_THM_* relocation family, which the loader does not implement.
#
# -mno-unaligned-access
#     Matches the kernel build.  Keeps the loader's explicit 32-bit
#     loads/stores in relo.c correct on strict-alignment paths.
#
# -fno-pic / -fno-stack-protector
#     No GOT/.plt in a module that is relocated by hand, and no stack canary
#     (the KPM is loaded into kernel context, not a userspace process).
#
# -mlong-calls   *** REQUIRED ***
#     Without it the compiler emits `bl <kernel_symbol>` (R_ARM_CALL), whose
#     signed 24-bit word offset only reaches +/-32 MB.  KPM code is allocated in
#     the KP exec pool (~0xffffffffd6751000 on this device) while the kernel it
#     calls lives at ~0xffffffffc0xxxxxx -- about 376 MB away, so the `bl`
#     literally cannot be encoded.  -mlong-calls makes GCC materialise the
#     callee into a register with movw/movt and branch with `blx rX`, which is a
#     full 32-bit address and needs only R_ARM_MOVW_ABS_NC / R_ARM_MOVT_ABS.
#     The loader rejects R_ARM_CALL with a message that says exactly this.
#
# -DCONFIG_ARM
#     Selects the Elf32_* width and the ARM relocation path in the kernel
#     headers the KPM includes.
#
# The resulting KPM is ELF32, ET_REL, SHT_REL -- which is what
# patch/module/relo.c's apply_relocate() now expects.

KPM_ARM32_CFLAGS := -std=gnu11 -ffreestanding \
                    -marm -march=armv7-a -mno-unaligned-access \
                    -fno-stack-protector -fno-pic -fno-builtin \
                    -mlong-calls -O2 -DCONFIG_ARM

# Include order matters: arch/arm must win over any arm64 header path.
KPM_ARM32_INCLUDE_DIRS := . include patch/include \
                          linux/include linux/arch/arm/include \
                          linux/include/uapi/linux linux/include/uapi/asm-generic

KPM_ARM32_INCLUDE_FLAGS := $(foreach dir,$(KPM_ARM32_INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))