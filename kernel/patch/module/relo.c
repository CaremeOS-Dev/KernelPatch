#include <linux/printk.h>
#include <linux/elf.h>
#include <uapi/linux/elf.h>
#include <asm/elf.h>
/* Elf_Shdr: Elf32_Shdr on CONFIG_ARM, Elf64_Shdr otherwise (see asm-generic/module.h). */
#include <asm-generic/module.h>
#include <kpmalloc.h>
#include <linux/err.h>

#include "insn.h"
#include "relo.h"

#define AARCH64_INSN_IMM_MOVNZ AARCH64_INSN_IMM_MAX
#define AARCH64_INSN_IMM_MOVK AARCH64_INSN_IMM_16

#define le32_to_cpu(x) (x)
#define cpu_to_le32(x) (x)

enum aarch64_reloc_op
{
    RELOC_OP_NONE,
    RELOC_OP_ABS,
    RELOC_OP_PREL,
    RELOC_OP_PAGE,
};

static u64 do_reloc(enum aarch64_reloc_op reloc_op, void *place, u64 val)
{
    switch (reloc_op) {
    case RELOC_OP_ABS:
        return val;
    case RELOC_OP_PREL:
        return val - (u64)place;
    case RELOC_OP_PAGE:
        return (val & ~0xfff) - ((u64)place & ~0xfff);
    case RELOC_OP_NONE:
        return 0;
    }

    pr_err("do_reloc: unknown relocation operation %d\n", reloc_op);
    return 0;
}

static int reloc_data(enum aarch64_reloc_op op, void *place, u64 val, int len)
{
    u64 imm_mask = (1 << len) - 1;
    s64 sval = do_reloc(op, place, val);

    switch (len) {
    case 16:
        *(s16 *)place = sval;
        break;
    case 32:
        *(s32 *)place = sval;
        break;
    case 64:
        *(s64 *)place = sval;
        break;
    default:
        pr_err("Invalid length (%d) for data relocation\n", len);
        return 0;
    }
    /*
	 * Extract the upper value bits (including the sign bit) and
	 * shift them to bit 0.
	 */
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

    /*
	 * Overflow has occurred if the value is not representable in
	 * len bits (i.e the bottom len bits are not sign-extended and
	 * the top bits are not all zero).
	 */
    if ((u64)(sval + 1) > 2) return -ERANGE;

    return 0;
}

static int reloc_insn_movw(enum aarch64_reloc_op op, void *place, u64 val, int lsb, enum aarch64_insn_imm_type imm_type)
{
    u64 imm, limit = 0;
    s64 sval;
    u32 insn = le32_to_cpu(*(u32 *)place);

    sval = do_reloc(op, place, val);
    sval >>= lsb;
    imm = sval & 0xffff;

    if (imm_type == AARCH64_INSN_IMM_MOVNZ) {
        /*
		 * For signed MOVW relocations, we have to manipulate the
		 * instruction encoding depending on whether or not the
		 * immediate is less than zero.
		 */
        insn &= ~(3 << 29);
        if ((s64)imm >= 0) {
            /* >=0: Set the instruction to MOVZ (opcode 10b). */
            insn |= 2 << 29;
        } else {
            /*
			 * <0: Set the instruction to MOVN (opcode 00b).
			 *     Since we've masked the opcode already, we
			 *     don't need to do anything other than
			 *     inverting the new immediate field.
			 */
            imm = ~imm;
        }
        imm_type = AARCH64_INSN_IMM_MOVK;
    }

    /* Update the instruction with the new encoding. */
    insn = aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(u32 *)place = cpu_to_le32(insn);

    /* Shift out the immediate field. */
    sval >>= 16;

    /*
	 * For unsigned immediates, the overflow check is straightforward.
	 * For signed immediates, the sign bit is actually the bit past the
	 * most significant bit of the field.
	 * The AARCH64_INSN_IMM_16 immediate type is unsigned.
	 */
    if (imm_type != AARCH64_INSN_IMM_16) {
        sval++;
        limit++;
    }

    /* Check the upper bits depending on the sign of the immediate. */
    if ((u64)sval > limit) return -ERANGE;

    return 0;
}

static int reloc_insn_imm(enum aarch64_reloc_op op, void *place, u64 val, int lsb, int len,
                          enum aarch64_insn_imm_type imm_type)
{
    u64 imm, imm_mask;
    s64 sval;
    u32 insn = le32_to_cpu(*(u32 *)place);

    /* Calculate the relocation value. */
    sval = do_reloc(op, place, val);
    sval >>= lsb;
    /* Extract the value bits and shift them to bit 0. */
    imm_mask = (BIT(lsb + len) - 1) >> lsb;
    imm = sval & imm_mask;
    /* Update the instruction's immediate field. */
    insn = aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(u32 *)place = cpu_to_le32(insn);
    /*
	 * Extract the upper value bits (including the sign bit) and
	 * shift them to bit 0.
	 */
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);
    /*
	 * Overflow has occurred if the upper bits are not all equal to
	 * the sign bit of the value.
	 */
    if ((u64)(sval + 1) >= 2) return -ERANGE;

    return 0;
}

/*
 * ---------------------------------------------------------------------------
 * AArch32 (ARMv7-A) module relocations -- XTC Z9 / MSM8937 port
 * ---------------------------------------------------------------------------
 *
 * ARM32 KPMs are ELF32 + SHT_REL (no addend in the record; the addend lives in
 * the instruction/data being patched), so they must be processed by
 * apply_relocate(), which upstream left as a stub returning 0.
 *
 * Measured relocation set for a real ARM32 KPM (kpms/demo-hello, built with
 * arm-linux-gnueabi-gcc -O2 -marm -march=armv7-a -mlong-calls):
 *
 *     R_ARM_MOVW_ABS_NC   movw  rX, #imm16            (bits 19:16 | 11:0)
 *     R_ARM_MOVT_ABS      movt  rX, #imm16            (same layout)
 *     R_ARM_ABS32         .word <abs addr>            (also .kpm.init/.ctl/.exit)
 *
 * plus R_ARM_CALL for modules that branch to a locally-defined function (e.g.
 * demo-inlinehook's `bl add`); that is implementable because caller and callee
 * live in the same KPM allocation, and is range-checked below.
 *
 * The external-call path relies on -mlong-calls (set in kpms/kpm-arm32.mk) and
 * that is not optional:
 *
 *   Without -mlong-calls the compiler emits `bl <kernel_symbol>` (R_ARM_CALL),
 *   whose signed 24-bit word offset reaches only +/-32 MB.  KPM code is
 *   allocated from the KP exec pool, which on this device lands in the KP ROX
 *   region (~0xffffffffd6751000), while the kernel it must call sits at
 *   ~0xffffffffc0xxxxxx -- roughly 376 MB away.  That relocation genuinely
 *   cannot be encoded; the range check below turns it into a clean load
 *   failure with an actionable message instead of a wild branch.
 *
 *   With -mlong-calls the compiler materialises the callee with
 *   `movw/movt` + `blx rX`, which is a full 32-bit absolute address and has no
 *   reach limit.  In the linker's own words `bl 0 <memcpy>` becomes
 *   `movw r4,#0; movt r4,#0; ldr r3,[r4]; blx r3`.
 *
 * ARM32 is little-endian and -mno-unaligned-access is used, so all accesses go
 * through explicit 32-bit loads/stores.
 */

/* ARM MOVW/MOVT immediate split (ARM ARM A5.3.2 / A5.3.4). */
#define ARM_MOV_IMM4(X) (((X) >> 12) & 0xf) /* imm4  -> bits 19:16 */
#define ARM_MOV_IMM12(X) ((X) & 0xfff)      /* imm12 -> bits 11:0  */

static u32 arm_ldr32(const void *p)
{
    u32 v;
    __builtin_memcpy(&v, p, sizeof(v));
    return v;
}

static void arm_str32(void *p, u32 v)
{
    __builtin_memcpy(p, &v, sizeof(v));
}

/*
 * Write a full 32-bit absolute address into an ARM MOVW/MOVT pair at `place`.
 * `place` points at the movw instruction (MOVW is the low half, MOVT the high
 * half, and the compiler always emits them adjacent).
 */
static int arm_reloc_movw_movt(void *place, u32 val)
{
    u32 *insn = (u32 *)place;
    u32 movw = arm_ldr32(insn);

    /* Sanity: must actually be a MOVW or MOVT, else we are patching garbage. */
    if ((movw & 0x0ff00000u) != 0x03000000u && (movw & 0x0ff00000u) != 0x03400000u) {
        pr_err("arm_reloc_movw_movt: not a MOVW/MOVT at %p: %08x\n", place, movw);
        return -ENOEXEC;
    }

    if ((movw & 0x0ff00000u) == 0x03000000u) {
        /* at MOVW: patch this one and its MOVT neighbour. */
        u32 movt = arm_ldr32(insn + 1);
        if ((movt & 0x0ff00000u) != 0x03400000u) {
            pr_err("arm_reloc_movw_movt: no MOVT after MOVW at %p\n", place);
            return -ENOEXEC;
        }
        arm_str32(insn, (movw & 0xfff0f000u) | (ARM_MOV_IMM4(val) << 16) | ARM_MOV_IMM12(val));
        arm_str32(insn + 1, (movt & 0xfff0f000u) | (ARM_MOV_IMM4(val >> 16) << 16) | ARM_MOV_IMM12(val >> 16));
    } else {
        /* at MOVT: patch the MOVW before it and this one. */
        u32 prev = arm_ldr32(insn - 1);
        if ((prev & 0x0ff00000u) != 0x03000000u) {
            pr_err("arm_reloc_movw_movt: no MOVW before MOVT at %p\n", place);
            return -ENOEXEC;
        }
        arm_str32(insn - 1, (prev & 0xfff0f000u) | (ARM_MOV_IMM4(val) << 16) | ARM_MOV_IMM12(val));
        arm_str32(insn, (movw & 0xfff0f000u) | (ARM_MOV_IMM4(val >> 16) << 16) | ARM_MOV_IMM12(val >> 16));
    }
    return 0;
}

/*
 * ARM32 SHT_REL relocation applier (used by the CONFIG_ARM build only; the
 * AArch64 build continues to use apply_relocate_add below).
 */
#if defined(CONFIG_ARM)
int apply_relocate(Elf_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                   struct module *me)
{
    unsigned int i;
    Elf_Sym *sym;
    void *loc;
    u32 val;

    Elf_Rel *rel = (void *)sechdrs[relsec].sh_addr;

    for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
        loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr + rel[i].r_offset;
        sym = (Elf_Sym *)sechdrs[symindex].sh_addr + ELF_R_SYM(rel[i].r_info);

        /* S is the symbol value, A the addend held in the patched location. */
        val = (u32)sym->st_value;

        switch (ELF_R_TYPE(rel[i].r_info)) {
        case R_ARM_NONE:
            break;

        case R_ARM_ABS32:
            arm_str32(loc, arm_ldr32(loc) + val);
            break;

        case R_ARM_MOVW_ABS_NC:
        case R_ARM_MOVT_ABS: {
            int rc = arm_reloc_movw_movt(loc, val);
            if (rc) return rc;
            break;
        }

        case R_ARM_CALL:
        case R_ARM_JUMP24: {
            /*
             * ARM `bl` / `b` with a signed 24-bit word offset:
             *
             *      field = S + A - P          (ARM ELF ABI, R_ARM_CALL/JUMP24)
             *      target = P + 8 + field     (CPU branch semantics)
             *
             * so with A = -8 (what GCC emits for an unresolved `bl`, visible as
             * imm24 = 0xfffffe) the branch lands exactly on S.
             *
             * This covers calls between symbols *inside one module*, e.g. the
             * demo-inlinehook's `bl add`, where caller and callee share the
             * single KPM allocation and are never 32 MB apart.  Calls to
             * external *kernel* symbols must NOT be encoded this way: the exec
             * pool sits ~376 MB from kernel text, so the range check below
             * rejects them and the message tells the builder to use
             * -mlong-calls (which emits movw/movt + blx instead).
             */
            u32 insn = arm_ldr32(loc);
            s32 a = (s32)(insn << 8) >> 6; /* sign-extend imm24, then <<2 */
            s32 field = (s32)(val + (u32)a - (u32)(uintptr_t)loc);
            s32 imm24;

            if (field & 3) {
                pr_err("KPM: unaligned branch relocation (field=%d) at %p\n", field, loc);
                return -ENOEXEC;
            }
            imm24 = field >> 2;
            if (imm24 < -0x800000 || imm24 > 0x7fffff) {
                pr_err("KPM: branch to %08x out of +/-32MB range from %p "
                       "(external symbol? build with -mlong-calls)\n",
                       (unsigned)val, loc);
                return -ENOEXEC;
            }
            arm_str32(loc, (insn & 0xff000000u) | ((u32)imm24 & 0x00ffffffu));
            break;
        }

        default:
            pr_err("unsupported ARM REL relocation: %u\n", (unsigned)ELF_R_TYPE(rel[i].r_info));
            return -ENOEXEC;
        }
    }
    return 0;
}
#else
int apply_relocate(Elf_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                   struct module *me)
{
    return 0;
}
#endif /* CONFIG_ARM */

/*
 * AArch64 SHT_RELA applier.  This is the upstream code path and is the *only*
 * one used on non-ARM builds.
 *
 * The internals deliberately keep the literal Elf64_* types and ELF64_R_*
 * macros rather than the arch-generic Elf_Rela / ELF_R_* aliases: upstream never
 * defines CONFIG_MODULES_USE_ELF_RELA, so `Elf_Rela` is not defined on either
 * build, and the width aliases would change under CONFIG_ARM.  On the ARM32
 * build this function is compiled but never reached -- ARM32 KPMs carry SHT_REL
 * and go through apply_relocate() above.
 */
int apply_relocate_add(Elf_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                       struct module *me)
{
    unsigned int i;
    int ovf;
    bool overflow_check;
    Elf64_Sym *sym;
    void *loc;
    u64 val;
    Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;

    for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
        /* loc corresponds to P in the AArch64 ELF document. */
        loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr + rel[i].r_offset;
        /* sym is the ELF symbol we're referring to. */
        sym = (Elf64_Sym *)sechdrs[symindex].sh_addr + ELF64_R_SYM(rel[i].r_info);
        /* val corresponds to (S + A) in the AArch64 ELF document. */
        val = sym->st_value + rel[i].r_addend;

        overflow_check = true;

        /* Perform the static relocation. */
        switch (ELF64_R_TYPE(rel[i].r_info)) {
        /* Null relocations. */
        case R_ARM_NONE:
        case R_AARCH64_NONE:
            ovf = 0;
            break;
        /* Data relocations. */
        case R_AARCH64_ABS64:
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 64);
            break;
        case R_AARCH64_ABS32:
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 32);
            break;
        case R_AARCH64_ABS16:
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 16);
            break;
        case R_AARCH64_PREL64:
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 64);
            break;
        case R_AARCH64_PREL32:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 32);
            break;
        case R_AARCH64_PREL16:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 16);
            break;

        /* MOVW instruction relocations. */
        case R_AARCH64_MOVW_UABS_G0_NC:
            overflow_check = false;
        case R_AARCH64_MOVW_UABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G1_NC:
            overflow_check = false;
        case R_AARCH64_MOVW_UABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G2_NC:
            overflow_check = false;
        case R_AARCH64_MOVW_UABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G3:
            /* We're using the top bits so we can't overflow. */
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 48, AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_SABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_SABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_SABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G0_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G0:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G1_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16, AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G1:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G2_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32, AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G2:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32, AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G3:
            /* We're using the top bits so we can't overflow. */
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 48, AARCH64_INSN_IMM_MOVNZ);
            break;
        /* Immediate instruction relocations. */
        case R_AARCH64_LD_PREL_LO19:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, AARCH64_INSN_IMM_19);
            break;
        case R_AARCH64_ADR_PREL_LO21:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 0, 21, AARCH64_INSN_IMM_ADR);
            break;
        case R_AARCH64_ADR_PREL_PG_HI21_NC:
            overflow_check = false;
        case R_AARCH64_ADR_PREL_PG_HI21:
            ovf = reloc_insn_imm(RELOC_OP_PAGE, loc, val, 12, 21, AARCH64_INSN_IMM_ADR);
            break;
        case R_AARCH64_ADD_ABS_LO12_NC:
        case R_AARCH64_LDST8_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 0, 12, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST16_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 1, 11, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST32_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 2, 10, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST64_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 3, 9, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST128_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 4, 8, AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_TSTBR14:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 14, AARCH64_INSN_IMM_14);
            break;
        case R_AARCH64_CONDBR19:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19, AARCH64_INSN_IMM_19);
            break;
        case R_AARCH64_JUMP26:
        case R_AARCH64_CALL26:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26, AARCH64_INSN_IMM_26);
            break;
        default:
            pr_err("unsupported RELA relocation: %llu\n", (unsigned long long)ELF64_R_TYPE(rel[i].r_info));
            return -ENOEXEC;
        }

        if (overflow_check && ovf == -ERANGE) goto overflow;
    }
    return 0;
overflow:
    pr_err("overflow in relocation type %d val %llx\n", (int)ELF64_R_TYPE(rel[i].r_info), (unsigned long long)val);
    return -ENOEXEC;
}