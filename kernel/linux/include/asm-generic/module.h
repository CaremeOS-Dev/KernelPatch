/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_MODULE_H
#define __ASM_GENERIC_MODULE_H

#include <uapi/linux/elf.h>

/*
 * Many architectures just need a simple module
 * loader without arch specific data.
 */
#ifndef CONFIG_HAVE_MOD_ARCH_SPECIFIC
struct mod_arch_specific
{
};
#endif

/*
 * XTC Z9 / MSM8937 AArch32 port: the ELF width of a KPM must match the width of
 * the kernel that loads it.  Upstream hardcodes `#define CONFIG_64BIT` here
 * because the only KPM consumer used to be arm64, which forced Elf64_Shdr /
 * Elf64_Sym / Elf64_Rela even in the CONFIG_ARM build.  An ARM32 KPM produced by
 * arm-linux-gnueabi is ELF32 (Class: ELF32, SHT_REL), and the loader reading it
 * through Elf64_* structs misreads every section header, symbol and relocation
 * record, so the module never loads.
 *
 * ARM32 KPMs are REL (SHT_REL / Elf32_Rel) and carry no addend in the record;
 * AArch64 KPMs are RELA (SHT_RELA / Elf64_Rela).
 */
#if !defined(CONFIG_ARM)
#define CONFIG_64BIT
#endif

/*
 * ARM32 KPM images are ET_REL linked with the default ARM EABI relocation
 * model, i.e. SHT_REL (Elf32_Rel, no in-record addend).  This must be decided
 * BEFORE the width block below, because that block selects Elf_Rel/Elf_Rela
 * from it.  AArch64 KPMs are SHT_RELA (Elf64_Rela).
 */
#if defined(CONFIG_ARM) && !defined(CONFIG_MODULES_USE_ELF_REL) && !defined(CONFIG_MODULES_USE_ELF_RELA)
#define CONFIG_MODULES_USE_ELF_REL
#endif

#ifdef CONFIG_64BIT
#define Elf_Shdr Elf64_Shdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Dyn Elf64_Dyn
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Addr Elf64_Addr
#ifdef CONFIG_MODULES_USE_ELF_REL
#define Elf_Rel Elf64_Rel
#endif
#ifdef CONFIG_MODULES_USE_ELF_RELA
#define Elf_Rela Elf64_Rela
#endif
#define ELF_R_TYPE(X) ELF64_R_TYPE(X)
#define ELF_R_SYM(X) ELF64_R_SYM(X)

#else /* CONFIG_64BIT */

#define Elf_Shdr Elf32_Shdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Sym Elf32_Sym
#define Elf_Dyn Elf32_Dyn
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Addr Elf32_Addr
#ifdef CONFIG_MODULES_USE_ELF_REL
#define Elf_Rel Elf32_Rel
#endif
#ifdef CONFIG_MODULES_USE_ELF_RELA
#define Elf_Rela Elf32_Rela
#endif
#define ELF_R_TYPE(X) ELF32_R_TYPE(X)
#define ELF_R_SYM(X) ELF32_R_SYM(X)
#endif

#endif /* __ASM_GENERIC_MODULE_H */