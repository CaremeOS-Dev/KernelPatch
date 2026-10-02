/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_TOOL_KPM_H_
#define _KP_TOOL_KPM_H_

#include "elf/elf.h"
#include "common.h"

/*
 * KPM ELF width/arch selection -- XTC Z9 / MSM8937 AArch32 port.
 *
 * kptools runs ON the device and inspects KPMs destined for that same kernel, so
 * its idea of the ELF width and e_machine must follow the architecture it was
 * compiled for, not a hardcoded AArch64:
 *
 *   armv7a-linux-androideabi27-clang -> __arm__    -> ELF32 / EM_ARM
 *   aarch64 / x86_64 host build      -> (else)     -> ELF64 / EM_AARCH64
 *
 * Before this, an ELF32 ARM32 KPM (Class: ELF32, Machine: ARM, SHT_REL) was
 * rejected by get_kpm_info() with -ENOEXEC, so the manager could not read the
 * name/version/author that it needs to install or list a module.
 */
#if defined(__arm__) || defined(__thumb__)
#define KP_KPM_ELF32 1
#else
#define KP_KPM_ELF32 0
#endif

#if KP_KPM_ELF32
#define Elf_Shdr Elf32_Shdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Sym Elf32_Sym
#define Elf_Dyn Elf32_Dyn
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Addr Elf32_Addr
#define ELF_R_TYPE(X) ELF32_R_TYPE(X)
#define ELF_R_SYM(X) ELF32_R_SYM(X)
#define KPM_ELF_ARCH_NAME "ARM32 (AArch32)"
#else
#define Elf_Shdr Elf64_Shdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Dyn Elf64_Dyn
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Addr Elf64_Addr
#define ELF_R_TYPE(X) ELF64_R_TYPE(X)
#define ELF_R_SYM(X) ELF64_R_SYM(X)
#define KPM_ELF_ARCH_NAME "AArch64"
#endif

#define INFO_EXTRA_KPM_SESSION "[kpm]"

struct load_info
{
    struct
    {
        const char *base;
        uint64_t size;
        const char *name, *version, *license, *author, *description;
    } info;
    Elf_Ehdr *hdr;
    uint64_t len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    uint64_t symoffs, stroffs;
    struct
    {
        uint32_t sym, str, mod, info;
    } index;
};

typedef struct
{
    const char *name, *version, *license, *author, *description;
} kpm_info_t;

int get_kpm_info(const char *kpm, int len, kpm_info_t *info);

void print_kpm_info(kpm_info_t *info);
int print_kpm_info_path(const char *kpm_path);

#endif