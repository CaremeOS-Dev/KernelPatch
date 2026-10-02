/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <uapi/asm-generic/errno.h>
#include <pgtable.h>
#include <kpmalloc.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/string.h>
#include <symbol.h>
#include <kallsyms.h>
#include <cache.h>
#include <common.h>
#include <linux/fs.h>
#include <uapi/linux/fs.h>
#include <hotpatch.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>

#include "module.h"
#include "relo.h"

#define SZ_128M 0x08000000

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)

#define align(X) ALIGN(X, page_size)

/*
 * XTC Z9 / MSM8937 AArch32 port: a KPM must be built for the kernel that loads
 * it.  Upstream only ever loaded AArch64 modules, so this was hardcoded to
 * EM_AARCH64; on the ARM32 build that rejects every valid ARM module and (worse)
 * lets the loader read an ELF32 image through Elf64_* structures.  The elf.h in
 * kernel/linux/arch/arm already defines elf_check_arch() as EM_ARM, so prefer it
 * and keep the literal only as a fallback.
 */
#ifndef elf_check_arch
#if defined(CONFIG_ARM)
#define elf_check_arch(x) ((x)->e_machine == EM_ARM)
#else
#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)
#endif
#endif

#define ARCH_SHF_SMALL 0

static void set_load_error(struct load_info *info, const char *message)
{
    if (!info || !message) return;
    snprintf(info->info.error_msg, sizeof(info->info.error_msg), "%s", message);
}

static const char *load_error(const struct load_info *info, const char *fallback)
{
    if (info && info->info.error_msg[0]) return info->info.error_msg;
    return fallback;
}

static bool kpm_load_result_enabled(void __user *reserved)
{
    if (!reserved) return false;

    struct kpm_load_result *result = memdup_user(reserved, sizeof(*result));
    if (!result || IS_ERR(result)) return false;

    bool enabled = result->magic == KPM_LOAD_RESULT_MAGIC && result->size >= sizeof(*result);
    kvfree(result);
    return enabled;
}

static void set_kpm_load_result(void __user *reserved, long code, const char *message)
{
    if (!kpm_load_result_enabled(reserved)) return;

    struct kpm_load_result result;
    memset(&result, 0, sizeof(result));
    result.magic = KPM_LOAD_RESULT_MAGIC;
    result.size = sizeof(result);
    result.code = code;
    if (message) snprintf(result.message, sizeof(result.message), "%s", message);
    compat_copy_to_user(reserved, &result, sizeof(result));
}

static inline bool strstarts(const char *str, const char *prefix)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

/*
 * Resolve a bare kernel-symbol name against KernelPatch's `kf_` trampolines.
 *
 * WHY THIS IS NEEDED (measured on the XTC Z9 / AArch32 port)
 * ----------------------------------------------------------
 * KernelPatch exposes kernel functions to modules through the `kfunc()` macro
 * (patch/include/ksyms.h:23):
 *
 *      #define kfunc(func)     kf_##func
 *      #define kfunc_def(func) (*kf_##func)
 *
 * and registers them in the symbol table under that PREFIXED name, e.g.
 * `KP_EXPORT_SYMBOL(kfunc(memcpy))` publishes "kf_memcpy" (whose table entry is
 * the ADDRESS OF THE POINTER VARIABLE, because `kf_memcpy` is a function
 * pointer, not a function).
 *
 * A module that writes `memcpy(...)` and gets rewritten by the macro therefore
 * references `kf_memcpy` and resolves fine.  But GCC ALSO emits IMPLICIT
 * memcpy/memset calls for struct assignment, aggregate initialisation and
 * zeroing, and those do not go through any macro -- the symbol arrives here as
 * the bare name `memcpy`.  That lookup used to fail, and the module was
 * rejected:
 *
 *      [-] KP E unknown symbol: memcpy
 *      [-] KP E unknown symbol: memset
 *      KP load AP KPM: .../kpm-hello-demo.kpm, event: post-fs-data, rc: -2
 *
 * So: on a direct miss, retry with the `kf_` prefix and DEREFERENCE the result,
 * because the table stores &kf_x (a pointer variable) while the call site needs
 * the kernel function x itself.
 */
static unsigned long symbol_lookup_kfunc_alias(const char *name)
{
    char alias[KP_SYMBOL_LEN + 8];
    int n = snprintf(alias, sizeof(alias), "kf_%s", name);
    if (n <= 0 || n >= (int)sizeof(alias)) return 0;

    unsigned long slot = symbol_lookup_name(alias);
    if (!slot) return 0;

    /* slot == &kf_<name>; dereference once to get the real function address. */
    return *(unsigned long *)slot;
}

static char *next_string(char *string, unsigned long *secsize)
{
    while (string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    while (!string[0]) {
        string++;
        if ((*secsize)-- <= 1) return 0;
    }
    return string;
}

/* Update size with this section: return offset. */
static long get_offset(struct module *mod, unsigned int *size, Elf_Shdr *sechdr, unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag, char *prev)
{
    char *p;
    unsigned int taglen = strlen(tag);
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    unsigned long size = infosec->sh_size;
    char *modinfo = (char *)info->hdr + infosec->sh_offset;
    if (prev) {
        size -= prev - modinfo;
        modinfo = next_string(prev, &size);
    }
    for (p = modinfo; p; p = next_string(p, &size)) {
        if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=') return p + taglen + 1;
    }
    return 0;
}

static char *get_modinfo(const struct load_info *info, const char *tag)
{
    return get_next_modinfo(info, tag, 0);
}

static int find_sec(const struct load_info *info, const char *name)
{
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if ((shdr->sh_flags & SHF_ALLOC) && strcmp(info->secstrings + shdr->sh_name, name) == 0) return i;
    }
    return 0;
}

static void *get_sh_base(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    void *addr = (void *)info->hdr + infosec->sh_offset;
    return addr;
}

static unsigned long get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_entsize;
}

static void layout_sections(struct module *mod, struct load_info *info)
{
    static unsigned long const masks[][2] = {
        /* NOTE: all executable code must be the first section in this array; otherwise modify the text_size finder in the two loops below */
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++)
        info->sechdrs[i].sh_entsize = ~0UL;

    // todo: tslf alloc all rwx and not page aligned
    for (int m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
        for (int i = 0; i < info->hdr->e_shnum; ++i) {
            Elf_Shdr *s = &info->sechdrs[i];
            if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;
            s->sh_entsize = get_offset(mod, &mod->size, s, i);
            // const char *sname = info->secstrings + s->sh_name;
        }
        switch (m) {
        case 0: /* executable */
            mod->size = align(mod->size);
            mod->text_size = mod->size;
            break;
        case 1: /* RO: text and ro-data */
            mod->size = align(mod->size);
            mod->ro_size = mod->size;
            break;
        case 2:
            break;
        case 3: /* whole */
            mod->size = align(mod->size);
            break;
        }
    }
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs, unsigned int shnum)
{
    const Elf_Shdr *sec;
    if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name) return false;
    sec = sechdrs + src->st_shndx;
    if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR)) return false;
    return true;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(struct module *mod, struct load_info *info)
{
    Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
    Elf_Sym *sym = (void *)symsec->sh_addr;
    unsigned long secbase;
    unsigned int i;
    int ret = 0;

    for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
        const char *name = info->strtab + sym[i].st_name;
        switch (sym[i].st_shndx) {
        case SHN_COMMON:
            if (!strncmp(name, "__gnu_lto", 9)) {
                logkd("Please compile with -fno-common\n");
                ret = -ENOEXEC;
            }
            break;
        case SHN_ABS:
            break;
        case SHN_UNDEF:
            unsigned long addr = symbol_lookup_name(name);
            /*
             * GCC-emitted implicit memcpy/memset (and any other bare kernel
             * function name) arrive without the `kf_` prefix that
             * KP_EXPORT_SYMBOL registered.  Fall back to the prefixed
             * trampoline before declaring the symbol missing.
             */
            if (!addr) addr = symbol_lookup_kfunc_alias(name);
            // kernel symbol cause overflow in relocation
            // if (!addr) addr = kallsyms_lookup_name(name);
            if (!addr) {
                logke("unknown symbol: %s\n", name);
                if (!info->info.error_msg[0])
                    snprintf(info->info.error_msg, sizeof(info->info.error_msg), "unknown symbol: %s", name);
                ret = -ENOENT;
                break;
            }
            sym[i].st_value = addr;
            break;
        default:
            secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
            sym[i].st_value += secbase;
            break;
        }
    }
    return ret;
}

static int apply_relocations(struct module *mod, const struct load_info *info)
{
    int rc = 0;
    unsigned int i;
    for (i = 1; i < info->hdr->e_shnum; i++) {
        unsigned int infosec = info->sechdrs[i].sh_info;
        if (infosec >= info->hdr->e_shnum) continue;
        if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC)) continue;
        if (info->sechdrs[i].sh_type == SHT_REL) {
            rc = apply_relocate(info->sechdrs, info->strtab, info->index.sym, i, mod);
        } else if (info->sechdrs[i].sh_type == SHT_RELA) {
            rc = apply_relocate_add(info->sechdrs, info->strtab, info->index.sym, i, mod);
        }
        if (rc < 0) break;
    }
    return rc;
}

// todo: free .strtab and .symtab after relocation
static void layout_symtab(struct module *mod, struct load_info *info)
{
    Elf_Shdr *symsect = info->sechdrs + info->index.sym;
    Elf_Shdr *strsect = info->sechdrs + info->index.str;
    const Elf_Sym *src;
    unsigned int i, nsrc, ndst, strtab_size = 0;

    /* Put symbol section at end of module. */
    symsect->sh_flags |= SHF_ALLOC;
    symsect->sh_entsize = get_offset(mod, &mod->size, symsect, info->index.sym);

    src = (void *)info->hdr + symsect->sh_offset;
    nsrc = symsect->sh_size / sizeof(*src);

    /* strtab always starts with a nul, so offset 0 is the empty string. */
    strtab_size = 1;
    /* Compute total space required for the core symbols' strtab. */
    for (ndst = i = 0; i < nsrc; i++) {
        if (i == 0 || is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
            strtab_size += strlen(&info->strtab[src[i].st_name]) + 1;
            ndst++;
        }
    }

    /* Append room for core symbols at end. */
    info->symoffs = ALIGN(mod->size, symsect->sh_addralign ?: 1);
    info->stroffs = mod->size = info->symoffs + ndst * sizeof(Elf_Sym);
    mod->size += strtab_size;

    /* Put string table section at end of module. */
    strsect->sh_flags |= SHF_ALLOC;
    strsect->sh_entsize = get_offset(mod, &mod->size, strsect, info->index.str);
}

static int rewrite_section_headers(struct load_info *info)
{
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS && info->len < shdr->sh_offset + shdr->sh_size) {
            return -ENOEXEC;
        }
        /* Mark all sections sh_addr with their address in the temporary image. */
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    return 0;
}

static int move_module(struct module *mod, struct load_info *info)
{
    // todo:
    /* `%llx` consumes 8 bytes of varargs; mod->size is 32-bit on AArch32, so
     * passing it directly printed (next_reg << 32) | size -- the
     * "alloc module size: c02481f8000034b1" seen in the device log. */
    logki("alloc module size: %llx\n", (unsigned long long)mod->size);
    mod->start = kp_malloc_exec(mod->size);
    if (!mod->start) {
        return -ENOMEM;
    }
    memset(mod->start, 0, mod->size);

    /* Transfer each section which specifies SHF_ALLOC */
    logkd("final section addresses:\n");

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        void *dest;
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;

        dest = mod->start + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;

        /* All three conversions are %llx: every argument must be widened to
         * 64 bits explicitly.  On AArch32 dest/sh_size are 32-bit, so passing
         * them bare made vsnprintf read register pairs -- "    .kpm.ctl0
         * 4d6753004 3000000002" in the device log instead of
         * "    0xd6753004 0x4". */
        logkd("    %s %llx %llx\n", sname, (unsigned long long)(uintptr_t)dest,
              (unsigned long long)shdr->sh_size);

        if (shdr->sh_type != SHT_NOBITS) memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

        shdr->sh_addr = (unsigned long)dest;

        if (!mod->init && !strcmp(".kpm.init", sname)) mod->init = (mod_initcall_t *)dest;

        if (!strcmp(".kpm.ctl0", sname)) mod->ctl0 = (mod_ctl0call_t *)dest;
        if (!strcmp(".kpm.ctl1", sname)) mod->ctl1 = (mod_ctl1call_t *)dest;

        if (!mod->exit && !strcmp(".kpm.exit", sname)) mod->exit = (mod_exitcall_t *)dest;
        if (!mod->event && !strcmp(".kpm.event", sname)) mod->event = (mod_eventcall_t *)dest;

        if (!mod->info.base && !strcmp(".kpm.info", sname)) mod->info.base = (const char *)dest;
    }
    mod->info.name = info->info.name - info->info.base + mod->info.base;
    mod->info.version = info->info.version - info->info.base + mod->info.base;

    if (info->info.license) mod->info.license = info->info.license - info->info.base + mod->info.base;
    if (info->info.author) mod->info.author = info->info.author - info->info.base + mod->info.base;
    if (info->info.description) mod->info.description = info->info.description - info->info.base + mod->info.base;

    return 0;
}

static int setup_load_info(struct load_info *info)
{
    int rc = 0;
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;

    if ((rc = rewrite_section_headers(info))) {
        logke("rewrite section error\n");
        set_load_error(info, "rewrite section headers failed");
        return rc;
    }

    if (!find_sec(info, ".kpm.init") || !find_sec(info, ".kpm.exit")) {
        logke("no .kpm.init or .kpm.exit section\n");
        set_load_error(info, "no .kpm.init or .kpm.exit section");
        return -ENOEXEC;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        logke("no .kpm.info section\n");
        set_load_error(info, "no .kpm.info section");
        return -ENOEXEC;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    const char *name = get_modinfo(info, "name");
    if (!name) {
        logke("module name not found\n");
        set_load_error(info, "module name not found");
        return -ENOEXEC;
    }
    info->info.name = name;
    logkd("loading module: \n");
    logkd("    name: %s\n", name);

    const char *version = get_modinfo(info, "version");
    if (!version) {
        logkd("module version not found\n");
        set_load_error(info, "module version not found");
        return -ENOEXEC;
    }
    info->info.version = version;
    logkd("    version: %s\n", version);

    const char *license = get_modinfo(info, "license");
    info->info.license = license;
    logkd("    license: %s\n", license);

    const char *author = get_modinfo(info, "author");
    info->info.author = author;
    logkd("    author: %s\n", author);
    const char *description = get_modinfo(info, "description");
    info->info.description = description;
    logkd("    description: %s\n", description);

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            info->index.sym = i;
            info->index.str = info->sechdrs[i].sh_link;
            info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
            break;
        }
    }

    if (info->index.sym == 0) {
        logkd("module has no symbols (stripped?)\n");
        set_load_error(info, "module has no symbols (stripped?)");
        return -ENOEXEC;
    }
    return 0;
}

static int elf_header_check(struct load_info *info)
{
    if (info->len <= sizeof(*(info->hdr))) {
        set_load_error(info, "ELF header is truncated");
        return -ENOEXEC;
    }
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) || info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr)) {
#if defined(CONFIG_ARM)
        set_load_error(info, "ELF header is not a supported ARM32 (AArch32) relocatable module");
#else
        set_load_error(info, "ELF header is not a supported AArch64 relocatable module");
#endif
        return -ENOEXEC;
    }
    if (info->hdr->e_shoff >= info->len || (info->hdr->e_shnum * sizeof(Elf_Shdr) > info->len - info->hdr->e_shoff)) {
        set_load_error(info, "ELF section headers are invalid");
        return -ENOEXEC;
    }
    return 0;
}

struct module modules = { 0 };
static spinlock_t module_lock;

long load_module_ex(const void *data, int len, const char *args, const char *event, const char *source,
                    void *__user reserved)
{
    struct load_info load_info = { .len = len, .hdr = data };
    struct load_info *info = &load_info;
    long rc = 0;

    if ((rc = elf_header_check(info))) goto out;
    if ((rc = setup_load_info(info))) goto out;

    if (find_module(info->info.name)) {
        logkfd("%s exist\n", info->info.name);
        set_load_error(info, "module already exists");
        rc = -EEXIST;
        goto out;
    }

    struct module *mod = (struct module *)vmalloc(sizeof(struct module));
    if (!mod) {
        set_load_error(info, "allocate module state failed");
        rc = -ENOMEM;
        goto out;
    }
    memset(mod, 0, sizeof(struct module));
    snprintf(mod->load_event, sizeof(mod->load_event), "%s", event ? event : "");
    snprintf(mod->load_source, sizeof(mod->load_source), "%s", source ? source : "embedded");

    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) {
            set_load_error(info, "allocate module args failed");
            rc = -ENOMEM;
            goto free1;
        }
        strcpy(mod->args, args);
    }

    layout_sections(mod, info);
    layout_symtab(mod, info);

    if ((rc = move_module(mod, info))) {
        set_load_error(info, "allocate executable module memory failed");
        goto free;
    }
    if ((rc = simplify_symbols(mod, info))) goto free;
    if ((rc = apply_relocations(mod, info))) {
        set_load_error(info, "apply relocations failed");
        goto free;
    }

    flush_icache_all();

    rc = (*mod->init)(mod->args, event, reserved);

    if (!rc) {
        logkfi("[%s] succeed with [%s] \n", mod->info.name, args);
        list_add_tail(&mod->list, &modules.list);
        goto out;
    } else {
        set_load_error(info, "module init failed");
        logkfi("[%s] failed with [%s] error: %d, try exit ...\n", mod->info.name, args, rc);
        (*mod->exit)(reserved);
    }

free:
    if (mod->args) kvfree(mod->args);
    kp_free_exec(mod->start);
free1:
    kvfree(mod);
out:
    set_kpm_load_result(reserved, rc, rc ? load_error(info, "load module failed") : "module loaded");
    return rc;
}

// todo: lock
long unload_module(const char *name, void *__user reserved)
{
    if (!name) return -EINVAL;
    logkfe("name: %s\n", name);

    rcu_read_lock();
    long rc = 0;

    struct module *mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }
    list_del(&mod->list);
    rc = (*mod->exit)(reserved);

    if (mod->args) kvfree(mod->args);
    if (mod->ctl_args) kvfree(mod->ctl_args);

    kp_free_exec(mod->start);
    kvfree(mod);

    logkfi("name: %s, rc: %d\n", name, rc);

out:
    rcu_read_unlock();
    return rc;
}

long load_module(const void *data, int len, const char *args, const char *event, void *__user reserved)
{
    return load_module_ex(data, len, args, event, "embedded", reserved);
}

long load_module_path_event(const char *path, const char *args, const char *event, void *__user reserved)
{
    long rc = 0;
    logkfd("%s\n", path);
    if (!path) {
        rc = -EINVAL;
        set_kpm_load_result(reserved, rc, "module path is null");
        return rc;
    }

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) {
        logkfe("open module: %s error\n", path);
        rc = PTR_ERR(filp);
        set_kpm_load_result(reserved, rc, "open module file failed");
        goto out;
    }
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    /* loff_t is 32-bit on AArch32; widen for %llx. */
    logkfd("module size: %llx\n", (unsigned long long)len);
    vfs_llseek(filp, 0, SEEK_SET);

    void *data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        set_kpm_load_result(reserved, rc, "allocate module file buffer failed");
        goto close;
    }
    memset(data, 0, len);

    loff_t pos = 0;
    kernel_read(filp, data, len, &pos);
    filp_close(filp, 0);
    filp = 0;

    if (pos != len) {
        logkfe("read module: %s error\n", path);
        rc = -EIO;
        set_kpm_load_result(reserved, rc, "read module file failed");
        goto free;
    }

    rc = load_module_ex(data, len, args, event ? event : "load-file", "file", reserved);
free:
    kvfree(data);
close:
    if (filp) filp_close(filp, 0);
out:
    return rc;
}

long load_module_path(const char *path, const char *args, void *__user reserved)
{
    return load_module_path_event(path, args, "load-file", reserved);
}

long module_control0(const char *name, const char *ctl_args, char *__user out_msg, int outlen)
{
    if (!name || !ctl_args) return -EINVAL;
    int args_len = strlen(ctl_args);
    if (args_len <= 0) return -EINVAL;

    logkfi("name %s, args: %s\n", name, ctl_args);

    long rc = 0;
    rcu_read_lock();

    struct module *mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    if (!mod->ctl0 || !*mod->ctl0) {
        logkfe("no ctl0\n");
        rc = -ENOSYS;
        goto out;
    }

    if (mod->ctl_args) kvfree(mod->ctl_args);

    mod->ctl_args = vmalloc(args_len + 1);
    if (!mod->ctl_args) {
        rc = -ENOMEM;
        goto out;
    }

    strcpy(mod->ctl_args, ctl_args);

    rc = (*mod->ctl0)(mod->ctl_args, out_msg, outlen);

    logkfi("name: %s, rc: %d\n", name, rc);
out:
    rcu_read_unlock();
    return rc;
}

long module_control1(const char *name, void *a1, void *a2, void *a3)
{
    /* Pointers are 32-bit on AArch32; widen every %llx argument. */
    logkfi("name %s, a1: %llx, a2: %llx, a3: %llx\n", name, (unsigned long long)(uintptr_t)a1,
           (unsigned long long)(uintptr_t)a2, (unsigned long long)(uintptr_t)a3);
    long rc = 0;
    rcu_read_lock();

    struct module *mod = find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    if (!mod->ctl1 || !*mod->ctl1) {
        logkfe("no ctl1\n");
        rc = -ENOSYS;
        goto out;
    }

    rc = (*mod->ctl1)(a1, a2, a3);

    logkfi("name: %s, rc: %d\n", name, rc);
out:
    rcu_read_unlock();
    return rc;
}

long notify_modules_event(const char *event, const char *args, void *__user reserved)
{
    if (!event) return -EINVAL;

    long result = 0;
    int count = 0;
    rcu_read_lock();

    struct module *pos;
    list_for_each_entry(pos, &modules.list, list)
    {
        if (!pos->event || !*pos->event) continue;

        long rc = (*pos->event)(event, args, reserved);
        logkfi("event: %s, module: %s, rc: %ld\n", event, pos->info.name, rc);
        if (rc < 0 && !result) result = rc;
        count++;
    }

    rcu_read_unlock();
    return result ?: count;
}
KP_EXPORT_SYMBOL(notify_modules_event);

struct module *find_module(const char *name)
{
    struct module *pos;
    list_for_each_entry(pos, &modules.list, list)
    {
        if (!strcmp(name, pos->info.name)) {
            return pos;
        }
    }
    return 0;
}

int get_module_nums()
{
    rcu_read_lock();

    struct module *pos;
    int n = 0;
    list_for_each_entry(pos, &modules.list, list)
    {
        n++;
    }
    rcu_read_unlock();

    logkfd("%d\n", n);
    return n;
}

int list_modules(char *out_names, int size)
{
    if (!out_names || size <= 0) return -EINVAL;
    out_names[0] = '\0';

    rcu_read_lock();

    struct module *pos;
    int off = 0;
    list_for_each_entry(pos, &modules.list, list)
    {
        off += snprintf(out_names + off, size - 1 - off, "%s\n", pos->info.name);
    }
    if (off > 0) out_names[off - 1] = '\0';

    rcu_read_unlock();
    return off;
}

int get_module_info(const char *name, char *out_info, int size)
{
    if (size <= 0) return 0;
    rcu_read_lock();

    struct module *mod = find_module(name);
    if (!mod) return -ENOENT;

    int sz = snprintf(out_info, size,
                      "name=%s\n"
                      "version=%s\n"
                      "license=%s\n"
                      "author=%s\n"
                      "description=%s\n"
                      "args=%s\n",
                      mod->info.name, mod->info.version, mod->info.license, mod->info.author, mod->info.description,
                      mod->args ? mod->args : "");

    if (sz < 0) sz = 0;
    if (sz < size) {
        int tail = snprintf(out_info + sz, size - sz,
                            "load_event=%s\n"
                            "load_source=%s\n",
                            mod->load_event, mod->load_source);
        if (tail > 0) sz += tail;
    }

    out_info[size - 1] = '\0';
    logkfd("%s", out_info);

    rcu_read_unlock();
    return sz;
}

void module_init()
{
    INIT_LIST_HEAD(&modules.list);
    spin_lock_init(&module_lock);
}
