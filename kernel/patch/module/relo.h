#ifndef _KP_RELO_H_
#define _KP_RELO_H_

#include <uapi/linux/elf.h>
#include <asm-generic/module.h> /* Elf_Shdr is Elf32_Shdr on CONFIG_ARM, Elf64_Shdr otherwise */

int apply_relocate_add(Elf_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                       struct module *me);
int apply_relocate(Elf_Shdr *sechdrs, const char *strtab, unsigned int symindex, unsigned int relsec,
                   struct module *me);

#endif