/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#define _GNU_SOURCE
#define __USE_GNU

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>

#include "kallsym.h"
#include "bootimg.h"
#include "patch.h"
#include "kallsym.h"
#include "image.h"
#include "common.h"
#include "order.h"
#include "preset.h"
#include "symbol.h"
#include "kpm.h"
#include "x86_64.h"
#include "lib/sha/sha256.h"

void read_kernel_file(const char *path, kernel_file_t *kernel_file)
{
    int img_offset = 0;
    read_file(path, &kernel_file->kfile, &kernel_file->kfile_len);
    kernel_file->is_uncompressed_img = kernel_file->kfile_len >= 20 &&
                                       !strncmp("UNCOMPRESSED_IMG", kernel_file->kfile, 16);
    if (kernel_file->is_uncompressed_img) img_offset = 20;
    kernel_file->kimg = kernel_file->kfile + img_offset;
    kernel_file->kimg_len = kernel_file->kfile_len - img_offset;
}

void update_kernel_file_img_len(kernel_file_t *kernel_file, int kimg_len, bool is_different_endian)
{
    kernel_file->kimg_len = kimg_len;
    if (kernel_file->is_uncompressed_img) {
        *(uint32_t *)(kernel_file->kfile + 16) = (uint32_t)(is_different_endian ? i32swp(kimg_len) : kimg_len);
        kernel_file->kfile_len = kimg_len + 20;
    } else {
        kernel_file->kfile_len = kimg_len;
    }
}

void new_kernel_file(kernel_file_t *kernel_file, kernel_file_t *old, int kimg_len, bool is_different_endian)
{
    int prefix_len = old->kimg - old->kfile;
    int new_len = kimg_len + prefix_len;
    kernel_file->kfile = (char *)malloc(new_len);
    kernel_file->kimg = kernel_file->kfile + prefix_len;
    memcpy(kernel_file->kfile, old->kfile, prefix_len);
    kernel_file->is_uncompressed_img = old->is_uncompressed_img;
    update_kernel_file_img_len(kernel_file, kimg_len, is_different_endian);
}

void write_kernel_file(kernel_file_t *kernel_file, const char *path)
{
    write_file(path, kernel_file->kfile, kernel_file->kfile_len, false);
}

void free_kernel_file(kernel_file_t *kernel_file)
{
    free(kernel_file->kfile);
    kernel_file->kfile = NULL;
    kernel_file->kimg = NULL;
}

preset_t *get_preset(const char *kimg, int kimg_len)
{
    char magic[MAGIC_LEN] = KP_MAGIC;
    return (preset_t *)memmem(kimg, kimg_len, magic, sizeof(magic));
}

uint32_t get_kpimg_version(const char *kpimg_path)
{
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file(kpimg_path, &kpimg, &kpimg_len);
    preset_t *preset = get_preset(kpimg, kpimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");
    version_t ver = preset->header.kp_version;
    uint32_t version = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    return version;
}

int extra_str_type(const char *extra_str)
{
    int extra_type = EXTRA_TYPE_NONE;
    if (!strcmp(extra_str, EXTRA_TYPE_KPM_STR)) {
        extra_type = EXTRA_TYPE_KPM;
    } else if (!strcmp(extra_str, EXTRA_TYPE_EXEC_STR)) {
        extra_type = EXTRA_TYPE_EXEC;
    } else if (!strcmp(extra_str, EXTRA_TYPE_SHELL_STR)) {
        extra_type = EXTRA_TYPE_SHELL;
    } else if (!strcmp(extra_str, EXTRA_TYPE_RAW_STR)) {
        extra_type = EXTRA_TYPE_RAW;
    } else if (!strcmp(extra_str, EXTRA_TYPE_ANDROID_RC_STR)) {
        extra_type = EXTRA_TYPE_ANDROID_RC;
    } else {
    }
    return extra_type;
}

const char *extra_type_str(extra_item_type extra_type)
{
    switch (extra_type) {
    case EXTRA_TYPE_KPM:
        return EXTRA_TYPE_KPM_STR;
    case EXTRA_TYPE_EXEC:
        return EXTRA_TYPE_EXEC_STR;
    case EXTRA_TYPE_SHELL:
        return EXTRA_TYPE_SHELL_STR;
    case EXTRA_TYPE_RAW:
        return EXTRA_TYPE_RAW_STR;
    case EXTRA_TYPE_ANDROID_RC:
        return EXTRA_TYPE_ANDROID_RC_STR;
    case EXTRA_TYPE_KCONFIG_LEGACY:
        return EXTRA_TYPE_KCONFIG_LEGACY_STR;
    default:
        return EXTRA_TYPE_NONE_STR;
    }
}

static bool header_backup_has_valid_primary_entry(const uint8_t *header_backup)
{
    uint32_t primary_entry = u32le(*(const uint32_t *)header_backup);
    if ((primary_entry & 0xFC000000) == 0x14000000) return true;

    if (!memcmp(header_backup, "MZ", 2)) {
        primary_entry = u32le(*(const uint32_t *)(header_backup + 4));
        if ((primary_entry & 0xFC000000) == 0x14000000) return true;
    }

    return false;
}

static uint32_t preset_version_num(const preset_t *preset)
{
    version_t ver = preset->header.kp_version;
    return (ver.major << 16) + (ver.minor << 8) + ver.patch;
}

static void push_header_backup_candidate(size_t *candidates, int *candidate_num, size_t candidate)
{
    for (int i = 0; i < *candidate_num; i++) {
        if (candidates[i] == candidate) return;
    }
    candidates[(*candidate_num)++] = candidate;
}

static const uint8_t *preset_header_backup(const preset_t *preset)
{
    const uint8_t *setup = (const uint8_t *)&preset->setup;
    size_t candidates[4];
    int candidate_num = 0;
    size_t current_header_backup_offset = offsetof(setup_preset_t, header_backup);

    uint32_t ver_num = preset_version_num(preset);
    if (ver_num <= VERSION(0, 13, 1)) {
        push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset - 16);
        push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset);
    } else {
        push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset);
        push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset - 16);
    }

    push_header_backup_candidate(candidates, &candidate_num, current_header_backup_offset - 8);

    for (int i = 0; i < candidate_num; i++) {
        const uint8_t *header_backup = setup + candidates[i];
        if (header_backup_has_valid_primary_entry(header_backup)) return header_backup;
    }

    return setup + candidates[0];
}

static preset_t *find_patched_preset(const char *kimg, int kimg_len, int32_t *saved_kimg_len, int *align_kimg_len)
{
    const char *search_ptr = kimg;
    int search_len = kimg_len;

    while (search_len > 0) {
        preset_t *candidate = get_preset(search_ptr, search_len);
        if (!candidate) break;

        int32_t candidate_saved_kimg_len = (int32_t)u64le(candidate->setup.kimg_size);
        int candidate_align_kimg_len = (int)((const char *)candidate - kimg);
        const uint8_t *header_backup = preset_header_backup(candidate);

        if (candidate_align_kimg_len == (int)align_ceil(candidate_saved_kimg_len, SZ_4K) &&
            header_backup_has_valid_primary_entry(header_backup)) {
            if (saved_kimg_len) *saved_kimg_len = candidate_saved_kimg_len;
            if (align_kimg_len) *align_kimg_len = candidate_align_kimg_len;
            return candidate;
        }

        tools_logw("found magic string at 0x%x but saved kernel image size/header backup mismatch, ignoring\n",
                   candidate_align_kimg_len);

        search_ptr = (const char *)candidate + 1;
        search_len = kimg_len - (int)(search_ptr - kimg);
    }

    return NULL;
}

static uint32_t extra_item_header_version(const patch_extra_item_t *item)
{
    return PATCH_EXTRA_FLAGS_GET_HEADER_VERSION(item->flags);
}

static void sanitize_legacy_extra_item(patch_extra_item_t *item)
{
    if (extra_item_header_version(item) == PATCH_EXTRA_HEADER_VERSION_LEGACY && item->flags) {
        tools_logw("legacy extra item %s has dirty flags 0x%x, clearing for compatibility\n", item->name,
                   (uint32_t)item->flags);
        item->flags = 0;
    }
}

static bool is_legacy_kconfig_extra(const patch_extra_item_t *item)
{
    return extra_item_header_version(item) == PATCH_EXTRA_HEADER_VERSION_LEGACY &&
           item->type == EXTRA_TYPE_KCONFIG_LEGACY && !strcmp(item->name, EXTRA_TYPE_KCONFIG_LEGACY_STR);
}

static char *bytes_to_hexstr(const unsigned char *data, int len)
{
    char *buf = (char *)malloc(2 * len + 1);
    buf[2 * len] = '\0';
    for (int i = 0; i < len; i++) {
        sprintf(&buf[2 * i], "%02x", data[i]);
    }
    return buf;
}

/* The preset header has no ARM32 flag (upstream only tracks CONFIG_FLAG_X86_64),
 * so "-l -k kpimg" used to report every non-x86 blob as "arm64" even for the
 * AArch32 port.  Derive the arch from the blob's entry instruction (kpimg links
 * its entry at 0x1000) and report it correctly:
 *   A32 b/bl : cond 000 101 imm24  -> bits 27..25 == 101
 *   A64 b/bl : 000101 imm26        -> (w & 0x7C000000) == 0x14000000
 */
static int g_kpimg_is_arm32 = -1;   /* -1 = unknown -> keep the old label */

static int blob_entry_is_arm32(const char *blob, int len)
{
    uint32_t w;
    if (!blob || len < 0x1004) return -1;
    memcpy(&w, blob + 0x1000, sizeof(w));
    if ((w & 0x7C000000u) == 0x14000000u) return 0;
    if (((w >> 25) & 7u) == 5u && ((w >> 28) & 0xFu) != 0xFu) return 1;
    return -1;
}

void print_preset_info(preset_t *preset)
{
    setup_header_t *header = &preset->header;
    setup_preset_t *setup = &preset->setup;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags & CONFIG_ANDROID;
    bool is_debug = header->config_flags & CONFIG_DEBUG;
    bool is_x86_64 = header->config_flags & CONFIG_FLAG_X86_64;

    fprintf(stdout, INFO_KP_IMG_SESSION "\n");
    fprintf(stdout, "version=0x%x\n", ver_num);
    fprintf(stdout, "compile_time=%s\n", header->compile_time);
    fprintf(stdout, "config=%s,%s\n", is_android ? "android" : "linux", is_debug ? "debug" : "release");
    fprintf(stdout, "arch=%s\n",
            is_x86_64 ? "x86_64" : (g_kpimg_is_arm32 == 1 ? "arm32" : "arm64"));
    fprintf(stdout, "superkey=%s\n", setup->superkey);

    // todo: remove compat version
    if (ver_num > 0xa04) {
        char *hexstr = bytes_to_hexstr(setup->root_superkey, ROOT_SUPER_KEY_HASH_LEN);
        fprintf(stdout, "root_superkey=%s\n", hexstr);
        free(hexstr);
    }

    fprintf(stdout, INFO_ADDITIONAL_SESSION "\n");
    char *addition = setup->additional;
    // todo: remove compat version
    if (ver_num <= 0xa04) {
        addition -= (ROOT_SUPER_KEY_HASH_LEN + SETUP_PRESERVE_LEN);
    }
    char *pos = addition;
    while (pos < addition + ADDITIONAL_LEN) {
        int len = *pos;
        if (!len) break;
        pos++;
        char backup = *(pos + len);
        *(pos + len) = 0;
        fprintf(stdout, "%s\n", pos);
        *(pos + len) = backup;
        pos += len;
    }
}

int print_kp_image_info_path(const char *kpimg_path)
{
    int rc = 0;
    char *kpimg;
    int len = 0;
    read_file(kpimg_path, &kpimg, &len);
    preset_t *preset = (preset_t *)kpimg;
    if (get_preset(kpimg, len) != preset) {
        rc = -ENOENT;
    } else {
        g_kpimg_is_arm32 = blob_entry_is_arm32(kpimg, len);
        print_preset_info(preset);
        fprintf(stdout, "\n");
        free(kpimg);
    }
    return rc;
}

int parse_image_patch_info(const char *kimg, int kimg_len, patched_kimg_t *pimg)
{
    pimg->kimg = kimg;
    pimg->kimg_len = kimg_len;

    preset_t *old_preset = NULL;
    int32_t saved_kimg_len = 0;
    int align_kimg_len = 0;

    old_preset = find_patched_preset(kimg, kimg_len, &saved_kimg_len, &align_kimg_len);
    if (old_preset) {
        tools_logi("restore header backup before parsing patched kernel image\n");
        memcpy((char *)kimg, preset_header_backup(old_preset), HDR_BACKUP_SIZE);
    }

    // kernel image infomation
    kernel_info_t *kinfo = &pimg->kinfo;
    if (get_kernel_info(kinfo, kimg, kimg_len)) tools_loge_exit("get_kernel_info error\n");

    // find banner
    char linux_banner_prefix[] = "Linux version ";
    size_t prefix_len = strlen(linux_banner_prefix);
    const char *imgend = pimg->kimg + pimg->kimg_len;
    const char *banner = (char *)pimg->kimg;
    while ((banner = (char *)memmem(banner + 1, imgend - banner, linux_banner_prefix, prefix_len)) != NULL) {
        if (isdigit(*(banner + prefix_len)) && *(banner + prefix_len + 1) == '.') {
            pimg->banner = banner;
            break;
        }
    }
    if (!pimg->banner) tools_loge_exit("can't find linux banner\n");

    if (!old_preset) {
        old_preset = find_patched_preset(kimg, kimg_len, &saved_kimg_len, &align_kimg_len);
        if (old_preset && (is_be() ^ kinfo->is_be)) {
            saved_kimg_len = i32swp(saved_kimg_len);
        }
    }

    pimg->preset = old_preset;

    if (!old_preset) {
        tools_logi("new kernel image ...\n");
        pimg->ori_kimg_len = pimg->kimg_len;
        return 0;
    }

    tools_logi("patched kernel image ...\n");
    pimg->ori_kimg_len = saved_kimg_len;

    memcpy((char *)kimg, preset_header_backup(old_preset), HDR_BACKUP_SIZE);

    // extra
    int extra_offset = align_kimg_len + old_preset->setup.kpimg_size;
    if (extra_offset > kimg_len) tools_loge_exit("kpimg length mismatch\n");
    if (extra_offset == kimg_len) return 0;

    int32_t extra_size = old_preset->setup.extra_size;
    if (is_be() ^ kinfo->is_be) extra_size = i32swp(extra_size);
    const char *item_pos = kimg + extra_offset;

    while (item_pos < kimg + extra_offset + extra_size) {
        patch_extra_item_t *item = (patch_extra_item_t *)item_pos;
        if (strcmp(EXTRA_HDR_MAGIC, item->magic)) break;
        if (item->type == EXTRA_TYPE_NONE) break;
        sanitize_legacy_extra_item(item);
        if (is_legacy_kconfig_extra(item)) {
            tools_logw("skip legacy embedded kconfig extra item during upgrade compatibility scan\n");
            item_pos += sizeof(patch_extra_item_t);
            item_pos += item->args_size;
            item_pos += item->con_size;
            continue;
        }
        if (pimg->embed_item_num >= EXTRA_ITEM_MAX_NUM) tools_loge_exit("too many embedded extra items\n");
        pimg->embed_item[pimg->embed_item_num++] = item;
        item_pos += sizeof(patch_extra_item_t);
        item_pos += item->args_size;
        item_pos += item->con_size;
    }

    return 0;
}

int parse_image_patch_info_path(const char *kimg_path, patched_kimg_t *pimg)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    int rc = parse_image_patch_info(kernel_file.kimg, kernel_file.kimg_len, pimg);
    free_kernel_file(&kernel_file);
    return rc;
}

int print_image_patch_info(patched_kimg_t *pimg)
{
    int rc = 0;

    preset_t *preset = pimg->preset;

    fprintf(stdout, INFO_KERNEL_IMG_SESSION "\n");
    fprintf(stdout, "banner=%s", pimg->banner);

    if (pimg->banner[strlen(pimg->banner) - 1] != '\n') fprintf(stdout, "\n");
    fprintf(stdout, "patched=%s\n", preset ? "true" : "false");

    if (preset) {
        print_preset_info(preset);

        fprintf(stdout, INFO_EXTRA_SESSION "\n");
        fprintf(stdout, "num=%d\n", pimg->embed_item_num);

        for (int i = 0; i < pimg->embed_item_num; i++) {
            patch_extra_item_t *item = pimg->embed_item[i];
            const char *type = extra_type_str(item->type);
            fprintf(stdout, INFO_EXTRA_SESSION_N "\n", i);
            fprintf(stdout, "index=%d\n", i);
            fprintf(stdout, "type=%s\n", type);
            fprintf(stdout, "name=%s\n", item->name);
            fprintf(stdout, "event=%s\n", item->event);
            fprintf(stdout, "priority=%d\n", item->priority);
            fprintf(stdout, "args_size=0x%x\n", item->args_size);
            fprintf(stdout, "args=%s\n", item->args_size > 0 ? (char *)item + sizeof(*item) : "");
            fprintf(stdout, "con_size=0x%x\n", item->con_size);
            fprintf(stdout, "flags=0x%x\n", item->flags);

            if (item->type == EXTRA_TYPE_KPM) {
                kpm_info_t kpm_info = { 0 };
                void *kpm = (kpm_info_t *)((uintptr_t)item + sizeof(patch_extra_item_t) + item->args_size);
                rc = get_kpm_info(kpm, item->con_size, &kpm_info);
                if (rc) tools_loge_exit("get kpm infomation error: %d\n", rc);
                fprintf(stdout, "version=%s\n", kpm_info.version);
                fprintf(stdout, "license=%s\n", kpm_info.license);
                fprintf(stdout, "author=%s\n", kpm_info.author);
                fprintf(stdout, "description=%s\n", kpm_info.description);
            }
        }
    }
    return rc;
}

int print_image_patch_info_path(const char *kimg_path)
{
    patched_kimg_t pimg = { 0 };
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    int rc = parse_image_patch_info(kernel_file.kimg, kernel_file.kimg_len, &pimg);
    print_image_patch_info(&pimg);
    free_kernel_file(&kernel_file);
    return rc;
}

static int extra_compare(const void *a, const void *b)
{
    extra_config_t *pa = (extra_config_t *)a;
    extra_config_t *pb = (extra_config_t *)b;
    return -(pa->priority - pb->priority);
}

static void extra_append(char *kimg, const void *data, int len, int *offset)
{
    memcpy(kimg + *offset, data, len);
    *offset += len;
}

static void hexstr_to_bytes(const char *hexstr, size_t out_len, unsigned char *out)
{
    for (size_t i = 0; i < out_len; i++) {
        char tmp[3] = { hexstr[i * 2], hexstr[i * 2 + 1], 0 };
        out[i] = (unsigned char)strtoul(tmp, NULL, 16);
    }
}

int hex_patch(char *img, size_t imglen,
                      const char *pattern_hex,
                      const char *replace_hex)
{
    size_t patternlen = strlen(pattern_hex) / 2;
    size_t replacelen = strlen(replace_hex) / 2;


    unsigned char pattern[32];
    unsigned char replace[32];

    hexstr_to_bytes(pattern_hex, patternlen, pattern);
    hexstr_to_bytes(replace_hex, replacelen, replace);

    unsigned char *p = memmem(img, imglen, pattern, patternlen);
    if (p) {
        memcpy(p, replace, replacelen);
    }else{
        return -1;
    }
    return 0;
}

static int disable_pi_map(char *img, size_t imglen)
{
    return hex_patch(
        img,
        imglen,
        "E60316AAE7031F2A3411889A",
        "E60316AAE7031F2AF40309AA"
    );
}

static int patch_update_x86(const char *kimg_path, const char *kpimg_path, const char *out_path,
                            const char *superkey, bool root_key, const char **additional,
                            int extra_config_num)
{
    if (extra_config_num) {
        tools_loge("x86 kpimg extras are not supported yet\n");
        return -1;
    }
    if (additional && additional[0]) {
        tools_loge("x86 kpimg additional properties are not supported yet\n");
        return -1;
    }

    x86_bzimage_t image;
    if (load_x86_bzimage(kimg_path, &image)) {
        tools_loge("load x86 bzImage failed\n");
        return -1;
    }

    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file(kpimg_path, &kpimg, &kpimg_len);
    if (kpimg_len < (int)sizeof(preset_t)) {
        tools_loge("x86 kpimg is too small\n");
        free(kpimg);
        free_x86_bzimage(&image);
        return -1;
    }

    preset_t *preset = (preset_t *)kpimg;
    char magic[MAGIC_LEN] = KP_MAGIC;
    if (memcmp(preset->header.magic, magic, MAGIC_LEN) ||
        !(preset->header.config_flags & CONFIG_FLAG_X86_64)) {
        tools_loge("kpimg is not an x86_64 payload\n");
        free(kpimg);
        free_x86_bzimage(&image);
        return -1;
    }

    setup_preset_t *setup = &preset->setup;
    memset(setup, 0, sizeof(*setup));
    kallsym_t kallsym = { 0 };
    int kver = 0;
    if (!find_linux_banner(&kallsym, image.flat, image.flat_size, &kver)) {
        setup->kernel_version.major = kallsym.version.major;
        setup->kernel_version.minor = kallsym.version.minor;
        setup->kernel_version.patch = kallsym.version.patch;
    }

    if (!root_key) {
        strncpy((char *)setup->superkey, superkey, SUPER_KEY_LEN - 1);
    } else if (superkey && superkey[0]) {
        BYTE digest[SHA256_BLOCK_SIZE];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const BYTE *)superkey, strnlen(superkey, SUPER_KEY_LEN));
        sha256_final(&ctx, digest);
        memcpy(setup->root_superkey, digest, ROOT_SUPER_KEY_HASH_LEN);
    }

    int rc = inject_x86_kpimg(&image, kpimg, kpimg_len);
    if (!rc) rc = write_x86_bzimage(&image, out_path);
    if (!rc) tools_logi("x86 patch done: %s\n", out_path);

    free(kpimg);
    free_x86_bzimage(&image);
    return rc;
}

/*
 * AArch32 .setup.map placement: refuse to drop the map region on top of any
 * kallsyms symbol.
 *
 * kallsyms carries no symbol sizes, so this can only check symbol *starts*.
 * That is sufficient here because the remaining case -- a symbol starting
 * before the page and running into it -- requires its successor to start at or
 * after the page end, and the all-zero check on the input image immediately
 * afterwards rejects any page that actually contains code or data.  Together
 * the two checks generalise to kernels whose layout we have never measured
 * (the real target is a 4.9.193 device kernel) instead of trusting that "the
 * bytes below __init_begin are linker padding" on every kernel.
 */
struct arm32_map_overlap {
    int32_t start;
    int32_t end;
    int32_t hit_index;
    int32_t hit_offset;
    char hit_symbol[KSYM_SYMBOL_LEN];
    char hit_type;
};

static int32_t arm32_map_overlap_cb(int32_t index, char type, const char *symbol, int32_t offset, void *userdata)
{
    struct arm32_map_overlap *d = (struct arm32_map_overlap *)userdata;
    if (offset >= d->start && offset < d->end) {
        d->hit_index = index;
        d->hit_offset = offset;
        d->hit_type = type;
        strncpy(d->hit_symbol, symbol, sizeof(d->hit_symbol) - 1);
        d->hit_symbol[sizeof(d->hit_symbol) - 1] = '\0';
        return 1;
    }
    return 0;
}

int patch_update_img_buf(const char *kimg, int kimg_len, const char *kpimg_path, const char *superkey,
                         bool root_key, const char **additional, extra_config_t *extra_configs,
                         int extra_config_num, char **out_kimg, int *out_kimg_len)
{
    if (!kpimg_path) tools_loge_exit("empty kpimg\n");
    if (!superkey && !root_key) tools_loge_exit("empty superkey\n");
    if (!out_kimg || !out_kimg_len) tools_loge_exit("empty out kernel buffer\n");
    *out_kimg = NULL;
    *out_kimg_len = 0;

    patched_kimg_t pimg = { 0 };
    kernel_file_t kernel_file = { 0 };
    kernel_file.kfile = (char *)kimg;
    kernel_file.kimg = (char *)kimg;
    kernel_file.kfile_len = kimg_len;
    kernel_file.kimg_len = kimg_len;

    int rc = parse_image_patch_info(kernel_file.kimg, kernel_file.kimg_len, &pimg);
    if (rc) tools_loge_exit("parse kernel image error\n");
    // print_image_patch_info(&pimg);

    // kimg base info
    kernel_info_t *kinfo = &pimg.kinfo;

    // kimg kallsym
    char *kallsym_kimg = (char *)malloc(pimg.ori_kimg_len);
    memcpy(kallsym_kimg, pimg.kimg, pimg.ori_kimg_len);
    kallsym_t kallsym = { 0 };
    int kver = 0;
    find_linux_banner(&kallsym, kallsym_kimg, pimg.ori_kimg_len, &kver);
    bool is_gki = kver >= 330240;  // 5.10
    tools_logi("is_gki: %s\n", is_gki ? "true" : "false");
    if (kver > 395008) {
        if(disable_pi_map(kernel_file.kimg, kernel_file.kimg_len))   //395008= (6<<16)+(7<<8)
        {
            tools_logi("kernel have patched or not found\n");
        }else{
            tools_logi("disabled PI_MAP for kernel version > 6.12.23\n");
        }


    }

    // aarch32 port: analyze a 32-bit ARM Image as ARM_LE / is_64=0.
    enum arch_type patch_arch = kinfo->is_arm32 ? ARM_LE : ARM64;
    int patch_is64 = kinfo->is_arm32 ? 0 : 1;
    if (analyze_kallsym_info(&kallsym, kallsym_kimg, pimg.ori_kimg_len, patch_arch, patch_is64)) {
        tools_loge_exit("analyze_kallsym_info error\n");
    }

    // aarch32: a raw 32-bit ARM Image carries no arm64 header, so
    // get_kernel_info() had to fall back to kinfo->kernel_size = file length.
    // That value EXCLUDES .bss (objcopy does not emit the NOBITS .bss into the
    // binary), yet the kernel wipes __bss_start.._end in __mmap_switched long
    // before paging_init runs. Placing start_offset at the file length (as
    // arm64 does with its header image_size, which DOES include .bss) therefore
    // drops both the appended kpimg and the relocated start image inside .bss,
    // where they are zeroed before the paging_init hook ever sees them.
    // Extend kernel_size to the kernel's real RAM footprint (_end - _text) and
    // keep a 1 MiB guard so an appended DTB / ATAGS parked right after _end
    // stays clear on real devices.
    if (kinfo->is_arm32) {
        int32_t end_off = get_symbol_offset_zero(&kallsym, kallsym_kimg, "_end");
        if (!end_off) end_off = get_symbol_offset_zero(&kallsym, kallsym_kimg, "__bss_stop");
        if (end_off <= 0) {
            /* A vendor 32-bit ARM kernel may not carry the linker-defined
             * _end/__bss_stop in kallsyms at all (measured on the XTC
             * 4.9.193-perf image: both absent, while _edata = 0x163bfb8 and the
             * highest bss symbol = 0x1889a84, i.e. the bss is ~2.4 MiB -- so
             * "_edata + guard" would still land inside bss).  Bound the bss end
             * from measurements instead of guessing:
             *   - _edata / __bss_start: start of bss,
             *   - highest kallsyms symbol of type 'b'/'B': every bss object
             *     lies inside bss, so this is a lower bound on _end.
             * Take the larger one; the SZ_1M guard then covers the last bss
             * object and any appended DTB/ATAGS parked after _end. */
            int32_t bss_start_off = get_symbol_offset_zero(&kallsym, kallsym_kimg, "_edata");
            if (!bss_start_off) bss_start_off = get_symbol_offset_zero(&kallsym, kallsym_kimg, "__bss_start");
            int32_t bss_max_off = get_bss_extent_symbol_offset(&kallsym, kallsym_kimg);
            end_off = bss_start_off > bss_max_off ? bss_start_off : bss_max_off;
            if (end_off > 0) {
                tools_logw("arm32: no _end/__bss_stop in kallsyms; measured bss bound 0x%x (_edata 0x%x, highest bss symbol 0x%x)\n",
                           end_off, bss_start_off, bss_max_off);
            }
        }
        if (end_off > 0) {
            if (end_off > kinfo->kernel_size) {
                tools_logi("arm32 kernel_size: file 0x%x -> image 0x%x (+.bss) +guard 0x%x\n", kinfo->kernel_size,
                           end_off, SZ_1M);
                kinfo->kernel_size = align_ceil(end_off, SZ_4K) + SZ_1M;
            }
        } else {
            tools_loge_exit("arm32: cannot resolve _end/__bss_stop/_edata/bss extent, start_offset would land inside .bss\n");
        }
    }
    int align_kernel_size = align_ceil(kinfo->kernel_size, SZ_4K);

    // locate the kernel's own IKCONFIG gzip blob; runtime puff-inflates it
    size_t kcfg_start = 0, kcfg_bytes = 0;
    int kcfg_rc = find_ikconfig_blob(kallsym_kimg, pimg.ori_kimg_len, &kcfg_start, &kcfg_bytes);
    if (kcfg_rc) {
        tools_logw("kernel IKCONFIG blob not found (rc=%d), kconfig unavailable at runtime\n", kcfg_rc);
    } else {
        tools_logi("ikconfig gzip blob at 0x%zx, size 0x%zx (runtime puff)\n", kcfg_start, kcfg_bytes);
    }

    // kpimg
    char *kpimg = NULL;
    int kpimg_len = 0;
    read_file_align(kpimg_path, &kpimg, &kpimg_len, 0x10);

    // extra
    int extra_size = 0;
    int extra_num = 0;

    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        if (config->is_path && config->extra_type == EXTRA_TYPE_NONE) {
            tools_loge_exit("extra type none\n");
        }
        if (config->set_event && strnlen(config->set_event, EXTRA_EVENT_LEN) >= EXTRA_EVENT_LEN) {
            tools_loge_exit("extra event too long: %s\n", config->set_event);
        }
        if (config->set_name && strnlen(config->set_name, EXTRA_NAME_LEN) >= EXTRA_NAME_LEN) {
            tools_loge_exit("extra name too long: %s\n", config->set_event);
        }

        patch_extra_item_t *item = NULL;
        if (config->item && config->data) {
            item = config->item;
        } else if (config->is_path) {
            // todo: free
            item = (patch_extra_item_t *)malloc(sizeof(patch_extra_item_t));
            memset(item, 0, sizeof(patch_extra_item_t));
            const char *path = config->path;
            char *data;
            int len = 0;
            read_file_align(path, &data, &len, EXTRA_ALIGN);
            config->data = data;
            item->con_size = len;
            // if name not set
            if (!config->set_name) {
                if (config->extra_type == EXTRA_TYPE_KPM) {
                    kpm_info_t kpm_info = { 0 };
                    int rc = get_kpm_info(data, len, &kpm_info);
                    if (rc) tools_loge_exit("can get infomation of kpm, path: %s\n", path);
                    strcpy(item->name, kpm_info.name);
                } else {
                    char *rsp = strrchr(path, '/');
                    strncpy(item->name, rsp ? rsp + 1 : path, EXTRA_NAME_LEN - 1);
                }
            }
        } else {
            const char *name = config->name;
            for (int j = 0; j < pimg.embed_item_num; j++) {
                item = pimg.embed_item[j];
                if (strcmp(name, item->name)) continue;
                if (is_be() ^ kinfo->is_be) {
                    item->type = i32swp(item->type);
                    item->priority = i32swp(item->priority);
                    item->con_size = i32swp(item->con_size);
                    item->args_size = i32swp(item->args_size);
                    item->flags = i32swp(item->flags);
                }
                sanitize_legacy_extra_item(item);
                if (!config->set_args && item->args_size > 0) {
                    config->set_args = (char *)item + sizeof(*item);
                }
                config->extra_type = item->type;
                config->data = (char *)item + sizeof(*item) + item->args_size;
                break;
            }
        }
        if (!item) tools_loge_exit("empty extra item\n");
        strcpy(item->magic, EXTRA_HDR_MAGIC);
        config->item = item;
        item->type = config->extra_type;
        if (config->set_args) item->args_size = align_ceil(strlen(config->set_args), EXTRA_ALIGN);
        if (config->set_name) strcpy(item->name, config->set_name);
        if (config->set_event) strcpy(item->event, config->set_event);
        if (config->priority) item->priority = config->priority;
    }

    qsort(extra_configs, extra_config_num, sizeof(extra_config_t), extra_compare);

    extra_size += sizeof(patch_extra_item_t); // ending with empty item

    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        extra_num++;
        extra_size += sizeof(patch_extra_item_t);
        extra_size += config->item->args_size;
        extra_size += config->item->con_size;
    }

    // copy to out image
    int ori_kimg_len = pimg.ori_kimg_len;
    int align_kimg_len = align_ceil(ori_kimg_len, SZ_4K);
    int out_img_len = align_kimg_len + kpimg_len;
    int out_all_len = out_img_len + extra_size;

    int start_offset = align_kernel_size;
    if (out_all_len > start_offset) {
        start_offset = align_ceil(out_all_len, SZ_4K);
        tools_logi("patch overlap, move start from 0x%x to 0x%x\n", align_kernel_size, start_offset);
    }
    tools_logi("layout kimg: 0x0,0x%x, kpimg: 0x%x,0x%x, extra: 0x%x,0x%x, end: 0x%x, start: 0x%x\n", ori_kimg_len,
               align_kimg_len, kpimg_len, out_img_len, extra_size, out_all_len, start_offset);

    kernel_file_t out_kernel_file;
    new_kernel_file(&out_kernel_file, &kernel_file, out_all_len, (bool)(is_be() ^ kinfo->is_be));
    memcpy(out_kernel_file.kimg, pimg.kimg, ori_kimg_len);
    memset(out_kernel_file.kimg + ori_kimg_len, 0, align_kimg_len - ori_kimg_len);
    memcpy(out_kernel_file.kimg + align_kimg_len, kpimg, kpimg_len);

    // set preset
    preset_t *preset = (preset_t *)(out_kernel_file.kimg + align_kimg_len);

    setup_header_t *header = &preset->header;
    version_t ver = header->kp_version;
    uint32_t ver_num = (ver.major << 16) + (ver.minor << 8) + ver.patch;
    bool is_android = header->config_flags & CONFIG_ANDROID;
    bool is_debug = header->config_flags & CONFIG_DEBUG;
    bool is_x86_64 = header->config_flags & CONFIG_FLAG_X86_64;
    tools_logi("kpimg version: %x\n", ver_num);
    tools_logi("kpimg compile time: %s\n", header->compile_time);
    tools_logi("kpimg config: %s, %s, %s\n", is_android ? "android" : "linux",
               is_debug ? "debug" : "release",
               is_x86_64 ? "x86_64"
                         : (blob_entry_is_arm32(kpimg, kpimg_len) == 1 ? "arm32" : "arm64"));

    setup_preset_t *setup = &preset->setup;
    memset(setup, 0, sizeof(preset->setup));

    setup->kernel_version.major = kallsym.version.major;
    setup->kernel_version.minor = kallsym.version.minor;
    setup->kernel_version.patch = kallsym.version.patch;
    setup->kimg_size = ori_kimg_len;
    setup->kpimg_size = kpimg_len;

    setup->kernel_size = kinfo->kernel_size;
    setup->page_shift = kinfo->page_shift;
    setup->setup_offset = align_kimg_len;
    setup->start_offset = start_offset;
    setup->extra_size = extra_size;

    int map_start, map_max_size;
    if (kinfo->is_arm32) {
        /*
         * AArch32: neither a kernel-text "map anchor hole" nor the BSS tail can
         * host .setup.map.  Both conclusions are measured on the 5.15.167
         * oracle, not assumed:
         *
         *  - select_map_area() picks a symbol and assumes the bytes after it are
         *    disposable function-alignment NOP padding.  That is an arm64/GKI
         *    property.  arm32 text has no such padding, so the picked region is
         *    LIVE code: tcp_init_sock at 0xd8c0ec is a real `bl`, and the
         *    0x890-byte .setup.map destroyed 14 live tcp functions down to
         *    tcp_sendmsg_locked.
         *
         *  - the tail [_end, round_up(_end,1MB)) is NOT executable after the
         *    real paging_init.  arch/arm/mm/mmu.c map_kernel(), called from
         *    paging_init(), splits the kernel sections as
         *        [kernel_sec_start,  round_up(__init_end,1MB)) MT_MEMORY_RWX
         *        [round_up(__init_end,1MB), round_up(_end,1MB)) MT_MEMORY_RW
         *    and on ARMv7 with XP build_mem_type_table() sets
         *    `mem_types[MT_MEMORY_RW].prot_sect |= PMD_SECT_XN`.  Measured:
         *    __init_end = 0xc1b00000, _end = 0xc1d8ac48, so all 0x753b8 bytes
         *    of tail lie in the NX half -- _paging_init would prefetch-abort the
         *    moment map_kernel() returned.
         *
         * The only region that is executable both before AND after
         * map_kernel(), is never zeroed, never freed and holds no live kernel
         * content is the SECTION_SIZE alignment padding the linker inserts
         * immediately below __init_begin.  STRICT_KERNEL_RWX forces the .init
         * section to be section-aligned (vmlinux.lds.S:
         * `. = ALIGN(1<<SECTION_SHIFT)` before __init_begin), arm_memblock_init()
         * already reserves the whole image via
         * `memblock_reserve(__pa(KERNEL_START), KERNEL_END - KERNEL_START)`, and
         * the padding is below __init_begin so free_initmem() does not touch it.
         * Measured on the oracle: [__stop_unwind_tab 0xc18a36a4, __init_begin
         * 0xc1900000) is 0x5c95c bytes of pure zeros containing no symbols, and
         * it is inside the RWX half.
         *
         * Placement is __init_begin - MAP_MAX_SIZE, validated by self-checks
         * that do not assume this kernel's layout (the real target is an
         * unmeasured 4.9.193 device kernel): the region must be in the image,
         * strictly below __init_begin, must contain no kallsyms symbol start,
         * and must be all-zero in the input image.  Any failure is fatal --
         * a wrong map_offset yields an unbootable image.
         */
        int32_t init_begin_off = get_symbol_offset_zero(&kallsym, kallsym_kimg, "__init_begin");
        int32_t init_end_off = get_symbol_offset_zero(&kallsym, kallsym_kimg, "__init_end");
        /* Test hook: force the search path on a kernel that DOES have __init_begin, so the
         * search-based placement can be validated on the QEMU oracle as well. */
        const char *force_search_str = getenv("KP_FORCE_MAP_SEARCH");
        int32_t force_search = force_search_str && atoi(force_search_str) ? 1 : 0;
        if (force_search && init_begin_off > 0) {
            tools_logw("arm32: KP_FORCE_MAP_SEARCH=1 -> ignoring __init_begin 0x%x and searching\n", init_begin_off);
            init_begin_off = 0;
        }
        int32_t last_content_off = get_symbol_offset_zero(&kallsym, kallsym_kimg, "__stop_unwind_tab");
        if (!last_content_off) last_content_off = get_symbol_offset_zero(&kallsym, kallsym_kimg, "__end_rodata");
        if (last_content_off <= 0) tools_loge_exit("arm32: cannot resolve __stop_unwind_tab/__end_rodata\n");

        map_max_size = MAP_MAX_SIZE;
        int32_t map_ceiling_off;
        if (init_begin_off > 0) {
            map_ceiling_off = init_begin_off;
            map_start = (int32_t)(init_begin_off - align_ceil(map_max_size, (int32_t)MAP_ALIGN));
            if (map_start < last_content_off) {
                tools_loge_exit("arm32: no linker padding below __init_begin (last content 0x%x, map_start 0x%x)\n",
                                last_content_off, map_start);
            }
        } else {
            /* Vendor kernels omit the linker-defined __init_begin/__init_end from
             * kallsyms entirely.  Measured on the real XTC 4.9.193-perf image (read-only
             * analysis, see port/XTC_DEVICE_KERNEL_READONLY_REPORT.md): neither symbol
             * exists, _sinittext = 0x13f82e0 is not SECTION-aligned (so there is no
             * STRICT_KERNEL_RWX alignment padding), and the 0x5a0 bytes immediately below
             * _sinittext are NOT zero.  The fixed "below __init_begin" formula is therefore
             * unusable there, so search instead.  The search only proposes a candidate:
             * checks 1a-1d below still validate it (inside the image, below the first init
             * symbol, no kallsyms symbol start inside, all-zero in the input image). */
            int32_t sinit_off = get_symbol_offset_zero(&kallsym, kallsym_kimg, "_sinittext");
            if (sinit_off <= 0)
                tools_loge_exit("arm32: cannot resolve __init_begin or _sinittext to place .setup.map\n");
            map_ceiling_off = sinit_off;
            map_start = search_zero_map_region(&kallsym, kallsym_kimg, pimg.ori_kimg_len, sinit_off, map_max_size,
                                               (int32_t)MAP_ALIGN);
            if (map_start <= 0)
                tools_loge_exit("arm32: no usable all-zero symbol-free region of 0x%x bytes below _sinittext 0x%x\n",
                                map_max_size, sinit_off);
            tools_logw("arm32: __init_begin absent; searched .setup.map region 0x%x..0x%x below _sinittext 0x%x\n",
                       map_start, map_start + map_max_size, sinit_off);
        }

        int32_t map_end_off = map_start + map_max_size;

        /*
         * 1a. In range, inside the image, and strictly below __init_begin.
         */
        if (map_start < 0 || map_end_off > pimg.ori_kimg_len) {
            tools_loge_exit("arm32: map region 0x%x..0x%x is outside the image (0x%x)\n", map_start, map_end_off,
                            pimg.ori_kimg_len);
        }
        if (map_end_off > map_ceiling_off) {
            tools_loge_exit("arm32: map region 0x%x..0x%x overlaps the init ceiling 0x%x\n", map_start, map_end_off,
                            map_ceiling_off);
        }

        /*
         * 1b. Executability, without any VA and without any alignment assumption.
         *
         * map_kernel() splits the kernel sections as
         *   [kernel_sec_start, round_up(__pa(__init_end), 1M))  MT_MEMORY_RWX
         *   [round_up(__pa(__init_end), 1M), kernel_sec_end)    MT_MEMORY_RW
         * and on ARMv7 with XP the MT_MEMORY_RW section descriptor carries
         * PMD_SECT_XN (build_mem_type_table()).  Since
         *   __pa(map_end) <= __pa(__init_begin) < __pa(__init_end)
         *                  <= round_up(__pa(__init_end), 1M)
         * the region is ALWAYS in the RWX half -- for any kernel, at any
         * alignment.  The earlier hard assertion that __init_end be
         * SECTION-aligned was both unnecessary and wrong: it was evaluated in
         * OFFSET space, where a 1 MB-aligned VA is not 1 MB-aligned (on this
         * kernel __init_end VA 0xc1b00000 has offset 0x18f8000, because _text is
         * 0xc0208000).  It would have rejected a perfectly good 4.9 kernel, so
         * it is now informational.
         */
        if (init_end_off > 0 && (init_end_off & (int32_t)(SZ_1M - 1))) {
            tools_logi("arm32: note: __init_end offset 0x%x is not SECTION-aligned. This is expected and NOT an "
                       "error: the offset base (kernel VA) is not 1MB-aligned either, and a region below "
                       "__init_begin lies in the RWX half regardless of alignment.\n",
                       init_end_off);
        }

        /*
         * 1c. No kallsyms symbol may start inside the region.  kptools has the
         * full symbol table, so on the unmeasured 4.9 device kernel this is what
         * replaces trusting that the bytes below __init_begin are padding.
         */
        struct arm32_map_overlap overlap = { 0 };
        overlap.start = map_start;
        overlap.end = map_end_off;
        overlap.hit_index = -1;
        on_each_symbol(&kallsym, kallsym_kimg, &overlap, arm32_map_overlap_cb);
        if (overlap.hit_index >= 0) {
            tools_loge_exit("arm32: refusing to place .setup.map at 0x%x..0x%x: kallsyms has '%s' (%c, index %d) "
                            "at 0x%x\n",
                            map_start, map_end_off, overlap.hit_symbol, overlap.hit_type, overlap.hit_index,
                            overlap.hit_offset);
        }

        /*
         * 1d. The target bytes must be zero in the INPUT image.  This is the
         * check that matters most on the real device: if that padding carries
         * data or a relocation there, overwriting it would brick boot, and a
         * hard refusal is the correct outcome.
         *
         * kallsym_kimg is the pristine copy of the input image taken at the top
         * of this function (the only code that ever modified it is the arm64
         * NOP-sync, which arm32 skips), and disable_pi_map() edits a different
         * buffer (kernel_file.kimg), so these are the bytes the kernel will
         * actually load at kernel_va + map_offset.
         */
        for (int32_t i = map_start; i < map_end_off; i++) {
            if (kallsym_kimg[i]) {
                tools_loge_exit("arm32: refusing to place .setup.map at 0x%x: input image byte at 0x%x is 0x%02x, "
                                "not padding\n",
                                map_start, i, (unsigned char)kallsym_kimg[i]);
            }
        }

        setup->map_offset = map_start;
        setup->map_max_size = map_max_size;
        tools_logi("arm32 map region: 0x%x..0x%x (size 0x%x); below __init_begin 0x%x, last symbol before it "
                   "'__stop_unwind_tab'/_rodata 0x%x; region is symbol-free, zero-filled in the input image and "
                   "in the RWX half of map_kernel()\n",
                   map_start, map_end_off, map_max_size, init_begin_off, last_content_off);
        // NOTE: no "Synced NOP modifications" pass for arm32.  That pass exists
        // only to bake select_map_area()'s NOP-stomping of kernel text into the
        // output image; arm32 no longer stomps anything.  Its disappearance from
        // the arm32 log is the observable proof that the anchor path is dead;
        // running it here would additionally copy `map_max_size * 2` bytes of
        // the *unmodified* kallsym_kimg into the output image, undoing any
        // earlier in-place edit to the image (e.g. disable_pi_map()).
    } else {
        select_map_area(&kallsym, kallsym_kimg, pimg.ori_kimg_len, &map_start, &map_max_size, is_gki);
        setup->map_offset = map_start;
        setup->map_max_size = map_max_size;
        tools_logi("map_start: 0x%x, max_size: 0x%x\n", map_start, map_max_size);

        int sync_start = map_start;
        int sync_size = map_max_size * 2;
        if (sync_start + sync_size > ori_kimg_len) {
            sync_size = ori_kimg_len - sync_start;
        }
        if (sync_size > 0) {
            memcpy(out_kernel_file.kimg + sync_start, kallsym_kimg + sync_start, sync_size);
            tools_logi("Synced NOP modifications from kallsym_kimg to output file (offset: 0x%x, size: 0x%x)\n",
                       sync_start, sync_size);
        }
    }

    const char *symbol_lookup_anchor_name = 0;
    setup->sprintf_offset = get_usable_symbol_offset_try(&kallsym, kallsym_kimg, ori_kimg_len, "sprintf");
    setup->symbol_lookup_anchor_offset =
        select_symbol_lookup_anchor_offset(&kallsym, kallsym_kimg, ori_kimg_len, &symbol_lookup_anchor_name);
    setup->kallsyms_lookup_name_offset =
        get_usable_symbol_offset_try(&kallsym, kallsym_kimg, ori_kimg_len, "kallsyms_lookup_name");
    if (setup->symbol_lookup_anchor_offset && setup->sprintf_offset) {
        tools_logi("prefer runtime forward scan anchor for kallsyms_lookup_name: %s, offset: 0x%08lx\n",
                   symbol_lookup_anchor_name, (unsigned long)setup->symbol_lookup_anchor_offset);
    } else if (setup->kallsyms_lookup_name_offset) {
        tools_logi("fallback to direct kallsyms_lookup_name symbol\n");
    } else {
        tools_loge_exit("no usable symbol scan anchor/sprintf chain and no kallsyms_lookup_name symbol\n");
    }

    setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "printk");
    if (!setup->printk_offset) setup->printk_offset = get_symbol_offset_zero(&kallsym, kallsym_kimg, "_printk");
    if (!setup->printk_offset) tools_loge_exit("no symbol printk\n");

    if ((is_be() ^ kinfo->is_be)) {
        setup->kimg_size = i64swp(setup->kimg_size);
        setup->kernel_size = i64swp(setup->kernel_size);
        setup->page_shift = i64swp(setup->page_shift);
        setup->setup_offset = i64swp(setup->setup_offset);
        setup->start_offset = i64swp(setup->start_offset);
        setup->extra_size = i64swp(setup->extra_size);
        setup->map_offset = i64swp(setup->map_offset);
        setup->map_max_size = i64swp(setup->map_max_size);
        setup->kallsyms_lookup_name_offset = i64swp(setup->kallsyms_lookup_name_offset);
        setup->sprintf_offset = i64swp(setup->sprintf_offset);
        setup->symbol_lookup_anchor_offset = i64swp(setup->symbol_lookup_anchor_offset);
        setup->paging_init_offset = i64swp(setup->paging_init_offset);
        setup->printk_offset = i64swp(setup->printk_offset);
    }

    // map symbol
    fillin_map_symbol(&kallsym, kallsym_kimg, &setup->map_symbol, kinfo->is_be);

    // header backup
    memcpy(setup->header_backup, kallsym_kimg, sizeof(setup->header_backup));

    // start symbol
    fillin_patch_config(&kallsym, kallsym_kimg, ori_kimg_len, &setup->patch_config, kinfo->is_be, 0);

    // superkey
    if (!root_key) {
        tools_logi("superkey: %s\n", superkey);
        strncpy((char *)setup->superkey, superkey, SUPER_KEY_LEN - 1);
    } else if (superkey && superkey[0] != '\0') {
        int len = SHA256_BLOCK_SIZE > ROOT_SUPER_KEY_HASH_LEN ? ROOT_SUPER_KEY_HASH_LEN : SHA256_BLOCK_SIZE;
        BYTE buf[SHA256_BLOCK_SIZE];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const BYTE *)superkey, strnlen(superkey, SUPER_KEY_LEN));
        sha256_final(&ctx, buf);
        memcpy(setup->root_superkey, buf, len);
        char *hexstr = bytes_to_hexstr(setup->root_superkey, len);
        tools_logi("root superkey hash: %s\n", hexstr);
        free(hexstr);
    } else {
        memset(setup->root_superkey, 0, ROOT_SUPER_KEY_HASH_LEN);
        tools_logi("root_key mode with empty superkey: root_superkey zeroed\n");
    }

    // modify kernel entry
    int paging_init_offset = get_symbol_offset_exit(&kallsym, kallsym_kimg, "paging_init");
    setup->paging_init_offset = relo_branch_func(kallsym_kimg, paging_init_offset);
    int text_offset = align_kimg_len + SZ_4K;
    if (kinfo->is_arm32) {
        // ARM (A32) B from the kernel entry (offset 0) to setup_entry.
        if (!b_arm((uint32_t *)(out_kernel_file.kimg + kinfo->b_stext_insn_offset), kinfo->b_stext_insn_offset,
                   text_offset))
            tools_loge_exit("arm32 entry branch out of range: 0x%x -> 0x%x\n", kinfo->b_stext_insn_offset, text_offset);
    } else {
        b((uint32_t *)(out_kernel_file.kimg + kinfo->b_stext_insn_offset), kinfo->b_stext_insn_offset, text_offset);
    }

    // additional [len key=value] set
    char *addition_pos = setup->additional;
    for (int i = 0;; i++) {
        const char *kv = additional[i];
        if (!kv) break;
        if (!strchr(kv, '=')) tools_loge_exit("addition must be format of key=value\n");

        int kvlen = strlen(kv);
        if (kvlen > 127) tools_loge_exit("addition %s too long\n", kv);
        if (addition_pos + kvlen + 1 > setup->additional + ADDITIONAL_LEN) tools_loge_exit("no memory for addition\n");

        *addition_pos = (char)kvlen;
        addition_pos++;

        tools_logi("adding addition: %s\n", kv);
        strcpy(addition_pos, kv);
        addition_pos += kvlen;
    }

// append extra
    int current_offset = out_img_len;
    for (int i = 0; i < extra_config_num; i++) {
        extra_config_t *config = extra_configs + i;
        patch_extra_item_t *item = config->item;
        const char *type = extra_type_str(item->type);
        tools_logi("embedding %s, name: %s, priority: %d, event: %s, args: %s, size: 0x%x+0x%x+0x%x\n", type,
                   item->name, item->priority, item->event, config->set_args ?: "", (int)sizeof(*item), item->args_size,
                   item->con_size);

        int args_len = item->args_size;
        int con_len = item->con_size;

        if (is_be() ^ kinfo->is_be) {
            item->type = i32swp(item->type);
            item->priority = i32swp(item->priority);
            item->con_size = i32swp(item->con_size);
            item->args_size = i32swp(item->args_size);
            item->flags = i32swp(item->flags);
        }

        extra_append(out_kernel_file.kimg, (void *)item, sizeof(*item), &current_offset);
        if (args_len > 0) extra_append(out_kernel_file.kimg, (void *)config->set_args, args_len, &current_offset);
        extra_append(out_kernel_file.kimg, (void *)config->data, con_len, &current_offset);
    }

    // record IKCONFIG gzip blob location for runtime puff inflation
    if (!kcfg_rc) {
        setup->kconfig_offset = (int64_t)kcfg_start;
        setup->kconfig_size = (int64_t)kcfg_bytes;
    }

    if ((is_be() ^ kinfo->is_be)) {
        setup->kconfig_offset = i64swp(setup->kconfig_offset);
        setup->kconfig_size = i64swp(setup->kconfig_size);
    }

    // guard extra
    patch_extra_item_t empty_item = { 0 };
    extra_append(out_kernel_file.kimg, (void *)&empty_item, sizeof(empty_item), &current_offset);

    // transfer ownership of the patched kernel buffer to the caller
    *out_kimg = out_kernel_file.kfile;
    *out_kimg_len = out_kernel_file.kfile_len;
    out_kernel_file.kfile = NULL;

    // free
    free(kallsym_kimg);
    free(kpimg);
    free_kernel_file(&out_kernel_file);

    return 0;
}

int patch_update_img(const char *kimg_path, const char *kpimg_path, const char *out_path, const char *superkey,
                     bool root_key, const char **additional, extra_config_t *extra_configs, int extra_config_num)
{
    set_log_enable(true);

    if (!kpimg_path) tools_loge_exit("empty kpimg\n");
    if (!out_path) tools_loge_exit("empty out image path\n");
    if (!superkey && !root_key) tools_loge_exit("empty superkey\n");

    char *probe = NULL;
    int probe_len = 0;
    read_file(kimg_path, &probe, &probe_len);
    bool x86_bzimage = is_x86_bzimage(probe, probe_len);
    free(probe);
    if (x86_bzimage) {
        int rc = patch_update_x86(kimg_path, kpimg_path, out_path, superkey, root_key, additional,
                                  extra_config_num);
        set_log_enable(false);
        return rc;
    }

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);
    if (kernel_file.is_uncompressed_img) tools_logw("kernel image with UNCOMPRESSED_IMG header\n");

    char *out_kimg = NULL;
    int out_kimg_len = 0;
    int rc = patch_update_img_buf(kernel_file.kimg, kernel_file.kimg_len, kpimg_path, superkey, root_key,
                                  additional, extra_configs, extra_config_num, &out_kimg, &out_kimg_len);

    if (!rc) {
        if (kernel_file.is_uncompressed_img) {
            kernel_file_t out_file = { 0 };
            new_kernel_file(&out_file, &kernel_file, out_kimg_len, false);
            memcpy(out_file.kimg, out_kimg, out_kimg_len);
            write_kernel_file(&out_file, out_path);
            free_kernel_file(&out_file);
        } else {
            write_file(out_path, out_kimg, out_kimg_len, false);
        }
        tools_logi("patch done: %s\n", out_path);
    }

    if (out_kimg) free(out_kimg);
    free_kernel_file(&kernel_file);

    set_log_enable(false);
    return rc;
}

int unpatch_img(const char *kimg_path, const char *out_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    if (!out_path) tools_loge_exit("empty out image path\n");

    char *probe = NULL;
    int probe_len = 0;
    read_file(kimg_path, &probe, &probe_len);
    bool x86_bzimage = is_x86_bzimage(probe, probe_len);
    free(probe);
    if (x86_bzimage) {
        set_log_enable(true);
        x86_bzimage_t image;
        if (load_x86_bzimage(kimg_path, &image)) {
            set_log_enable(false);
            return -1;
        }
        int rc = remove_x86_kpimg(&image);
        if (!rc) rc = write_x86_bzimage(&image, out_path);
        free_x86_bzimage(&image);
        set_log_enable(false);
        return rc;
    }

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    preset_t *preset = get_preset(kernel_file.kimg, kernel_file.kimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");

    // todo: check whether the endian is different or not
    memcpy(kernel_file.kimg, preset->setup.header_backup, sizeof(preset->setup.header_backup));
    int kimg_size = preset->setup.kimg_size ?: ((char *)preset - kernel_file.kimg);
    update_kernel_file_img_len(&kernel_file, kimg_size, false);

    write_kernel_file(&kernel_file, out_path);
    free_kernel_file(&kernel_file);
    return 0;
}

int reset_key(const char *kimg_path, const char *out_path, const char *superkey)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    if (!out_path) tools_loge_exit("empty out image path\n");
    if (!superkey) tools_loge_exit("empty superkey\n");

    if (strlen(superkey) <= 0) tools_loge_exit("empty superkey\n");
    if (strlen(superkey) >= SUPER_KEY_LEN) tools_loge_exit("too long superkey\n");

    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    preset_t *preset = get_preset(kernel_file.kimg, kernel_file.kimg_len);
    if (!preset) tools_loge_exit("not patched kernel image\n");

    char *origin_key = strdup((char *)preset->setup.superkey);
    strcpy((char *)preset->setup.superkey, superkey);
    tools_logi("reset superkey: %s -> %s\n", origin_key, preset->setup.superkey);

    write_kernel_file(&kernel_file, out_path);

    free(origin_key);
    free_kernel_file(&kernel_file);

    return 0;
}

int dump_kallsym(const char *kimg_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    set_log_enable(true);

    char *probe = 0;
    int probe_len = 0;
    read_file(kimg_path, &probe, &probe_len);
    bool bzimage = is_x86_bzimage(probe, probe_len);
    free(probe);
    if (bzimage) {
        x86_bzimage_t image;
        if (load_x86_bzimage(kimg_path, &image)) {
            fprintf(stderr, "load x86 bzImage error\n");
            return -1;
        }
        kallsym_t kallsym;
        int rc = analyze_kallsym_info(&kallsym, image.flat, image.flat_size, X86_64, 1);
        if (rc) {
            fprintf(stderr, "analyze x86 kallsyms error\n");
        } else {
            dump_all_symbols(&kallsym, image.flat);
        }
        free_x86_bzimage(&image);
        set_log_enable(false);
        return rc;
    }

    // read image files
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    kallsym_t kallsym;
    // aarch32 port: a 32-bit ARM Image has no arm64 header; analyze it as ARM_LE.
    int dump_is64 = !is_arm32_kernel_image(kernel_file.kimg, kernel_file.kimg_len);
    enum arch_type dump_arch = dump_is64 ? ARM64 : ARM_LE;
    if (analyze_kallsym_info(&kallsym, kernel_file.kimg, kernel_file.kimg_len, dump_arch, dump_is64)) {
        fprintf(stdout, "analyze_kallsym_info error\n");
        return -1;
    }
    dump_all_symbols(&kallsym, kernel_file.kimg);
    set_log_enable(false);
    free_kernel_file(&kernel_file);
    return 0;
}
int dump_ikconfig(const char *kimg_path)
{
    if (!kimg_path) tools_loge_exit("empty kernel image\n");
    set_log_enable(true);

    char *probe = 0;
    int probe_len = 0;
    read_file(kimg_path, &probe, &probe_len);
    bool bzimage = is_x86_bzimage(probe, probe_len);
    free(probe);
    if (bzimage) {
        x86_bzimage_t image;
        if (load_x86_bzimage(kimg_path, &image)) return -1;
        int rc = dump_all_ikconfig(image.flat, image.flat_size);
        free_x86_bzimage(&image);
        set_log_enable(false);
        return rc;
    }

    // read image files
    kernel_file_t kernel_file;
    read_kernel_file(kimg_path, &kernel_file);

    
    dump_all_ikconfig(kernel_file.kimg,kernel_file.kimg_len);
    set_log_enable(false);
    free_kernel_file(&kernel_file);
    return 0;
}
