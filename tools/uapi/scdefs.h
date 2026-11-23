/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_UAPI_SCDEF_H_
#define _KP_UAPI_SCDEF_H_

#include <ktypes.h>

static inline long hash_key(const char *key)
{
    long hash = 1000000007;
    for (int i = 0; key[i]; i++) {
        hash = hash * 31 + key[i];
    }
    return hash;
}

#define SUPERCALL_HELLO_ECHO "hello1158"

// #define __NR_supercall __NR3264_truncate // 45
#define __NR_supercall 45

#define SUPERCALL_HELLO 0x1000
#define SUPERCALL_KLOG 0x1004

#define SUPERCALL_BUILD_TIME 0x1007
#define SUPERCALL_KERNELPATCH_VER 0x1008
#define SUPERCALL_KERNEL_VER 0x1009


#define SUPERCALL_SKEY_GET 0x100a
#define SUPERCALL_SKEY_SET 0x100b
#define SUPERCALL_SKEY_ROOT_ENABLE 0x100c
#define SUPERCALL_AP_LOAD_PACKAGE_CONFIG 0x100d

#define SUPERCALL_SU 0x1010
#define SUPERCALL_SU_TASK 0x1011 // syscall(__NR_gettid)

#define SUPERCALL_KPM_LOAD 0x1020
#define SUPERCALL_KPM_UNLOAD 0x1021
#define SUPERCALL_KPM_CONTROL 0x1022

#define SUPERCALL_KPM_NUMS 0x1030
#define SUPERCALL_KPM_LIST 0x1031
#define SUPERCALL_KPM_INFO 0x1032

#define KPM_LOAD_RESULT_MAGIC 0x4b504d52
#define KPM_LOAD_ERROR_MESSAGE_LEN 160

struct kpm_load_result
{
    unsigned int magic;
    unsigned int size;
    int code;
    char message[KPM_LOAD_ERROR_MESSAGE_LEN];
};

struct kernel_storage
{
    void *data;
    int len;
};

#define SUPERCALL_KSTORAGE_ALLOC_GROUP 0x1040
#define SUPERCALL_KSTORAGE_WRITE 0x1041
#define SUPERCALL_KSTORAGE_READ 0x1042
#define SUPERCALL_KSTORAGE_LIST_IDS 0x1043
#define SUPERCALL_KSTORAGE_REMOVE 0x1044
#define SUPERCALL_KSTORAGE_REMOVE_GROUP 0x1045

#define SUPERCALL_CONTROL_FEATURE 0x1046

#define KSTORAGE_SU_LIST_GROUP 0
#define KSTORAGE_EXCLUDE_LIST_GROUP 1
#define KSTORAGE_UNUSED_GROUP_2 2
#define KSTORAGE_UNUSED_GROUP_3 3

#define SUPERCALL_BOOTLOG 0x10fd
#define SUPERCALL_PANIC 0x10fe
#define SUPERCALL_TEST 0x10ff

#define SUPERCALL_KEY_MAX_LEN 0x40
#define SUPERCALL_SCONTEXT_LEN 0x60

struct su_profile
{
    uid_t uid;
    uid_t to_uid;
    char scontext[SUPERCALL_SCONTEXT_LEN];
};

#ifdef ANDROID
#define SH_PATH "/system/bin/sh"
#define SU_PATH "/system/bin/kp"
#define LEGACY_SU_PATH "/system/bin/su"
#define ECHO_PATH "/system/bin/echo"
#define KERNELPATCH_DATA_DIR "/data/adb/kp"
#define KERNELPATCH_MODULE_DATA_DIR KERNELPATCH_DATA_DIR "/modules"
#define APD_PATH "/data/adb/apd"
#define ALL_ALLOW_SCONTEXT "u:r:kp:s0"
#define ALL_ALLOW_SCONTEXT_MAGISK "u:r:magisk:s0"
#define ALL_ALLOW_SCONTEXT_KERNEL "u:r:kernel:s0"
#else
#define SH_PATH "/usr/bin/sh"
#define ECHO_PATH "/usr/bin/echo"
#define SU_PATH "/usr/bin/kp"
#define ALL_ALLOW_SCONTEXT "u:r:kernel:s0"
#endif

#define SU_PATH_MAX_LEN 128

#define SUPERCMD "/system/bin/truncate"

#define SAFE_MODE_FLAG_FILE "/dev/.safemode"

#define SUPERCALL_SU_GRANT_UID 0x1100
#define SUPERCALL_SU_REVOKE_UID 0x1101
#define SUPERCALL_SU_NUMS 0x1102
#define SUPERCALL_SU_LIST 0x1103
#define SUPERCALL_SU_PROFILE 0x1104
#define SUPERCALL_SU_GET_ALLOW_SCTX 0x1105
#define SUPERCALL_SU_SET_ALLOW_SCTX 0x1106
#define SUPERCALL_SU_GET_PATH 0x1110
#define SUPERCALL_SU_RESET_PATH 0x1111
#define SUPERCALL_SU_GET_SAFEMODE 0x1112

/*
 * SU prompt (弹窗确认) extension.
 *
 * Standard APatch is a whitelist: handle_before_execve() grants root the moment
 * the calling uid is in the su list. These two commands add a confirmation
 * stage for uids that are NOT in the whitelist: the kernel parks the su exec in
 * an interruptible wait, exposes the pending request to the trusted manager via
 * SUPERCALL_SU_PENDING_POLL, and only calls commit_su() after the manager replies
 * SUPERCALL_SU_DECISION(ALLOW).
 *
 * Both commands live in the is_authed gate (superkey or trusted-manager uid),
 * so a whitelisted third-party app cannot manufacture its own ALLOW decision.
 */
#define SUPERCALL_SU_PENDING_POLL 0x1113
#define SUPERCALL_SU_DECISION     0x1114

/* Decision values written back by the manager (and read back by the kernel). */
#define SU_DECISION_PENDING  0
#define SU_DECISION_ALLOW    1
#define SU_DECISION_DENY    (-1)
#define SU_DECISION_TIMEOUT (-2)

#define SU_REQ_COMM_LEN 16

/*
 * One pending su request. Stored in kstorage group KSTORAGE_UNUSED_GROUP_2,
 * keyed by the requesting process tgid so concurrent requests do not collide.
 * The kernel writes it before waiting; the manager reads a snapshot through
 * PENDING_POLL and writes only the `decision` field back via SU_DECISION.
 */
struct su_request
{
    uid_t uid;                              /* requesting app uid */
    uid_t to_uid;                           /* target uid, normally 0 (root) */
    pid_t pid;                              /* requesting tgid, decision key */
    unsigned long stamp;                    /* jiffies when queued */
    int decision;                           /* one of SU_DECISION_* */
    char scontext[SUPERCALL_SCONTEXT_LEN];  /* proposed SELinux context */
    char comm[SU_REQ_COMM_LEN];             /* process comm, display hint only */
};

#define SUPERCALL_MAX 0x1200

#define SUPERCALL_RES_SUCCEED 0

#define SUPERCALL_HELLO_MAGIC 0x11581158

#endif
