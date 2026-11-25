/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <linux/list.h>
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <linux/syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <syscall.h>
#include <predata.h>
#include <predata.h>
#include <kconfig.h>
#include <linux/vmalloc.h>
#include <sucompat.h>
#include <userd.h>
#include <symbol.h>
#include <kallsyms.h>
#include <uapi/linux/limits.h>
#include <predata.h>
#include <kstorage.h>
#include <selinux_hide.h>

const char sh_path[] = SH_PATH;
const char default_su_path[] = SU_PATH;
/* Where a refused su is pointed at, so execve fails with ENOENT instead of the
 * getname_flags rewrite turning it into /system/bin/sh. Must never exist. */
static const char denied_su_path[] = "/system/bin/.su-refused-by-kpatch";

/* udata bits for the fstatat/faccessat probes: bit0 = the syscall dispatcher
 * already gated by uid, bit1 = this registration is the access-class probe whose
 * path must stay hidden from un-granted uids. */

#ifdef ANDROID
const char legacy_su_path[] = LEGACY_SU_PATH;
const char apd_path[] = APD_PATH;
extern int android_is_safe_mode;
#endif
const char sucompat_file[] = "/data/adb/ap/sucompat";
static const char *current_su_path = 0;

static int su_kstorage_gid = -1;
static int exclude_kstorage_gid = -1;
static int su_prompt_kstorage_gid = -1;
/* uids the user explicitly refused: their next su fails immediately (no prompt),
 * exactly like a non-whitelisted caller on stock KernelPatch. */
static int su_deny_kstorage_gid = -1;
/* uids that must not see su at all (root detectors that probe `which su`).
 * kstorage group 4; managed by the manager through KSTORAGE_WRITE/REMOVE, so no
 * extra supercall is needed. */
static volatile int su_prompt_on = 0;   /* off by default; toggled via control_feature("su_prompt") */
/* What to do when the manager does not answer within SU_PROMPT_TIMEOUT_MS:
 * 0 = deny (default), 1 = allow. Toggled via control_feature("su_prompt_timeout"). */
static volatile int su_prompt_timeout_allow = 0;

/* kfunc_def(msleep) declares the resolved-symbol pointer kf_msleep in
 * patch/ksyms/misc.c. This tree ships no linux/delay.h, so declare it here.
 * When the kernel did not export it (kallsyms miss) the pointer stays NULL and
 * we fall back to the asynchronous path below instead of calling through NULL. */
extern void kfunc_def(msleep)(unsigned int msecs);
/* 1 while su_register_path_probe_hooks() has the fstatat/faccessat probes
 * installed.  Stays 0 under the AArch32 safety gate so the unregister path
 * never unwraps a hook that was never installed. */
/* Off by default; controlFeature("path_probe") turns the stat/access split on.
 * Kept runtime-only so a bad interaction cannot survive a reboot. */
static int su_hook_getname_flags(void);
static int su_syscall_gate(void);
long kp_control_feature_sc(const char __user *uname, int state)
{
    char name[64];
    int len = compat_strncpy_from_user(name, uname, sizeof(name));
    if (len <= 0)
        return -EINVAL;

    if (!strcmp(name, "selinux_hide")) {
        return selinux_hide_control(state);
    }

    if (!strcmp(name, "su_prompt")) {
        if (state >= 0) {
            __atomic_store_n(&su_prompt_on, state ? 1 : 0, __ATOMIC_RELAXED);
            logkfi("su_prompt %s\n", state ? "enabled" : "disabled");
        }
        return __atomic_load_n(&su_prompt_on, __ATOMIC_RELAXED);
    }

    if (!strcmp(name, "su_prompt_timeout")) {
        if (state >= 0) {
            __atomic_store_n(&su_prompt_timeout_allow, state ? 1 : 0, __ATOMIC_RELAXED);
            logkfi("su_prompt timeout -> %s\n", state ? "allow" : "deny");
        }
        return __atomic_load_n(&su_prompt_timeout_allow, __ATOMIC_RELAXED);
    }

    /*
     * sucompat_extra / path_probe used to install the fstatat/faccessat probes.
     * That mechanism is retired: on this kernel the syscall probes corrupted
     * callers system-wide (linker Bad address / Invalid argument, adbd fork()
     * EFAULT), and the `which`-hiding they were meant to provide now happens in
     * the getname_flags after-hook, which never writes user memory.
     *
     * The names stay accepted so an older manager asking about them gets a
     * definite answer instead of -ENOENT, but they are inert: nothing can install
     * the dangerous hooks again, not even by accident. Reporting 0 (rather than
     * the requested state) is deliberate -- a caller must not believe the probes
     * are active.
     */
    if (!strcmp(name, "sucompat_extra") || !strcmp(name, "path_probe")) {
        logkfi("feature %s is retired (no-op), state ignored: %d\n", name, state);
        return 0;
    }

    /* Unknown feature name. */
    return -ENOENT;
}
KP_EXPORT_SYMBOL(kp_control_feature_sc);

/*
 * is_su_allow_uid() walks the kstorage hash under RCU. It runs on every
 * fstatat/faccessat (the su-path probe) and in every su-gated callback, so that
 * walk is a measurable per-call cost and a timing fingerprint for those syscalls.
 * Memoise the answer per uid in a lockless direct-mapped table, keyed by
 * kstorage_generation() which every list write bumps. An entry stamped with the
 * current generation can only have been produced by a lookup that already
 * observed the new list; a stale rendezvous just misses and re-queries, never
 * returns a stale answer. Only the membership bit is cached: profiles/scontext
 * are still read live where they are needed.
 */
#define SU_ALLOW_CACHE_N 256
/* Entries never expire by time; they are invalidated by kstorage_generation().
 * 31 generation bits put wrap at ~2.1e9 writes, so an entry can never survive
 * long enough to alias the current generation. */
#define SU_ALLOW_GEN_BITS 31
#define SU_ALLOW_GEN_MASK ((1u << SU_ALLOW_GEN_BITS) - 1)
static u64 su_allow_cache[SU_ALLOW_CACHE_N];

static int is_su_allow_uid_slow(uid_t uid)
{
    int rc = 0;
    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR_OR_NULL(ks) || ks->dlen <= 0) goto out;

    struct su_profile *profile = (struct su_profile *)ks->data;
    rc = profile->uid == uid;

out:
    rcu_read_unlock();
    return rc;
}

int is_su_allow_uid(uid_t uid)
{
    u32 gen = kstorage_generation();
    u32 slot = (uid * 2654435761u) & (SU_ALLOW_CACHE_N - 1);
    u64 e = __atomic_load_n(&su_allow_cache[slot], __ATOMIC_RELAXED);

    if ((u32)(e >> 32) == (u32)uid && (u32)((e >> 1) & SU_ALLOW_GEN_MASK) == (gen & SU_ALLOW_GEN_MASK))
        return (int)(e & 1);

    int granted = is_su_allow_uid_slow(uid) ? 1 : 0;
    u64 ne = ((u64)(u32)uid << 32) | ((u64)(gen & SU_ALLOW_GEN_MASK) << 1) | (u64)(u32)granted;
    __atomic_store_n(&su_allow_cache[slot], ne, __ATOMIC_RELAXED);
    return granted;
}
KP_EXPORT_SYMBOL(is_su_allow_uid);

/* ---- SU prompt: pending-request plumbing ---------------------------------- */

int su_prompt_enabled(void)
{
    return __atomic_load_n(&su_prompt_on, __ATOMIC_RELAXED);
}

/* True when the payload can hold an execve() in the kernel. Sleeping inside the
 * execve hook is legal (process context, no locks held), but only if msleep
 * actually resolved -- otherwise the asynchronous path is used. */
int su_prompt_can_wait(void)
{
    return kf_msleep != 0;
}

/* Bounded wait for the manager's answer. *timed_out says whether the answer came
 * from the user or from the clock: a user decision is remembered, a timeout is
 * not, so the next su asks again. */
static int su_prompt_wait(pid_t pid, int *timed_out)
{
    struct su_request req;
    *timed_out = 0;
    for (int waited = 0; waited < SU_PROMPT_TIMEOUT_MS; waited += SU_PROMPT_POLL_MS) {
        if (!kf_msleep) break;
        kf_msleep(SU_PROMPT_POLL_MS);
        if (read_kstorage(su_prompt_kstorage_gid, (long)pid, &req, 0, sizeof(req), false) < 0)
            return SU_DECISION_DENY_ONCE;     /* record vanished -> deny, remember nothing */
        if (req.decision == SU_DECISION_ALLOW || req.decision == SU_DECISION_ALLOW_ONCE ||
            req.decision == SU_DECISION_DENY || req.decision == SU_DECISION_DENY_ONCE ||
            req.decision == SU_DECISION_TIMEOUT)
            return req.decision;
    }
    /* Nobody answered: the configured policy decides, and nothing is persisted. */
    *timed_out = 1;
    return __atomic_load_n(&su_prompt_timeout_allow, __ATOMIC_RELAXED)
               ? SU_DECISION_ALLOW_ONCE
               : SU_DECISION_DENY_ONCE;
}

/* ---- SU prompt: remembered decisions ------------------------------------- */

int is_su_deny_uid(uid_t uid)
{
    if (su_deny_kstorage_gid < 0) return 0;
    int denied = 0;
    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_deny_kstorage_gid, uid);
    denied = !IS_ERR_OR_NULL(ks) && ks->dlen > 0;
    rcu_read_unlock();
    return denied;
}

static void su_deny_add(uid_t uid)
{
    u32 on = 1;
    if (su_deny_kstorage_gid < 0) return;
    write_kstorage(su_deny_kstorage_gid, (long)uid, &on, 0, sizeof(on), false);
    logkfi("su_deny add uid: %d\n", uid);
}

static void su_deny_remove(uid_t uid)
{
    if (su_deny_kstorage_gid < 0) return;
    if (remove_kstorage(su_deny_kstorage_gid, (long)uid) >= 0)
        logkfi("su_deny remove uid: %d\n", uid);
}

/* Apply a decision. A user answer is remembered in the whitelist/denylist; a
 * timeout is not. The pending record is always dropped, so group 2 does not
 * accumulate one entry per su forever. */
static void su_prompt_apply(uid_t uid, pid_t pid, int decision, int timed_out)
{
    int allow = (decision == SU_DECISION_ALLOW || decision == SU_DECISION_ALLOW_ONCE);
    /* Only ALLOW / DENY (not the *_ONCE variants) are remembered, and a timeout
     * is never remembered. */
    int remember = !timed_out && (decision == SU_DECISION_ALLOW || decision == SU_DECISION_DENY);

    if (remember) {
        if (allow) {
            su_deny_remove(uid);
            su_add_allow_uid(uid, 0, all_allow_sctx);
            logkfi("su_prompt remember ALLOW uid: %d\n", uid);
        } else {
            su_remove_allow_uid(uid);
            su_deny_add(uid);
            logkfi("su_prompt remember DENY uid: %d\n", uid);
        }
    } else {
        logkfi("su_prompt %s uid: %d -> %s (not remembered)\n",
               timed_out ? "timeout" : "one-shot", uid, allow ? "allow" : "deny");
    }
    remove_kstorage(su_prompt_kstorage_gid, (long)pid);
}

/* True for a uid that can reach the prompt: feature on, not whitelisted, not
 * refused before. Such a caller must also *see* /system/bin/su -- on this port the
 * path is virtual (getname_flags redirects it to /system/bin/sh), so hiding it
 * would make the shell's PATH lookup fail before execve() and the prompt could
 * never fire. */
static int su_prompt_reachable(uid_t uid)
{
    return su_prompt_enabled() && !is_su_allow_uid(uid) && !is_trusted_manager_uid(uid) &&
           !is_su_deny_uid(uid);
}

/* True when `gid` is the kstorage group that holds pending su requests. Used by
 * the supercall dispatcher to keep that group write-protected for callers that
 * are not authenticated (see SUPERCALL_KSTORAGE_WRITE). */
int su_prompt_is_group(int gid)
{
    return su_prompt_kstorage_gid >= 0 && gid == su_prompt_kstorage_gid;
}
KP_EXPORT_SYMBOL(su_prompt_enabled);

struct su_prompt_poll_ctx {
    struct su_request *kernel_buf;
    int max;
    int idx;
};

static int su_prompt_poll_cb(struct kstorage *ks, void *udata)
{
    struct su_prompt_poll_ctx *ctx = (struct su_prompt_poll_ctx *)udata;
    if (ctx->idx >= ctx->max) return -ENOBUFS;
    if (ks->dlen < (int)sizeof(struct su_request)) return 0;

    struct su_request *req = (struct su_request *)ks->data;
    if (req->decision != SU_DECISION_PENDING) return 0;

    memcpy(&ctx->kernel_buf[ctx->idx], req, sizeof(struct su_request));
    ctx->idx++;
    return 0;
}

int su_prompt_poll(struct su_request __user *out_reqs, int max)
{
    if (!out_reqs || max <= 0 || max > 64) return -EINVAL;

    struct su_request *buf = vmalloc(sizeof(struct su_request) * max);
    if (!buf) return -ENOMEM;

    struct su_prompt_poll_ctx ctx = { buf, max, 0 };
    /* on_each_kstorage_elem() walks under rcu_read_lock(): copy into a kernel
     * buffer here, do the (sleeping) copy_to_user only after the walk ends. */
    on_each_kstorage_elem(su_prompt_kstorage_gid, su_prompt_poll_cb, &ctx);

    int n = ctx.idx;
    if (n > 0) {
        long copied = compat_copy_to_user(out_reqs, buf, sizeof(struct su_request) * n);
        if (copied <= 0) n = -EFAULT;
    }
    kvfree(buf);
    return n;
}
KP_EXPORT_SYMBOL(su_prompt_poll);

int su_prompt_decision(pid_t pid, int decision)
{
    struct su_request req;
    long rc = read_kstorage(su_prompt_kstorage_gid, (long)pid, &req, 0, sizeof(req), false);
    if (rc < 0) return -ENOENT;

    /* A duplicate/late decision must not revive an already-finished request. */
    if (req.decision != SU_DECISION_PENDING) return 0;

    req.decision = decision;
    rc = write_kstorage(su_prompt_kstorage_gid, (long)pid, &req, 0, sizeof(req), false);
    /* apd polls this kstorage record from userspace; no kernel wakeup needed. */
    logkfi("su_prompt decision pid: %d, uid: %d, decision: %d, rc: %ld\\n",
           pid, req.uid, decision, rc);
    return rc;
}
KP_EXPORT_SYMBOL(su_prompt_decision);

int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext)
{
    if (!scontext) scontext = "";
    struct su_profile profile = {
        uid,
        to_uid,
    };
    memcpy(profile.scontext, scontext, SUPERCALL_SCONTEXT_LEN);
    int rc = write_kstorage(su_kstorage_gid, uid, &profile, 0, sizeof(struct su_profile), false);
    logkfd("uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, scontext, rc);
    return rc;
}
KP_EXPORT_SYMBOL(su_add_allow_uid);

int su_remove_allow_uid(uid_t uid)
{
    return remove_kstorage(su_kstorage_gid, uid);
}
KP_EXPORT_SYMBOL(su_remove_allow_uid);

int su_allow_uid_nums()
{
    return kstorage_group_size(su_kstorage_gid);
}
KP_EXPORT_SYMBOL(su_allow_uid_nums);

static int allow_uids_cb(struct kstorage *kstorage, void *udata)
{
    struct
    {
        int is_user;
        uid_t *out_uids;
        int idx;
        int out_num;
    } *up = (typeof(up))udata;

    if (up->idx >= up->out_num) {
        return -ENOBUFS;
    }

    struct su_profile *profile = (struct su_profile *)kstorage->data;

    if (up->is_user) {
        int cprc = compat_copy_to_user(up->out_uids + up->idx, &profile->uid, sizeof(uid_t));
        if (cprc <= 0) {
            logkfd("compat_copy_to_user error: %d", cprc);
            return cprc;
        }
    } else {
        up->out_uids[up->idx] = profile->uid;
    }

    up->idx++;

    return 0;
}

int su_allow_uids(int is_user, uid_t *out_uids, int out_num)
{
    struct
    {
        int iu;
        uid_t *up;
        int idx;
        int out_num;
    } udata = { is_user, out_uids, 0, out_num };

    on_each_kstorage_elem(su_kstorage_gid, allow_uids_cb, &udata);

    return udata.idx;
}
KP_EXPORT_SYMBOL(su_allow_uids);

int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *out_profile)
{
    int rc = 0;

    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR(ks)) {
        rc = -ENOENT;
        goto out;
    }
    struct su_profile *profile = (struct su_profile *)ks->data;

    if (is_user) {
        rc = compat_copy_to_user(out_profile, profile, sizeof(struct su_profile));
        if (rc <= 0) {
            logkfd("compat_copy_to_user error: %d", rc);
            goto out;
        }
    } else {
        memcpy(out_profile, profile, sizeof(struct su_profile));
    }

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(su_allow_uid_profile);

// no free, no lock
int su_reset_path(const char *path)
{
    if (!path) return -EINVAL;
    if (IS_ERR(path)) return PTR_ERR(path);
    current_su_path = path;
    logkfd("%s\n", current_su_path);
    dsb(ish);
    return 0;
}
KP_EXPORT_SYMBOL(su_reset_path);

const char *su_get_path()
{
    if (!current_su_path) current_su_path = default_su_path;
    return current_su_path;
}
KP_EXPORT_SYMBOL(su_get_path);

static void handle_before_execve(char **__user u_filename_p, char **__user uargv, void *udata)
{
    uid_t uid = current_uid();
    int trusted = is_trusted_manager_uid(uid);
    int allowed = is_su_allow_uid(uid);

    /* Explicitly refused before: fail like a missing binary, do not ask again. */
    if (!trusted && !allowed && is_su_deny_uid(uid)) return;
    /* Only a non-whitelisted caller can enter prompt mode, and only when the
     * trusted manager explicitly enabled the feature via control_feature. */
    int prompt_mode = !trusted && !allowed && su_prompt_enabled();

    if (!trusted && !allowed && !prompt_mode) return;

    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

#ifdef ANDROID
    int matched_su = !strcmp(filename, current_su_path) || !strcmp(filename, legacy_su_path);
#else
    int matched_su = !strcmp(filename, current_su_path);
#endif
    if (!matched_su) {
        /* SUPERCMD stays exclusive to whitelisted/trusted callers: a prompt-mode
         * caller must not be able to redirect an ordinary truncate invocation. */
        if ((trusted || allowed) && !strcmp(SUPERCMD, filename)) {
            void handle_supercmd(char **__user u_filename_p, char **__user uargv);
            handle_supercmd(u_filename_p, uargv);
        }
        return;
    }

    struct su_profile profile = { .to_uid = 0 };

    if (prompt_mode) {
        pid_t pid = (pid_t)task_pid_vnr(current);
        /* Stack-allocated: this KP blob does not resolve kmalloc/kzalloc kfuncs
         * (see supercmd.c), and GFP_KERNEL is not defined in freestanding KP. */
        struct su_request req;
        memset(&req, 0, sizeof(req));
        req.uid = uid;
        req.to_uid = 0;
        req.pid = pid;
        req.decision = SU_DECISION_PENDING;
        strncpy(req.scontext, all_allow_sctx, sizeof(req.scontext) - 1);
        req.scontext[sizeof(req.scontext) - 1] = '\0';
        memset(req.comm, 0, sizeof(req.comm));
        /* No stamp: freestanding KP has no jiffies/ktime. */
        long wrc = write_kstorage(su_prompt_kstorage_gid, (long)pid, &req, 0, sizeof(req), false);
        if (wrc < 0) return;

        logkfi("su_prompt pending uid: %d, pid: %d\n", uid, pid);

        /* Synchronous arbitration: hold the syscall in the kernel (bounded by
         * SU_PROMPT_TIMEOUT_MS) and let the manager's answer decide it.
         *
         * Denying is just "do not redirect": execve then tries the real
         * /system/bin/su, which does not exist, so the caller gets ENOENT --
         * byte for byte what a non-whitelisted caller sees on stock
         * KernelPatch. No hook-frame surgery needed.
         * If msleep did not resolve (kallsyms miss) fall through to the
         * asynchronous apd-side wait. */
        if (su_prompt_can_wait()) {
            int timed_out = 0;
            int decision = su_prompt_wait(pid, &timed_out);
            su_prompt_apply(uid, pid, decision, timed_out);
            if (decision != SU_DECISION_ALLOW && decision != SU_DECISION_ALLOW_ONCE) {
                /* Deny by pointing the exec at a path that cannot exist. Simply
                 * dropping the redirect is not enough once su is visible to this
                 * uid: after_getname_flags would rewrite /system/bin/su to
                 * /system/bin/sh and hand the caller a plain shell. */
                char __user *uptr = copy_to_user_stack(denied_su_path, sizeof(denied_su_path));
                if (uptr && !IS_ERR(uptr)) *u_filename_p = uptr;
                logkfi("su_prompt denied uid: %d pid: %d -> ENOENT\n", uid, pid);
                return;
            }
            logkfi("su_prompt allowed uid: %d pid: %d\n", uid, pid);
        } else {
            logkfi("su_prompt async (msleep unresolved), apd will arbitrate\n");
        }

        /* Allowed (or asynchronous fallback): elevate + exec apd as usual. */
        strncpy(profile.scontext, all_allow_sctx, sizeof(profile.scontext) - 1);
        profile.scontext[sizeof(profile.scontext) - 1] = '\0';
        goto commit_and_redirect;
    }

    if (trusted) {
        strncpy(profile.scontext, all_allow_sctx, sizeof(profile.scontext) - 1);
        profile.scontext[sizeof(profile.scontext) - 1] = '\0';
    } else if (su_allow_uid_profile(0, uid, &profile)) {
        return;
    }

commit_and_redirect:
    {
        uid_t to_uid = profile.to_uid;
        const char *sctx = profile.scontext;
        commit_su(to_uid, sctx);

#ifdef ANDROID
        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (!filp || IS_ERR(filp)) {
#endif
            void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
            if (uptr && !IS_ERR(uptr)) {
                *u_filename_p = (char *__user)uptr;
            }
            logkfi("call su uid: %d, to_uid: %d, sctx: %s, uptr: %llx\\n", uid, to_uid, sctx,
                   (unsigned long long)(unsigned long)uptr);
#ifdef ANDROID
        } else {
            filp_close(filp, 0);

#if defined(CONFIG_ARM)
            uintptr_t sp = 0;
#else
            uint64_t sp = 0;
#endif
            sp = current_user_stack_pointer();
            sp -= sizeof(apd_path);
            sp &= 0xFFFFFFFFFFFFFFF8;
            int cplen = compat_copy_to_user((void *)sp, apd_path, sizeof(apd_path));
            if (cplen > 0) {
                *u_filename_p = (char *)sp;
            }

            int argv_cplen = 0;
            if (strcmp(legacy_su_path, filename)) {
                if (argv_cplen <= 0) {
                    sp = sp ?: current_user_stack_pointer();
                    sp -= sizeof(legacy_su_path);
                    sp &= 0xFFFFFFFFFFFFFFF8;
                    argv_cplen = compat_copy_to_user((void *)sp, legacy_su_path, sizeof(legacy_su_path));
                    if (argv_cplen > 0) {
                        int rc = set_user_arg_ptr(0, *uargv, 0, sp);
                        if (rc < 0) {
                            logkfi("call apd argv error, uid: %d, to_uid: %d, sctx: %s, rc: %d\\n", uid, to_uid, sctx,
                                   rc);
                        }
                    }
                }
            }
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s, cplen: %d, %d\\n", uid, to_uid, sctx, cplen, argv_cplen);
        }
#endif // ANDROID
    }
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2107
// COMPAT_SYSCALL_DEFINE3(execve, const char __user *, filename,
// 	const compat_uptr_t __user *, argv,
// 	const compat_uptr_t __user *, envp)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2087
// SYSCALL_DEFINE3(execve, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp)

static void before_execve(hook_fargs3_t *args, void *udata)
{
    void *arg0p = syscall_argn_p(args, 0);
    void *arg1p = syscall_argn_p(args, 1);
    handle_before_execve((char **)arg0p, (char **)arg1p, udata);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2114
// COMPAT_SYSCALL_DEFINE5(execveat, int, fd,
// 		       const char __user *, filename,
// 		       const compat_uptr_t __user *, argv,
// 		       const compat_uptr_t __user *, envp,
// 		       int,  flags)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2095
// SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp, int, flags)
__maybe_unused static void before_execveat(hook_fargs5_t *args, void *udata)
{
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    handle_before_execve((char **)arg1p, (char **)arg2p, udata);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/stat.c#L431
// SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
// 		struct stat __user *, statbuf, int, flag)

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L492
// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L497
// SYSCALL_DEFINE4(faccessat2, int, dfd, const char __user *, filename, int, mode, int, flags)

// https://elixir.bootlin.com/linux/v6.1/source/fs/stat.c#L661
// SYSCALL_DEFINE5(statx,
// 		int, dfd, const char __user *, filename, unsigned, flags,
// 		unsigned int, mask,
// 		struct statx __user *, buffer)
/* Evaluated once per syscall by the dispatcher (syscall_hook_set_gate). Only
 * root / su-allow / trusted-manager callers reach the callbacks at all, which is
 * what lets su_handler_arg1_ufilename_before and friends drop their own root
 * checks: for everyone else the dispatcher runs no callback, on any syscall, so
 * there is no per-syscall signature and no cross-syscall inconsistency. */
/* True for a uid that can reach the prompt: feature on, not whitelisted, not
 * refused before. Such a caller must also *see* /system/bin/su -- on this port the
 * path is virtual (getname_flags redirects it to /system/bin/sh), so hiding it
 * would make the shell's PATH lookup fail before execve() and the prompt could
 * never fire. */
static int su_prompt_reachable(uid_t uid);

static int su_syscall_gate(void)
{
    uid_t uid = current_uid();
    return uid == 0 || is_su_allow_uid(uid) || is_trusted_manager_uid(uid) ||
           su_prompt_reachable(uid);
}

__maybe_unused static void su_handler_arg1_ufilename_before(hook_fargs6_t *args, void *udata)
{
    /*
     * faccessat probe: hide /system/bin/su from access(2), which is what `which su`
     * and root detectors use, while stat() keeps finding it for the shell (the
     * getname_flags rewrite handles stat).
     *
     * This is read-only on purpose. The earlier version copied a replacement path
     * into the caller's stack and pointed the argument at it on *every*
     * fstatat/faccessat in the system; on this kernel that corrupted long-lived
     * processes (linker: `reading "/system/etc/ld.config.txt": Bad address`, and
     * adbd's fork() reporting EFAULT). Nothing here writes user memory: the path is
     * read into a kernel buffer, and a hit is answered by skipping the syscall and
     * returning -ENOENT through the hook frame.
     */
    (void)udata;

    uid_t uid = current_uid();
    /* Granted uids must see su; denied uids are already past caring. */
    if (!su_prompt_reachable(uid)) return;

    char __user *ufilename = (char __user *)args->arg1;
    if (!ufilename) return;

    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

#ifdef ANDROID
    if (strcmp(filename, current_su_path) && strcmp(filename, legacy_su_path)) return;
#else
    if (strcmp(filename, current_su_path)) return;
#endif

    args->skip_origin = 1;
    args->ret = (uint64_t)(long)(-ENOENT);
    logkfi("su access probe: uid %d -> ENOENT\n", uid);
}

/*
 * Programs whose job is to *report* whether a file exists: which, type, command -v,
 * whereis. Those are the only callers that must be told "no such file".
 *
 * Deliberately NOT listed:
 *   - "sh"/"ash"/"mksh": the shell resolves the same path when the user runs su, and
 *     hiding it there would make su unreachable, so the prompt could never fire.
 *   - "busybox": it multiplexes hundreds of applets; hiding su from all of them
 *     breaks `busybox ls`-style usage without helping the probe.
 *
 * comm is TASK_COMM_LEN (16) bytes, NUL-terminated, and may hold a truncated name.
 * Only the prefix is compared, over exactly strlen(name) bytes, so a shorter comm
 * ("typ") does not match and no read goes past the string's end.
 */
static int su_comm_is_path_probe(const char *comm)
{
    static const char *const names[] = {
        "which", "type", "command", "whereis", NULL,
    };

    if (!comm) return 0;

    for (int i = 0; names[i]; i++) {
        if (!strncmp(comm, names[i], strlen(names[i]))) return 1;
    }
    return 0;
}

static void after_getname_flags(hook_fargs3_t *args, void *udata)
{
    struct filename *fn = (struct filename *)args->ret;
    if (IS_ERR_OR_NULL(fn)) return;

    uid_t uid = current_uid();
    const char *name = fn->name;
    if (!name || strcmp(name, su_get_path())) return;

    int trusted = (uid == 0) || is_su_allow_uid(uid) || is_trusted_manager_uid(uid);

    /*
     * The probe, exactly as specified: a which-class process asking for su, from an
     * uid that is not trusted, is told the file does not exist.
     *
     * Nothing is written to user memory and no syscall is hooked. getname_flags has
     * already allocated the filename, so this after-hook replaces the result with
     * -ENOENT and releases that allocation with putname(). An earlier attempt hooked
     * fstatat/faccessat and rewrote the caller's argument instead, which corrupted
     * long-lived processes system-wide on this kernel (linker: Bad address /
     * Invalid argument, adbd fork(): EFAULT); that route is gone for good.
     *
     * putname() is mandatory before returning the error: skipping it would leak one
     * struct filename per probe, and a detector polling `which su` would drip kernel
     * memory until it OOMs. When putname is unavailable the probe is skipped rather
     * than leaking -- a visible su beats an unbounded leak.
     * The probe also only applies while su prompting is on, so a device that never
     * enabled the feature cannot answer differently from stock.
     */
    if (!trusted && su_prompt_enabled()) {
        const char *comm = get_task_comm(current);
        if (su_comm_is_path_probe(comm) && kfunc(putname)) {
            kfunc(putname)(fn);
            args->ret = (uint64_t)(long)(-ENOENT);
            logkfi("su probe: %s (uid %d) -> ENOENT\n", comm, uid);
            return;
        }
    }

    /* Everything else keeps the old behaviour: granted uids get the sh redirect
     * (that is what a root shell is), and a uid that can still be prompted must
     * merely find the path so its shell reaches execve(), where the exec hook
     * decides -- on deny it points the exec at denied_su_path. */
    if (!trusted && !su_prompt_reachable(uid)) return;

    if (strlen(sh_path) <= strlen(name)) {
        strcpy((char *)name, sh_path);
        return;
    }

    if (kfunc(getname_kernel) && kfunc(putname)) {
        struct filename *nf = kfunc(getname_kernel)(sh_path);
        if (!IS_ERR_OR_NULL(nf)) {
            kfunc(putname)(fn);
            args->ret = (uint64_t)nf;
            return;
        }
    }

    logkfi("uid: %d, cannot redirect su path to %s\n", uid, sh_path);
}

// stat-class probes on a real third-party su binary: security_inode_getattr fires
// because the file genuinely exists. Show it only to granted uids (return 0, same
// as the virtual su path which getname_flags redirects to sh for them) and hide
// it from everyone else by failing the getattr (-ENOENT), which makes vfs_getattr
// report ENOENT and the probe sees no su. struct path is { mnt; dentry; }.
typedef char *(*su_dentry_path_raw_t)(void *dentry, char *buf, int buflen);
static su_dentry_path_raw_t su_dentry_path_raw = 0;

static void after_security_inode_getattr(hook_fargs1_t *args, void *udata)
{
    if ((long)args->ret < 0) return; // already an error, nothing to do

    uid_t uid = current_uid();
    bool granted = is_su_allow_uid(uid) || is_trusted_manager_uid(uid);

    void *path = (void *)args->arg0;
    if (!path) return;
    void *dentry = *(void **)((char *)path + 8); // path->dentry
    if (!dentry || !su_dentry_path_raw) return;

    char buf[PATH_MAX];
    char *p = su_dentry_path_raw(dentry, buf, sizeof(buf));
    if (!p || !p[0]) return;

#ifdef ANDROID
    if (strcmp(p, su_get_path()) && strcmp(p, legacy_su_path)) return;
#else
    if (strcmp(p, su_get_path())) return;
#endif

    // Hide the real su file from unprivileged callers; keep it visible to granted ones.
    if (!granted) {
        args->ret = (uint64_t)-ENOENT;
        logkfi("uid: %d, hide real su file: %s\n", uid, p);
    } else {
        logkfi("uid: %d, show real su file: %s\n", uid, p);
    }
}

int set_ap_mod_exclude(uid_t uid, int exclude)
{
    int rc = 0;
    if (exclude) {
        rc = write_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    } else {
        rc = remove_kstorage(exclude_kstorage_gid, uid);
    }
    return rc;
}
KP_EXPORT_SYMBOL(set_ap_mod_exclude);

int get_ap_mod_exclude(uid_t uid)
{
    int exclude = 0;
    int rc = read_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    if (rc < 0) return 0;
    return exclude;
}
KP_EXPORT_SYMBOL(get_ap_mod_exclude);

int list_ap_mod_exclude(uid_t *uids, int len)
{
    long ids[len];
    int cnt = list_kstorage_ids(exclude_kstorage_gid, ids, len, false);
    for (int i = 0; i < len; i++) {
        uids[i] = (uid_t)ids[i];
    }
    return cnt;
}
KP_EXPORT_SYMBOL(list_ap_mod_exclude);

int su_compat_init()
{
    current_su_path = default_su_path;

    su_kstorage_gid = try_alloc_kstroage_group();
    if (su_kstorage_gid != KSTORAGE_SU_LIST_GROUP) return -ENOMEM;

    exclude_kstorage_gid = try_alloc_kstroage_group();
    if (exclude_kstorage_gid != KSTORAGE_EXCLUDE_LIST_GROUP) return -ENOMEM;

    su_prompt_kstorage_gid = try_alloc_kstroage_group();
    if (su_prompt_kstorage_gid != KSTORAGE_UNUSED_GROUP_2) return -ENOMEM;

    /* Remembers uids the user refused, so their next su is a plain ENOENT. */
    su_deny_kstorage_gid = try_alloc_kstroage_group();
    if (su_deny_kstorage_gid != KSTORAGE_UNUSED_GROUP_3) return -ENOMEM;

#ifdef ANDROID
    // default shell
    if (!all_allow_sctx[0]) {
        strcpy(all_allow_sctx, ALL_ALLOW_SCONTEXT_MAGISK);
    }
    su_add_allow_uid(2000, 0, all_allow_sctx);
    su_add_allow_uid(0, 0, all_allow_sctx);
#endif

    /* Gate every syscall-hook callback on the caller's uid, once per syscall, in
     * the dispatcher. Installed before the hooks below so none of them ever runs
     * for an unprivileged process. */
    syscall_hook_set_gate(su_syscall_gate);

    hook_err_t rc = HOOK_NO_ERR;

    uint8_t su_config = patch_config->patch_su_config;
    bool enable = !!(su_config & PATCH_CONFIG_SU_ENABLE);
    bool wrap = !!(su_config & PATCH_CONFIG_SU_HOOK_NO_WRAP);
    log_boot("su config: %x, enable: %d, wrap: %d\n", su_config, enable, wrap);

    // if (!enable) return;

    rc = hook_syscalln(__NR_execve, 3, before_execve, 0, (void *)0);
    log_boot("hook __NR_execve rc: %d\n", rc);

    /* Android init may execute commands through execveat().  Keep the
     * SUPERCMD/su redirection on both entry points; otherwise /system/bin/
     * truncate is executed literally and every apd bootstrap command exits
     * with status 1. */
    rc = hook_syscalln(__NR_execveat, 5, before_execveat, 0, (void *)0);
    log_boot("hook __NR_execveat rc: %d\n", rc);

    // __NR_execve 11
    rc = hook_compat_syscalln(11, 3, before_execve, 0, (void *)1);
    log_boot("hook 32 __NR_execve rc: %d\n", rc);

    // __NR_execveat 387 on arm64 compat
    rc = hook_compat_syscalln(387, 5, before_execveat, 0, (void *)1);
    log_boot("hook 32 __NR_execveat rc: %d\n", rc);

    /* REGRESSION FIX (v11 -> 0.13.9): the merge extracted the getname_flags
     * hook into su_hook_getname_flags() but never called it, so the hook was
     * dead code and `su` disappeared from the shell.
     *
     * after_getname_flags() rewrites struct filename->name from the su path to
     * /system/bin/sh for granted uids, so `stat()`/`access()` on the su path
     * reports it present.  A shell resolves a command with stat()/access()
     * BEFORE execve(), so without this hook mksh sees ENOENT, prints
     * "su: not found" and never reaches the before_execve() redirect that
     * actually grants root.  v11 called hook_wrap3() on getname_flags inline
     * here; 0.13.9 lost that call.
     *
     * This is the getname_flags wrap (an after-hook on struct filename), NOT
     * the fstatat/faccessat path-probe hooks that the AArch32 safety gate in
     * su_register_path_probe_hooks() still keeps disabled.  It was live in v11
     * and is independent of the EFAULT storm that gate guards against. */
    rc = su_hook_getname_flags();
    log_boot("hook getname_flags rc: %d\n", rc);

    /* The fstatat/faccessat probes are retired (see kp_control_feature_sc): the
     * `which`-hiding they provided now lives in after_getname_flags, which cannot
     * corrupt a caller. Nothing is registered here any more. */

    return 0;
}
static int su_hook_getname_flags(void)
{
    // Redirect the su path only for granted uids: after_getname_flags checks
    // is_su_allow_uid/is_trusted_manager_uid, so a granted app's stat/access on
    // /system/bin/su or /system/bin/kp lands on the real /system/bin/sh and the
    // probe reports it present, while unprivileged callers keep the virtual su
    // path un-redirected and get ENOENT (hidden).
    //
    // LTO kernels (e.g. OPPO 6.1) emit getname_flags as a CFI wrapper with zero
    // callers; the real entry all path syscalls reach is __original_getname_flags.
    // Prefer it, fall back to getname_flags for non-LTO builds.
    hook_err_t rc = 0;
    unsigned long getname_flags_addr = 0;
    getname_flags_addr = kallsyms_lookup_name("__original_getname_flags");
    if (!getname_flags_addr) {
        getname_flags_addr = kallsyms_lookup_name("getname_flags");
    }else{
        logkfi("found __original_getname_flags: %llx\n", (unsigned long long)getname_flags_addr);
    }
    if (getname_flags_addr) {
        rc = hook_wrap3((void *)getname_flags_addr, 0, after_getname_flags, (void *)0);
        log_boot("hook getname_flags rc: %d\n", rc);
    } else {
        log_boot("getname_flags not found\n");
        rc = -HOOK_BAD_ADDRESS;
    }
    return rc;
}

void sucompat_init()
{
    /* Retired: the fstatat/faccessat probes are gone for good (they corrupted
     * callers on this kernel). sucompat no longer needs a marker file, because the
     * only thing it would have enabled is that retired probe. The getname_flags
     * wrap is installed unconditionally from android_user_init(). */
}
