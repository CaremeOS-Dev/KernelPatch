/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <log.h>
#include <stdbool.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/vmalloc.h>
#include <baselib.h>
#include <linux/pid.h>
#include <asm/current.h>
#include <linux/security.h>
#include <syscall.h>
#include <uapi/linux/prctl.h>
#include <uapi/linux/magic.h>
#include <linux/capability.h>
#include <linux/seccomp.h>
#include <linux/sched/mm.h>
#include <ksyms.h>
#include <pgtable.h>
#include <symbol.h>
#include <linux/mm_types.h>
#include <asm/processor.h>

#define TASK_COMM_LEN 16

#define TASK_STRUCT_MAX_SIZE 0x1800
#define THREAD_INFO_MAX_SIZE 0x90
#define CRED_MAX_SIZE 0x100
#define MM_STRUCT_MAX_SIZE 0xb0

struct mm_struct_offset mm_struct_offset = {
    .mmap_base_offset = -1,
    .task_size_offset = -1,
    .pgd_offset = -1,
    .map_count_offset = -1,
    .total_vm_offset = -1,
    .locked_vm_offset = -1,
    .pinned_vm_offset = -1,
    .data_vm_offset = -1,
    .exec_vm_offset = -1,
    .stack_vm_offset = -1,
    .start_code_offset = -1,
    .end_code_offset = -1,
    .start_data_offset = -1,
    .end_data_offset = -1,
    .start_brk_offset = -1,
    .brk_offset = -1,
    .start_stack_offset = -1,
    .arg_start_offset = -1,
    .arg_end_offset = -1,
    .env_start_offset = -1,
    .env_end_offset = -1,
};
KP_EXPORT_SYMBOL(mm_struct_offset);

struct task_struct_offset task_struct_offset = {
    .pid_offset = -1,
    .tgid_offset = -1,
    .thread_pid_offset = -1,
    .ptracer_cred_offset = -1,
    .real_cred_offset = -1,
    .cred_offset = -1,
    .fs_offset = -1,
    .files_offset = -1,
    .loginuid_offset = -1,
    .sessionid_offset = -1,
    .comm_offset = -1,
    .seccomp_offset = -1,
    .security_offset = -1,
    .stack_offset = -1,
    .tasks_offset = -1,
    .mm_offset = -1,
    .active_mm_offset = -1,
};
KP_EXPORT_SYMBOL(task_struct_offset);

struct cred_offset cred_offset = {
    .usage_offset = -1,
    .subscribers_offset = -1,
    .magic_offset = -1,
    .uid_offset = -1,
    .gid_offset = -1,
    .suid_offset = -1,
    .sgid_offset = -1,
    .euid_offset = -1,
    .egid_offset = -1,
    .fsuid_offset = -1,
    .fsgid_offset = -1,
    .securebits_offset = -1,
    .cap_inheritable_offset = -1,
    .cap_permitted_offset = -1,
    .cap_effective_offset = -1,
    .cap_bset_offset = -1,
    .cap_ambient_offset = -1,

    .user_offset = -1,
    .user_ns_offset = -1,
    .ucounts_offset = -1,
    .group_info_offset = -1,

    .session_keyring_offset = -1,
    .process_keyring_offset = -1,
    .thread_keyring_offset = -1,
    .request_key_auth_offset = -1,

    .security_offset = -1,

    .rcu_offset = -1,
};
KP_EXPORT_SYMBOL(cred_offset);

struct task_struct *init_task = 0;
const struct cred *init_cred = 0;
const struct mm_struct *init_mm = 0;

int thread_size = 0;
KP_EXPORT_SYMBOL(thread_size);

int thread_info_in_task = 0;
KP_EXPORT_SYMBOL(thread_info_in_task);

#if defined(CONFIG_ARM)
/*
 * AArch32 has no SP_EL0.  The register that plays its role is TPIDRPRW
 * (CP15 c13,c0,3): the kernel loads it with the task pointer on context switch
 * when CONFIG_THREAD_INFO_IN_TASK=y, and linux/arch/arm/include/asm/current.h
 * calls the resulting flag `tpidrprw_is_current`.  Keep ONE storage with both
 * names rather than two variables that could silently drift apart; the
 * assignment sites in resolve_current() below use the arm64-era spelling, so
 * the alias points that way.  KP_EXPORT_SYMBOL() expands its argument before
 * stringifying, so both the defined symbol and the exported name become
 * tpidrprw_is_current -- which is the name the AArch32 asm/current.h links
 * against.
 */
int tpidrprw_is_current = 0;
#define sp_el0_is_current tpidrprw_is_current
#else
int sp_el0_is_current = 0;
#endif
KP_EXPORT_SYMBOL(sp_el0_is_current);

int sp_el0_is_thread_info = 0;
KP_EXPORT_SYMBOL(sp_el0_is_thread_info);

int task_in_thread_info_offset = -1;
KP_EXPORT_SYMBOL(task_in_thread_info_offset);

int stack_in_task_offset = -1;
KP_EXPORT_SYMBOL(stack_in_task_offset);

int stack_end_offset = 0x90;
KP_EXPORT_SYMBOL(stack_end_offset);

static int16_t *bl_list = 0;
static int bl_cap = 0;

static void reinit_bllist(int num)
{
    bl_cap = num;
    bl_list = (int16_t *)vmalloc(bl_cap * sizeof(int16_t));
    for (int i = 0; i < bl_cap; i++) {
        bl_list[i] = -1;
    }
}

static void uninit_bllist()
{
    bl_cap = 0;
    vfree(bl_list);
}

static int is_bl(int16_t off)
{
    for (int i = 0; i < bl_cap; i++) {
        if (bl_list[i] < 0) break;
        if (bl_list[i] == off) return 1;
    }
    return 0;
}

static void add_bll(int16_t off, int16_t size)
{
    for (int i = 0; i < bl_cap; i++) {
        if (bl_list[i] < 0) {
            bl_list[i] = off;
            if (size == 8) bl_list[i + 1] = off + 4;
            break;
        }
    }
}

int resolve_cred_offset()
{
    log_boot("struct cred: \n");

    reinit_bllist(128);

    struct cred *cred = (struct cred *)vmalloc(CRED_MAX_SIZE);
    struct cred *cred1 = (struct cred *)vmalloc(CRED_MAX_SIZE);
    struct task_struct *task = vmalloc(TASK_STRUCT_MAX_SIZE);
    lib_memcpy(cred, init_cred, CRED_MAX_SIZE);
    lib_memcpy(cred1, init_cred, CRED_MAX_SIZE);
    lib_memcpy(task, init_task, TASK_STRUCT_MAX_SIZE);

    *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset) = cred;
    *(struct cred **)((uintptr_t)task + task_struct_offset.real_cred_offset) = cred;

    const struct task_struct *backup = override_current(task);

    // cap_inheritable, cap_permitted, cap_effective
    kernel_cap_t effective, inheritable, permitted;
    cap_capget(task, &effective, &inheritable, &permitted);
    full_cap.val = effective.val;
    log_boot("    full_cap capability: %x\n", (unsigned int)full_cap.val);

    kernel_cap_t new_cap_e = { 0xff }, new_cap_i = { 0xf }, new_cap_p = { 0xfff };
    cap_capset(cred1, cred, &new_cap_e, &new_cap_i, &new_cap_p);

    for (int i = 0; i + (int)sizeof(kernel_cap_t) <= CRED_MAX_SIZE; i += sizeof(uint32_t)) {
        if (is_bl(i)) continue;
        kernel_cap_t cap = *(kernel_cap_t *)((uintptr_t)cred + i);
        kernel_cap_t cap1 = *(kernel_cap_t *)((uintptr_t)cred1 + i);
        if (cap.val == effective.val && cap1.val == new_cap_e.val) {
            cred_offset.cap_effective_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
            continue;
        }
        if (cap.val == inheritable.val && cap1.val == new_cap_i.val) {
            cred_offset.cap_inheritable_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
            continue;
        }
        if (cap.val == permitted.val && cap1.val == new_cap_p.val) {
            cred_offset.cap_permitted_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
            continue;
        }
    }

    // cap_bset
    for (int i = 0; i + (int)sizeof(kernel_cap_t) <= CRED_MAX_SIZE; i += sizeof(uint32_t)) {
        if (is_bl(i)) continue;
        kernel_cap_t cap1 = *(kernel_cap_t *)((uintptr_t)cred1 + i);
        if (cap1.val == effective.val) {
            cred_offset.cap_bset_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
        }
    }
    log_boot("    cap_effective offset: %x\n", cred_offset.cap_effective_offset);
    log_boot("    cap_inheritable offset: %x\n", cred_offset.cap_inheritable_offset);
    log_boot("    cap_permitted offset: %x\n", cred_offset.cap_permitted_offset);
    log_boot("    cap_bset offset: %x\n", cred_offset.cap_bset_offset);

    // securebits
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(uint32_t)) {
        if (is_bl(i)) continue;
        unsigned *sbitsp = (unsigned *)((uintptr_t)cred + i);
        unsigned oribits = *sbitsp;
        *sbitsp = 1158;
        unsigned sbits = cap_task_prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
        if (sbits != 1158) {
            *sbitsp = oribits;
            continue;
        }
        *sbitsp = oribits;
        cred_offset.securebits_offset = i;
        add_bll(i, sizeof(unsigned));
        break;
    }
    log_boot("    securebits offset: %x\n", cred_offset.securebits_offset);

    // euid, uid, egid, gid
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(uint32_t)) {
        if (is_bl(i)) continue;
        uid_t *uidp = (uid_t *)((uintptr_t)cred + i);
        if (*uidp) continue;
        *uidp = 1158;
#if defined(CONFIG_ARM)
        /* AArch32 EABI call numbers:  getuid32=199, getgid32=200,
         * geteuid32=201, getegid32=202.  The asm-generic numbers (174-177)
         * that the arm64 build resolves __NR_geteuid/etc. to are WRONG here: raw_syscall0
         * looks the number up in the *native* sys_call_table, so 175 there is
         * some unrelated syscall (munlock family) and the probe crashes. */
#define KP_NR_GETUID  199
#define KP_NR_GETGID  200
#define KP_NR_GETEUID 201
#define KP_NR_GETEGID 202
#define KP_NR_SETFSUID  138
#define KP_NR_SETFSGID  139
#define KP_NR_SETRESUID 164
#define KP_NR_SETRESGID 170
#else
#define KP_NR_GETUID  __NR_getuid
#define KP_NR_GETGID  __NR_getgid
#define KP_NR_GETEUID __NR_geteuid
#define KP_NR_GETEGID __NR_getegid
#define KP_NR_SETFSUID  __NR_setfsuid
#define KP_NR_SETFSGID  __NR_setfsgid
#define KP_NR_SETRESUID __NR_setresuid
#define KP_NR_SETRESGID __NR_setresgid
#endif
        if (raw_syscall0(KP_NR_GETEUID) == 1158) {
            cred_offset.euid_offset = i;
        } else if (raw_syscall0(KP_NR_GETUID) == 1158) {
            cred_offset.uid_offset = i;
        } else if (raw_syscall0(KP_NR_GETEGID) == 1158) {
            cred_offset.egid_offset = i;
        } else if (raw_syscall0(KP_NR_GETGID) == 1158) {
            cred_offset.gid_offset = i;
        } else {
            *uidp = 0;
            continue;
        }
        *uidp = 0;
        add_bll(i, sizeof(uid_t));
    }
    log_boot("    uid offset: %x\n", cred_offset.uid_offset);
    log_boot("    euid offset: %x\n", cred_offset.euid_offset);
    log_boot("    gid offset: %x\n", cred_offset.gid_offset);
    log_boot("    egid offset: %x\n", cred_offset.egid_offset);

    // fsuid
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(uint32_t)) {
        if (is_bl(i)) continue;
        uid_t *uidp = (uid_t *)((uintptr_t)cred + i);
        uid_t backup = *uidp;
        *uidp = 1158;
        uid_t old_uid = raw_syscall1(KP_NR_SETFSUID, -1);
        *uidp = backup;
        if (old_uid == 1158) {
            cred_offset.fsuid_offset = i;
            add_bll(i, sizeof(uid_t));
            break;
        }
    }
    log_boot("    fsuid offset: %x\n", cred_offset.fsuid_offset);

    // fsgid
    struct cred *new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(uint32_t)) {
        if (is_bl(i)) continue;
        gid_t *gidp = (gid_t *)((uintptr_t)new_cred + i);
        gid_t backup = *gidp;
        *gidp = 1158;
        gid_t old_gid = raw_syscall1(KP_NR_SETFSGID, -1);
        *gidp = backup;
        if (old_gid == 1158) {
            cred_offset.fsgid_offset = i;
            add_bll(i, sizeof(gid_t));
            break;
        }
    }
    log_boot("    fsgid offset: %x\n", cred_offset.fsgid_offset);

    // suid
    raw_syscall3(KP_NR_SETRESUID, 0, 0, 1158);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(uint32_t)) {
        if (is_bl(i)) continue;
        uid_t *uidp = (uid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.suid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(uid_t));
            break;
        }
    }
    log_boot("    suid offset: %x\n", cred_offset.suid_offset);

    // sgid
    raw_syscall3(KP_NR_SETRESGID, 0, 0, 1158);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    for (int i = 0; i < CRED_MAX_SIZE; i += sizeof(uint32_t)) {
        if (is_bl(i)) continue;
        gid_t *uidp = (gid_t *)((uintptr_t)new_cred + i);
        if (*uidp == 1158) {
            cred_offset.sgid_offset = i;
            *uidp = 0;
            add_bll(i, sizeof(gid_t));
            break;
        }
    }
    log_boot("    sgid offset: %x\n", cred_offset.sgid_offset);

    // cap_ambient
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_effective_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_inheritable_offset) = full_cap;
    *(kernel_cap_t *)((uintptr_t)new_cred + cred_offset.cap_permitted_offset) = full_cap;
    *(unsigned *)((uintptr_t)new_cred + cred_offset.securebits_offset) = 0;
    cap_task_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 0xf, 0, 0);
    new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
    /* prctl installed a slab cred, not one of our CRED_MAX_SIZE scratch buffers. */
    unsigned long (*cred_size)(const void *) = (typeof(cred_size))kallsyms_lookup_name("ksize");
    unsigned long ambient_scan_len = cred_size ? cred_size(new_cred) : CRED_MAX_SIZE;
    for (int i = 0; i + (int)sizeof(kernel_cap_t) <= CRED_MAX_SIZE &&
                    i + (int)sizeof(kernel_cap_t) <= ambient_scan_len; i += sizeof(uint32_t)) {
        if (is_bl(i)) continue;
        kernel_cap_t cap = *(kernel_cap_t *)((uintptr_t)cred + i);
        kernel_cap_t new_cap = *(kernel_cap_t *)((uintptr_t)new_cred + i);
        if (!cap.val && new_cap.val == (1 << 0xf)) {
            cred_offset.cap_ambient_offset = i;
            add_bll(i, sizeof(kernel_cap_t));
        }
    }
    log_boot("    cap_ambient offset: %x\n", cred_offset.cap_ambient_offset);

    revert_current(backup);

    vfree(cred);
    vfree(cred1);
    vfree(task);

    uninit_bllist();
    return 0;
}

static int find_swapper_comm_offset(uint64_t start, int size)
{
#if defined(CONFIG_ARM)
    /* AArch32: init_task etc. live in the kernel *linear* map (c0000000+ page
     * tables), which is NOT a KP-vmalloc range, so is_kimg_range() would make
     * every probe return -1 and all offsets stay 0xffffffff.  The linear map
     * is live here (MMU on) and task_struct is fully mapped, so a bounded
     * read is safe.  Keep the range gate for arm64/x86, where the caller
     * hands over KP-mapped addresses. */
#else
    if (!is_kimg_range(start) || !is_kimg_range(start + size)) return -1;
#endif
    char swapper_comm[TASK_COMM_LEN] = "swapper";
    char swapper_comm_1[TASK_COMM_LEN] = "swapper/0";
    /*
     * Iterate with a pointer-sized index: `i` is dereferenced as a (char *),
     * and on ILP32 a uint64_t index would need an int-to-pointer cast that is
     * both a warning and a width lie.  (uintptr_t is uint64_t on LP64, so this
     * is a no-op for the AArch64 build.)
     */
    for (uintptr_t i = (uintptr_t)start; i < (uintptr_t)(start + size); i += sizeof(uint32_t)) {
        if (!lib_strcmp(swapper_comm, (char *)i) || !lib_strcmp(swapper_comm_1, (char *)i)) {
            return (int)(i - (uintptr_t)start);
        }
    }
    return -1;
}

int resolve_task_offset()
{
    log_boot("struct task_struct: \n");

    struct task_struct *task = (struct task_struct *)vmalloc(TASK_STRUCT_MAX_SIZE);
    lib_memcpy(task, init_task, TASK_STRUCT_MAX_SIZE);

    const struct task_struct *backup = override_current(task);

    // init_cred
    int cred_offset[2];
    int cred_offset_idx = 0;
    init_cred = get_task_cred(init_task); // todo: get_task_cred not export
    log_boot("    init_cred addr: %llx\n", (unsigned long long)init_cred);
    for (uintptr_t i = (uintptr_t)init_task; i + sizeof(uintptr_t) <= (uintptr_t)init_task + TASK_STRUCT_MAX_SIZE;
         i += sizeof(uint32_t)) {
        uintptr_t val = *(uintptr_t *)i;
        if (val == (uintptr_t)init_cred) {
            cred_offset[cred_offset_idx++] = i - (uintptr_t)init_task;
            if (cred_offset_idx >= 2) break;
        }
    }

    char flag_cred[CRED_MAX_SIZE];
    lib_memcpy(flag_cred, init_cred, sizeof(flag_cred));
    *(uintptr_t *)((uintptr_t)init_task + cred_offset[0]) = (uintptr_t)flag_cred;
    if ((uintptr_t)init_cred == (uintptr_t)flag_cred) {
        task_struct_offset.real_cred_offset = cred_offset[0];
        task_struct_offset.cred_offset = cred_offset[1];
    } else {
        task_struct_offset.real_cred_offset = cred_offset[1];
        task_struct_offset.cred_offset = cred_offset[0];
    }
    *(uintptr_t *)((uintptr_t)init_task + cred_offset[0]) = (uintptr_t)init_cred;

    log_boot("    cred offset: %x\n", task_struct_offset.cred_offset);
    log_boot("    real_cred offset: %x\n", task_struct_offset.real_cred_offset);

    // seccomp
    if (kfunc(prctl_get_seccomp)) {
        for (uintptr_t i = (uintptr_t)task; i < (uintptr_t)task + TASK_STRUCT_MAX_SIZE; i += sizeof(uint32_t)) {
            int *modep = (int *)i;
            int mode_back = *modep;
            if (mode_back) continue;
            *modep = 1158;
            int mode = prctl_get_seccomp();
            if (mode == 1158) {
                task_struct_offset.seccomp_offset = i - (uintptr_t)task;
            }
            *modep = mode_back;
        }
    }
    log_boot("    seccomp offset: %x\n", task_struct_offset.seccomp_offset);

    // active_mm
    init_mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
    if (init_mm) {
        for (uintptr_t i = (uintptr_t)task; i + sizeof(uintptr_t) <= (uintptr_t)task + TASK_STRUCT_MAX_SIZE;
             i += sizeof(uint32_t)) {
            uintptr_t active_mm = *(uintptr_t *)i;
            if (active_mm == (uintptr_t)init_mm) {
                task_struct_offset.active_mm_offset = i - (uintptr_t)task;
                break;
            }
        }
    } else {
        // todo
    }
    log_boot("    active_mm offset: %x\n", task_struct_offset.active_mm_offset);

    revert_current(backup);
    vfree(task);
    return 0;
}

int resolve_current()
{
    log_boot("current: \n");
    uint64_t sp_el0;
    uint32_t sp32;
#if defined(CONFIG_ARM)
    /*
     * AArch32 has no SP_EL0.  The register that holds `current` in kernel mode
     * is TPIDRPRW (CP15 c13,c0,3) -- see asm/current.h -- so probe it exactly
     * the way the AArch64 path probes SP_EL0.  Under the legacy
     * !THREAD_INFO_IN_TASK layout it holds something else and the probe below
     * classifies it as "useless", which is the correct outcome there: current
     * is then reached through the thread_info at the base of the kernel stack.
     */
    sp_el0 = read_tpidrprw();
#else
    asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
#endif
    asm volatile("mov %0, sp" : "=r"(sp32));
    uint64_t sp = sp32;

    log_boot("    sp_el0: %llx\n", sp_el0);
    log_boot("    sp: %llx\n", sp);

    // default value
    sp_el0_is_current = 0;
    sp_el0_is_thread_info = 0;

    init_task = (struct task_struct *)kallsyms_lookup_name("init_task");
    uint64_t init_thread_union_addr = kallsyms_lookup_name("init_thread_union");

#if 0
    init_task = 0;
    init_thread_union_addr = 0;
#endif

    log_boot("    init_task addr lookup: %llx\n", (unsigned long long)init_task);
    log_boot("    init_thread_union addr lookup: %llx\n", init_thread_union_addr);
#if defined(CONFIG_ARM)
    /*
     * arm32: THREAD_SIZE = PAGE_SIZE << THREAD_SIZE_ORDER (arch/arm/include/
     * asm/thread_info.h -> order 1, i.e. 0x2000, when KASAN is off) and
     * end_of_stack() == (struct thread_info *)(task_thread_info(p) + 1)
     * (include/linux/sched/task_stack.h), so the kernel writes STACK_END_MAGIC
     * at stack_base + sizeof(struct thread_info) -- NOT at stack_base.  The
     * scan below therefore matches with any candidate >= the real size and
     * used to latch onto 0x4000 for an 8 KiB stack; every task then computed
     * its thread_info 8 KiB below its own stack and read a stale neighbour
     * task_struct (silently wrong current/uid) or unmapped garbage (oops).
     * The linker hands us the exact value: __end_init_task -
     * __start_init_task is INIT_TASK_DATA(THREAD_SIZE) (plus init_task itself
     * when CONFIG_ARCH_TASK_STRUCT_ON_STACK), so round down to a power of two.
     */
    uint32_t arm_thread_size = 0;
    uint64_t init_task_data_start = kallsyms_lookup_name("__start_init_task");
    uint64_t init_task_data_end = kallsyms_lookup_name("__end_init_task");
    if (init_task_data_start && init_task_data_end > init_task_data_start &&
        (init_task_data_end - init_task_data_start) <= 0x10000) {
        uint32_t sz = (uint32_t)(init_task_data_end - init_task_data_start);
        while (sz & (sz - 1)) sz &= sz - 1;
        arm_thread_size = sz;
    }
    log_boot("    arm32 THREAD_SIZE: %x (init_task_data %llx..%llx)\n", arm_thread_size,
             (unsigned long long)init_task_data_start, (unsigned long long)init_task_data_end);
#endif

    if (is_kimg_range(sp_el0)) {
        if (sp_el0 == init_thread_union_addr) {
            sp_el0_is_thread_info = 1;
            log_boot("    sp_el0: current_thread_info\n");
        } else if ((uintptr_t)init_task == (uintptr_t)sp_el0 || (sp_el0 & (page_size - 1)) ||
                   (task_struct_offset.comm_offset = find_swapper_comm_offset(sp_el0, TASK_STRUCT_MAX_SIZE)) > 0) {
            sp_el0_is_current = 1;
            init_task = (struct task_struct *)(uintptr_t)sp_el0;

            log_boot("    sp_el0: current\n");
            log_boot("    init_task addr: %llx\n", (unsigned long long)init_task);
            if (task_struct_offset.comm_offset > 0) {
                log_boot("    comm_offset of task: %x\n", task_struct_offset.comm_offset);
            }
        } else {
            sp_el0_is_thread_info = 1;
            log_boot("    sp_el0: current_thread_info\n");
        }
    } else {
        // use sp
        log_boot("    sp_el0: useless\n");
    }

    // THREAD_SIZE and end_of_stack and CONFIG_THREAD_INFO_IN_TASK
    // don't worry, we use little stack until here
    int thread_shift_cand[] = { 14, 15, 13, 16, 12 };
    for (int i = 0; i < sizeof(thread_shift_cand) / sizeof(thread_shift_cand[0]); i++) {
        int tsz = 1 << thread_shift_cand[i];
#if defined(CONFIG_ARM)
        /* arm32: only the linker-derived size is trustworthy */
        if (arm_thread_size && tsz != (int)arm_thread_size) continue;
#endif
        uint64_t sp_low = sp & ~(tsz - 1);
        // uint64_t sp_high = sp_low + tsz; // user_stack_pointer
        uint64_t psp = sp_low;
        for (; psp < sp_low + tsz; psp += sizeof(uint32_t)) {
            /*
             * STACK_END_MAGIC is written by the kernel as an `unsigned long`
             * (set_task_stack_end_magic stores it through an unsigned long *),
             * so read it at exactly that width: on ILP32 a uint64_t read would
             * compare the magic together with the adjacent word and never
             * match.  On LP64 the two are the same read.
             */
            if (*(unsigned long *)(uintptr_t)psp == (unsigned long)STACK_END_MAGIC) {
                if (psp == sp_low) {
                    thread_size = tsz;
                    stack_end_offset = 0;
                    thread_info_in_task = 1;
                } else {
                    thread_size = tsz;
                    stack_end_offset = psp - sp_low;
                    thread_info_in_task = 0;
                }
                break;
            }
        }
        if (thread_size > 0) {
            log_boot("    init stack end: %llx\n", psp);
            break;
        }
    }

    /* Newer GKI kernels may compile set_task_stack_end_magic() to an empty
     * function when the scheduler stack-end check is disabled.  In that case
     * the init stack contains no STACK_END_MAGIC even though its layout is
     * otherwise unchanged.  The init_thread_union symbol is the exact base of
     * the boot task's stack, so use it to select the smallest candidate that
     * contains the current SP.  For a downward-growing arm64 stack this is the
     * real THREAD_SIZE: a smaller candidate aligns SP above the stack base.
     *
     * Only take this path when sp_el0 identified current as task_struct.  If
     * sp_el0 is thread_info, an absent magic also means we cannot safely infer
     * the end_of_stack offset used by old !THREAD_INFO_IN_TASK kernels. */
#if defined(CONFIG_ARM)
    if (!thread_size && arm_thread_size) {
        /* set_task_stack_end_magic() may be compiled out (no magic in the init
         * stack); keep the linker-derived size and bound the thread_info scan
         * to a maximum sizeof(struct thread_info). */
        thread_size = arm_thread_size;
        stack_end_offset = 0x400;
        thread_info_in_task = 0;
        log_boot("    arm32 stack size from linker (no magic): %x\n", thread_size);
    }
#endif
#if !defined(CONFIG_ARM)
    if (!thread_size && init_thread_union_addr && sp_el0_is_current) {
        for (int i = 0; i < sizeof(thread_shift_cand) / sizeof(thread_shift_cand[0]); i++) {
            int tsz = 1 << thread_shift_cand[i];
            uint64_t sp_low = sp & ~(tsz - 1);
            if (sp_low != init_thread_union_addr) continue;

            thread_size = tsz;
            stack_end_offset = 0;
            thread_info_in_task = 1;
            log_boot("    stack size inferred from init_thread_union: %x\n", thread_size);
            break;
        }
    }
#endif

    /* Keep the historical arm64 default as a last-resort compatibility path
     * for kernels that hide init_thread_union from kallsyms. */
    if (!thread_size) {
#if defined(CONFIG_ARM)
        /* arm32 default: PAGE_SIZE << THREAD_SIZE_ORDER (order 1, KASAN off) */
        thread_size = 0x2000;
        stack_end_offset = 0x400;
        thread_info_in_task = 0;
#else
        thread_size = 0x4000;
        stack_end_offset = 0;
        thread_info_in_task = 1;
#endif
        log_boot("    stack size fallback: %x\n", thread_size);
    }

    log_boot("    thread_size: %x\n", thread_size);
    log_boot("    stack_end_offset: %x\n", stack_end_offset);
    log_boot("    thread_info_in_task: %x\n", thread_info_in_task);

    // task_in_thread_info_offset, 16 generally, see thread_info_be490
    if (!thread_info_in_task) {
        /*
         * Pointer-sized, not uint64_t: what is searched for is a
         * task_struct * and the cell holding it is one pointer wide.  On ILP32
         * a uint64_t read also picks up the neighbouring word, so the
         * comparison would silently never match.
         */
        uintptr_t thread_info_addr = (uintptr_t)current_thread_info_sp();
        if (init_task) {
            for (uintptr_t ptr = thread_info_addr; ptr < thread_info_addr + stack_end_offset; ptr += sizeof(uint32_t)) {
                uintptr_t pv = *(uintptr_t *)ptr;
                if (pv == (uintptr_t)init_task) {
                    task_in_thread_info_offset = ptr - thread_info_addr;
                    break;
                }
            }
        } else { // unlikely
            for (uintptr_t ptr = thread_info_addr; ptr < thread_info_addr + stack_end_offset; ptr += sizeof(uint32_t)) {
                uintptr_t pv = *(uintptr_t *)ptr;
                task_struct_offset.comm_offset = find_swapper_comm_offset(pv, TASK_STRUCT_MAX_SIZE);
                if (task_struct_offset.comm_offset > 0) {
                    init_task = (struct task_struct *)pv;
                    task_in_thread_info_offset = ptr - thread_info_addr;
                    log_boot("    init_task addr: %llx\n", (unsigned long long)init_task);
                    log_boot("    comm_offset of task: %x\n", task_struct_offset.comm_offset);
                }
            }
        }
        log_boot("    task_in_thread_info_offset: %x\n", task_in_thread_info_offset);
    }

    if (task_struct_offset.comm_offset <= 0) {
        task_struct_offset.comm_offset = find_swapper_comm_offset((uintptr_t)init_task, TASK_STRUCT_MAX_SIZE);
        log_boot("    comm_offset of task: %x\n", task_struct_offset.comm_offset);
    }

    // stack,
    uint64_t stack_base = (sp & ~(thread_size - 1));
    for (uintptr_t i = (uintptr_t)init_task; i < (uintptr_t)init_task + TASK_STRUCT_MAX_SIZE; i += sizeof(uint32_t)) {
        uintptr_t val = *(uintptr_t *)i;
        if (stack_base == val) {
            stack_in_task_offset = i - (uintptr_t)init_task;
            task_struct_offset.stack_offset = stack_in_task_offset;
            break;
        }
    }
    log_boot("    stack offset of task: %x\n", task_struct_offset.stack_offset);

    return 0;
}

// todo
int resolve_mm_struct_offset()
{
    if (!init_mm) return 0;

    log_boot("struct mm_struct: \n");

    // struct mm_struct *mm = get_task_mm(init_task);
    // uintptr_t init_mm_addr = (uintptr_t)mm;

    uintptr_t init_mm_addr = (uintptr_t)init_mm;
    if (!init_mm_addr) return 0;

    for (uintptr_t i = init_mm_addr; i < init_mm_addr + MM_STRUCT_MAX_SIZE; i += sizeof(uint32_t)) {
        uint64_t pgd = *(uintptr_t *)i;
        if (pgd == phys_to_kimg(pgd_pa)) {
            mm_struct_offset.pgd_offset = i - init_mm_addr;
        }
    }
    log_boot("    pgd offset: %x\n", mm_struct_offset.pgd_offset);
    return 0;
}

int resolve_struct()
{
    full_cap = CAP_FULL_SET;

    int err = 0;

    if ((err = resolve_current())) goto out;

    if ((err = resolve_task_offset())) goto out;

    if ((err = resolve_cred_offset())) goto out;

    resolve_mm_struct_offset();

out:
    return err;
}
