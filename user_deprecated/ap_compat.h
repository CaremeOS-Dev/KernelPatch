/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * APatch / KernelPatch path constants required by user_deprecated/android/android_user.c
 * and user_deprecated/su.c.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * These identifiers are *used* by the user_deprecated sources but are defined nowhere in
 * this repository -- verified with
 *     git grep -n -E '<name>' $(git rev-list --all)
 * which finds only uses, never a definition, in any commit.
 *
 * The reason is that user_deprecated/uapi/ is a *generated* copy of the kernel headers:
 * user_deprecated/.gitignore:34 ignores "uapi", and user_deprecated/Makefile's `clean`
 * target does "rm -rf uapi".  Originally that directory held this tree's kernel-side
 * kernel/patch/include/uapi/scdefs.h, whose "#ifdef ANDROID" block defined all of these.
 * The port replaced user_deprecated/uapi/scdefs.h with APatch's Bionic-clean userspace
 * version (E:\Apatch For XTC\APatch\app\src\main\cpp\uapi\scdefs.h, byte-identical, needed
 * because the kernel-side one does `#include <ktypes.h>` and collides with the NDK
 * sysroot).  APatch's userspace scdefs.h contains NONE of these defines (grep: no match),
 * so the definitions were lost.
 *
 * They are also absent from this repo's current kernel-side header: at HEAD,
 * kernel/patch/include/uapi/scdefs.h:104 is the only "#ifdef ANDROID" and it defines just
 * APD_PATH (:111).  The buildable upstream revision that still defined them is KernelPatch
 * v0.10.7, whose kernel/patch/include/uapi/scdefs.h:65-88 reads:
 *
 *     #ifdef ANDROID
 *     #define KPATCH_DATA_PATH       "/data/adb/kpatch"
 *     #define KPATCH_DEV_PATH        "/dev/kpatch"
 *     #define APD_PATH               "/data/adb/apd"
 *     #define ADB_FLODER             "/data/adb/"
 *     #define APATCH_FLODER          "/data/adb/ap/"
 *     #define APATCH_BIN_FLODER      APATCH_FLODER "bin/"
 *     #define APATCH_LOG_FLODER      APATCH_FLODER "log/"
 *     #define EARLY_INIT_LOG_0       "/dev/early_init_0.log"
 *     #define EARLY_INIT_LOG_1       "/dev/early_init_1.log"
 *     #endif
 *
 * (retrieved from https://github.com/bmax121/KernelPatch/archive/refs/tags/0.10.7.tar.gz;
 * also matched by the .gitignore'd build_android.sh mechanism -- user_deprecated/.gitignore:38
 * ignores build_android.sh, which is where upstream passed these in.)
 *
 * The names used by *this* tree's stale sources differ from the v0.10.7 spelling; the
 * mapping is recorded per-constant below.  Every value is corroborated a second, independent
 * way by the string literals of the prebuilt AArch64 kpatch binary that APatch actually
 * ships, E:\Apatch For XTC\APatch\app\libs\arm64-v8a\libkpatch.so (the KernelPatch 0.10.7
 * "kpatch-android" release downloaded by APatch\app\build.gradle.kts:257-262), dumped with
 *     llvm-strings.exe -n 3 ...\arm64-v8a\libkpatch.so
 * which contains exactly: "/data/adb/", "/data/adb/ap/", "/data/adb/ap/bin/magiskpolicy",
 * "/data/adb/ap/log/", "/dev/early_init_0.log", "/dev/early_init_1.log", "/data/adb/kpatch",
 * "/dev/kpatch" is not separately visible there (the compiler folded that comparison), so
 * v0.10.7 scdefs.h:73 is the authority for it.
 */
#ifndef _KP_AP_COMPAT_H_
#define _KP_AP_COMPAT_H_

/* v0.10.7 spelling: ADB_FLODER.  Used by su.c:40 (DEFAULT_ROOT_PATH). */
#define ADB_DIR "/data/adb/"

/* v0.10.7 spelling: APATCH_FLODER.  Used by android_user.c:33,34,240
 * (also "package_config" / "su_path", both confirmed by the prebuilt libkpatch.so). */
#define AP_DIR "/data/adb/ap/"

/* v0.10.7 spelling: APATCH_BIN_FLODER.  Used by android_user.c:32 and su.c:39. */
#define AP_BIN_DIR AP_DIR "bin/"

/* v0.10.7 spelling: APATCH_LOG_FLODER == APATCH_FLODER "log/".  Used by
 * android_user.c:241,243,304,308; must keep the trailing '/' because :308 concatenates it
 * with "trigger_%s.dmesg.log".  Corroborated by kernel/patch/android/userd.c:132
 * ("mv -f /dev/user_init_log/ /data/adb/ap/log/") and by APatch
 * app/src/main/java/me/bmax/apatch/util/LogEvent.kt:45 ("tar -czf <f> -C /data/adb/ap/log ."). */
#define APATCH_LOG_FLODER "/data/adb/ap/log/"

/* v0.10.7 scdefs.h:85-86.  Written during early-init, before /data exists, hence /dev. */
#define EARLY_INIT_LOG_0 "/dev/early_init_0.log"
#define EARLY_INIT_LOG_1 "/dev/early_init_1.log"

/* v0.10.7 scdefs.h:72. */
#define KPATCH_DATA_PATH "/data/adb/kpatch"

/* v0.10.7 scdefs.h:73.  The kernel writes the userspace binary here and execs it at
 * early-init, then post-fs-data-init copies it to KPATCH_DATA_PATH; see v0.10.7
 * kernel/patch/android/userd.c:280-298, which emits this init script:
 *   "    exec -- " SUPERCMD " %s " KPATCH_DEV_PATH  " %s android_user early-init -k\n"
 *   "    exec -- " SUPERCMD " %s " KPATCH_DATA_PATH " %s android_user post-fs-data-init -k\n"
 *   "    rm " KPATCH_DEV_PATH "\n" */
#define KPATCH_DEV_PATH "/dev/kpatch"

#endif /* _KP_AP_COMPAT_H_ */
