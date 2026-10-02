/* Emit the __NR_* values the A32 build actually sees, as plain strings inside a
 * compiled object, so `strings` can read them back.  Compiled with exactly
 * ARM_FULL_CFLAGS / ARM_FULL_INCLUDE so the answer is the build's answer, not a
 * hand-rolled include order.
 *
 * ARM EABI (what a 4.9 armv7 kernel's native sys_call_table uses):
 *     execve 11, execveat 387, openat 322, faccessat 334, supercall 394
 * asm-generic (WRONG for a 32-bit ARM kernel):
 *     execve 221, execveat 281, openat 56, faccessat 48
 */
#include <ktypes.h>
#include <syscall.h>
#include <uapi/scdefs.h>

#define S1(x) #x
#define S(x) S1(x)

const char kp_nr_probe[] =
    "NRPROBE"
    " execve=" S(__NR_execve)
    " execveat=" S(__NR_execveat)
    " openat=" S(__NR_openat)
    " supercall=" S(__NR_supercall)
#ifdef __NR_faccessat
    " faccessat=" S(__NR_faccessat)
#endif
#ifdef __NR_getuid
    " getuid=" S(__NR_getuid)
#endif
    " END";

const char kp_arch_probe[] =
    "ARCHPROBE"
#ifdef CONFIG_ARM
    " CONFIG_ARM=1"
#endif
#ifdef __arm__
    " __arm__=1"
#endif
#ifdef __aarch64__
    " __aarch64__=1"
#endif
    " END";
