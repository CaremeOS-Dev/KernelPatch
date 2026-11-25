/*
 * Host-side model of the su probe decision table.
 *
 * The two functions below are copied verbatim from
 * kernel/patch/common/sucompat.c (su_comm_is_path_probe and the probe branch of
 * after_getname_flags). The kernel context is stubbed so the decision can be
 * exercised without a device: a wrong answer here is a wrong answer on the Z9,
 * because the logic is the same.
 *
 * Build/run: gcc -O1 -std=gnu11 -o /tmp/su_probe_test su_probe_model.c && /tmp/su_probe_test
 */
#include <stdio.h>
#include <string.h>

#define TASK_COMM_LEN 16

/* ---- copied from sucompat.c ------------------------------------------- */
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
/* ----------------------------------------------------------------------- */

/* Model of the probe branch: returns 1 when the caller must be told ENOENT. */
static int probe_hides(const char *name, int uid, int trusted, int prompt_on,
                       const char *comm)
{
    if (!name || strcmp(name, "/system/bin/kp")) return 0;   /* su_get_path() */
    if (!trusted && prompt_on) {
        if (su_comm_is_path_probe(comm)) return 1;
    }
    return 0;
}

static int failures = 0;

static void expect(const char *what, int got, int want)
{
    if (got != want) {
        printf("FAIL  %-58s got=%d want=%d\n", what, got, want);
        failures++;
    } else {
        printf("ok    %-58s %d\n", what, got);
    }
}

int main(void)
{
    /* The whole point: other paths are never affected, by anyone. */
    expect("which sh   (untrusted)", probe_hides("/system/bin/sh", 10099, 0, 1, "which"), 0);
    expect("which ls   (untrusted)", probe_hides("/system/bin/ls", 10099, 0, 1, "which"), 0);
    expect("ld.config.txt (linker)", probe_hides("/system/etc/ld.config.txt", 10099, 0, 1, "which"), 0);
    expect("liblog.so  (linker)", probe_hides("/system/lib/liblog.so", 10099, 0, 1, "linker"), 0);

    /* The probe itself. */
    expect("which su   (untrusted)", probe_hides("/system/bin/kp", 10099, 0, 1, "which"), 1);
    expect("type su    (untrusted)", probe_hides("/system/bin/kp", 10099, 0, 1, "type"), 1);
    expect("command su (untrusted)", probe_hides("/system/bin/kp", 10099, 0, 1, "command"), 1);
    expect("whereis su (untrusted)", probe_hides("/system/bin/kp", 10099, 0, 1, "whereis"), 1);

    /* Trusted uids keep seeing su, even through which. */
    expect("which su   (whitelisted)", probe_hides("/system/bin/kp", 10099, 1, 1, "which"), 0);
    expect("which su   (root)", probe_hides("/system/bin/kp", 0, 1, 1, "which"), 0);

    /* Shells and the app itself are not probes: su must stay reachable. */
    expect("su         (app exec)", probe_hides("/system/bin/kp", 10099, 0, 1, "com.example"), 0);
    expect("su         (sh)", probe_hides("/system/bin/kp", 10099, 0, 1, "sh"), 0);
    expect("su         (mksh)", probe_hides("/system/bin/kp", 10099, 0, 1, "mksh"), 0);
    expect("su         (busybox)", probe_hides("/system/bin/kp", 10099, 0, 1, "busybox"), 0);

    /* Feature off: behave exactly like stock. */
    expect("which su   (prompt off)", probe_hides("/system/bin/kp", 10099, 0, 0, "which"), 0);

    /* Prefix matching must not over-reach. */
    expect("comm 'typ' must not match 'type'", su_comm_is_path_probe("typ"), 0);
    expect("comm 'whic' must not match 'which'", su_comm_is_path_probe("whic"), 0);
    expect("comm 'which' matches", su_comm_is_path_probe("which"), 1);
    expect("comm 'which-longer' matches (truncation)", su_comm_is_path_probe("which-longer"), 1);
    expect("comm NULL is safe", su_comm_is_path_probe(NULL), 0);
    expect("comm '' is safe", su_comm_is_path_probe(""), 0);

    printf("\n%s (%d failure(s))\n", failures ? "MODEL FAILED" : "MODEL OK", failures);
    return failures ? 1 : 0;
}
