/*
 * Host-side model of the su prompt state machine.
 *
 * Mirrors su_prompt_apply(), su_prompt_reachable() and the exec path's use of
 * is_su_allow_uid()/is_su_deny_uid() from kernel/patch/common/sucompat.c, with the
 * kstorage calls replaced by in-memory sets. The point is the *semantics* the user
 * asked for, which no amount of build success can demonstrate:
 *
 *   allow        -> whitelist, next su is silent
 *   allow once   -> nothing remembered, next su asks again
 *   deny         -> denylist (and whitelist cleared), next su is ENOENT with no ask
 *   deny once    -> nothing remembered, next su asks again
 *   timeout deny -> nothing remembered, next su asks again, this call denied
 *   timeout allow-> nothing remembered, next su asks again, this call allowed
 *
 * Build/run: gcc -O1 -std=gnu11 -o /tmp/t su_prompt_state_model.c && /tmp/t
 */
#include <stdio.h>
#include <string.h>

#define SU_DECISION_ALLOW 1
#define SU_DECISION_ALLOW_ONCE 2
#define SU_DECISION_DENY (-1)
#define SU_DECISION_TIMEOUT (-2)
#define SU_DECISION_DENY_ONCE (-3)

#define MAX_UID 70000   /* Android app uids are 10000+, so an array is simpler than a map */

static int whitelist[MAX_UID];   /* su allow list            (kstorage group 0) */
static int denylist[MAX_UID];    /* refused uids             (kstorage group 3) */
static int prompt_on = 1;
static int pending_pid = 0;      /* the PENDING record       (kstorage group 2) */

static int is_su_allow_uid(int uid) { return whitelist[uid]; }
static int is_su_deny_uid(int uid) { return denylist[uid]; }
static int is_trusted_manager_uid(int uid) { return uid == 0; }
static int su_prompt_enabled(void) { return prompt_on; }

/* ---- copied from sucompat.c (bodies unchanged, kstorage -> sets) ------- */
static void su_prompt_apply(int uid, int pid, int decision, int timed_out)
{
    int allow = (decision == SU_DECISION_ALLOW || decision == SU_DECISION_ALLOW_ONCE);
    int remember = !timed_out && (decision == SU_DECISION_ALLOW || decision == SU_DECISION_DENY);

    if (remember) {
        if (allow) {
            denylist[uid] = 0;
            whitelist[uid] = 1;
        } else {
            whitelist[uid] = 0;
            denylist[uid] = 1;
        }
    }
    /* always drop the pending record */
    if (pid == pending_pid) pending_pid = 0;
}

static int su_prompt_reachable(int uid)
{
    return su_prompt_enabled() && !is_su_allow_uid(uid) && !is_trusted_manager_uid(uid) &&
           !is_su_deny_uid(uid);
}
/* ----------------------------------------------------------------------- */

/* Outcome of one `su` attempt, as the caller experiences it. */
enum outcome { O_PROMPT, O_SILENT_ROOT, O_ENOENT };

static enum outcome try_su(int uid)
{
    if (is_su_allow_uid(uid) || is_trusted_manager_uid(uid)) return O_SILENT_ROOT;
    if (is_su_deny_uid(uid)) return O_ENOENT;         /* hidden + refused, no prompt */
    if (su_prompt_reachable(uid)) return O_PROMPT;
    return O_ENOENT;                                  /* feature off */
}

static int failures;
static void expect(const char *what, int got, int want)
{
    if (got != want) { printf("FAIL  %-56s got=%d want=%d\n", what, got, want); failures++; }
    else             { printf("ok    %-56s %d\n", what, got); }
}

static void reset(void)
{
    memset(whitelist, 0, sizeof(whitelist));
    memset(denylist, 0, sizeof(denylist));
    prompt_on = 1;
}

int main(void)
{
    const int U = 10099;

    /* allow + remember */
    reset();
    expect("fresh uid asks", try_su(U), O_PROMPT);
    su_prompt_apply(U, 4242, SU_DECISION_ALLOW, 0);
    expect("after ALLOW: next su is silent root", try_su(U), O_SILENT_ROOT);

    /* allow once */
    reset();
    su_prompt_apply(U, 4242, SU_DECISION_ALLOW_ONCE, 0);
    expect("after ALLOW_ONCE: asks again", try_su(U), O_PROMPT);

    /* deny + remember */
    reset();
    su_prompt_apply(U, 4242, SU_DECISION_DENY, 0);
    expect("after DENY: ENOENT without asking", try_su(U), O_ENOENT);

    /* deny once */
    reset();
    su_prompt_apply(U, 4242, SU_DECISION_DENY_ONCE, 0);
    expect("after DENY_ONCE: asks again", try_su(U), O_PROMPT);

    /* timeout, deny policy: this call is denied, nothing remembered */
    reset();
    su_prompt_apply(U, 4242, SU_DECISION_DENY_ONCE, 1);
    expect("timeout(deny): asks again next time", try_su(U), O_PROMPT);

    /* timeout, allow policy: this call allowed, nothing remembered */
    reset();
    su_prompt_apply(U, 4242, SU_DECISION_ALLOW_ONCE, 1);
    expect("timeout(allow): asks again next time", try_su(U), O_PROMPT);

    /* deny then allow must clear the other list */
    reset();
    su_prompt_apply(U, 1, SU_DECISION_DENY, 0);
    expect("denied", try_su(U), O_ENOENT);
    su_prompt_apply(U, 2, SU_DECISION_ALLOW, 0);
    expect("re-allowed overrides deny", try_su(U), O_SILENT_ROOT);
    expect("denylist was cleared", is_su_deny_uid(U), 0);

    /* allow then deny must clear the whitelist */
    reset();
    su_prompt_apply(U, 1, SU_DECISION_ALLOW, 0);
    su_prompt_apply(U, 2, SU_DECISION_DENY, 0);
    expect("whitelist was cleared", is_su_allow_uid(U), 0);
    expect("denied wins", try_su(U), O_ENOENT);

    /* the pending record is always dropped, otherwise pid reuse wedges later su */
    reset();
    pending_pid = 4242;
    su_prompt_apply(U, 4242, SU_DECISION_ALLOW, 0);
    expect("pending record removed", pending_pid, 0);

    /* feature off: behaves like stock, no prompt */
    reset();
    prompt_on = 0;
    expect("prompt off: no prompt", try_su(U), O_ENOENT);

    /* root and the manager never prompt */
    reset();
    expect("root never prompts", try_su(0), O_SILENT_ROOT);

    printf("\n%s (%d failure(s))\n", failures ? "STATE MODEL FAILED" : "STATE MODEL OK", failures);
    return failures ? 1 : 0;
}
