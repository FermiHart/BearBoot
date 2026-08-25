/* Hosted Wave 20 rollback policy tests; no firmware is required. */
#include <stdint.h>
#include <stdio.h>

#include "../experimental/rollback/bbp_boot_state.h"

static int failures;

#define CHECK(condition, message) do { \
    if (!(condition)) { printf("FAIL: %s\n", (message)); failures++; } \
    else printf("ok:   %s\n", (message)); \
} while (0)

static void test_generation_window(void)
{
    struct bbp_boot_policy_result result;

    result = bbp_boot_policy_evaluate(8u, 7u, BBP_BOOT_ROLE_RELEASE);
    CHECK(result.decision == BBP_BOOT_REJECT_ROLLBACK && result.floor == 8u,
          "generation below the floor is rejected without changing it");

    result = bbp_boot_policy_evaluate(8u, 8u, BBP_BOOT_ROLE_RELEASE);
    CHECK(result.decision == BBP_BOOT_ACCEPT_RETRY && result.floor == 8u,
          "release at the floor is an idempotent retry");

    result = bbp_boot_policy_evaluate(8u, 9u, BBP_BOOT_ROLE_RELEASE);
    CHECK(result.decision == BBP_BOOT_ACCEPT_UPDATE && result.floor == 9u,
          "release exactly one generation ahead raises the floor");

    result = bbp_boot_policy_evaluate(8u, 10u, BBP_BOOT_ROLE_RELEASE);
    CHECK(result.decision == BBP_BOOT_REJECT_GAP && result.floor == 8u,
          "release generation gaps are rejected");
}

static void test_role_constraints(void)
{
    struct bbp_boot_policy_result result;

    result = bbp_boot_policy_evaluate(12u, 12u, BBP_BOOT_ROLE_RECOVERY);
    CHECK(result.decision == BBP_BOOT_ACCEPT_RETRY && result.floor == 12u,
          "recovery is accepted only at the established floor");

    result = bbp_boot_policy_evaluate(12u, 13u, BBP_BOOT_ROLE_RECOVERY);
    CHECK(result.decision == BBP_BOOT_REJECT_ROLE && result.floor == 12u,
          "recovery cannot advance the monotonic floor");

    result = bbp_boot_policy_evaluate(12u, 12u,
                                      (enum bbp_boot_role)99);
    CHECK(result.decision == BBP_BOOT_REJECT_ROLE && result.floor == 12u,
          "unknown artifact roles fail closed");
}

static void test_uint64_exhaustion(void)
{
    struct bbp_boot_policy_result result;

    result = bbp_boot_policy_evaluate(UINT64_MAX, UINT64_MAX,
                                      BBP_BOOT_ROLE_RELEASE);
    CHECK(result.decision == BBP_BOOT_ACCEPT_RETRY &&
          result.floor == UINT64_MAX,
          "the maximum generation remains retryable");

    result = bbp_boot_policy_evaluate(UINT64_MAX - 1u, UINT64_MAX,
                                      BBP_BOOT_ROLE_RELEASE);
    CHECK(result.decision == BBP_BOOT_ACCEPT_UPDATE &&
          result.floor == UINT64_MAX,
          "the final representable generation can be committed");

    result = bbp_boot_policy_evaluate(UINT64_MAX, 0u,
                                      BBP_BOOT_ROLE_RELEASE);
    CHECK(result.decision == BBP_BOOT_REJECT_EXHAUSTED &&
          result.floor == UINT64_MAX,
          "a wrapped candidate is reported as exhaustion, never generation zero");
}

int main(void)
{
    printf("== BBP durable rollback policy self-test ==\n");
    test_generation_window();
    test_role_constraints();
    test_uint64_exhaustion();
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures != 0;
}
