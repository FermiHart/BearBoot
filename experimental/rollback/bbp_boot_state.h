#ifndef BBP_BOOT_STATE_H
#define BBP_BOOT_STATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum bbp_boot_role {
    BBP_BOOT_ROLE_RELEASE = 1,
    BBP_BOOT_ROLE_RECOVERY = 2
};

enum bbp_boot_decision {
    BBP_BOOT_REJECT_ROLLBACK = 0,
    BBP_BOOT_ACCEPT_RETRY,
    BBP_BOOT_ACCEPT_UPDATE,
    BBP_BOOT_REJECT_GAP,
    BBP_BOOT_REJECT_EXHAUSTED,
    BBP_BOOT_REJECT_ROLE
};

struct bbp_boot_policy_result {
    enum bbp_boot_decision decision;
    uint64_t floor;
};

/* Pure policy: no storage, clock, firmware, or TPM access is performed. */
struct bbp_boot_policy_result bbp_boot_policy_evaluate(
    uint64_t floor, uint64_t generation, enum bbp_boot_role role);

#ifdef __cplusplus
}
#endif

#endif
