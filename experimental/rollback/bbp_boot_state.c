#include "bbp_boot_state.h"

#include <stdint.h>

struct bbp_boot_policy_result bbp_boot_policy_evaluate(
    uint64_t floor, uint64_t generation, enum bbp_boot_role role)
{
    struct bbp_boot_policy_result result;

    result.floor = floor;
    if (role != BBP_BOOT_ROLE_RELEASE && role != BBP_BOOT_ROLE_RECOVERY) {
        result.decision = BBP_BOOT_REJECT_ROLE;
        return result;
    }

    if (floor == UINT64_MAX && generation != floor) {
        result.decision = BBP_BOOT_REJECT_EXHAUSTED;
        return result;
    }
    if (generation < floor) {
        result.decision = BBP_BOOT_REJECT_ROLLBACK;
        return result;
    }
    if (generation == floor) {
        result.decision = BBP_BOOT_ACCEPT_RETRY;
        return result;
    }
    if (generation - floor != 1u) {
        result.decision = BBP_BOOT_REJECT_GAP;
        return result;
    }
    if (role == BBP_BOOT_ROLE_RECOVERY) {
        result.decision = BBP_BOOT_REJECT_ROLE;
        return result;
    }

    result.decision = BBP_BOOT_ACCEPT_UPDATE;
    result.floor = generation;
    return result;
}
