/* SPDX-License-Identifier: BSD-3-Clause */
/* Experimental host-oriented v2 HMAC framing. Not a deployment key policy. */
#ifndef BBP_V2_AUTH_H
#define BBP_V2_AUTH_H

#include <stddef.h>
#include <stdint.h>

#include <bbp/bbp_v2.h>

#define BBP_V2_AUTH_MAGIC_BYTES \
    { 'B', 'B', 'P', '2', 'A', 'U', 'T', 'H' }
#define BBP_V2_AUTH_VERSION       1u
#define BBP_V2_AUTH_ALG_HMAC_SHA256 1u
#define BBP_V2_AUTH_HEADER_SIZE   80u
#define BBP_V2_AUTH_KEY_ID_SIZE   16u
#define BBP_V2_AUTH_TAG_SIZE      32u
#define BBP_V2_AUTH_TAG_OFFSET    48u
#define BBP_V2_AUTH_MAX_CAPSULE_SIZE BBP_V2_MAX_EXTENT

struct bbp_v2_auth_header {
    uint8_t magic[8];
    uint16_t version;
    uint16_t algorithm;
    uint32_t flags;
    uint64_t rollback_index;
    uint64_t capsule_size;
    uint8_t key_identity[BBP_V2_AUTH_KEY_ID_SIZE];
    uint8_t tag[BBP_V2_AUTH_TAG_SIZE];
} __attribute__((packed));

_Static_assert(sizeof(struct bbp_v2_auth_header) == BBP_V2_AUTH_HEADER_SIZE,
               "bbp_v2_auth_header ABI");
_Static_assert(offsetof(struct bbp_v2_auth_header, tag) ==
               BBP_V2_AUTH_TAG_OFFSET, "bbp_v2_auth_header.tag ABI");

typedef enum bbp_v2_auth_status {
    BBP_V2_AUTH_OK = 0,
    BBP_V2_AUTH_ERR_NULL,
    BBP_V2_AUTH_ERR_MAGIC,
    BBP_V2_AUTH_ERR_VERSION,
    BBP_V2_AUTH_ERR_ALGORITHM,
    BBP_V2_AUTH_ERR_FLAGS,
    BBP_V2_AUTH_ERR_EXTENT,
    BBP_V2_AUTH_ERR_MAC,
    BBP_V2_AUTH_ERR_CAPSULE,
    BBP_V2_AUTH_ERR_POLICY
} bbp_v2_auth_status_t;

/* header contains all 80 wire bytes with its tag field zeroed. The verifier
 * must authenticate header followed by capsule and compare against tag. */
typedef int (*bbp_v2_auth_mac_verify_fn)(
    void *context,
    const uint8_t key_identity[BBP_V2_AUTH_KEY_ID_SIZE],
    const uint8_t header[BBP_V2_AUTH_HEADER_SIZE],
    const uint8_t *capsule,
    size_t capsule_size,
    const uint8_t tag[BBP_V2_AUTH_TAG_SIZE]);

/* The policy callback runs only after authentication and generic v2 parsing.
 * It returns nonzero to accept the rollback index and capsule semantics. */
typedef int (*bbp_v2_auth_policy_fn)(
    void *context,
    uint64_t rollback_index,
    const uint8_t key_identity[BBP_V2_AUTH_KEY_ID_SIZE],
    const struct bbp_v2_view *capsule);

struct bbp_v2_auth_view {
    const uint8_t *envelope;
    size_t envelope_size;
    uint64_t rollback_index;
    uint8_t key_identity[BBP_V2_AUTH_KEY_ID_SIZE];
    struct bbp_v2_view capsule;
};

bbp_v2_auth_status_t bbp_v2_auth_parse(
    const void *envelope,
    size_t extent,
    bbp_v2_auth_mac_verify_fn verify_mac,
    void *mac_context,
    bbp_v2_auth_policy_fn policy,
    void *policy_context,
    struct bbp_v2_auth_view *out);

const char *bbp_v2_auth_strstatus(bbp_v2_auth_status_t status);

#endif
