#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bbp/bbp_v2_auth.h>
#include <bbp/bbp_v2_profile.h>

static int failures;
#define CHECK(condition, name) do { \
    if (!(condition)) { printf("FAIL: %s\n", name); failures++; } \
} while (0)

struct oracle {
    const uint8_t *envelope;
    size_t extent;
};

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t size)
{
    unsigned difference = 0;
    while (size--) difference |= (unsigned)(*a++ ^ *b++);
    return difference == 0;
}

static int oracle_mac(void *opaque, const uint8_t identity[16],
                      const uint8_t header[BBP_V2_AUTH_HEADER_SIZE],
                      const uint8_t *capsule, size_t capsule_size,
                      const uint8_t tag[BBP_V2_AUTH_TAG_SIZE])
{
    struct oracle *oracle = opaque;
    uint8_t canonical[BBP_V2_AUTH_HEADER_SIZE];
    (void)identity;
    if (oracle->extent != BBP_V2_AUTH_HEADER_SIZE + capsule_size)
        return 0;
    memcpy(canonical, oracle->envelope, sizeof(canonical));
    memset(canonical + BBP_V2_AUTH_TAG_OFFSET, 0, BBP_V2_AUTH_TAG_SIZE);
    return bytes_equal(header, canonical, sizeof(canonical))
        && bytes_equal(tag, oracle->envelope + BBP_V2_AUTH_TAG_OFFSET,
                       BBP_V2_AUTH_TAG_SIZE)
        && bytes_equal(capsule,
                       oracle->envelope + BBP_V2_AUTH_HEADER_SIZE,
                       capsule_size);
}

static int profile_policy(void *opaque, uint64_t rollback_index,
                          const uint8_t identity[16],
                          const struct bbp_v2_view *capsule)
{
    struct bbp_v2_p0_view profile;
    (void)opaque;
    (void)identity;
    return rollback_index == 42
        && bbp_v2_p0_validate(capsule, &profile) == BBP_V2_OK;
}

static int reject_policy(void *opaque, uint64_t rollback_index,
                         const uint8_t identity[16],
                         const struct bbp_v2_view *capsule)
{
    (void)opaque;
    (void)rollback_index;
    (void)identity;
    (void)capsule;
    return 0;
}

static char *read_file(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    char *data;
    long length;
    if (!file || fseek(file, 0, SEEK_END) != 0
        || (length = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) {
        if (file) fclose(file);
        return NULL;
    }
    data = malloc((size_t)length + 1u);
    if (!data || fread(data, 1, (size_t)length, file) != (size_t)length) {
        free(data);
        fclose(file);
        return NULL;
    }
    fclose(file);
    data[length] = '\0';
    *size = (size_t)length;
    return data;
}

static int hex_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static uint8_t *json_hex(const char *json, const char *field, size_t *size)
{
    char needle[80];
    const char *start, *end;
    uint8_t *result;
    size_t i, digits;
    if (snprintf(needle, sizeof(needle), "\"%s\": \"", field)
        >= (int)sizeof(needle)) return NULL;
    start = strstr(json, needle);
    if (!start) return NULL;
    start += strlen(needle);
    end = strchr(start, '"');
    if (!end || ((digits = (size_t)(end - start)) & 1u) != 0) return NULL;
    result = malloc(digits / 2u);
    if (!result) return NULL;
    for (i = 0; i < digits; i += 2u) {
        int high = hex_value(start[i]);
        int low = hex_value(start[i + 1u]);
        if (high < 0 || low < 0) { free(result); return NULL; }
        result[i / 2u] = (uint8_t)((high << 4) | low);
    }
    *size = digits / 2u;
    return result;
}

static void expect_unchanged(const uint8_t *envelope, size_t extent,
                             struct oracle *oracle,
                             bbp_v2_auth_status_t expected, const char *name)
{
    struct bbp_v2_auth_view output;
    struct bbp_v2_auth_view before;
    bbp_v2_auth_status_t status;
    memset(&output, 0xa5, sizeof(output));
    before = output;
    status = bbp_v2_auth_parse(envelope, extent, oracle_mac, oracle,
                               profile_policy, NULL, &output);
    CHECK(status == expected && memcmp(&output, &before, sizeof(output)) == 0,
          name);
}

int main(int argc, char **argv)
{
    char *json;
    uint8_t *envelope, *capsule, *identity, *mutated;
    size_t json_size, extent, capsule_size, identity_size;
    struct oracle oracle;
    struct bbp_v2_auth_view output;
    bbp_v2_auth_status_t status;
    if (argc != 2 || !(json = read_file(argv[1], &json_size))) return 2;
    (void)json_size;
    envelope = json_hex(json, "envelope_hex", &extent);
    capsule = json_hex(json, "capsule_hex", &capsule_size);
    identity = json_hex(json, "key_id_hex", &identity_size);
    free(json);
    if (!envelope || !capsule || !identity) {
        free(envelope);
        free(capsule);
        free(identity);
        return 2;
    }
    oracle.envelope = envelope;
    oracle.extent = extent;

    status = bbp_v2_auth_parse(envelope, extent, oracle_mac, &oracle,
                               profile_policy, NULL, &output);
    CHECK(status == BBP_V2_AUTH_OK && output.rollback_index == 42
          && output.capsule.total_size == capsule_size
          && bytes_equal(output.capsule.data, capsule, capsule_size)
          && identity_size == BBP_V2_AUTH_KEY_ID_SIZE
          && bytes_equal(output.key_identity, identity, identity_size),
          "canonical vector");

    expect_unchanged(envelope, extent - 1u, &oracle,
                     BBP_V2_AUTH_ERR_EXTENT, "truncation is atomic");
    mutated = malloc(extent);
    if (!mutated) { free(envelope); return 2; }
    memcpy(mutated, envelope, extent);
    mutated[10]++;
    expect_unchanged(mutated, extent, &oracle, BBP_V2_AUTH_ERR_ALGORITHM,
                     "unknown algorithm");
    memcpy(mutated, envelope, extent);
    mutated[12] = 1;
    expect_unchanged(mutated, extent, &oracle, BBP_V2_AUTH_ERR_FLAGS,
                     "unknown flags");
    memcpy(mutated, envelope, extent);
    memset(mutated + 24, 0, 8);
    mutated[24] = 1;
    mutated[27] = 4;
    expect_unchanged(mutated, extent, &oracle, BBP_V2_AUTH_ERR_EXTENT,
                     "64 MiB bound and exact extent");
    memcpy(mutated, envelope, extent);
    mutated[extent - 1u] ^= 1u;
    expect_unchanged(mutated, extent, &oracle, BBP_V2_AUTH_ERR_MAC,
                     "tamper");

    memcpy(mutated, envelope, extent);
    memcpy(mutated + BBP_V2_AUTH_HEADER_SIZE, "NOTV2CAP", 8);
    oracle.envelope = mutated;
    expect_unchanged(mutated, extent, &oracle, BBP_V2_AUTH_ERR_CAPSULE,
                     "authenticated non-capsule");
    oracle.envelope = envelope;

    memset(&output, 0xa5, sizeof(output));
    {
        struct bbp_v2_auth_view before = output;
        status = bbp_v2_auth_parse(envelope, extent, oracle_mac, &oracle,
                                   reject_policy, NULL, &output);
        CHECK(status == BBP_V2_AUTH_ERR_POLICY
              && memcmp(&output, &before, sizeof(output)) == 0,
              "semantic policy rejection");
    }

    free(identity);
    free(capsule);
    free(mutated);
    free(envelope);
    printf("BBP v2 authenticated transport: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures ? 1 : 0;
}
