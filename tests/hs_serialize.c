/* Round-trip + tamper tests for hs_serialize / hs_deserialize. */
#include "hs/hs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned int       id;
    unsigned long long from;
    unsigned long long to;
} hit_t;

typedef struct { hit_t *h; size_t n; size_t cap; } ctx_t;

static int cb(unsigned int id, unsigned long long from, unsigned long long to,
              unsigned int flags, void *vctx) {
    (void)flags;
    ctx_t *c = vctx;
    if (c->n >= c->cap) return 1;
    c->h[c->n++] = (hit_t){ id, from, to };
    return 0;
}

#define FAIL(...) do { printf("[FAIL] " __VA_ARGS__); return 1; } while (0)

static size_t scan_all(hs_database_t *db, const char *text, hit_t *out, size_t cap) {
    hs_scratch_t *sc = NULL;
    if (hs_alloc_scratch(db, &sc) != HS_SUCCESS) return (size_t)-1;
    ctx_t c = { out, 0, cap };
    hs_scan(db, text, (unsigned)strlen(text), 0, sc, cb, &c);
    hs_free_scratch(sc);
    return c.n;
}

int main(void) {
    const char *exprs[] = { "^arm", "a.m", "neon$", "foo|bar" };
    unsigned int flags[] = { 0, HS_FLAG_CASELESS, 0, HS_FLAG_SINGLEMATCH };
    unsigned int ids[]   = { 10, 20, 30, 40 };

    hs_database_t *db = NULL; hs_compile_error_t *ce = NULL;
    if (hs_compile_multi(exprs, flags, ids, 4, HS_MODE_BLOCK, NULL, &db, &ce)
        != HS_SUCCESS) FAIL("compile %s\n", ce ? ce->message : "?");

    const char *text = "arm AIM neon foo bar";

    hit_t orig[32] = {0};
    size_t n_orig = scan_all(db, text, orig, 32);

    /* Round-trip. */
    char  *blob = NULL;
    size_t blob_len = 0;
    if (hs_serialize_database(db, &blob, &blob_len) != HS_SUCCESS)
        FAIL("serialize\n");

    char *info = NULL;
    if (hs_serialized_database_info(blob, blob_len, &info) != HS_SUCCESS)
        FAIL("info\n");
    printf("info: %s (%zu bytes)\n", info, blob_len);
    free(info);

    size_t hint = 0;
    if (hs_serialized_database_size(blob, blob_len, &hint) != HS_SUCCESS)
        FAIL("size\n");

    hs_database_t *db2 = NULL;
    if (hs_deserialize_database(blob, blob_len, &db2) != HS_SUCCESS)
        FAIL("deserialize\n");

    hit_t reh[32] = {0};
    size_t n_reh = scan_all(db2, text, reh, 32);

    if (n_orig != n_reh) FAIL("count orig=%zu reh=%zu\n", n_orig, n_reh);
    for (size_t i = 0; i < n_orig; i++) {
        if (orig[i].id != reh[i].id || orig[i].from != reh[i].from ||
            orig[i].to != reh[i].to)
            FAIL("hit %zu mismatch\n", i);
    }

    /* Tamper: flip the magic and expect a clean refusal. */
    char *bad = (char *)malloc(blob_len);
    memcpy(bad, blob, blob_len);
    bad[0] ^= 0xff;
    hs_database_t *db3 = NULL;
    if (hs_deserialize_database(bad, blob_len, &db3) == HS_SUCCESS)
        FAIL("tamper accepted\n");
    free(bad);

    /* Truncate: middle of pattern block. */
    hs_database_t *db4 = NULL;
    if (hs_deserialize_database(blob, blob_len / 2, &db4) == HS_SUCCESS)
        FAIL("truncate accepted\n");

    free(blob);
    hs_free_database(db);
    hs_free_database(db2);
    printf("[PASS] hs_serialize (%zu hits)\n", n_orig);
    return 0;
}
