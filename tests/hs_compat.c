/* Smoke + key-flag tests for the Hyperscan-compat layer. */
#include "hs/hs.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned int       id;
    unsigned long long from;
    unsigned long long to;
} hit_t;

typedef struct {
    hit_t *items;
    size_t count;
    size_t cap;
} ctx_t;

static int on_match(unsigned int id,
                    unsigned long long from,
                    unsigned long long to,
                    unsigned int flags,
                    void *vctx) {
    (void)flags;
    ctx_t *c = (ctx_t *)vctx;
    if (c->count >= c->cap) return 1;
    c->items[c->count++] = (hit_t){ id, from, to };
    return 0;
}

#define FAIL(...) do { printf("[FAIL] " __VA_ARGS__); return 1; } while (0)

static int test_basic(void) {
    const char *exprs[] = { "arm", "a.m", "neon" };
    unsigned int ids[]  = { 11, 12, 13 };

    hs_database_t *db = NULL;
    hs_compile_error_t *err = NULL;
    if (hs_compile_multi(exprs, NULL, ids, 3, HS_MODE_BLOCK, NULL, &db, &err)
        != HS_SUCCESS) {
        FAIL("compile_multi msg=%s\n", err ? err->message : "?");
    }
    hs_scratch_t *sc = NULL;
    if (hs_alloc_scratch(db, &sc) != HS_SUCCESS) FAIL("alloc_scratch\n");

    hit_t buf[16] = {0};
    ctx_t c = { buf, 0, 16 };
    if (hs_scan(db, "aim arm neon", 12, 0, sc, on_match, &c) != HS_SUCCESS) {
        FAIL("scan rc\n");
    }
    if (c.count != 4) FAIL("basic count=%zu\n", c.count);

    hs_free_scratch(sc);
    hs_free_database(db);
    return 0;
}

static int test_caseless(void) {
    const char *exprs[] = { "arm" };
    unsigned int flags[] = { HS_FLAG_CASELESS };
    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    if (hs_compile_multi(exprs, flags, NULL, 1, HS_MODE_BLOCK, NULL, &db, &err)
        != HS_SUCCESS) FAIL("caseless compile\n");
    hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
    hit_t buf[8] = {0}; ctx_t c = { buf, 0, 8 };
    hs_scan(db, "ARM Arm aRm arm", 15, 0, sc, on_match, &c);
    if (c.count != 4) FAIL("caseless count=%zu\n", c.count);
    hs_free_scratch(sc); hs_free_database(db);
    return 0;
}

static int test_singlematch(void) {
    const char *exprs[] = { "a" };
    unsigned int flags[] = { HS_FLAG_SINGLEMATCH };
    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    hs_compile_multi(exprs, flags, NULL, 1, HS_MODE_BLOCK, NULL, &db, &err);
    hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
    hit_t buf[8] = {0}; ctx_t c = { buf, 0, 8 };
    hs_scan(db, "aaaaa", 5, 0, sc, on_match, &c);
    if (c.count != 1) FAIL("singlematch count=%zu\n", c.count);
    hs_free_scratch(sc); hs_free_database(db);
    return 0;
}

static int abort_cb(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void *ctx) {
    (void)id; (void)from; (void)to; (void)flags;
    (*(int *)ctx)++;
    return 1;
}

static int test_terminated(void) {
    const char *exprs[] = { "a" };
    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    hs_compile_multi(exprs, NULL, NULL, 1, HS_MODE_BLOCK, NULL, &db, &err);
    hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
    int n = 0;
    hs_error_t rc = hs_scan(db, "aaa", 3, 0, sc, abort_cb, &n);
    if (rc != HS_SCAN_TERMINATED) FAIL("terminated rc=%d\n", rc);
    if (n != 1) FAIL("terminated cb-calls=%d\n", n);
    hs_free_scratch(sc); hs_free_database(db);
    return 0;
}

static int test_reject_flags(void) {
    const char *exprs[] = { "a" };
    unsigned int flags[] = { HS_FLAG_UTF8 };
    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    hs_error_t rc = hs_compile_multi(exprs, flags, NULL, 1,
                                     HS_MODE_BLOCK, NULL, &db, &err);
    if (rc != HS_COMPILER_ERROR) FAIL("reject-flag rc=%d\n", rc);
    if (!err || err->expression != 0) FAIL("reject-flag err meta\n");
    hs_free_compile_error(err);
    return 0;
}

static int test_reject_mode(void) {
    const char *exprs[] = { "a" };
    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    hs_error_t rc = hs_compile_multi(exprs, NULL, NULL, 1,
                                     HS_MODE_STREAM, NULL, &db, &err);
    if (rc != HS_DB_MODE_ERROR) FAIL("reject-mode rc=%d\n", rc);
    hs_free_compile_error(err);
    return 0;
}

static int test_reject_regex(void) {
    /* Backslash-b (word boundary) is intentionally not supported. */
    const char *exprs[] = { "foo\\bbar" };
    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    hs_error_t rc = hs_compile_multi(exprs, NULL, NULL, 1,
                                     HS_MODE_BLOCK, NULL, &db, &err);
    if (rc != HS_COMPILER_ERROR) FAIL("reject-regex rc=%d\n", rc);
    hs_free_compile_error(err);
    return 0;
}

static int test_anchors(void) {
    /* ^ at start, $ at end, both. */
    const char *exprs[] = { "^arm", "neon$", "^abc$" };
    unsigned int ids[] = { 1, 2, 3 };
    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    if (hs_compile_multi(exprs, NULL, ids, 3, HS_MODE_BLOCK, NULL, &db, &err)
        != HS_SUCCESS) FAIL("anchor compile %s\n", err ? err->message : "?");
    hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);

    /* "arm neon" : "^arm" matches at 0, "neon$" matches at end; "^abc$" no. */
    hit_t buf[8] = {0}; ctx_t c = { buf, 0, 8 };
    hs_scan(db, "arm neon", 8, 0, sc, on_match, &c);
    if (c.count != 2) FAIL("anchor count=%zu\n", c.count);
    if (buf[0].id != 1 || buf[0].from != 0 || buf[0].to != 3) FAIL("anchor#1\n");
    if (buf[1].id != 2 || buf[1].from != 4 || buf[1].to != 8) FAIL("anchor#2\n");

    /* "arm in middle arm" -> "^arm" matches only at 0. */
    c.count = 0;
    hs_scan(db, "armX arm", 8, 0, sc, on_match, &c);
    if (c.count != 1 || buf[0].id != 1) FAIL("anchor-start dedup\n");

    hs_free_scratch(sc); hs_free_database(db);

    /* "^abc$" exact match. */
    const char *e2[] = { "^abc$" };
    db = NULL; err = NULL;
    hs_compile_multi(e2, NULL, NULL, 1, HS_MODE_BLOCK, NULL, &db, &err);
    sc = NULL; hs_alloc_scratch(db, &sc);
    hit_t b2[4] = {0}; ctx_t c2 = { b2, 0, 4 };
    hs_scan(db, "abc", 3, 0, sc, on_match, &c2);
    if (c2.count != 1) FAIL("full-anchor exact count=%zu\n", c2.count);
    c2.count = 0;
    hs_scan(db, "abcd", 4, 0, sc, on_match, &c2);
    if (c2.count != 0) FAIL("full-anchor reject count=%zu\n", c2.count);
    hs_free_scratch(sc); hs_free_database(db);
    return 0;
}

static int test_alternation(void) {
    /* "arm|neon|aim" -> all three branches share id 7. */
    const char *exprs[] = { "arm|neon|aim" };
    unsigned int ids[] = { 7 };
    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    if (hs_compile_multi(exprs, NULL, ids, 1, HS_MODE_BLOCK, NULL, &db, &err)
        != HS_SUCCESS) FAIL("alt compile %s\n", err ? err->message : "?");
    hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
    hit_t buf[8] = {0}; ctx_t c = { buf, 0, 8 };
    hs_scan(db, "aim arm neon", 12, 0, sc, on_match, &c);
    if (c.count != 3) FAIL("alt count=%zu\n", c.count);
    for (size_t i = 0; i < 3; i++)
        if (buf[i].id != 7) FAIL("alt id[%zu]=%u\n", i, buf[i].id);
    hs_free_scratch(sc); hs_free_database(db);

    /* SINGLEMATCH dedup must span branches of one alternation. */
    const char *e2[] = { "arm|neon" };
    unsigned int f2[] = { HS_FLAG_SINGLEMATCH };
    db = NULL; err = NULL;
    hs_compile_multi(e2, f2, NULL, 1, HS_MODE_BLOCK, NULL, &db, &err);
    sc = NULL; hs_alloc_scratch(db, &sc);
    hit_t b2[8] = {0}; ctx_t c2 = { b2, 0, 8 };
    hs_scan(db, "arm neon arm", 12, 0, sc, on_match, &c2);
    if (c2.count != 1) FAIL("alt singlematch count=%zu\n", c2.count);
    hs_free_scratch(sc); hs_free_database(db);

    /* Escaped pipe is a literal. */
    const char *e3[] = { "a\\|b" };
    db = NULL; err = NULL;
    if (hs_compile_multi(e3, NULL, NULL, 1, HS_MODE_BLOCK, NULL, &db, &err)
        != HS_SUCCESS) FAIL("escaped-pipe compile\n");
    sc = NULL; hs_alloc_scratch(db, &sc);
    hit_t b3[4] = {0}; ctx_t c3 = { b3, 0, 4 };
    hs_scan(db, "xx a|b yy", 9, 0, sc, on_match, &c3);
    if (c3.count != 1 || b3[0].from != 3 || b3[0].to != 6)
        FAIL("escaped-pipe match\n");
    hs_free_scratch(sc); hs_free_database(db);
    return 0;
}

int main(void) {
    if (test_basic())         return 1;
    if (test_caseless())      return 1;
    if (test_singlematch())   return 1;
    if (test_terminated())    return 1;
    if (test_reject_flags())  return 1;
    if (test_reject_mode())   return 1;
    if (test_reject_regex())  return 1;
    if (test_anchors())       return 1;
    if (test_alternation())   return 1;
    printf("[PASS] hs_compat\n");
    return 0;
}
