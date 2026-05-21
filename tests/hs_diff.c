/* Differential test: hs_scan vs a brute-force reference scanner.
 * Reference enumerates matches in end-offset order, breaking ties by the
 * compile-time pattern index, to mirror the engine's documented ordering. */
#include "hs/hs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned int       id;
    unsigned long long from;
    unsigned long long to;
} hit_t;

typedef struct {
    hit_t *items; size_t count; size_t cap;
} ctx_t;

static int cb(unsigned int id, unsigned long long from,
              unsigned long long to, unsigned int flags, void *vctx) {
    (void)flags;
    ctx_t *c = vctx;
    if (c->count >= c->cap) return 1;
    c->items[c->count++] = (hit_t){ id, from, to };
    return 0;
}

static int literal_match_at(const char *pat, const char *text,
                            size_t from, size_t text_len) {
    size_t m = strlen(pat);
    if (from + m > text_len) return 0;
    for (size_t i = 0; i < m; i++) {
        if (pat[i] == '.') continue;
        if (pat[i] != text[from + i]) return 0;
    }
    return 1;
}

typedef struct { hit_t h; unsigned int idx; } sortable_t;

static int by_end_then_idx(const void *a, const void *b) {
    const sortable_t *x = a, *y = b;
    if (x->h.to != y->h.to) return (x->h.to < y->h.to) ? -1 : 1;
    if (x->idx != y->idx)   return (x->idx < y->idx) ? -1 : 1;
    return 0;
}

static size_t reference(const char *const *exprs, const unsigned int *ids,
                        size_t n, const char *text, hit_t *out, size_t cap) {
    size_t tl = strlen(text);
    sortable_t *tmp = malloc(sizeof(sortable_t) * cap);
    size_t k = 0;
    for (size_t e = 0; e < n; e++) {
        size_t m = strlen(exprs[e]);
        if (m == 0 || m > tl) continue;
        for (size_t i = 0; i + m <= tl; i++) {
            if (literal_match_at(exprs[e], text, i, tl) && k < cap) {
                tmp[k++] = (sortable_t){
                    { ids[e], (unsigned long long)i,
                      (unsigned long long)(i + m) },
                    (unsigned int)e };
            }
        }
    }
    qsort(tmp, k, sizeof(sortable_t), by_end_then_idx);
    for (size_t i = 0; i < k; i++) out[i] = tmp[i].h;
    free(tmp);
    return k;
}

int main(void) {
    const char *exprs[] = { "arm", "a.m", "neon", "aaa", "x.z" };
    unsigned int ids[]  = { 1001, 1002, 1003, 1004, 1005 };
    const char *text = "aim arm neon aaaaa xyz arm";

    hs_database_t *db = NULL; hs_compile_error_t *err = NULL;
    if (hs_compile_multi(exprs, NULL, ids, 5, HS_MODE_BLOCK, NULL, &db, &err)
        != HS_SUCCESS) {
        printf("[FAIL] compile %s\n", err ? err->message : "?");
        return 1;
    }
    hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);

    hit_t got[256] = {0};   ctx_t c = { got, 0, 256 };
    hs_scan(db, text, (unsigned)strlen(text), 0, sc, cb, &c);

    hit_t want[256] = {0};
    size_t wn = reference(exprs, ids, 5, text, want, 256);

    int fail = 0;
    if (c.count != wn) {
        printf("[FAIL] count want=%zu got=%zu\n", wn, c.count);
        fail = 1;
    }
    for (size_t i = 0; i < wn && i < c.count; i++) {
        if (got[i].id != want[i].id ||
            got[i].from != want[i].from || got[i].to != want[i].to) {
            printf("[FAIL] i=%zu got=(%u,%llu,%llu) want=(%u,%llu,%llu)\n",
                   i, got[i].id, got[i].from, got[i].to,
                   want[i].id, want[i].from, want[i].to);
            fail = 1;
        }
    }

    hs_free_scratch(sc); hs_free_database(db);
    if (fail) return 1;
    printf("[PASS] hs_diff (%zu hits)\n", wn);
    return 0;
}
