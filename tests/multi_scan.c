/* Verifies ns_db_scan ordering, callback termination and SINGLEMATCH. */
#include "nanoscan.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned int id;
    size_t       from;
    size_t       to;
} match_t;

typedef struct {
    match_t *items;
    size_t   count;
    size_t   cap;
    size_t   stop_after;
} ctx_t;

static int collect(unsigned int id, size_t from, size_t to, void *vctx) {
    ctx_t *c = (ctx_t *)vctx;
    if (c->count >= c->cap) return 1;
    c->items[c->count++] = (match_t){ id, from, to };
    if (c->stop_after && c->count >= c->stop_after) return 1;
    return 0;
}

static int run(void) {
    /* End-offset ordering across patterns. */
    {
        const char *pat[] = { "arm", "a.m", "neon" };
        unsigned int ids[] = { 101, 102, 103 };
        const char *text = "aim arm neon";

        ns_db_t *db = ns_db_compile(pat, NULL, ids, 3, NULL, 0, NULL);
        if (!db) { printf("[FAIL] compile\n"); return 1; }

        match_t buf[16] = {0};
        ctx_t c = { buf, 0, 16, 0 };
        int term = 0;
        size_t n = ns_db_scan(db, text, strlen(text), collect, &c, &term);
        if (n != 4 || c.count != 4 || term != 0) {
            printf("[FAIL] count n=%zu collected=%zu term=%d\n", n, c.count, term);
            ns_db_free(db); return 1;
        }
        /* expected order, by end-offset then by pattern index: */
        match_t want[] = {
            { 102, 0, 3 }, /* "aim" */
            { 101, 4, 7 }, /* "arm" */
            { 102, 4, 7 }, /* "a.m" -> arm */
            { 103, 8, 12 } /* "neon" */
        };
        for (int i = 0; i < 4; i++) {
            if (buf[i].id != want[i].id ||
                buf[i].from != want[i].from ||
                buf[i].to   != want[i].to) {
                printf("[FAIL] match %d got (%u,%zu,%zu) want (%u,%zu,%zu)\n",
                       i, buf[i].id, buf[i].from, buf[i].to,
                       want[i].id, want[i].from, want[i].to);
                ns_db_free(db); return 1;
            }
        }
        ns_db_free(db);
    }

    /* Callback termination. */
    {
        const char *pat[] = { "a" };
        ns_db_t *db = ns_db_compile(pat, NULL, NULL, 1, NULL, 0, NULL);
        match_t buf[16] = {0};
        ctx_t c = { buf, 0, 16, 2 };
        int term = 0;
        ns_db_scan(db, "aaaaa", 5, collect, &c, &term);
        if (c.count != 2 || term != 1) {
            printf("[FAIL] termination count=%zu term=%d\n", c.count, term);
            ns_db_free(db); return 1;
        }
        ns_db_free(db);
    }

    /* SINGLEMATCH: at most one match per id. */
    {
        const char *pat[] = { "a" };
        unsigned int flags[] = { NS_FLAG_SINGLEMATCH };
        ns_db_t *db = ns_db_compile(pat, flags, NULL, 1, NULL, 0, NULL);
        match_t buf[16] = {0};
        ctx_t c = { buf, 0, 16, 0 };
        int term = 0;
        size_t n = ns_db_scan(db, "aaaaa", 5, collect, &c, &term);
        if (n != 1 || c.count != 1) {
            printf("[FAIL] singlematch n=%zu collected=%zu\n", n, c.count);
            ns_db_free(db); return 1;
        }
        ns_db_free(db);
    }
    return 0;
}

int main(void) {
    if (run() != 0) return 1;
    printf("[PASS] multi_scan\n");
    return 0;
}
