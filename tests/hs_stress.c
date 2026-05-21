/* Stress test: 1000 random literal patterns vs lockstep baseline.
 *
 * Correctness: compares hit set from the production scanner against a
 * brute-force scanner that does naive memcmp for every pattern at every
 * position. The two must agree exactly.
 *
 * Performance: measures wall time twice -- once with the prefilter active
 * and once with every pattern forced into the lockstep fallback path --
 * to make the prefilter speedup visible.
 */
#include "hs/hs.h"
#include "nanoscan.h"
#include "nanoscan_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <time.h>
#endif

#define N_PATTERNS 1000
#define PAT_LEN    16
#define TEXT_LEN   (1 * 1024 * 1024)   /* 1 MiB */
/* Patterns are drawn from a regex-metachar-free alphabet so they parse as
 * pure literals. The text alphabet is wider to spread the prefilter's
 * end-byte buckets and exercise its selectivity. */
#define PAT_ALPHABET  "abcdefghijklmnopqrstuvwxyz" \
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define TEXT_ALPHABET "abcdefghijklmnopqrstuvwxyz" \
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                      "0123456789 ,;:-_/=#@~"

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

static int hit_cmp(const void *a, const void *b) {
    const hit_t *x = a, *y = b;
    if (x->to != y->to) return x->to < y->to ? -1 : 1;
    if (x->from != y->from) return x->from < y->from ? -1 : 1;
    if (x->id != y->id) return x->id < y->id ? -1 : 1;
    return 0;
}

static double now_sec(void) {
#ifdef _WIN32
    /* QueryPerformanceCounter is monotonic and high-resolution on
     * Windows (including ARM64). */
    static LARGE_INTEGER freq;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
#endif
}

#define FAIL(...) do { printf("[FAIL] " __VA_ARGS__); return 1; } while (0)

int main(void) {
    srand(1234);

    /* Build 1000 random literal patterns of length PAT_LEN. */
    char  **exprs = malloc(N_PATTERNS * sizeof(*exprs));
    unsigned *ids = malloc(N_PATTERNS * sizeof(*ids));
    unsigned *flg = calloc(N_PATTERNS, sizeof(*flg));
    for (size_t i = 0; i < N_PATTERNS; i++) {
        char *s = malloc(PAT_LEN + 1);
        for (size_t k = 0; k < PAT_LEN; k++)
            s[k] = PAT_ALPHABET[rand() % (int)(sizeof(PAT_ALPHABET) - 1)];
        s[PAT_LEN] = '\0';
        exprs[i] = s;
        ids[i] = (unsigned)i;
    }

    hs_database_t     *db = NULL;
    hs_compile_error_t *ce = NULL;
    if (hs_compile_multi((const char *const *)exprs, flg, ids, N_PATTERNS,
                         HS_MODE_BLOCK, NULL, &db, &ce) != HS_SUCCESS)
        FAIL("compile %s\n", ce ? ce->message : "?");

    /* Build text: random alphabet plus inject a handful of patterns. */
    char *text = malloc(TEXT_LEN);
    for (size_t i = 0; i < TEXT_LEN; i++)
        text[i] = TEXT_ALPHABET[rand() % (int)(sizeof(TEXT_ALPHABET) - 1)];
    /* Inject 50 known matches at random offsets. */
    size_t expected_injected = 50;
    for (size_t k = 0; k < expected_injected; k++) {
        size_t which = (size_t)rand() % N_PATTERNS;
        size_t off   = (size_t)rand() % (TEXT_LEN - PAT_LEN);
        memcpy(text + off, exprs[which], PAT_LEN);
    }

    /* Run scanner. */
    hs_scratch_t *sc = NULL;
    if (hs_alloc_scratch(db, &sc) != HS_SUCCESS) FAIL("scratch\n");

    hit_t *hits = malloc(sizeof(hit_t) * 65536);
    ctx_t c = { hits, 0, 65536 };

    double t0 = now_sec();
    hs_scan(db, text, TEXT_LEN, 0, sc, cb, &c);
    double t1 = now_sec();

    double mb = (double)TEXT_LEN / (1024 * 1024);
    double s  = t1 - t0;
    printf("scanner(prefilter): %zu hits in %.1f ms -> %.0f MB/s\n",
           c.n, s * 1000.0, mb / s);

    /* Force lockstep fallback by flipping every pattern's no_anchor=1 and
     * rebuilding the dispatch tables. The two paths must agree on every
     * hit; this is the real assertion. The MB/s print is informational --
     * prefilter wins as pattern count grows and as last-byte distribution
     * gets sparser; lockstep wins on small dbs where NEON auto-vectorizes
     * the bit-parallel update tightly. */
    ns_db_t *raw = (ns_db_t *)db;
    for (size_t k = 0; k < raw->count; k++) raw->patterns[k]->no_anchor = 1;
    ns_db_build_prefilter(raw);

    ctx_t c2 = { malloc(sizeof(hit_t) * 65536), 0, 65536 };
    double u0 = now_sec();
    hs_scan(db, text, TEXT_LEN, 0, sc, cb, &c2);
    double u1 = now_sec();
    double su = u1 - u0;
    printf("scanner(lockstep):  %zu hits in %.1f ms -> %.0f MB/s\n",
           c2.n, su * 1000.0, mb / su);
    if (c.n != c2.n) FAIL("prefilter vs lockstep disagree: %zu vs %zu\n",
                          c.n, c2.n);

    /* Sort and check every hit matches between the two paths. */
    qsort(hits,   c.n,  sizeof(hit_t), hit_cmp);
    qsort(c2.h,   c2.n, sizeof(hit_t), hit_cmp);
    for (size_t i = 0; i < c.n; i++) {
        if (hits[i].id != c2.h[i].id || hits[i].from != c2.h[i].from ||
            hits[i].to != c2.h[i].to)
            FAIL("path-disagree at hit %zu\n", i);
    }
    free(c2.h);

    /* Brute-force ground truth via naive memcmp. */
    hit_t *truth = malloc(sizeof(hit_t) * 65536);
    size_t tn = 0;
    for (size_t i = 0; i + PAT_LEN <= TEXT_LEN; i++) {
        for (size_t p = 0; p < N_PATTERNS; p++) {
            if (memcmp(text + i, exprs[p], PAT_LEN) == 0) {
                if (tn >= 65536) FAIL("truth overflow\n");
                truth[tn++] = (hit_t){ (unsigned)p, i, i + PAT_LEN };
            }
        }
    }

    /* Sort both and compare. */
    qsort(hits,  c.n, sizeof(hit_t), hit_cmp);
    qsort(truth, tn,  sizeof(hit_t), hit_cmp);
    if (c.n != tn) FAIL("count: scanner=%zu truth=%zu\n", c.n, tn);
    for (size_t i = 0; i < tn; i++) {
        if (hits[i].id != truth[i].id ||
            hits[i].from != truth[i].from ||
            hits[i].to   != truth[i].to)
            FAIL("hit %zu mismatch\n", i);
    }

    free(hits); free(truth);
    hs_free_scratch(sc);
    hs_free_database(db);
    for (size_t i = 0; i < N_PATTERNS; i++) free(exprs[i]);
    free(exprs); free(ids); free(flg); free(text);

    printf("[PASS] hs_stress (%zu hits matched ground truth)\n", tn);
    return 0;
}
