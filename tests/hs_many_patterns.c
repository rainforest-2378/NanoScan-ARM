#include "hs/hs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <time.h>
#endif

#define DEFAULT_PATTERNS 500
#define MAX_PATTERN_LEN  64

typedef struct {
    unsigned *hits;
    size_t    n_patterns;
    size_t    total_hits;
} scan_ctx_t;

static double now_sec(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#endif
}

static int on_match(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void *ctx) {
    (void)from;
    (void)to;
    (void)flags;
    scan_ctx_t *c = (scan_ctx_t *)ctx;
    if ((size_t)id < c->n_patterns) c->hits[id]++;
    c->total_hits++;
    return 0;
}

static void build_pattern(size_t i, char *out, size_t out_cap) {
    switch (i % 8u) {
        case 0: snprintf(out, out_cap, "user%03zu", i); break;
        case 1: snprintf(out, out_cap, "warn_(foo|bar)%02zu", i % 100u); break;
        case 2: snprintf(out, out_cap, "[a-z]{2}%03zu", i % 1000u); break;
        case 3: snprintf(out, out_cap, "id%03zu_[0-9]+", i % 1000u); break;
        case 4: snprintf(out, out_cap, "x(yz)?%02zu", i % 100u); break;
        case 5: snprintf(out, out_cap, "ab*c%02zu", i % 100u); break;
        case 6: snprintf(out, out_cap, "token%03zu@(dev|prod)", i % 1000u); break;
        default: snprintf(out, out_cap, "\\d{2}cat%02zu", i % 100u); break;
    }
}

static void build_probe(size_t i, char *out, size_t out_cap) {
    switch (i % 8u) {
        case 0: snprintf(out, out_cap, "user%03zu", i); break;
        case 1: snprintf(out, out_cap, "warn_foo%02zu", i % 100u); break;
        case 2: snprintf(out, out_cap, "az%03zu", i % 1000u); break;
        case 3: snprintf(out, out_cap, "id%03zu_12345", i % 1000u); break;
        case 4: snprintf(out, out_cap, "xyz%02zu", i % 100u); break;
        case 5: snprintf(out, out_cap, "abbbc%02zu", i % 100u); break;
        case 6: snprintf(out, out_cap, "token%03zu@dev", i % 1000u); break;
        default: snprintf(out, out_cap, "42cat%02zu", i % 100u); break;
    }
}

int main(int argc, char **argv) {
    size_t n_patterns = DEFAULT_PATTERNS;
    if (argc > 1) {
        char *end = NULL;
        unsigned long v = strtoul(argv[1], &end, 10);
        if (end && *end == '\0' && v > 0) n_patterns = (size_t)v;
    }

    const char **exprs = (const char **)calloc(n_patterns, sizeof(*exprs));
    unsigned   *flags = (unsigned *)calloc(n_patterns, sizeof(*flags));
    unsigned   *ids = (unsigned *)calloc(n_patterns, sizeof(*ids));
    char       *pool = (char *)calloc(n_patterns, MAX_PATTERN_LEN);
    if (!exprs || !flags || !ids || !pool) {
        printf("[FAIL] alloc patterns\n");
        free((void *)exprs);
        free(flags);
        free(ids);
        free(pool);
        return 1;
    }

    for (size_t i = 0; i < n_patterns; i++) {
        char *p = pool + i * MAX_PATTERN_LEN;
        build_pattern(i, p, MAX_PATTERN_LEN);
        exprs[i] = p;
        flags[i] = 0;
        ids[i] = (unsigned)i;
    }

    hs_database_t *db = NULL;
    hs_compile_error_t *ce = NULL;

    double c0 = now_sec();
    hs_error_t cr = hs_compile_multi(exprs, flags, ids, (unsigned)n_patterns,
                                     HS_MODE_BLOCK, NULL, &db, &ce);
    double c1 = now_sec();
    if (cr != HS_SUCCESS) {
        printf("[FAIL] compile: %s\n", ce ? ce->message : "unknown");
        hs_free_compile_error(ce);
        free((void *)exprs);
        free(flags);
        free(ids);
        free(pool);
        return 1;
    }

    size_t text_cap = n_patterns * 64u + 128u;
    char *text = (char *)calloc(text_cap, 1);
    if (!text) {
        printf("[FAIL] alloc text\n");
        hs_free_database(db);
        free((void *)exprs);
        free(flags);
        free(ids);
        free(pool);
        return 1;
    }

    size_t len = 0;
    memcpy(text + len, "BEGIN ", 6);
    len += 6;
    for (size_t i = 0; i < n_patterns; i++) {
        char probe[MAX_PATTERN_LEN];
        size_t chunk;
        build_probe(i, probe, sizeof(probe));
        chunk = strlen(probe);
        if (len + chunk + 3 >= text_cap) break;
        memcpy(text + len, probe, chunk);
        len += chunk;
        memcpy(text + len, " ; ", 3);
        len += 3;
    }
    memcpy(text + len, " END", 4);
    len += 4;

    hs_scratch_t *scratch = NULL;
    if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
        printf("[FAIL] alloc scratch\n");
        hs_free_database(db);
        free(text);
        free((void *)exprs);
        free(flags);
        free(ids);
        free(pool);
        return 1;
    }

    unsigned *hits = (unsigned *)calloc(n_patterns, sizeof(*hits));
    if (!hits) {
        printf("[FAIL] alloc hits\n");
        hs_free_scratch(scratch);
        hs_free_database(db);
        free(text);
        free((void *)exprs);
        free(flags);
        free(ids);
        free(pool);
        return 1;
    }

    scan_ctx_t ctx = { hits, n_patterns, 0 };
    double s0 = now_sec();
    hs_error_t sr = hs_scan(db, text, (unsigned)len, 0, scratch, on_match, &ctx);
    double s1 = now_sec();

    if (sr != HS_SUCCESS) {
        printf("[FAIL] scan failed: %d\n", (int)sr);
        free(hits);
        hs_free_scratch(scratch);
        hs_free_database(db);
        free(text);
        free((void *)exprs);
        free(flags);
        free(ids);
        free(pool);
        return 1;
    }

    size_t missed = 0;
    for (size_t i = 0; i < n_patterns; i++) {
        if (hits[i] == 0) missed++;
    }

    printf("patterns=%zu text_len=%zu compile=%.2fms scan=%.2fms hits=%zu missed=%zu\n",
           n_patterns, len, (c1 - c0) * 1000.0, (s1 - s0) * 1000.0,
           ctx.total_hits, missed);

    if (missed != 0) {
        printf("[FAIL] %zu patterns did not match their probe text\n", missed);
        free(hits);
        hs_free_scratch(scratch);
        hs_free_database(db);
        free(text);
        free((void *)exprs);
        free(flags);
        free(ids);
        free(pool);
        return 1;
    }

    printf("[PASS] hs_many_patterns\n");

    free(hits);
    hs_free_scratch(scratch);
    hs_free_database(db);
    free(text);
    free((void *)exprs);
    free(flags);
    free(ids);
    free(pool);
    return 0;
}
