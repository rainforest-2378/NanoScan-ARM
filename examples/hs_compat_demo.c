/* Tiny demo using the Hyperscan-compatible API. */
#include "hs/hs.h"

#include <stdio.h>
#include <string.h>

static int on_match(unsigned int id,
                    unsigned long long from,
                    unsigned long long to,
                    unsigned int flags,
                    void *ctx) {
    (void)flags;
    (*(unsigned *)ctx)++;
    printf("  hit id=%u [%llu, %llu)\n", id, from, to);
    return 0;
}

int main(void) {
    const char *exprs[] = { "arm", "a.m", "NEON" };
    unsigned int ids[]  = { 1, 2, 3 };
    unsigned int flags[] = { 0, 0, HS_FLAG_CASELESS };
    const char *text = "aim arm neon, ARM neon!";

    hs_database_t *db = NULL;
    hs_compile_error_t *err = NULL;
    hs_error_t rc = hs_compile_multi(exprs, flags, ids, 3,
                                     HS_MODE_BLOCK, NULL, &db, &err);
    if (rc != HS_SUCCESS) {
        fprintf(stderr, "compile failed: %s\n", err ? err->message : "?");
        hs_free_compile_error(err);
        return 1;
    }

    hs_scratch_t *scratch = NULL;
    if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
        hs_free_database(db);
        return 1;
    }

    unsigned count = 0;
    rc = hs_scan(db, text, (unsigned)strlen(text), 0, scratch, on_match, &count);
    printf("hs_scan rc=%d matches=%u (%s)\n",
           rc, count, hs_version());

    hs_free_scratch(scratch);
    hs_free_database(db);
    return 0;
}
