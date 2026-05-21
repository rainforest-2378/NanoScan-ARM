/* Tiny demo using the internal nanoscan API directly. */
#include "nanoscan.h"

#include <stdio.h>
#include <string.h>

static int on_match(unsigned int id, size_t from, size_t to, void *ctx) {
    (void)ctx;
    printf("hit id=%u [%zu, %zu)\n", id, from, to);
    return 0;
}

int main(void) {
    const char *patterns[] = { "arm", "a.m" };
    unsigned int ids[]     = { 10, 20 };
    const char *text = "aim high, arm neon is powerful!";

    char err[128] = {0};
    ns_db_t *db = ns_db_compile(patterns, NULL, ids, 2,
                                err, sizeof(err), NULL);
    if (!db) {
        fprintf(stderr, "compile failed: %s\n", err);
        return 1;
    }

    int terminated = 0;
    size_t n = ns_db_scan(db, text, strlen(text), on_match, NULL, &terminated);
    printf("total matches: %zu (terminated=%d)\n", n, terminated);

    ns_db_free(db);
    return 0;
}
