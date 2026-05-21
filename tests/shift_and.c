#include "nanoscan.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *pattern;
    const char *text;
    size_t      expected;
} case_t;

int main(void) {
    case_t cases[] = {
        { "arm", "arm neon arm", 2 },
        { "a.m", "aim arm atom", 2 },
        { "aaa", "aaaaa",        3 },
        { "xyz", "abcabc",       0 },
    };

    size_t failed = 0;
    size_t total  = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < total; i++) {
        size_t got = ns_shiftand_count(cases[i].pattern,
                                       cases[i].text,
                                       strlen(cases[i].text));
        if (got != cases[i].expected) {
            failed++;
            printf("[FAIL] %zu pat=\"%s\" text=\"%s\" want=%zu got=%zu\n",
                   i, cases[i].pattern, cases[i].text,
                   cases[i].expected, got);
        }
    }
    if (failed) {
        printf("[FAIL] shift_and %zu/%zu failed\n", failed, total);
        return 1;
    }
    printf("[PASS] shift_and %zu/%zu\n", total, total);
    return 0;
}
