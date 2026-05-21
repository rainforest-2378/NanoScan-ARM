/*
 * Standalone Shift-And counter, kept primarily for tests and as a teaching
 * aid. Production scans go through ns_db_scan in multi_scan.c which reuses
 * the precomputed char_mask table.
 */
#include "nanoscan.h"

#include <stdint.h>
#include <string.h>

size_t ns_shiftand_count(const char *pattern, const char *text, size_t len) {
    if (!pattern || !text) return 0;

    size_t m = strlen(pattern);
    if (m == 0 || m > 64 || len < m) return 0;

    uint64_t char_mask[256] = {0};
    for (size_t i = 0; i < m; i++) {
        uint64_t bit = (uint64_t)1 << i;
        if (pattern[i] == '.') {
            for (int c = 0; c < 256; c++) char_mask[c] |= bit;
        } else {
            char_mask[(uint8_t)pattern[i]] |= bit;
        }
    }

    uint64_t state = 0;
    uint64_t accept = (uint64_t)1 << (m - 1);
    size_t   matches = 0;

    for (size_t i = 0; i < len; i++) {
        state = ((state << 1) | 1ULL) & char_mask[(uint8_t)text[i]];
        if (state & accept) matches++;
    }
    return matches;
}
