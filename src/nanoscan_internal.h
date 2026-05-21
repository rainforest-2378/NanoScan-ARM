#ifndef NANOSCAN_INTERNAL_H
#define NANOSCAN_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "nanoscan.h"

/* Portable count-trailing-zeros for uint64_t. GCC/Clang ship the builtin;
 * MSVC has _BitScanForward64. Both compile to a single instruction on
 * AArch64/x86_64. */
#if defined(__GNUC__) || defined(__clang__)
static inline int ns_ctz64(uint64_t x) { return __builtin_ctzll(x); }
#elif defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(_BitScanForward64)
static inline int ns_ctz64(uint64_t x) {
    unsigned long idx;
    _BitScanForward64(&idx, x);
    return (int)idx;
}
#else
static inline int ns_ctz64(uint64_t x) {
    int n = 0;
    while (!(x & 1u)) { x >>= 1; n++; }
    return n;
}
#endif

/* NFA position count limit: positions are stored as bits of a uint64_t.
 * A "position" is one matched atom (character / class / dot).  Quantifier
 * expansion can inflate the count, so {n,m} is bounded so the unrolled
 * NFA still fits. */
#define NS_MAX_POSITIONS    64
#define NS_MAX_QUANT_REPEAT 64

/* Compiled pattern: bit-parallel Glushkov NFA.
 *
 *   initial    = positions reachable as the first matched atom
 *   accept     = positions whose match completes the pattern
 *   follow[i]  = positions reachable directly after position i
 *   byte_pos[c]= positions whose atom matches byte c
 *
 * Scan step (per input byte c at offset i):
 *   reach = (UNION over j in state of follow[j])
 *         | (anchor_start && i > 0 ? 0 : initial)
 *   state = reach & byte_pos[c]
 *   if state & accept -> a match ends at offset i+1
 *
 * Start-offset tracking is done by a parallel per-position uint32_t array
 * in the scanner; it is not stored on the pattern. */
struct ns_pattern {
    char        *source;
    unsigned int flags;        /* NS_FLAG_* */
    uint8_t      anchor_start; /* '^' at start  */
    uint8_t      anchor_end;   /* '$' at end    */
    uint8_t      n_pos;        /* 1..NS_MAX_POSITIONS */
    uint8_t      pad0;
    uint64_t     initial;
    uint64_t     accept;
    uint64_t     follow[NS_MAX_POSITIONS];
    uint64_t     byte_pos[256];
    uint32_t     min_len;
    uint32_t     max_len;      /* UINT32_MAX if unbounded */

    /* --- Derived prefilter fields, rebuilt at compile/deserialize. --- */
    uint8_t      is_fixed_len; /* min_len == max_len && max_len != UINT32_MAX */
    uint8_t      is_literal;   /* every position has exactly one byte */
    uint8_t      no_anchor;    /* set when no single end-trigger byte */
    uint8_t      anchor_byte;  /* bucket key when !no_anchor */
    uint8_t      literal[NS_MAX_POSITIONS]; /* valid iff is_literal */
};

struct ns_db {
    ns_pattern_t **patterns;
    unsigned int  *ids;
    size_t         count;

    uint8_t        present[256];
    uint32_t      *bucket_idx[256];
    uint32_t       bucket_n[256];
    uint32_t      *no_anchor_list;
    uint32_t       no_anchor_n;
};

int ns_db_build_prefilter(ns_db_t *db);

#endif /* NANOSCAN_INTERNAL_H */
