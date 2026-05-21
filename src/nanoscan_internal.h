#ifndef NANOSCAN_INTERNAL_H
#define NANOSCAN_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nanoscan.h"

/* Portable count-trailing-zeros for uint64_t. */
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

/* NFA position count limit.
 *
 * A "position" is one matched atom (literal byte, class, '.').  The NFA
 * state is a bitset of positions held in `NS_STATE_WORDS` 64-bit words.
 * Bumping NS_MAX_POSITIONS scales linearly with per-pattern memory
 * (byte_pos[256] dominates: 256 * NS_STATE_WORDS * 8 bytes).
 *
 *   NS_MAX_POSITIONS=256, NS_STATE_WORDS=4   -> ~8 KiB per pattern
 *
 * NS_MAX_QUANT_REPEAT caps {n,m} unrolling so the unrolled NFA still
 * fits.  Practical patterns of a few hundred atoms compile fine.
 */
#define NS_MAX_POSITIONS    256
#define NS_STATE_WORDS      ((NS_MAX_POSITIONS + 63) / 64)
#define NS_MAX_QUANT_REPEAT 128

typedef uint64_t ns_state_t[NS_STATE_WORDS];

static inline void ns_state_zero(ns_state_t s) {
    for (int i = 0; i < NS_STATE_WORDS; i++) s[i] = 0;
}
static inline void ns_state_copy(ns_state_t d, const ns_state_t s) {
    for (int i = 0; i < NS_STATE_WORDS; i++) d[i] = s[i];
}
static inline void ns_state_or(ns_state_t d, const ns_state_t s) {
    for (int i = 0; i < NS_STATE_WORDS; i++) d[i] |= s[i];
}
static inline void ns_state_and(ns_state_t d, const ns_state_t s) {
    for (int i = 0; i < NS_STATE_WORDS; i++) d[i] &= s[i];
}
static inline int ns_state_nz(const ns_state_t s) {
    uint64_t x = 0;
    for (int i = 0; i < NS_STATE_WORDS; i++) x |= s[i];
    return x != 0;
}
static inline int ns_state_and_nz(const ns_state_t a, const ns_state_t b) {
    uint64_t x = 0;
    for (int i = 0; i < NS_STATE_WORDS; i++) x |= a[i] & b[i];
    return x != 0;
}
static inline int ns_state_test(const ns_state_t s, int j) {
    return (int)((s[(unsigned)j >> 6] >> ((unsigned)j & 63)) & 1u);
}
static inline void ns_state_setb(ns_state_t s, int j) {
    s[(unsigned)j >> 6] |= (uint64_t)1 << ((unsigned)j & 63);
}

/* Iterate every set bit j in `s`, executing BODY each time.
 * BODY may reference `j` as a const int and may use `break;`/`continue;`
 * relative to its own surrounding loop -- not relative to the macro. */
#define NS_STATE_FOREACH(s, j, BODY)                                        \
    do {                                                                    \
        for (int _wi = 0; _wi < NS_STATE_WORDS; _wi++) {                    \
            uint64_t _ww = (s)[_wi];                                        \
            while (_ww) {                                                   \
                int j = (_wi << 6) + ns_ctz64(_ww);                         \
                BODY;                                                       \
                _ww &= _ww - 1;                                             \
            }                                                               \
        }                                                                   \
    } while (0)

/* Number of 64-bit state words actually needed to represent n_pos
 * positions. Used by the on-disk format to avoid storing zero tails. */
static inline unsigned ns_state_words_for(unsigned n_pos) {
    if (n_pos == 0) return 1;
    return (n_pos + 63u) / 64u;
}

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
 */
struct ns_pattern {
    char        *source;
    unsigned int flags;        /* NS_FLAG_* */
    uint8_t      anchor_start; /* '^' at start  */
    uint8_t      anchor_end;   /* '$' at end    */
    uint16_t     n_pos;        /* 1..NS_MAX_POSITIONS */
    ns_state_t   initial;
    ns_state_t   accept;
    ns_state_t   follow[NS_MAX_POSITIONS];
    ns_state_t   byte_pos[256];
    uint32_t     min_len;
    uint32_t     max_len;      /* UINT32_MAX if unbounded */

    /* --- Derived prefilter fields, rebuilt at compile/deserialize. --- */
    uint8_t      is_fixed_len;
    uint8_t      is_literal;
    uint8_t      no_anchor;
    uint8_t      anchor_byte;
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
