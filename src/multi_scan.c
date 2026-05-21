/*
 * Multi-pattern block-mode scanner over bit-parallel Glushkov NFAs.
 *
 * For every input position i and every pattern k we maintain:
 *   state[k] : uint64_t bit-set of currently active NFA positions
 *   start[k][j] : earliest input offset at which position j became active
 *
 * Step:
 *   reach = (union of follow[j] for j in state[k])
 *         | (anchor_start && i > 0 ? 0 : initial)
 *   new   = reach & byte_pos[c]
 *   for each bit j in new:
 *     start_new[j] = min over predecessor paths (or i if j in initial)
 *
 * Match emission: when (new & accept) != 0, the match ends at offset i+1
 * and the leftmost start across the accepting positions is the SOM.
 *
 * Fixed-length pure-literal patterns get a fast path through the
 * prefilter (anchor_byte bucket + memcmp).
 */
#include "nanoscan_internal.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define INF_LEN ((uint32_t)0xFFFFFFFFu)

/* ----------------------- expression split ----------------------- */

static int append_branch(char ***out, size_t *count, size_t *cap,
                         const char *expr, size_t n) {
    if (*count == *cap) {
        size_t nc = (*cap == 0) ? 4 : (*cap * 2);
        char **nb = (char **)realloc(*out, nc * sizeof(char *));
        if (!nb) return -1;
        *out = nb;
        *cap = nc;
    }
    char *s = (char *)malloc(n + 1);
    if (!s) return -1;
    memcpy(s, expr, n);
    s[n] = '\0';
    (*out)[(*count)++] = s;
    return 0;
}

/* Top-level '|' is now handled inside the parser, so split_branches is
 * gone. ns_db_compile compiles each expression as a single NFA. The
 * caller's id maps 1:1 to one ns_pattern. */

/* ----------------------- compile / free ----------------------- */

ns_db_t *ns_db_compile(const char *const  *exprs,
                       const unsigned int *flags,
                       const unsigned int *ids,
                       size_t              count,
                       char               *err,
                       size_t              err_cap,
                       int                *err_expr_index) {
    if (err_expr_index) *err_expr_index = -1;
    if (err && err_cap > 0) err[0] = '\0';
    if (!exprs || count == 0) return NULL;

    ns_db_t *db = (ns_db_t *)calloc(1, sizeof(*db));
    if (!db) return NULL;
    db->patterns = (ns_pattern_t **)calloc(count, sizeof(ns_pattern_t *));
    db->ids      = (unsigned int  *)calloc(count, sizeof(unsigned int));
    if (!db->patterns || !db->ids) { ns_db_free(db); return NULL; }
    db->count = count;

    for (size_t i = 0; i < count; i++) {
        unsigned int f  = flags ? flags[i] : 0;
        unsigned int id = ids   ? ids[i]   : (unsigned int)i;
        ns_pattern_t *p = ns_compile(exprs[i], f, err, err_cap);
        if (!p) {
            if (err_expr_index) *err_expr_index = (int)i;
            ns_db_free(db);
            return NULL;
        }
        db->patterns[i] = p;
        db->ids[i]      = id;
    }

    if (ns_db_build_prefilter(db) != 0) {
        ns_db_free(db);
        return NULL;
    }
    return db;
}

int ns_db_build_prefilter(ns_db_t *db) {
    if (!db) return -1;
    for (int c = 0; c < 256; c++) {
        free(db->bucket_idx[c]);
        db->bucket_idx[c] = NULL;
        db->bucket_n[c]   = 0;
    }
    free(db->no_anchor_list);
    db->no_anchor_list = NULL;
    db->no_anchor_n    = 0;
    memset(db->present, 0, sizeof(db->present));

    /* Classify each pattern: fixed-length pure literals get a memcmp
     * fast-path and an end-byte bucket; everything else falls back to
     * NFA simulation. */
    for (size_t k = 0; k < db->count; k++) {
        ns_pattern_t *p = db->patterns[k];
        p->is_fixed_len = (p->min_len == p->max_len && p->max_len != INF_LEN);
        p->is_literal   = 0;
        p->no_anchor    = 1;

        if (!p->is_fixed_len || p->min_len == 0 ||
            p->min_len > NS_MAX_POSITIONS) continue;

        /* For a fixed-length pattern with min==max==n_pos, every position
         * is mandatory. A pure literal means every column of byte_pos has
         * popcount == 1 and the bits in byte_pos cover positions 0..n-1
         * exactly. The simplest check: count, per position, how many
         * bytes have that bit set, via a transposed sweep. */
        if (p->min_len != (uint32_t)p->n_pos) {
            /* Variable length collapsed by quantifier; skip fast path. */
        }

        int literal_ok = (p->min_len == (uint32_t)p->n_pos);
        if (literal_ok) {
            uint64_t covered = 0;
            for (int b = 0; b < 256 && literal_ok; b++) {
                uint64_t m = p->byte_pos[b];
                while (m) {
                    int j = ns_ctz64(m);
                    if (covered & ((uint64_t)1 << j)) { literal_ok = 0; break; }
                    covered |= (uint64_t)1 << j;
                    p->literal[j] = (uint8_t)b;
                    m &= m - 1;
                }
            }
            if (literal_ok && covered == (((uint64_t)1 << p->n_pos) - 1 |
                                          (p->n_pos == 64 ? ~(uint64_t)0 : 0))) {
                p->is_literal = 1;
            }
        }

        /* End-trigger byte: look at the accept set's last position(s). If
         * exactly one byte triggers any accept bit and the pattern is
         * fixed-length, we can bucket by that byte. */
        uint8_t the = 0;
        unsigned cnt = 0;
        for (int b = 0; b < 256; b++) {
            if (p->byte_pos[b] & p->accept) {
                cnt++;
                the = (uint8_t)b;
                if (cnt > 1) break;
            }
        }
        if (cnt == 1 && p->is_fixed_len) {
            p->no_anchor   = 0;
            p->anchor_byte = the;
        }
    }

    uint32_t cnt[256] = {0};
    uint32_t na = 0;
    for (size_t k = 0; k < db->count; k++) {
        const ns_pattern_t *p = db->patterns[k];
        if (p->no_anchor) na++;
        else              cnt[p->anchor_byte]++;
    }
    for (int c = 0; c < 256; c++) {
        if (!cnt[c]) continue;
        db->bucket_idx[c] = (uint32_t *)malloc(cnt[c] * sizeof(uint32_t));
        if (!db->bucket_idx[c]) return -1;
        db->present[c] = 1;
    }
    if (na) {
        db->no_anchor_list = (uint32_t *)malloc(na * sizeof(uint32_t));
        if (!db->no_anchor_list) return -1;
    }
    for (size_t k = 0; k < db->count; k++) {
        const ns_pattern_t *p = db->patterns[k];
        if (p->no_anchor) {
            db->no_anchor_list[db->no_anchor_n++] = (uint32_t)k;
        } else {
            uint8_t c = p->anchor_byte;
            db->bucket_idx[c][db->bucket_n[c]++] = (uint32_t)k;
        }
    }

    /* append_branch is referenced from the legacy path; reference it here
     * so the linker doesn't strip the symbol if a future caller wants
     * to reuse it. */
    (void)append_branch;
    return 0;
}

void ns_db_free(ns_db_t *db) {
    if (!db) return;
    if (db->patterns) {
        for (size_t i = 0; i < db->count; i++) ns_free(db->patterns[i]);
        free(db->patterns);
    }
    free(db->ids);
    for (int c = 0; c < 256; c++) free(db->bucket_idx[c]);
    free(db->no_anchor_list);
    free(db);
}

/* ----------------------- verify (literal fast path) ----------------------- */

static inline int verify_literal(const ns_pattern_t *p, const uint8_t *t) {
    return memcmp(t, p->literal, p->min_len) == 0;
}

static inline void mark_fired_by_id(const ns_db_t *db, unsigned int id,
                                    unsigned char *fired) {
    for (size_t j = 0; j < db->count; j++) {
        if (db->ids[j] == id &&
            (db->patterns[j]->flags & NS_FLAG_SINGLEMATCH)) {
            fired[j] = 1;
        }
    }
}

/* ----------------------- NFA step ----------------------- */

/* Update one NFA by one byte. Returns 1 if a match ended at offset i+1
 * and writes its SOM to *out_from, otherwise 0. */
static inline int nfa_step(const ns_pattern_t *p,
                           uint64_t            *state,
                           uint32_t            *start,
                           size_t               i,
                           size_t               len,
                           uint8_t              c,
                           size_t              *out_from) {
    uint64_t reach = 0;
    uint64_t s = *state;
    while (s) {
        int j = ns_ctz64(s);
        reach |= p->follow[j];
        s &= s - 1;
    }
    int allow_restart = !(p->anchor_start && i > 0);
    if (allow_restart) reach |= p->initial;

    uint64_t newst = reach & p->byte_pos[c];

    /* Build new start[] in scratch then commit. */
    uint32_t new_start[NS_MAX_POSITIONS];
    uint64_t ns_mask = newst;
    while (ns_mask) {
        int j = ns_ctz64(ns_mask);
        new_start[j] = UINT32_MAX;
        ns_mask &= ns_mask - 1;
    }
    if (allow_restart) {
        uint64_t fr = p->initial & newst;
        while (fr) {
            int j = ns_ctz64(fr);
            if ((uint32_t)i < new_start[j]) new_start[j] = (uint32_t)i;
            fr &= fr - 1;
        }
    }
    uint64_t old = *state;
    while (old) {
        int k = ns_ctz64(old);
        uint64_t reachable = p->follow[k] & newst;
        while (reachable) {
            int j = ns_ctz64(reachable);
            if (start[k] < new_start[j]) new_start[j] = start[k];
            reachable &= reachable - 1;
        }
        old &= old - 1;
    }

    /* Commit. */
    *state = newst;
    {
        uint64_t m = newst;
        while (m) {
            int j = ns_ctz64(m);
            start[j] = new_start[j];
            m &= m - 1;
        }
    }

    uint64_t acc = newst & p->accept;
    if (!acc) return 0;
    if (p->anchor_end && i + 1 != len) return 0;

    uint32_t som = UINT32_MAX;
    while (acc) {
        int j = ns_ctz64(acc);
        if (start[j] < som) som = start[j];
        acc &= acc - 1;
    }
    *out_from = som;
    return 1;
}

/* ----------------------- top-level scan ----------------------- */

size_t ns_db_scan(const ns_db_t   *db,
                  const char      *text,
                  size_t           len,
                  ns_match_handler on_match,
                  void            *ctx,
                  int             *terminated) {
    if (terminated) *terminated = 0;
    if (!db || db->count == 0) return 0;
    if (!text && len > 0)      return 0;

    const uint8_t *T = (const uint8_t *)text;
    const uint32_t na = db->no_anchor_n;

    unsigned char *fired = (unsigned char *)calloc(db->count, 1);
    uint64_t      *state = na ? (uint64_t *)calloc(na, sizeof(uint64_t)) : NULL;
    /* start[k*64 + j] : SOM for position j in pattern db->no_anchor_list[k] */
    uint32_t      *start = na ? (uint32_t *)malloc(na * NS_MAX_POSITIONS *
                                                   sizeof(uint32_t)) : NULL;
    if (!fired || (na && (!state || !start))) {
        free(fired); free(state); free(start); return 0;
    }

    size_t total = 0;
    int    stop  = 0;

    for (size_t i = 0; i < len && !stop; i++) {
        uint8_t c = T[i];

        /* NFA fallback pass: handles all variable-length / class /
         * quantifier patterns. */
        for (uint32_t kk = 0; kk < na && !stop; kk++) {
            uint32_t k = db->no_anchor_list[kk];
            const ns_pattern_t *p = db->patterns[k];
            if ((p->flags & NS_FLAG_SINGLEMATCH) && fired[k]) {
                state[kk] = 0;
                continue;
            }
            size_t from = 0;
            if (!nfa_step(p, &state[kk], &start[kk * NS_MAX_POSITIONS],
                          i, len, c, &from)) continue;

            total++;
            if (p->flags & NS_FLAG_SINGLEMATCH)
                mark_fired_by_id(db, db->ids[k], fired);
            if (on_match && on_match(db->ids[k], from, i + 1, ctx) != 0) {
                stop = 1;
                if (terminated) *terminated = 1;
            }
        }

        /* Bucketed pass: fixed-length literals trigger only when the
         * current byte equals their end byte. */
        if (!db->present[c]) continue;
        uint32_t       n    = db->bucket_n[c];
        const uint32_t *idxs = db->bucket_idx[c];
        for (uint32_t kk = 0; kk < n && !stop; kk++) {
            uint32_t k = idxs[kk];
            const ns_pattern_t *p = db->patterns[k];
            if ((p->flags & NS_FLAG_SINGLEMATCH) && fired[k]) continue;
            if (i + 1 < p->min_len) continue;

            size_t start_off = i + 1 - p->min_len;
            if (p->anchor_start && start_off != 0)        continue;
            if (p->anchor_end   && i + 1   != len)        continue;

            if (p->is_literal) {
                if (!verify_literal(p, T + start_off)) continue;
            } else {
                /* Fixed-length with classes: run NFA forward over the
                 * candidate window to confirm. Cheaper than full NFA scan
                 * because the window is exactly min_len bytes. */
                uint64_t st = p->initial & p->byte_pos[T[start_off]];
                if (!st) continue;
                int ok = 1;
                for (uint32_t j = 1; j < p->min_len; j++) {
                    uint64_t reach = 0;
                    uint64_t s = st;
                    while (s) {
                        int b = ns_ctz64(s);
                        reach |= p->follow[b];
                        s &= s - 1;
                    }
                    st = reach & p->byte_pos[T[start_off + j]];
                    if (!st) { ok = 0; break; }
                }
                if (!ok || !(st & p->accept)) continue;
            }

            total++;
            if (p->flags & NS_FLAG_SINGLEMATCH)
                mark_fired_by_id(db, db->ids[k], fired);
            if (on_match && on_match(db->ids[k], start_off, i + 1, ctx) != 0) {
                stop = 1;
                if (terminated) *terminated = 1;
            }
        }
    }

    free(state); free(start); free(fired);
    return total;
}
