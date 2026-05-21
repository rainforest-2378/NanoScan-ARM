/*
 * Multi-pattern block-mode scanner over bit-parallel Glushkov NFAs.
 *
 * Per-byte step (for every active pattern k):
 *   reach = (UNION over j in state[k] of follow[j])
 *         | (anchor_start && i > 0 ? 0 : initial)
 *   new   = reach & byte_pos[c]
 *   if (new & accept) -> match ends at offset i+1
 *
 * Fixed-length pure-literal patterns get a fast path via the prefilter
 * (anchor_byte bucket + memcmp).
 */
#include "nanoscan_internal.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define INF_LEN ((uint32_t)0xFFFFFFFFu)

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

    for (size_t k = 0; k < db->count; k++) {
        ns_pattern_t *p = db->patterns[k];
        p->is_fixed_len = (p->min_len == p->max_len && p->max_len != INF_LEN);
        p->is_literal   = 0;
        p->no_anchor    = 1;

        if (!p->is_fixed_len || p->min_len == 0 ||
            p->min_len > NS_MAX_POSITIONS) continue;

        /* Pure literal: every position must accept exactly one byte and
         * positions 0..n_pos-1 must all be covered exactly once across
         * the byte_pos table. */
        int literal_ok = (p->min_len == (uint32_t)p->n_pos);
        if (literal_ok) {
            ns_state_t covered;
            ns_state_zero(covered);
            for (int b = 0; b < 256 && literal_ok; b++) {
                ns_state_t row;
                ns_state_copy(row, p->byte_pos[b]);
                NS_STATE_FOREACH(row, j, {
                    if (ns_state_test(covered, j)) { literal_ok = 0; }
                    ns_state_setb(covered, j);
                    if (j < NS_MAX_POSITIONS) p->literal[j] = (uint8_t)b;
                });
            }
            if (literal_ok) {
                /* All n_pos positions covered? */
                for (int i = 0; i < p->n_pos && literal_ok; i++) {
                    if (!ns_state_test(covered, i)) literal_ok = 0;
                }
                if (literal_ok) p->is_literal = 1;
            }
        }

        /* End-trigger byte: exactly one byte must, for a fixed-length
         * pattern, contain any of the accept positions. */
        uint8_t the = 0;
        unsigned cnt = 0;
        for (int b = 0; b < 256; b++) {
            if (ns_state_and_nz(p->byte_pos[b], p->accept)) {
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
 * and writes its SOM to *out_from, otherwise 0.
 *
 * `state`     : ns_state_t bitset for this pattern, updated in-place
 * `start`     : per-position SOM array (NS_MAX_POSITIONS entries)
 * `i,len,c`   : current byte index, total length, byte value
 */
static inline int nfa_step(const ns_pattern_t *p,
                           ns_state_t           state,
                           uint32_t            *start,
                           size_t               i,
                           size_t               len,
                           uint8_t              c,
                           size_t              *out_from) {
    ns_state_t reach;
    ns_state_zero(reach);

    NS_STATE_FOREACH(state, j, {
        ns_state_or(reach, p->follow[j]);
    });

    int allow_restart = !(p->anchor_start && i > 0);
    if (allow_restart) ns_state_or(reach, p->initial);

    ns_state_t newst;
    ns_state_copy(newst, reach);
    ns_state_and (newst, p->byte_pos[c]);

    /* new_start[j] for each bit j set in newst. */
    uint32_t new_start[NS_MAX_POSITIONS];
    NS_STATE_FOREACH(newst, j, {
        new_start[j] = UINT32_MAX;
    });

    if (allow_restart) {
        ns_state_t fr;
        ns_state_copy(fr, p->initial);
        ns_state_and (fr, newst);
        NS_STATE_FOREACH(fr, j, {
            if ((uint32_t)i < new_start[j]) new_start[j] = (uint32_t)i;
        });
    }

    NS_STATE_FOREACH(state, k, {
        ns_state_t reachable;
        ns_state_copy(reachable, p->follow[k]);
        ns_state_and (reachable, newst);
        NS_STATE_FOREACH(reachable, j, {
            if (start[k] < new_start[j]) new_start[j] = start[k];
        });
    });

    /* Commit. */
    ns_state_copy(state, newst);
    NS_STATE_FOREACH(newst, j, {
        start[j] = new_start[j];
    });

    if (!ns_state_and_nz(newst, p->accept)) return 0;
    if (p->anchor_end && i + 1 != len) return 0;

    uint32_t som = UINT32_MAX;
    ns_state_t acc;
    ns_state_copy(acc, newst);
    ns_state_and (acc, p->accept);
    NS_STATE_FOREACH(acc, j, {
        if (start[j] < som) som = start[j];
    });
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
    ns_state_t    *state = na ? (ns_state_t *)calloc(na, sizeof(ns_state_t)) : NULL;
    /* start[k*NS_MAX_POSITIONS + j] : SOM for position j in pattern k. */
    uint32_t      *start = na ? (uint32_t *)malloc(na * NS_MAX_POSITIONS *
                                                   sizeof(uint32_t)) : NULL;
    if (!fired || (na && (!state || !start))) {
        free(fired); free(state); free(start); return 0;
    }

    size_t total = 0;
    int    stop  = 0;

    for (size_t i = 0; i < len && !stop; i++) {
        uint8_t c = T[i];

        /* NFA fallback pass for variable-length / no-end-trigger patterns. */
        for (uint32_t kk = 0; kk < na && !stop; kk++) {
            uint32_t k = db->no_anchor_list[kk];
            const ns_pattern_t *p = db->patterns[k];
            if ((p->flags & NS_FLAG_SINGLEMATCH) && fired[k]) {
                ns_state_zero(state[kk]);
                continue;
            }
            size_t from = 0;
            if (!nfa_step(p, state[kk], &start[kk * NS_MAX_POSITIONS],
                          i, len, c, &from)) continue;

            total++;
            if (p->flags & NS_FLAG_SINGLEMATCH)
                mark_fired_by_id(db, db->ids[k], fired);
            if (on_match && on_match(db->ids[k], from, i + 1, ctx) != 0) {
                stop = 1;
                if (terminated) *terminated = 1;
            }
        }

        /* Bucketed pass: fixed-length patterns triggered by current byte. */
        if (!db->present[c]) continue;
        uint32_t       n    = db->bucket_n[c];
        const uint32_t *idxs = db->bucket_idx[c];
        for (uint32_t kk = 0; kk < n && !stop; kk++) {
            uint32_t k = idxs[kk];
            const ns_pattern_t *p = db->patterns[k];
            if ((p->flags & NS_FLAG_SINGLEMATCH) && fired[k]) continue;
            if (i + 1 < p->min_len) continue;

            size_t start_off = i + 1 - p->min_len;
            if (p->anchor_start && start_off != 0) continue;
            if (p->anchor_end   && i + 1   != len) continue;

            if (p->is_literal) {
                if (!verify_literal(p, T + start_off)) continue;
            } else {
                /* Fixed-length with classes: forward NFA over window. */
                ns_state_t st;
                ns_state_copy(st, p->initial);
                ns_state_and (st, p->byte_pos[T[start_off]]);
                if (!ns_state_nz(st)) continue;
                int ok = 1;
                for (uint32_t j = 1; j < p->min_len; j++) {
                    ns_state_t reach;
                    ns_state_zero(reach);
                    NS_STATE_FOREACH(st, b, {
                        ns_state_or(reach, p->follow[b]);
                    });
                    ns_state_copy(st, reach);
                    ns_state_and (st, p->byte_pos[T[start_off + j]]);
                    if (!ns_state_nz(st)) { ok = 0; break; }
                }
                if (!ok || !ns_state_and_nz(st, p->accept)) continue;
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
