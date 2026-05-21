/*
 * Hyperscan-compatible API surface (block mode subset) implemented on top
 * of the nanoscan engine. Keeps the public shape and key semantics:
 *   - Per-pattern flag validation (only supported flags accepted).
 *   - HS_FLAG_CASELESS / HS_FLAG_DOTALL / HS_FLAG_SINGLEMATCH honoured.
 *   - HS_FLAG_MULTILINE accepted as a no-op (^ / $ already supported at
 *     the extremes of the pattern).
 *   - HS_FLAG_SOM_LEFTMOST accepted as a no-op (start-of-match is always
 *     reported).
 *   - HS_SCAN_TERMINATED returned when a callback aborts the scan.
 *   - hs_compile_error_t carries a human-readable message.
 */
#include "hs/hs.h"
#include "nanoscan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NANO_HS_VERSION "nano-hyperscan-arm 0.1.0 (block-mode subset)"

#define SUPPORTED_FLAGS                                                      \
    (HS_FLAG_CASELESS | HS_FLAG_DOTALL | HS_FLAG_MULTILINE                   \
     | HS_FLAG_SINGLEMATCH | HS_FLAG_ALLOWEMPTY | HS_FLAG_SOM_LEFTMOST)

typedef struct {
    match_event_handler on_event;
    void               *user_ctx;
} bridge_ctx_t;

static char *dup_cstr(const char *s) {
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (out) memcpy(out, s, n);
    return out;
}

static hs_error_t make_error(hs_compile_error_t **out,
                             int expr_index,
                             const char *msg,
                             hs_error_t code) {
    if (!out) return code;
    hs_compile_error_t *e = (hs_compile_error_t *)malloc(sizeof(*e));
    if (!e) return HS_NOMEM;
    e->expression = expr_index;
    e->message    = dup_cstr(msg ? msg : "compile error");
    if (!e->message) { free(e); return HS_NOMEM; }
    *out = e;
    return code;
}

static int bridge_on_match(unsigned int id, size_t from, size_t to, void *ctx) {
    bridge_ctx_t *b = (bridge_ctx_t *)ctx;
    if (!b || !b->on_event) return 0;
    return b->on_event(id,
                       (unsigned long long)from,
                       (unsigned long long)to,
                       0,
                       b->user_ctx);
}

hs_error_t hs_compile_multi(const char *const   *expressions,
                            const unsigned int  *flags,
                            const unsigned int  *ids,
                            unsigned int         elements,
                            unsigned int         mode,
                            const void          *platform,
                            hs_database_t      **db,
                            hs_compile_error_t **error) {
    (void)platform;
    if (error) *error = NULL;

    if (!db || !expressions || elements == 0) {
        return make_error(error, -1, "invalid compile arguments", HS_INVALID);
    }
    if (mode != HS_MODE_BLOCK) {
        return make_error(error, -1,
                          "only HS_MODE_BLOCK is supported in this build",
                          HS_DB_MODE_ERROR);
    }

    for (unsigned int i = 0; i < elements; i++) {
        if (!expressions[i]) {
            return make_error(error, (int)i,
                              "expression must not be NULL", HS_COMPILER_ERROR);
        }
        if (flags) {
            unsigned int unsupported = flags[i] & ~SUPPORTED_FLAGS;
            if (unsupported) {
                char msg[96];
                snprintf(msg, sizeof(msg),
                         "unsupported flag bits 0x%x on expression %u",
                         unsupported, i);
                return make_error(error, (int)i, msg, HS_COMPILER_ERROR);
            }
        }
    }

    char err_buf[160];
    int  err_idx = -1;
    ns_db_t *nsdb = ns_db_compile(expressions, flags, ids,
                                  (size_t)elements,
                                  err_buf, sizeof(err_buf),
                                  &err_idx);
    if (!nsdb) {
        return make_error(error, err_idx,
                          err_buf[0] ? err_buf : "database compile failed",
                          HS_COMPILER_ERROR);
    }

    *db = (hs_database_t *)nsdb;
    return HS_SUCCESS;
}

hs_error_t hs_compile(const char         *expression,
                      unsigned int        flags,
                      unsigned int        mode,
                      const void         *platform,
                      hs_database_t     **db,
                      hs_compile_error_t **error) {
    if (!expression) {
        if (error) *error = NULL;
        return make_error(error, -1, "expression must not be NULL", HS_INVALID);
    }
    const char  *exprs[1] = { expression };
    unsigned int fl[1]    = { flags };
    unsigned int ids[1]   = { 0 };
    return hs_compile_multi(exprs, fl, ids, 1, mode, platform, db, error);
}

/* Scratch is trivial in block mode for this implementation, but we still
 * give it a real definition so that taking sizeof in user code matches and
 * future state (e.g. per-thread match buffers) can live here. */
struct hs_scratch {
    const hs_database_t *owner;
};

hs_error_t hs_alloc_scratch(const hs_database_t *db, hs_scratch_t **scratch) {
    if (!db || !scratch) return HS_INVALID;
    /* Reuse existing scratch if the caller passes one in (matches upstream). */
    if (*scratch) {
        (*scratch)->owner = db;
        return HS_SUCCESS;
    }
    hs_scratch_t *s = (hs_scratch_t *)malloc(sizeof(*s));
    if (!s) return HS_NOMEM;
    s->owner = db;
    *scratch = s;
    return HS_SUCCESS;
}

hs_error_t hs_clone_scratch(const hs_scratch_t *src, hs_scratch_t **dst) {
    if (!src || !dst) return HS_INVALID;
    hs_scratch_t *s = (hs_scratch_t *)malloc(sizeof(*s));
    if (!s) return HS_NOMEM;
    s->owner = src->owner;
    *dst = s;
    return HS_SUCCESS;
}

hs_error_t hs_free_scratch(hs_scratch_t *scratch) {
    free(scratch);
    return HS_SUCCESS;
}

hs_error_t hs_scan(const hs_database_t *db,
                   const char          *data,
                   unsigned int         length,
                   unsigned int         flags,
                   hs_scratch_t        *scratch,
                   match_event_handler  on_event,
                   void                *context) {
    (void)flags;
    if (!db || !scratch) return HS_INVALID;
    if (!data && length > 0) return HS_INVALID;
    if (scratch->owner && scratch->owner != db) return HS_SCRATCH_IN_USE;

    bridge_ctx_t bridge = { on_event, context };
    int terminated = 0;
    ns_db_scan((const ns_db_t *)db, data, (size_t)length,
               on_event ? bridge_on_match : NULL,
               on_event ? (void *)&bridge : NULL,
               &terminated);
    return terminated ? HS_SCAN_TERMINATED : HS_SUCCESS;
}

hs_error_t hs_free_database(hs_database_t *db) {
    ns_db_free((ns_db_t *)db);
    return HS_SUCCESS;
}

hs_error_t hs_free_compile_error(hs_compile_error_t *error) {
    if (!error) return HS_SUCCESS;
    free(error->message);
    free(error);
    return HS_SUCCESS;
}

const char *hs_version(void) {
    return NANO_HS_VERSION;
}

hs_error_t hs_valid_platform(void) {
    /* We do not require any specific CPU feature in the portable build. */
    return HS_SUCCESS;
}

hs_error_t hs_serialize_database(const hs_database_t *db,
                                 char               **bytes,
                                 size_t              *length) {
    if (!db || !bytes || !length) return HS_INVALID;
    void *buf = NULL;
    size_t n  = 0;
    if (ns_db_serialize((const ns_db_t *)db, &buf, &n) != 0) return HS_NOMEM;
    *bytes  = (char *)buf;
    *length = n;
    return HS_SUCCESS;
}

hs_error_t hs_deserialize_database(const char     *bytes,
                                   size_t          length,
                                   hs_database_t **db) {
    if (!bytes || !db || length == 0) return HS_INVALID;
    ns_db_t *out = ns_db_deserialize(bytes, length);
    if (!out) return HS_DB_VERSION_ERROR;
    *db = (hs_database_t *)out;
    return HS_SUCCESS;
}

hs_error_t hs_serialized_database_size(const char *bytes,
                                       size_t      length,
                                       size_t     *deserialized_size) {
    /* For this engine the in-memory and on-wire footprints are tied: a
     * deserialized database needs roughly the same number of bytes plus a
     * fixed overhead for the C-side bookkeeping. We just return `length`
     * which is a safe upper bound and matches what most callers want
     * (an mmap sizing hint). */
    if (!bytes || !deserialized_size || length == 0) return HS_INVALID;
    *deserialized_size = length;
    return HS_SUCCESS;
}

hs_error_t hs_serialized_database_info(const char  *bytes,
                                       size_t       length,
                                       char       **info) {
    if (!bytes || !info || length < 16) return HS_INVALID;
    if (bytes[0] != 'N' || bytes[1] != 'H' ||
        bytes[2] != 'S' || bytes[3] != '\0') return HS_DB_VERSION_ERROR;
    uint32_t version, count;
    memcpy(&version, bytes + 4, sizeof(version));
    memcpy(&count,   bytes + 8, sizeof(count));
    char buf[96];
    int n = snprintf(buf, sizeof(buf),
                     "nano-hyperscan wire v%u, %u pattern(s)",
                     (unsigned)version, (unsigned)count);
    if (n < 0) return HS_NOMEM;
    char *out = (char *)malloc((size_t)n + 1);
    if (!out) return HS_NOMEM;
    memcpy(out, buf, (size_t)n + 1);
    *info = out;
    return HS_SUCCESS;
}
