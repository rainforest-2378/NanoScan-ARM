/*
 * NanoScan internal-but-public C API.
 *
 * The Hyperscan-compatible layer in <hs/hs.h> is built on top of this.
 * Business code typically should NOT include this header; include <hs/hs.h>
 * instead so that swapping the implementation later stays painless.
 */
#ifndef NANOSCAN_H
#define NANOSCAN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pattern compile flags. Bit values intentionally match HS_FLAG_* so the
 * compat layer can forward without translation. */
#define NS_FLAG_CASELESS     (1U << 0)
#define NS_FLAG_DOTALL       (1U << 1)
#define NS_FLAG_MULTILINE    (1U << 2)
#define NS_FLAG_SINGLEMATCH  (1U << 3)
#define NS_FLAG_ALLOWEMPTY   (1U << 4)

/* Opaque handles. */
typedef struct ns_pattern ns_pattern_t;
typedef struct ns_db      ns_db_t;

/* Match callback. Return non-zero to terminate scanning. */
typedef int (*ns_match_handler)(unsigned int id,
                                size_t       from,
                                size_t       to,
                                void        *ctx);

/* Compile a single pattern. Returns NULL on syntax/limit error; if `err` is
 * non-NULL it is filled with a short human-readable description. */
ns_pattern_t *ns_compile(const char *re,
                         unsigned int flags,
                         char        *err,
                         size_t       err_cap);

void ns_free(ns_pattern_t *p);

/* Compile a multi-pattern database. `flags` and `ids` may be NULL. */
ns_db_t *ns_db_compile(const char *const  *exprs,
                       const unsigned int *flags,
                       const unsigned int *ids,
                       size_t              count,
                       char               *err,
                       size_t              err_cap,
                       int                *err_expr_index);

void ns_db_free(ns_db_t *db);

/* Block-mode scan. Returns total match count delivered to the callback.
 * If `*terminated` is non-NULL, it is set to 1 when the callback asked to
 * stop early, otherwise 0. */
size_t ns_db_scan(const ns_db_t   *db,
                  const char      *text,
                  size_t           len,
                  ns_match_handler on_match,
                  void            *ctx,
                  int             *terminated);

/* Standalone Shift-And counter, retained for tests and quick experiments.
 * Treats '.' as wildcard; pattern length must be 1..64. */
size_t ns_shiftand_count(const char *pattern, const char *text, size_t len);

/* Serialize / deserialize a compiled database. The buffer returned by
 * ns_db_serialize must be released with free(). */
int ns_db_serialize(const ns_db_t *db, void **bytes, size_t *length);
ns_db_t *ns_db_deserialize(const void *bytes, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* NANOSCAN_H */
