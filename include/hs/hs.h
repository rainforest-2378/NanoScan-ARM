/*
 * NanoScan-ARM: a minimal, ARM-friendly Hyperscan-compatible block-mode engine.
 *
 * This header is intentionally a strict subset of upstream Hyperscan's public
 * API. Error codes and flag bit values match upstream so that existing call
 * sites compile and behave the same for the supported subset.
 *
 * Supported in this build:
 *   - HS_MODE_BLOCK only
 *   - Per-pattern flags: HS_FLAG_CASELESS, HS_FLAG_DOTALL, HS_FLAG_MULTILINE,
 *     HS_FLAG_SINGLEMATCH, HS_FLAG_ALLOWEMPTY (the last three are honoured
 *     where meaningful for the supported regex grammar).
 *   - Regex grammar: literal bytes, '.' wildcard, and backslash escapes
 *     (\\., \\\\, \\n, \\r, \\t). Patterns must be 1..64 bytes after parsing.
 *
 * Unsupported features are rejected at compile time with HS_COMPILER_ERROR
 * rather than being silently ignored.
 */
#ifndef HS_HS_H
#define HS_HS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Error codes (numerically aligned with upstream Hyperscan) --- */
#define HS_SUCCESS             0
#define HS_INVALID             (-1)
#define HS_NOMEM               (-2)
#define HS_SCAN_TERMINATED     (-3)
#define HS_COMPILER_ERROR      (-4)
#define HS_DB_VERSION_ERROR    (-5)
#define HS_DB_PLATFORM_ERROR   (-6)
#define HS_DB_MODE_ERROR       (-7)
#define HS_BAD_ALIGN           (-8)
#define HS_BAD_ALLOC           (-9)
#define HS_SCRATCH_IN_USE      (-10)
#define HS_ARCH_ERROR          (-11)
#define HS_INSUFFICIENT_SPACE  (-12)
#define HS_UNKNOWN_ERROR       (-13)

/* --- Compilation modes --- */
#define HS_MODE_BLOCK     1U
#define HS_MODE_NOSTREAM  HS_MODE_BLOCK
#define HS_MODE_STREAM    2U
#define HS_MODE_VECTORED  4U

/* --- Per-pattern flags (bit values match upstream) --- */
#define HS_FLAG_CASELESS     (1U << 0)
#define HS_FLAG_DOTALL       (1U << 1)
#define HS_FLAG_MULTILINE    (1U << 2)
#define HS_FLAG_SINGLEMATCH  (1U << 3)
#define HS_FLAG_ALLOWEMPTY   (1U << 4)
#define HS_FLAG_UTF8         (1U << 5)
#define HS_FLAG_UCP          (1U << 6)
#define HS_FLAG_PREFILTER    (1U << 7)
#define HS_FLAG_SOM_LEFTMOST (1U << 8)

typedef int hs_error_t;

/* Opaque handles; never dereference in user code. */
typedef struct hs_database hs_database_t;
typedef struct hs_scratch  hs_scratch_t;

typedef struct hs_compile_error {
    char *message;
    int   expression;
} hs_compile_error_t;

typedef int (*match_event_handler)(unsigned int       id,
                                   unsigned long long from,
                                   unsigned long long to,
                                   unsigned int       flags,
                                   void              *context);

/* --- Compilation --- */
hs_error_t hs_compile(const char         *expression,
                      unsigned int        flags,
                      unsigned int        mode,
                      const void         *platform,
                      hs_database_t     **db,
                      hs_compile_error_t **error);

hs_error_t hs_compile_multi(const char *const   *expressions,
                            const unsigned int  *flags,
                            const unsigned int  *ids,
                            unsigned int         elements,
                            unsigned int         mode,
                            const void          *platform,
                            hs_database_t      **db,
                            hs_compile_error_t **error);

/* --- Scratch (block mode: lightweight, but single-thread per scratch) --- */
hs_error_t hs_alloc_scratch(const hs_database_t *db, hs_scratch_t **scratch);
hs_error_t hs_clone_scratch(const hs_scratch_t *src, hs_scratch_t **dst);
hs_error_t hs_free_scratch(hs_scratch_t *scratch);

/* --- Block-mode scan --- */
hs_error_t hs_scan(const hs_database_t *db,
                   const char          *data,
                   unsigned int         length,
                   unsigned int         flags,
                   hs_scratch_t        *scratch,
                   match_event_handler  on_event,
                   void                *context);

/* --- Resource release --- */
hs_error_t hs_free_database(hs_database_t *db);
hs_error_t hs_free_compile_error(hs_compile_error_t *error);

/* --- Serialization ---
 * Snapshot a compiled database into a self-describing byte buffer so the
 * caller can persist it (file, shared memory, ...) and rehydrate later
 * without paying the compile cost again. Wire format includes a magic,
 * a version, and the engine kind, so a stale blob is rejected with
 * HS_DB_VERSION_ERROR rather than silently producing wrong matches. */
hs_error_t hs_serialize_database(const hs_database_t *db,
                                 char               **bytes,
                                 size_t              *length);

hs_error_t hs_deserialize_database(const char     *bytes,
                                   size_t          length,
                                   hs_database_t **db);

hs_error_t hs_serialized_database_size(const char *bytes,
                                       size_t      length,
                                       size_t     *deserialized_size);

hs_error_t hs_serialized_database_info(const char  *bytes,
                                       size_t       length,
                                       char       **info);

/* --- Introspection --- */
const char *hs_version(void);
hs_error_t  hs_valid_platform(void);

#ifdef __cplusplus
}
#endif

#endif /* HS_HS_H */
