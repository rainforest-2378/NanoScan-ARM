/*
 * Database serialization (wire v2, NFA-based engine).
 *
 *   header  ::= magic "NHS\0" | u32 version=2 | u32 pattern_count | u32 reserved
 *   pattern ::= u32 flags
 *             | u8 anchor_start | u8 anchor_end | u8 n_pos | u8 reserved
 *             | u64 initial
 *             | u64 accept
 *             | u64 follow[NS_MAX_POSITIONS]
 *             | u64 byte_pos[256]
 *             | u32 min_len | u32 max_len
 *             | u32 source_len | u8 source[source_len]
 *             | u32 id
 *
 * Prefilter / fast-path fields are derived and rebuilt after load.
 * Deserialize refuses on bad magic, version mismatch, sanity failure,
 * or trailing bytes.
 */
#include "nanoscan_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NS_MAGIC0 'N'
#define NS_MAGIC1 'H'
#define NS_MAGIC2 'S'
#define NS_MAGIC3 '\0'
#define NS_DB_WIRE_VERSION 2u

/* --- writer --- */

typedef struct {
    uint8_t  *buf;
    size_t    cap;
    size_t    len;
    int       oom;
} writer_t;

static void w_grow(writer_t *w, size_t need) {
    if (w->oom) return;
    if (w->len + need <= w->cap) return;
    size_t nc = w->cap ? w->cap : 256;
    while (nc < w->len + need) nc *= 2;
    uint8_t *nb = (uint8_t *)realloc(w->buf, nc);
    if (!nb) { w->oom = 1; return; }
    w->buf = nb;
    w->cap = nc;
}
static void w_bytes(writer_t *w, const void *src, size_t n) {
    w_grow(w, n);
    if (w->oom) return;
    memcpy(w->buf + w->len, src, n);
    w->len += n;
}
static void w_u32(writer_t *w, uint32_t v) { w_bytes(w, &v, sizeof(v)); }
static void w_u64(writer_t *w, uint64_t v) { w_bytes(w, &v, sizeof(v)); }
static void w_u8 (writer_t *w, uint8_t  v) { w_bytes(w, &v, sizeof(v)); }

int ns_db_serialize(const ns_db_t *db, void **bytes, size_t *length) {
    if (!db || !bytes || !length) return -1;

    writer_t w = {0};
    uint8_t magic[4] = { NS_MAGIC0, NS_MAGIC1, NS_MAGIC2, NS_MAGIC3 };
    w_bytes(&w, magic, 4);
    w_u32(&w, NS_DB_WIRE_VERSION);
    w_u32(&w, (uint32_t)db->count);
    w_u32(&w, 0u);

    for (size_t i = 0; i < db->count; i++) {
        const ns_pattern_t *p = db->patterns[i];
        w_u32(&w, p->flags);
        w_u8(&w, p->anchor_start);
        w_u8(&w, p->anchor_end);
        w_u8(&w, p->n_pos);
        w_u8(&w, 0);
        w_u64(&w, p->initial);
        w_u64(&w, p->accept);
        w_bytes(&w, p->follow,   sizeof(p->follow));
        w_bytes(&w, p->byte_pos, sizeof(p->byte_pos));
        w_u32(&w, p->min_len);
        w_u32(&w, p->max_len);
        uint32_t slen = p->source ? (uint32_t)strlen(p->source) : 0;
        w_u32(&w, slen);
        if (slen) w_bytes(&w, p->source, slen);
        w_u32(&w, db->ids[i]);
    }

    if (w.oom) { free(w.buf); return -1; }
    *bytes  = w.buf;
    *length = w.len;
    return 0;
}

/* --- reader --- */

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
    int            bad;
} reader_t;

static int r_take(reader_t *r, void *dst, size_t n) {
    if (r->bad) return -1;
    if (r->pos + n > r->len) { r->bad = 1; return -1; }
    memcpy(dst, r->buf + r->pos, n);
    r->pos += n;
    return 0;
}
static int r_skip_ref(reader_t *r, size_t n, const uint8_t **out) {
    if (r->bad) return -1;
    if (r->pos + n > r->len) { r->bad = 1; return -1; }
    *out = r->buf + r->pos;
    r->pos += n;
    return 0;
}

static int parse_header(reader_t *r, uint32_t *count) {
    uint8_t magic[4];
    uint32_t version, reserved;
    if (r_take(r, magic, 4) != 0) return -1;
    if (magic[0] != NS_MAGIC0 || magic[1] != NS_MAGIC1 ||
        magic[2] != NS_MAGIC2 || magic[3] != NS_MAGIC3) return -1;
    if (r_take(r, &version,  4) != 0) return -1;
    if (version != NS_DB_WIRE_VERSION) return -1;
    if (r_take(r, count,     4) != 0) return -1;
    if (r_take(r, &reserved, 4) != 0) return -1;
    if (reserved != 0) return -1;
    return 0;
}

ns_db_t *ns_db_deserialize(const void *bytes, size_t length) {
    if (!bytes || length == 0) return NULL;

    reader_t r = { (const uint8_t *)bytes, length, 0, 0 };
    uint32_t count = 0;
    if (parse_header(&r, &count) != 0) return NULL;
    if (count == 0) return NULL;

    ns_db_t *db = (ns_db_t *)calloc(1, sizeof(*db));
    if (!db) return NULL;
    db->patterns = (ns_pattern_t **)calloc(count, sizeof(ns_pattern_t *));
    db->ids      = (unsigned int  *)calloc(count, sizeof(unsigned int));
    if (!db->patterns || !db->ids) { ns_db_free(db); return NULL; }
    db->count = count;

    for (uint32_t i = 0; i < count; i++) {
        ns_pattern_t *p = (ns_pattern_t *)calloc(1, sizeof(*p));
        if (!p) { ns_db_free(db); return NULL; }
        db->patterns[i] = p;

        uint32_t flags;
        uint8_t  as, ae, n_pos, pad;
        if (r_take(&r, &flags,  4) != 0) goto bad;
        if (r_take(&r, &as,     1) != 0) goto bad;
        if (r_take(&r, &ae,     1) != 0) goto bad;
        if (r_take(&r, &n_pos,  1) != 0) goto bad;
        if (r_take(&r, &pad,    1) != 0) goto bad;
        if (n_pos == 0 || n_pos > NS_MAX_POSITIONS) goto bad;
        p->flags        = flags;
        p->anchor_start = as;
        p->anchor_end   = ae;
        p->n_pos        = n_pos;

        if (r_take(&r, &p->initial, 8)               != 0) goto bad;
        if (r_take(&r, &p->accept,  8)               != 0) goto bad;
        if (r_take(&r, p->follow,   sizeof(p->follow))   != 0) goto bad;
        if (r_take(&r, p->byte_pos, sizeof(p->byte_pos)) != 0) goto bad;

        if (r_take(&r, &p->min_len, 4) != 0) goto bad;
        if (r_take(&r, &p->max_len, 4) != 0) goto bad;

        uint32_t slen, id;
        if (r_take(&r, &slen, 4) != 0) goto bad;
        const uint8_t *src_ref = NULL;
        if (slen) {
            if (r_skip_ref(&r, slen, &src_ref) != 0) goto bad;
            p->source = (char *)malloc(slen + 1);
            if (!p->source) goto bad;
            memcpy(p->source, src_ref, slen);
            p->source[slen] = '\0';
        }
        if (r_take(&r, &id, 4) != 0) goto bad;
        db->ids[i] = id;
    }

    if (r.pos != r.len) { ns_db_free(db); return NULL; }

    if (ns_db_build_prefilter(db) != 0) { ns_db_free(db); return NULL; }
    return db;

bad:
    ns_db_free(db);
    return NULL;
}
