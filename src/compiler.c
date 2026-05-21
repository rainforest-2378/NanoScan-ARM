/*
 * Regex compiler: tokenize -> AST -> Glushkov bit-parallel NFA.
 *
 * Grammar (precedence low to high):
 *
 *   re      ::= ['^'] alt ['$']        ; '^' / '$' only at the very ends
 *   alt     ::= concat ('|' concat)*
 *   concat  ::= quant+
 *   quant   ::= atom suffix?
 *   suffix  ::= '?' | '*' | '+'
 *             | '{' n '}' | '{' n ',' '}' | '{' n ',' m '}'
 *   atom    ::= literal | '.' | '\' esc
 *             | '[' class ']' | '(' [?:]? alt ')'
 *
 * Quantifiers / classes / groups all expand into a bit-parallel Glushkov
 * NFA. NFA position width is configured by NS_MAX_POSITIONS in
 * nanoscan_internal.h. The state is held in NS_STATE_WORDS 64-bit words.
 *
 * Reverse references are NOT supported. SOM is computed exactly by the
 * scanner via a per-position start-offset table.
 */
#include "nanoscan_internal.h"

#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INF_LEN ((uint32_t)0xFFFFFFFFu)

static void set_err(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* ------------------------- byte-set helpers ------------------------- */

typedef uint8_t byteset_t[32];

static void bs_clear(byteset_t bs) { memset(bs, 0, 32); }
static void bs_set(byteset_t bs, int b) { bs[(b >> 3) & 31] |= (uint8_t)(1u << (b & 7)); }
static int  bs_get(const byteset_t bs, int b) {
    return (bs[(b >> 3) & 31] >> (b & 7)) & 1;
}
static void bs_negate(byteset_t bs) { for (int i = 0; i < 32; i++) bs[i] = (uint8_t)~bs[i]; }
static int  bs_popcount(const byteset_t bs) {
    int n = 0;
    for (int b = 0; b < 256; b++) if (bs_get(bs, b)) n++;
    return n;
}
static int  bs_first(const byteset_t bs) {
    for (int b = 0; b < 256; b++) if (bs_get(bs, b)) return b;
    return -1;
}
static void bs_set_range(byteset_t bs, int lo, int hi) {
    if (lo < 0) lo = 0;
    if (hi > 255) hi = 255;
    for (int b = lo; b <= hi; b++) bs_set(bs, b);
}
static void bs_apply_caseless(byteset_t bs) {
    for (int b = 'a'; b <= 'z'; b++) {
        int U = b - 'a' + 'A';
        if (bs_get(bs, b)) bs_set(bs, U);
        if (bs_get(bs, U)) bs_set(bs, b);
    }
}

static void bs_class_d(byteset_t bs) { bs_clear(bs); bs_set_range(bs, '0', '9'); }
static void bs_class_w(byteset_t bs) {
    bs_clear(bs);
    bs_set_range(bs, '0', '9');
    bs_set_range(bs, 'A', 'Z');
    bs_set_range(bs, 'a', 'z');
    bs_set(bs, '_');
}
static void bs_class_s(byteset_t bs) {
    bs_clear(bs);
    static const char ws[] = " \t\n\r\f\v";
    for (size_t i = 0; ws[i]; i++) bs_set(bs, (uint8_t)ws[i]);
}

/* ----------------------------- AST ----------------------------- */

typedef enum {
    N_ATOM,
    N_CONCAT,
    N_ALT,
    N_QUEST,
    N_STAR,
    N_PLUS,
    N_EMPTY
} node_kind;

typedef struct node {
    node_kind     kind;
    struct node  *a;
    struct node  *b;
    byteset_t     bs;     /* atoms only */
    int           pos;    /* atoms only, assigned post-expansion */
} node_t;

static node_t *node_new(node_kind k) {
    node_t *n = (node_t *)calloc(1, sizeof(*n));
    if (n) n->kind = k;
    return n;
}
static void node_free(node_t *n) {
    if (!n) return;
    node_free(n->a);
    node_free(n->b);
    free(n);
}
static node_t *node_atom(const byteset_t bs) {
    node_t *n = node_new(N_ATOM);
    if (!n) return NULL;
    memcpy(n->bs, bs, 32);
    return n;
}
static node_t *node_unary(node_kind k, node_t *c) {
    node_t *n = node_new(k);
    if (!n) { node_free(c); return NULL; }
    n->a = c;
    return n;
}
static node_t *node_binary(node_kind k, node_t *l, node_t *r) {
    if (!l) return r;
    if (!r) return l;
    node_t *n = node_new(k);
    if (!n) { node_free(l); node_free(r); return NULL; }
    n->a = l; n->b = r;
    return n;
}
static node_t *clone_ast(const node_t *n) {
    if (!n) return NULL;
    node_t *c = node_new(n->kind);
    if (!c) return NULL;
    memcpy(c->bs, n->bs, 32);
    c->pos = 0;
    if (n->a) {
        c->a = clone_ast(n->a);
        if (!c->a) { node_free(c); return NULL; }
    }
    if (n->b) {
        c->b = clone_ast(n->b);
        if (!c->b) { node_free(c); return NULL; }
    }
    return c;
}

static node_t *repeat_range(node_t *body, int n, int m, char *err, size_t err_cap) {
    if (n < 0) n = 0;
    if (m >= 0 && m < n) {
        set_err(err, err_cap, "invalid {n,m}: m < n");
        node_free(body);
        return NULL;
    }
    if (n > NS_MAX_QUANT_REPEAT || (m >= 0 && m > NS_MAX_QUANT_REPEAT)) {
        set_err(err, err_cap,
                "quantifier count exceeds limit of %d", NS_MAX_QUANT_REPEAT);
        node_free(body);
        return NULL;
    }

    node_t *result = NULL;
    for (int k = 0; k < n; k++) {
        node_t *c = clone_ast(body);
        if (!c) goto oom;
        result = node_binary(N_CONCAT, result, c);
        if (!result) goto oom;
    }
    if (m < 0) {
        node_t *c = clone_ast(body);
        if (!c) goto oom;
        node_t *star = node_unary(N_STAR, c);
        if (!star) goto oom;
        result = node_binary(N_CONCAT, result, star);
        if (!result) goto oom;
    } else {
        for (int k = n; k < m; k++) {
            node_t *c = clone_ast(body);
            if (!c) goto oom;
            node_t *opt = node_unary(N_QUEST, c);
            if (!opt) goto oom;
            result = node_binary(N_CONCAT, result, opt);
            if (!result) goto oom;
        }
    }
    if (!result) result = node_new(N_EMPTY);
    node_free(body);
    return result;
oom:
    node_free(body);
    node_free(result);
    set_err(err, err_cap, "out of memory expanding quantifier");
    return NULL;
}

/* ----------------------------- parser ----------------------------- */

typedef struct {
    const char  *re;
    size_t       i;
    size_t       n;
    unsigned int flags;
    char        *err;
    size_t       err_cap;
} parser_t;

static node_t *parse_alt(parser_t *p);

static int parse_escape(parser_t *p, byteset_t out) {
    if (p->i >= p->n) {
        set_err(p->err, p->err_cap, "trailing '\\' at end of pattern");
        return 0;
    }
    char e = p->re[p->i++];
    bs_clear(out);
    switch (e) {
        case 'n':  bs_set(out, '\n'); return 1;
        case 'r':  bs_set(out, '\r'); return 1;
        case 't':  bs_set(out, '\t'); return 1;
        case 'f':  bs_set(out, '\f'); return 1;
        case 'v':  bs_set(out, '\v'); return 1;
        case '0':  bs_set(out, '\0'); return 1;
        case 'd':  bs_class_d(out);   return 1;
        case 'D':  bs_class_d(out); bs_negate(out); return 1;
        case 'w':  bs_class_w(out);   return 1;
        case 'W':  bs_class_w(out); bs_negate(out); return 1;
        case 's':  bs_class_s(out);   return 1;
        case 'S':  bs_class_s(out); bs_negate(out); return 1;
        case '\\': case '.': case '|': case '^': case '$':
        case '(': case ')': case '[': case ']':
        case '{': case '}': case '?': case '*': case '+': case '-':
        case '/':
            bs_set(out, (uint8_t)e);
            return 1;
        default:
            set_err(p->err, p->err_cap,
                    "unsupported escape '\\%c'", e);
            return 0;
    }
}

static node_t *parse_class(parser_t *p) {
    int negate = 0;
    if (p->i < p->n && p->re[p->i] == '^') { negate = 1; p->i++; }
    byteset_t bs; bs_clear(bs);
    if (p->i < p->n && p->re[p->i] == ']') {
        set_err(p->err, p->err_cap, "empty character class");
        return NULL;
    }

    while (p->i < p->n && p->re[p->i] != ']') {
        byteset_t one; bs_clear(one);
        int lo = -1;

        if (p->re[p->i] == '\\') {
            p->i++;
            if (!parse_escape(p, one)) return NULL;
            if (bs_popcount(one) == 1) lo = bs_first(one);
        } else {
            lo = (uint8_t)p->re[p->i++];
            bs_set(one, lo);
        }

        if (lo >= 0 && p->i + 1 < p->n &&
            p->re[p->i] == '-' && p->re[p->i + 1] != ']') {
            p->i++;
            int hi;
            byteset_t two; bs_clear(two);
            if (p->re[p->i] == '\\') {
                p->i++;
                if (!parse_escape(p, two)) return NULL;
                if (bs_popcount(two) != 1) {
                    set_err(p->err, p->err_cap,
                            "range endpoint must be a single character");
                    return NULL;
                }
                hi = bs_first(two);
            } else {
                hi = (uint8_t)p->re[p->i++];
            }
            if (hi < lo) {
                set_err(p->err, p->err_cap, "range out of order: %d-%d", lo, hi);
                return NULL;
            }
            for (int b = lo; b <= hi; b++) bs_set(bs, b);
        } else {
            for (int b = 0; b < 256; b++) if (bs_get(one, b)) bs_set(bs, b);
        }
    }

    if (p->i >= p->n || p->re[p->i] != ']') {
        set_err(p->err, p->err_cap, "unterminated character class");
        return NULL;
    }
    p->i++;

    if (negate) bs_negate(bs);
    if (p->flags & NS_FLAG_CASELESS) bs_apply_caseless(bs);
    return node_atom(bs);
}

static node_t *parse_atom(parser_t *p) {
    if (p->i >= p->n) {
        set_err(p->err, p->err_cap, "unexpected end of pattern");
        return NULL;
    }
    char c = p->re[p->i];

    if (c == '(') {
        p->i++;
        if (p->i + 1 < p->n && p->re[p->i] == '?' && p->re[p->i + 1] == ':') {
            p->i += 2;
        }
        node_t *inner = parse_alt(p);
        if (!inner) return NULL;
        if (p->i >= p->n || p->re[p->i] != ')') {
            set_err(p->err, p->err_cap, "missing ')'");
            node_free(inner);
            return NULL;
        }
        p->i++;
        return inner;
    }
    if (c == '[') {
        p->i++;
        return parse_class(p);
    }
    if (c == '.') {
        p->i++;
        byteset_t bs; bs_clear(bs);
        for (int b = 0; b < 256; b++) bs_set(bs, b);
        if (!(p->flags & NS_FLAG_DOTALL)) {
            bs[('\n' >> 3) & 31] &= (uint8_t)~(1u << ('\n' & 7));
        }
        return node_atom(bs);
    }
    if (c == '\\') {
        p->i++;
        byteset_t bs;
        if (!parse_escape(p, bs)) return NULL;
        if (p->flags & NS_FLAG_CASELESS) bs_apply_caseless(bs);
        return node_atom(bs);
    }
    if (c == '|' || c == ')' || c == ']' || c == '}' ||
        c == '?' || c == '*' || c == '+' || c == '{' ||
        c == '^' || c == '$') {
        set_err(p->err, p->err_cap,
                "unexpected '%c' at offset %zu", c, p->i);
        return NULL;
    }
    p->i++;
    byteset_t bs; bs_clear(bs);
    bs_set(bs, (uint8_t)c);
    if (p->flags & NS_FLAG_CASELESS) bs_apply_caseless(bs);
    return node_atom(bs);
}

static node_t *parse_quant(parser_t *p) {
    node_t *a = parse_atom(p);
    if (!a) return NULL;
    if (p->i >= p->n) return a;
    char c = p->re[p->i];
    if (c == '?') { p->i++; return node_unary(N_QUEST, a); }
    if (c == '*') { p->i++; return node_unary(N_STAR,  a); }
    if (c == '+') { p->i++; return node_unary(N_PLUS,  a); }
    if (c == '{') {
        size_t save = p->i;
        p->i++;
        int n = 0, m = -1;
        if (p->i >= p->n || !isdigit((unsigned char)p->re[p->i])) {
            p->i = save;
            return a;
        }
        while (p->i < p->n && isdigit((unsigned char)p->re[p->i]))
            n = n * 10 + (p->re[p->i++] - '0');
        if (p->i < p->n && p->re[p->i] == ',') {
            p->i++;
            if (p->i < p->n && isdigit((unsigned char)p->re[p->i])) {
                m = 0;
                while (p->i < p->n && isdigit((unsigned char)p->re[p->i]))
                    m = m * 10 + (p->re[p->i++] - '0');
            }
        } else {
            m = n;
        }
        if (p->i >= p->n || p->re[p->i] != '}') {
            set_err(p->err, p->err_cap, "expected '}' to close quantifier");
            node_free(a);
            return NULL;
        }
        p->i++;
        return repeat_range(a, n, m, p->err, p->err_cap);
    }
    return a;
}

static node_t *parse_concat(parser_t *p) {
    node_t *r = NULL;
    while (p->i < p->n && p->re[p->i] != '|' && p->re[p->i] != ')') {
        node_t *q = parse_quant(p);
        if (!q) { node_free(r); return NULL; }
        r = node_binary(N_CONCAT, r, q);
        if (!r) return NULL;
    }
    if (!r) r = node_new(N_EMPTY);
    return r;
}

static node_t *parse_alt(parser_t *p) {
    node_t *l = parse_concat(p);
    if (!l) return NULL;
    while (p->i < p->n && p->re[p->i] == '|') {
        p->i++;
        node_t *r = parse_concat(p);
        if (!r) { node_free(l); return NULL; }
        l = node_binary(N_ALT, l, r);
        if (!l) return NULL;
    }
    return l;
}

/* --------------------------- Glushkov NFA --------------------------- */

typedef struct {
    int        nullable;
    ns_state_t first;
    ns_state_t last;
    uint32_t   min_len;
    uint32_t   max_len;
} gl_t;

static uint32_t add_sat(uint32_t a, uint32_t b) {
    if (a == INF_LEN || b == INF_LEN) return INF_LEN;
    uint64_t s = (uint64_t)a + b;
    return s > INF_LEN - 1 ? INF_LEN : (uint32_t)s;
}
static uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t max_u32(uint32_t a, uint32_t b) {
    if (a == INF_LEN || b == INF_LEN) return INF_LEN;
    return a > b ? a : b;
}

static int assign_positions(node_t *n, node_t **pos_nodes, int *next,
                            char *err, size_t err_cap) {
    if (!n) return 0;
    if (n->kind == N_ATOM) {
        if (*next >= NS_MAX_POSITIONS) {
            set_err(err, err_cap,
                    "pattern exceeds %d NFA positions after expansion",
                    NS_MAX_POSITIONS);
            return -1;
        }
        n->pos = *next;
        pos_nodes[(*next)++] = n;
        return 0;
    }
    if (assign_positions(n->a, pos_nodes, next, err, err_cap) != 0) return -1;
    if (assign_positions(n->b, pos_nodes, next, err, err_cap) != 0) return -1;
    return 0;
}

static gl_t glushkov(node_t *n, ns_state_t *follow) {
    gl_t r;
    r.nullable = 1;
    ns_state_zero(r.first);
    ns_state_zero(r.last);
    r.min_len = 0;
    r.max_len = 0;
    if (!n) return r;

    switch (n->kind) {
        case N_EMPTY:
            return r;
        case N_ATOM: {
            r.nullable = 0;
            ns_state_setb(r.first, n->pos);
            ns_state_setb(r.last,  n->pos);
            r.min_len = 1;
            r.max_len = 1;
            return r;
        }
        case N_CONCAT: {
            gl_t A = glushkov(n->a, follow);
            gl_t B = glushkov(n->b, follow);
            NS_STATE_FOREACH(A.last, j, {
                ns_state_or(follow[j], B.first);
            });
            r.nullable = A.nullable && B.nullable;
            ns_state_copy(r.first, A.first);
            if (A.nullable) ns_state_or(r.first, B.first);
            ns_state_copy(r.last, B.last);
            if (B.nullable) ns_state_or(r.last, A.last);
            r.min_len = add_sat(A.min_len, B.min_len);
            r.max_len = add_sat(A.max_len, B.max_len);
            return r;
        }
        case N_ALT: {
            gl_t A = glushkov(n->a, follow);
            gl_t B = glushkov(n->b, follow);
            r.nullable = A.nullable || B.nullable;
            ns_state_copy(r.first, A.first);
            ns_state_or  (r.first, B.first);
            ns_state_copy(r.last,  A.last);
            ns_state_or  (r.last,  B.last);
            r.min_len = min_u32(A.min_len, B.min_len);
            r.max_len = max_u32(A.max_len, B.max_len);
            return r;
        }
        case N_QUEST: {
            gl_t C = glushkov(n->a, follow);
            r.nullable = 1;
            ns_state_copy(r.first, C.first);
            ns_state_copy(r.last,  C.last);
            r.min_len = 0;
            r.max_len = C.max_len;
            return r;
        }
        case N_STAR: {
            gl_t C = glushkov(n->a, follow);
            NS_STATE_FOREACH(C.last, j, {
                ns_state_or(follow[j], C.first);
            });
            r.nullable = 1;
            ns_state_copy(r.first, C.first);
            ns_state_copy(r.last,  C.last);
            r.min_len = 0;
            r.max_len = INF_LEN;
            return r;
        }
        case N_PLUS: {
            gl_t C = glushkov(n->a, follow);
            NS_STATE_FOREACH(C.last, j, {
                ns_state_or(follow[j], C.first);
            });
            r.nullable = C.nullable;
            ns_state_copy(r.first, C.first);
            ns_state_copy(r.last,  C.last);
            r.min_len = C.min_len;
            r.max_len = INF_LEN;
            return r;
        }
    }
    return r;
}

/* --------------------------- entry point --------------------------- */

ns_pattern_t *ns_compile(const char *re, unsigned int flags,
                         char *err, size_t err_cap) {
    if (err && err_cap > 0) err[0] = '\0';
    if (!re) {
        set_err(err, err_cap, "expression must not be NULL");
        return NULL;
    }

    size_t n = strlen(re);
    uint8_t anc_start = 0, anc_end = 0;
    size_t lo = 0, hi = n;

    if (hi > lo && re[lo] == '^') { anc_start = 1; lo++; }
    if (hi > lo && re[hi - 1] == '$' &&
        (hi - 1 == 0 || re[hi - 2] != '\\')) {
        anc_end = 1;
        hi--;
    }

    parser_t pr = { re + lo, 0, hi - lo, flags, err, err_cap };
    node_t *ast = parse_alt(&pr);
    if (!ast) return NULL;
    if (pr.i != pr.n) {
        set_err(err, err_cap, "trailing input at offset %zu", lo + pr.i);
        node_free(ast);
        return NULL;
    }

    node_t **pos_nodes = (node_t **)calloc(NS_MAX_POSITIONS, sizeof(node_t *));
    if (!pos_nodes) { node_free(ast); set_err(err, err_cap, "out of memory"); return NULL; }
    int next = 0;
    if (assign_positions(ast, pos_nodes, &next, err, err_cap) != 0) {
        free(pos_nodes);
        node_free(ast);
        return NULL;
    }
    if (next == 0) {
        if (!(flags & NS_FLAG_ALLOWEMPTY)) {
            set_err(err, err_cap,
                    "empty pattern (set HS_FLAG_ALLOWEMPTY to permit)");
        } else {
            set_err(err, err_cap, "empty patterns are accepted but never match");
        }
        free(pos_nodes);
        node_free(ast);
        return NULL;
    }

    ns_pattern_t *p = (ns_pattern_t *)calloc(1, sizeof(*p));
    if (!p) {
        free(pos_nodes);
        node_free(ast);
        set_err(err, err_cap, "out of memory");
        return NULL;
    }

    /* Allocate follow on the heap once -- it's NS_MAX_POSITIONS * NS_STATE_WORDS
     * u64 entries, fits on a 64KiB stack but cleaner this way. */
    ns_state_t *follow = (ns_state_t *)calloc(NS_MAX_POSITIONS, sizeof(ns_state_t));
    if (!follow) {
        free(p); free(pos_nodes); node_free(ast);
        set_err(err, err_cap, "out of memory");
        return NULL;
    }

    gl_t g = glushkov(ast, follow);

    p->flags = flags;
    p->anchor_start = anc_start;
    p->anchor_end   = anc_end;
    p->n_pos        = (uint16_t)next;
    ns_state_copy(p->initial, g.first);
    ns_state_copy(p->accept,  g.last);
    for (int i = 0; i < next; i++) ns_state_copy(p->follow[i], follow[i]);
    p->min_len      = g.min_len;
    p->max_len      = g.max_len;

    free(follow);

    if (g.nullable && g.min_len == 0) {
        set_err(err, err_cap,
                "pattern matches the empty string; refuse to compile");
        free(p); free(pos_nodes); node_free(ast);
        return NULL;
    }

    /* Build byte_pos[c] from each atom's byte set. */
    for (int i = 0; i < next; i++) {
        node_t *atom = pos_nodes[i];
        for (int c = 0; c < 256; c++) {
            if (bs_get(atom->bs, c)) ns_state_setb(p->byte_pos[c], i);
        }
    }

    p->source = (char *)malloc(n + 1);
    if (!p->source) {
        free(p); free(pos_nodes); node_free(ast);
        set_err(err, err_cap, "oom");
        return NULL;
    }
    memcpy(p->source, re, n + 1);

    free(pos_nodes);
    node_free(ast);
    return p;
}

void ns_free(ns_pattern_t *p) {
    if (!p) return;
    free(p->source);
    free(p);
}
