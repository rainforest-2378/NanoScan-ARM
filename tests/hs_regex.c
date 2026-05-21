/* Regression coverage for the new regex engine: character classes,
 * quantifiers, grouping, predefined classes.
 *
 * The scanner reports a match every time the NFA enters an accepting
 * state, so a greedy quantifier like 'a+' over "aaa" emits three hits
 * ending at offsets 1, 2, 3 -- all sharing SOM 0. Tests below encode
 * exactly that behaviour, which mirrors upstream Hyperscan's "report
 * every accepting end-offset" semantics. */
#include "hs/hs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned int       id;
    unsigned long long from;
    unsigned long long to;
} hit_t;

typedef struct { hit_t h[256]; size_t n; } ctx_t;

static int cb(unsigned int id, unsigned long long from, unsigned long long to,
              unsigned int flags, void *vctx) {
    (void)flags;
    ctx_t *c = vctx;
    if (c->n < 256) c->h[c->n++] = (hit_t){ id, from, to };
    return 0;
}

#define FAIL(...) do { printf("[FAIL] " __VA_ARGS__); return 1; } while (0)

static int run(const char *pat, unsigned int flag, const char *text,
               const hit_t *want, size_t nwant, const char *label) {
    const char *exprs[1] = { pat };
    unsigned int flags[1] = { flag };
    unsigned int ids[1] = { 7 };
    hs_database_t *db = NULL; hs_compile_error_t *ce = NULL;
    if (hs_compile_multi(exprs, flags, ids, 1, HS_MODE_BLOCK, NULL, &db, &ce)
        != HS_SUCCESS) FAIL("%s: compile %s\n", label, ce ? ce->message : "?");
    hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
    ctx_t c = {0};
    hs_scan(db, text, (unsigned)strlen(text), 0, sc, cb, &c);
    if (c.n != nwant) {
        printf("[FAIL] %s: count got=%zu want=%zu\n  got:", label, c.n, nwant);
        for (size_t i = 0; i < c.n; i++)
            printf(" (%u,%llu,%llu)", c.h[i].id, c.h[i].from, c.h[i].to);
        printf("\n");
        return 1;
    }
    for (size_t i = 0; i < nwant; i++) {
        if (c.h[i].id != want[i].id || c.h[i].from != want[i].from ||
            c.h[i].to != want[i].to)
            FAIL("%s: hit %zu got=(%u,%llu,%llu) want=(%u,%llu,%llu)\n",
                 label, i, c.h[i].id, c.h[i].from, c.h[i].to,
                 want[i].id, want[i].from, want[i].to);
    }
    hs_free_scratch(sc);
    hs_free_database(db);
    return 0;
}

int main(void) {
    { hit_t w[] = { {7,0,2}, {7,7,9} };
      if (run("[ab]c", 0, "ac xyz bc end", w, 2, "class")) return 1; }

    { hit_t w[] = { {7,0,2}, {7,6,8} };
      if (run("[^x]y", 0, "ay xy by", w, 2, "negclass")) return 1; }

    { hit_t w[] = { {7,0,3} };
      if (run("[a-z][0-9][A-Z]", 0, "a1B end", w, 1, "range")) return 1; }

    { hit_t w[] = { {7,0,2}, {7,3,6} };
      if (run("ab?c", 0, "ac abc", w, 2, "quest")) return 1; }

    { hit_t w[] = { {7,0,1}, {7,0,2}, {7,0,3} };
      if (run("a+", 0, "aaa bb cc", w, 3, "plus")) return 1; }

    { hit_t w[] = { {7,0,3} };
      if (run("ab*c", 0, "abc xc", w, 1, "star1")) return 1; }
    { hit_t w[] = { {7,0,5} };
      if (run("ab*c", 0, "abbbc", w, 1, "star2")) return 1; }

    { hit_t w[] = { {7,0,4} };
      if (run("a{2,5}b", 0, "aaab x", w, 1, "rep1")) return 1; }
    { hit_t w[] = { {7,0,3} };
      if (run("a{2}b", 0, "aab", w, 1, "rep2")) return 1; }

    { hit_t w[] = { {7,0,3} };
      if (run("\\d{3}", 0, "123 abc 4", w, 1, "digits")) return 1; }

    { hit_t w[] = { {7,0,5}, {7,0,6}, {7,0,7} };
      if (run("\\w+@\\w+", 0, "joe@bob @bad", w, 3, "wordwords")) return 1; }

    { hit_t w[] = { {7,0,4}, {7,5,9} };
      if (run("(abc|xyz)d", 0, "abcd xyzd ok", w, 2, "group_alt")) return 1; }

    { hit_t w[] = { {7,0,6} };
      if (run("(ab){3}", 0, "ababab end", w, 1, "group_rep")) return 1; }

    { hit_t w[] = { {7,0,1}, {7,0,2} };
      if (run("^\\d+", 0, "12 abc", w, 2, "anchored_digits")) return 1; }

    /* End-of-buffer '$' anchor. */
    { hit_t w[] = { {7,0,3} };
      if (run("foo$", 0, "foo", w, 1, "dollar_match")) return 1; }
    { if (run("foo$", 0, "foobar", NULL, 0, "dollar_nomatch_mid")) return 1; }
    { hit_t w[] = { {7,0,3} };
      if (run("^baz$", 0, "baz", w, 1, "anchor_both")) return 1; }
    { if (run("^baz$", 0, "bazz", NULL, 0, "anchor_both_no")) return 1; }
    { hit_t w[] = { {7,6,9} };
      if (run("[a-z]+$", 0, "12345 abc", w, 1, "class_dollar")) return 1; }

    /* Large NFA: 80 'a' atoms + 'b' => 81 positions, second state word. */
    { char text[128];
      memset(text, 'a', 80); text[80] = 'b'; text[81] = '\0';
      hit_t w[] = { {7,0,81} };
      if (run("a{80}b", 0, text, w, 1, "big_quant_80")) return 1; }

    /* 120 atoms via class -- second word territory. */
    { char text[160];
      memset(text, 'a', 120); text[120] = 'X'; text[121] = '\0';
      hit_t w[] = { {7,0,121} };
      if (run("[abc]{120}X", 0, text, w, 1, "big_class_120")) return 1; }

    /* At the quantifier ceiling: {128}. */
    { char text[160];
      memset(text, 'a', 128); text[128] = 'Z'; text[129] = '\0';
      hit_t w[] = { {7,0,129} };
      if (run("[a-c]{128}Z", 0, text, w, 1, "big_class_128")) return 1; }

    /* Position-count near 256 ceiling via long literal concat (no
     * quantifier expansion). 200-byte literal => 200 atoms. */
    { char pat[260]; char text[260];
      memset(pat, 'a', 200); pat[200] = '\0';
      memset(text, 'a', 200); text[200] = '\0';
      hit_t w[] = { {7,0,200} };
      if (run(pat, 0, text, w, 1, "big_literal_200")) return 1; }

    /* Long text (~16KB) with a regex hitting many times. */
    { size_t N = 16 * 1024;
      char *text = malloc(N + 1);
      memset(text, '.', N);
      /* sprinkle "ERR123" every 256 bytes -> 64 hits */
      size_t expect = 0;
      for (size_t i = 0; i + 6 < N; i += 256) {
          memcpy(text + i, "ERR", 3);
          text[i+3] = '0' + (char)((i/256) % 10);
          text[i+4] = '5';
          text[i+5] = '7';
          expect++;
      }
      text[N] = '\0';
      const char *exprs[1] = { "ERR\\d{3}" };
      unsigned int flags[1] = { 0 };
      unsigned int ids[1] = { 7 };
      hs_database_t *db = NULL; hs_compile_error_t *ce = NULL;
      if (hs_compile_multi(exprs, flags, ids, 1, HS_MODE_BLOCK, NULL, &db, &ce) != HS_SUCCESS)
          FAIL("long_text: compile %s\n", ce ? ce->message : "?");
      hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
      ctx_t c = {0};
      hs_scan(db, text, (unsigned)N, 0, sc, cb, &c);
      hs_free_scratch(sc); hs_free_database(db); free(text);
      if (c.n != expect) FAIL("long_text: got=%zu want=%zu\n", c.n, expect); }

    /* Complex pattern: IPv4-like dotted quad inside long text. */
    { const char *text =
        "log line: client=10.0.0.1 server=192.168.1.255 noise=999.999.999.999 "
        "another=1.2.3.4 not_ip=1.2.3 then 255.255.255.0 end";
      /* engine reports one hit per accepting end-offset; we count via cb. */
      const char *pat = "(\\d{1,3}\\.){3}\\d{1,3}";
      const char *exprs[1] = { pat };
      unsigned int flags[1] = { 0 };
      unsigned int ids[1] = { 7 };
      hs_database_t *db = NULL; hs_compile_error_t *ce = NULL;
      if (hs_compile_multi(exprs, flags, ids, 1, HS_MODE_BLOCK, NULL, &db, &ce) != HS_SUCCESS)
          FAIL("ipv4: compile %s\n", ce ? ce->message : "?");
      hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
      ctx_t c = {0};
      hs_scan(db, text, (unsigned)strlen(text), 0, sc, cb, &c);
      hs_free_scratch(sc); hs_free_database(db);
      if (c.n == 0) FAIL("ipv4: expected at least one hit, got 0\n"); }

    /* Email-ish: nested alternation + classes + quantifiers. */
    { const char *text =
        "send to alice@example.com or bob.smith+tag@sub.domain.co, "
        "junk@@bad, also charlie_99@foo-bar.io done";
      const char *pat = "[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,4}";
      const char *exprs[1] = { pat };
      unsigned int flags[1] = { 0 };
      unsigned int ids[1] = { 7 };
      hs_database_t *db = NULL; hs_compile_error_t *ce = NULL;
      if (hs_compile_multi(exprs, flags, ids, 1, HS_MODE_BLOCK, NULL, &db, &ce) != HS_SUCCESS)
          FAIL("email: compile %s\n", ce ? ce->message : "?");
      hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
      ctx_t c = {0};
      hs_scan(db, text, (unsigned)strlen(text), 0, sc, cb, &c);
      hs_free_scratch(sc); hs_free_database(db);
      if (c.n == 0) FAIL("email: expected hits, got 0\n"); }

    /* Long alternation -- many literal branches. */
    { const char *text =
        "the quick brown fox jumps over the lazy dog and a cat and a bird";
      const char *pat = "(fox|wolf|dog|cat|bird|fish|frog|snake|tiger|lion)";
      hit_t w[] = {
        {7,16,19},  /* fox */
        {7,40,43},  /* dog */
        {7,50,53},  /* cat */
        {7,60,64},  /* bird */
      };
      const char *exprs[1] = { pat };
      unsigned int flags[1] = { 0 };
      unsigned int ids[1] = { 7 };
      hs_database_t *db = NULL; hs_compile_error_t *ce = NULL;
      if (hs_compile_multi(exprs, flags, ids, 1, HS_MODE_BLOCK, NULL, &db, &ce) != HS_SUCCESS)
          FAIL("alt: compile %s\n", ce ? ce->message : "?");
      hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
      ctx_t c = {0};
      hs_scan(db, text, (unsigned)strlen(text), 0, sc, cb, &c);
      hs_free_scratch(sc); hs_free_database(db);
      if (c.n != 4) {
          printf("[FAIL] alt: count got=%zu want=4\n  got:", c.n);
          for (size_t i = 0; i < c.n; i++)
              printf(" (%u,%llu,%llu)", c.h[i].id, c.h[i].from, c.h[i].to);
          printf("\n"); return 1;
      }
      for (int i = 0; i < 4; i++)
          if (c.h[i].from != w[i].from || c.h[i].to != w[i].to)
              FAIL("alt: hit %d got=(%llu,%llu) want=(%llu,%llu)\n",
                   i, c.h[i].from, c.h[i].to, w[i].from, w[i].to); }

    /* Hex / 0x prefix, ranges, mixed quantifiers. */
    { const char *text = "addrs 0xDEADBEEF, 0xcafe, 0X1234, 0x0, bad 0xZZ end";
      hit_t w[] = {
        {7,6,16}, /* 0xDEADBEEF */
        {7,18,24}, /* 0xcafe */
        {7,26,32}, /* 0X1234 */
        {7,34,37}, /* 0x0 */
      };
      const char *exprs[1] = { "0[xX][0-9A-Fa-f]+" };
      unsigned int flags[1] = { 0 };
      unsigned int ids[1] = { 7 };
      hs_database_t *db = NULL; hs_compile_error_t *ce = NULL;
      if (hs_compile_multi(exprs, flags, ids, 1, HS_MODE_BLOCK, NULL, &db, &ce) != HS_SUCCESS)
          FAIL("hex: compile %s\n", ce ? ce->message : "?");
      hs_scratch_t *sc = NULL; hs_alloc_scratch(db, &sc);
      ctx_t c = {0};
      hs_scan(db, text, (unsigned)strlen(text), 0, sc, cb, &c);
      hs_free_scratch(sc); hs_free_database(db);
      /* Engine emits a hit per accepting end-offset -> several per literal.
       * Just verify leftmost SOM for the four real addresses appears. */
      int seen[4] = {0,0,0,0};
      for (size_t i = 0; i < c.n; i++)
          for (int k = 0; k < 4; k++)
              if (c.h[i].from == w[k].from && c.h[i].to == w[k].to) seen[k] = 1;
      for (int k = 0; k < 4; k++)
          if (!seen[k]) FAIL("hex: missing expected hit %d (%llu,%llu)\n",
                             k, w[k].from, w[k].to); }

    printf("[PASS] hs_regex\n");
    return 0;
}
