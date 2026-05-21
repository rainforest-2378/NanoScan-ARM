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

    /* Large NFA: pattern with ~80 positions to exercise multi-word state.
     * "a{80}b" expands to 80 'a' atoms + one 'b' = 81 positions. */
    { hit_t w[] = {
        {7,0,81}, {7,0,82}, {7,0,83}, {7,0,84}
      };
      char text[200];
      for (int i = 0; i < 84; i++) text[i] = 'a';
      text[80] = 'b';  /* 80 a's then b at position 80..80, so match (0,81) */
      /* Actually want one clean match: 80 a's + b. Build deterministic
       * input: 80 a's, then 'b'. Expect exactly one hit (0,81). */
      memset(text, 'a', 80);
      text[80] = 'b';
      text[81] = '\0';
      hit_t w1[] = { {7,0,81} };
      (void)w;
      if (run("a{80}b", 0, text, w1, 1, "big_quant_80")) return 1; }

    /* Even larger: 120 'a' atoms via class to push past the old 64 limit
     * and well into the second state word. */
    { char text[160];
      memset(text, 'a', 120);
      text[120] = 'X';
      text[121] = '\0';
      hit_t w1[] = { {7,0,121} };
      if (run("[abc]{120}X", 0, text, w1, 1, "big_class_120")) return 1; }

    printf("[PASS] hs_regex\n");
    return 0;
}
