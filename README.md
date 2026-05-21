# NanoScan-ARM

A tiny, portable, **block-mode** multi-pattern matcher with a
**Hyperscan-compatible C API**. Drop-in replacement target for projects
that link against `hs.h` / `libhs.a` (Unix) or `hs.lib` (Windows MSVC)
and only ever use the block-mode subset.

> 中文：`NanoScan-ARM` 是一个极简、可移植的多模式字符串匹配引擎，提供与
> Intel Hyperscan 公开 C API **接口兼容**的子集（仅 block 模式）。目标是让
> 业务代码"不改一行"就能在 **ARM/x86 + Linux/macOS/Windows ARM64** 上跑。

## What you get

- A single static library, emitted under **both** `libnanoscan.a` and
  `libhs.a` (Windows: `nanoscan.lib` / `hs.lib`). Identical archive,
  two file names.
- Public headers: `<hs/hs.h>`, `"hs.h"`, `"hs_compat.h"` — all equivalent.
- Block-mode `hs_compile_multi` / `hs_alloc_scratch` / `hs_scan` /
  `hs_free_*` with the original calling conventions.
- Honoured per-pattern flags: `HS_FLAG_CASELESS`, `HS_FLAG_DOTALL`,
  `HS_FLAG_SINGLEMATCH`, `HS_FLAG_MULTILINE` (no-op, accepted).
- Callback termination returns `HS_SCAN_TERMINATED`, matching upstream.
- Matches reported in **end-offset order** across the whole database.
- Serialization: `hs_serialize_database` / `hs_deserialize_database`
  with a versioned wire format (`"NHS\0"` v3).
- Unsupported flags / modes / regex constructs produce
  `HS_COMPILER_ERROR` / `HS_DB_MODE_ERROR` with a readable message —
  never silently ignored.

## Supported regex grammar

PCRE subset, parsed into a **bit-parallel Glushkov NFA** (≤ 256 atoms
per pattern, state held in 4×64-bit words):

      re     ::= ['^'] alt ['$']           ; '^' / '$' only at extreme ends
      alt    ::= concat ('|' concat)*
      concat ::= quant*
      quant  ::= atom ('?' | '*' | '+' | '{' n [',' [m]] '}')?
      atom   ::= literal-byte
               | '.'                       ; any byte; non-'\n' by default,
                                             any byte with HS_FLAG_DOTALL
               | '[' '^'? class-item+ ']'  ; ranges + escapes inside
               | '(' alt ')'               ; non-capturing
               | '\' escape

Escapes: `\n \r \t \f \v \0`, predefined classes `\d \D \w \W \s \S`,
and literal-escape for `. \\ | ^ $ ( ) [ ] { } ? * + - /`.

What's NOT supported (and fails loudly at compile time):

- Streaming and vectored modes (`HS_MODE_STREAM`, `HS_MODE_VECTORED`).
- Backreferences, lookaround, named groups, possessive quantifiers,
  Unicode property escapes, `\b` word boundary.
- `HS_FLAG_UTF8 / UCP / PREFILTER / SOM_LEFTMOST` (rejected).
- Compiled NFA wider than **256 positions** or `{n,m}` expansions
  beyond 128 atoms.

If you need any of the above, keep using upstream Hyperscan. This
project covers the common case: "compile a handful of regexes or
literals and scan a buffer fast".

## Build

### POSIX (Linux / macOS, x86_64 or ARM64)

```bash
make           # libnanoscan.a, libhs.a, demos, tests
make test      # runs all tests
```

### CMake (cross-platform; recommended for Windows)

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### Windows ARM64 (MSVC)

From a *Developer Command Prompt for VS*:

```bat
cmake -S . -B build -A ARM64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

### Visual Studio 2019 exact commands

If you are using VS 2019 specifically (generator `Visual Studio 16 2019`),
use one of these:

```bat
:: ARM64
cmake -S . -B build-vs2019-arm64 -G "Visual Studio 16 2019" -A ARM64 && cmake --build build-vs2019-arm64 --config Release && ctest --test-dir build-vs2019-arm64 -C Release --output-on-failure

:: x64
cmake -S . -B build-vs2019-x64 -G "Visual Studio 16 2019" -A x64 && cmake --build build-vs2019-x64 --config Release && ctest --test-dir build-vs2019-x64 -C Release --output-on-failure
```

Produces `build\Release\nanoscan.lib` and `build\Release\hs.lib`.

`-march=native` is **off by default** for portability. Enable with
`cmake -DNANOSCAN_NATIVE=ON ...` (GCC/Clang only) when you control the
deploy target.

## Drop-in usage from existing Hyperscan code

```c
#include <hs/hs.h>      // or "hs.h"

const char *pats[]  = { "arm",   "a.m",   "\\d{3}" };
unsigned    flags[] = { HS_FLAG_CASELESS, 0, 0 };
unsigned    ids[]   = { 1, 2, 3 };

hs_database_t *db = NULL;
hs_compile_error_t *err = NULL;
hs_compile_multi(pats, flags, ids, 3, HS_MODE_BLOCK, NULL, &db, &err);

hs_scratch_t *sc = NULL;
hs_alloc_scratch(db, &sc);

hs_scan(db, buf, (unsigned)len, 0, sc, on_event, ctx);

hs_free_scratch(sc);
hs_free_database(db);
```

In your build:

1. Add `include/` to your include path.
2. Replace `-lhyperscan` with `-lhs` (Unix) or link `hs.lib` (Windows).

## Project layout

```
include/hs/hs.h     # canonical public API (Hyperscan subset)
include/hs.h        # convenience forward
include/hs_compat.h # back-compat forward
include/nanoscan.h  # native (ns_*) API
src/compiler.c      # regex parser + Glushkov NFA builder
src/multi_scan.c    # multi-pattern NFA scanner + literal prefilter
src/serialize.c     # versioned database serializer (v2)
src/shift_and.c     # standalone Shift-And helper (literals, teaching)
src/hs_compat.c     # hs_* -> ns_* bridge
src/nanoscan_internal.h
tests/              # ctest-driven correctness + differential tests
examples/           # minimal demos for both APIs
```

## How the engine works (1-minute version)

Each pattern compiles into a **bit-parallel Glushkov NFA** held in a
fixed-size bitset of 4×`uint64_t` (up to 256 positions):

- Position `j` is set in `state` iff the NFA can be at atom `j` after
  consuming the input prefix.
- `byte_pos[c]` holds the bitmask of positions whose atom accepts byte
  `c` (handles literals, `.`, character classes, `\d \w \s` …).
- `follow[j]` holds the bitmask of positions reachable in one step from
  `j`, precomputed via Glushkov's construction from the parse tree.
- Each step: `reach = ⋃ follow[j∈state] | initial; state = reach & byte_pos[c]`.
  A match ends here iff `state & accept`.
- Start-of-match is tracked per active position with a parallel
  `uint32_t start[64]`, so SOM is exact and leftmost.

The multi-pattern scanner first runs a **fixed-length end-byte
prefilter** (memcmp for pure literals) before falling back to the NFA
for the variable-length tail, so common deployments where most patterns
are literal-ish keep Shift-And-class throughput.

## Licence

MIT. See [LICENCE](LICENCE).
