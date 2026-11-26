# Good first issues

Each item below is self-contained: one file or a small group of files, one behavior, one acceptance checklist. Comment on the issue to claim it, then open a pull request with the tests and the change together. All 15 items keep the library dependency free and work in both ESM and CJS.

## 1. Express static adapter

Add `src/adapters/express.mjs` and `cjs/adapters/express.cjs` exporting `cageStatic(rootDir, options)` that returns middleware calling `createCage().realpathCheck()` on the request path and forwarding `PathCageError` to `next()`.

Acceptance: rejects `../` and absolute paths with HTTP 400 (or via `next(error)`), serves a nested file, ships a test under `tests/adapters.test.mjs`, and does not import Express at runtime.

## 2. Fastify upload adapter

Add a `cageUpload(rootDir, options)` helper that sanitizes an uploaded filename with `sanitizeFilename()` and resolves it with `createCage().resolve()`.

Acceptance: rejects empty filenames when no fallback is set, neutralizes `CON.txt` and `..\evil.txt`, exposes both module formats, and has no Fastify dependency.

## 3. tar entry adapter

Add a mapper from tar entry metadata (`name`, `type`, `size`, `linkname`) to the `validateArchiveEntry` object shape, including type mapping for directory, file, symlink and hardlink.

Acceptance: maps GNU longname and PAX path fields when present, rejects an escaping `linkname`, and is covered by at least 8 cases.

## 4. unzipper entry adapter

Add a mapper from unzipper-style entry fields (`path`, `type`, `uncompressedSize`, `compressedSize`) to the archive guard, including the `Directory` type string.

Acceptance: correctly classifies directory entries, applies compressed size to the ratio check, and does not import unzipper.

## 5. MCP filesystem tool adapter

Add a helper that wraps a tool schema with `createCage().assertInside()` so every path argument is validated before file access.

Acceptance: rejects paths outside the configured workspace root, rejects symlinks by default, and includes an example in README.md.

## 6. Windows drive-relative paths

Audit and harden detection of drive-relative forms such as `C:foo`, `C:dir/file` and `C:$DATA`, ensuring all variants produce `ERR_PATHCAGE_WINDOWS_DRIVE` or `ERR_PATHCAGE_ALTERNATE_DATA_STREAM` consistently.

Acceptance: at least 10 new vector tests, correct code for each, and the documented code list is unchanged.

## 7. UNC and extended-prefix variants

Cover additional UNC and extended-length spellings: slash/backslash mixtures, `\\?\UNC\server\share`, `\\.\` device paths, and repeated slashes.

Acceptance: each variant is rejected with `WINDOWS_UNC` or `WINDOWS_PREFIX`, and sanitizeFilename neutralizes them into a flat name.

## 8. Percent-decoding layers

Extend `decodeCheck` to inspect up to three decoding layers and report the layer at which traversal appeared.

Acceptance: single, double and triple encoded `..` sequences are rejected, benign encoded characters such as `%20` are accepted, and the error reason names the offending layer.

## 9. Reserved device names on all platforms

Verify that `CON`, `PRN`, `AUX`, `NUL`, `COM1` through `COM9` and `LPT1` through `LPT9` are rejected with or without a single extension, while lookalikes such as `COM10` and `console.txt` remain valid.

Acceptance: full 26-name matrix in tests, one dedicated test for each boundary, and no regression for `con.txt.bak`.

## 10. Case-insensitive collision report

Enhance `validateBatch()` to return the colliding pair in `error.input` when duplicate paths differ only by case.

Acceptance: `README.md` plus `readme.md` reports both original strings, the collision is still `ERR_PATHCAGE_DUPLICATE_PATH`, and the tuple shape is documented in types/index.d.ts.

## 11. Archive hardlink containment

Add tests and hardening for hardlink entries whose target escapes the archive root, including absolute targets and `..` segments.

Acceptance: escaping targets produce `ERR_PATHCAGE_ARCHIVE_LINK`, internal hardlinks pass, and `allowHardlinks: true` still rejects escapes.

## 12. Decompression-bomb edge cases

Cover ratio checks with zero compressed size, zero uncompressed size, and a single very large entry near `maxFileSize`.

Acceptance: no division by zero, no integer overflow, correct code (`ARCHIVE_ZIP_BOMB` versus `ARCHIVE_LIMIT`) for each case, and at least 6 new tests.

## 13. TypeScript declaration tests

Add a compile-only test file that exercises every public API with the strict declarations.

Acceptance: `tsc --noEmit --strict` passes using only dev tooling, no dependency is added to `dependencies`, and the test is wired into CI without requiring a network install at runtime.

## 14. Symlink hop budget

Document and test the symlink hop limit in `createCage().realpathCheck()` for chains of 39, 40 and 41 links.

Acceptance: chains at or below the limit resolve or reject for containment reasons only, the 41st link fails predictably, and each test creates its links in a fresh `mkdtempSync` directory that is removed afterward.

## 15. Benchmark script

Add `bench/bench.mjs` that measures `resolveSafePath`, `sanitizeFilename`, `validateArchiveEntry` and `createCage().resolve` without external libraries.

Acceptance: uses only `node:perf_hooks`, prints median and p99, includes no personal paths or machine-specific configuration, and is documented in CONTRIBUTING.md as optional tooling.
