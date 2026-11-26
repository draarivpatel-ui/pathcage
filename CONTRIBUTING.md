# Contributing to pathcage

Thanks for helping make filesystem paths safer for everyone. This project is deliberately small and dependency free, so contributions are reviewed with an emphasis on correctness, clarity and auditability.

## Ground rules

- Zero runtime dependencies. Only `node:path` and `node:fs` may be imported from shipped code.
- No network calls, subprocesses or dynamic code evaluation in library code.
- Every behavior change needs a deterministic test. No sleeps, no network, no timing assumptions.
- Any test that touches the real filesystem must create its directory with `fs.mkdtempSync(path.join(os.tmpdir(), 'pathcage-...'))` and remove it in `afterEach` or `finally`.
- Keep ESM, CJS and the TypeScript definitions in sync. All three entry points expose the same API.
- Use ASCII punctuation in prose. No em dashes or en dashes.

## Development setup

No install step is required. The package has no dependencies.

```sh
node --version        # 18 or newer
npm test              # node --test tests/*.test.mjs
```

The suite has 167 tests covering traversal, Windows syntax, archives, symlinks, error metadata, ESM/CJS parity and vector matrices. A change is not done until all 167 pass.

## Project layout

```text
src/core.cjs          shared implementation, used by both module formats
src/index.mjs         ESM entry point (createRequire bridge to core.cjs)
cjs/index.cjs         CommonJS entry point
types/index.d.ts      strict TypeScript declarations
tests/*.test.mjs      node:test suites
tests/helpers.mjs     shared fixtures and assertion helpers
```

## How to propose a change

1. Open an issue describing the behavior or vulnerability you are addressing. For a security bug, follow SECURITY.md instead of opening a public issue.
2. Add a failing test first. Name it after the specific vector or behavior.
3. Make the smallest change that fixes it. Prefer explicit checks over clever regex composition.
4. Run `npm test` and report the exact count.
5. In your pull request, explain the attack scenario and why the fix generalizes beyond the single example.

## Commit and PR style

- Use plain, descriptive commit subjects (for example: `Reject drive-relative paths in archive entries`).
- Do not add badge edits, formatting churn or unrelated refactors to security fixes.
- If a change alters an error code or a public option, update README.md and types/index.d.ts in the same commit.

## Good first contributions

See GOOD_FIRST_ISSUES.md for 15 scoped, modular tasks. Each is independent and has an explicit acceptance checklist. Claim one by commenting on the corresponding issue before starting.

## Code of conduct

Be respectful and assume good intent. Review the code, not the person. Harassment of any kind is not welcome.
