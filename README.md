# pathcage

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/pathcage/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/pathcage)

Zero-dependency path traversal, zip-slip and symlink-escape protection for Node.js.

`pathcage` is a small, auditable security library for any code that turns untrusted strings into filesystem paths: upload endpoints, archive extractors, static file servers, plugin loaders, MCP filesystem tools and agent sandboxes. It works on every platform, in both ESM and CommonJS, with strict TypeScript definitions and no runtime dependencies.

- **Zero dependencies.** Only `node:path` and `node:fs` are used at runtime.
- **Dual module.** Native ESM (`import`) and CommonJS (`require`) entry points, plus a strict `.d.ts`.
- **Containment by segments.** Never uses string prefixes, so `/app/uploads-evil` is not mistaken for a child of `/app/uploads`.
- **Real filesystem checks.** Resolves existing ancestors and every symlink hop, then verifies the result is inside the cage root.
- **Unicode aware.** Rejects compatibility lookalikes (fullwidth slashes and dots) that become separators under NFKC normalization, and bidirectional control characters used for filename spoofing.
- **Archive aware.** Validates archive entry paths, link targets, file counts, sizes, compression ratios and normalization-insensitive collisions.

**Tests:** 199 passing with `npm test` (Node 18+).

## Install

```sh
npm install pathcage
```

No install scripts, no native builds, no transitive dependencies.

## Quick start

### ESM

```js
import { createCage } from 'pathcage';

const cage = createCage('/srv/app/uploads');

app.post('/upload', async (req, res) => {
  const safe = cage.resolve(req.body.filename);
  // safe is an absolute path guaranteed to be lexically inside /srv/app/uploads
  await writeFile(safe, req.body.bytes);
});
```

### CommonJS

```js
const { createCage } = require('pathcage');

const cage = createCage('/srv/app/uploads', {
  allowSymlinksInsideRoot: false
});

const target = cage.assertInside(req.params.name);
```

## Core API

### `resolveSafePath(input, options)`

Returns an absolute path built from `options.root` and the relative `input`. Throws `PathCageError` on any violation.

```js
resolveSafePath('reports/q3.pdf', { root: '/srv/app/uploads' });
// => '/srv/app/uploads/reports/q3.pdf'

resolveSafePath('../../etc/passwd', { root: '/srv/app/uploads' });
// throws ERR_PATHCAGE_TRAVERSAL
```

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `root` | required | Absolute root directory. |
| `decodeCheck` | `false` | Decode up to eight percent-encoded layers and reject encoded traversal, separators, streams and invalid UTF-8 escapes. |
| `maxPathLength` | `4096` | Reject inputs longer than this. |

### `assertSafePath(input, options)`

Alias of `resolveSafePath`.

### `sanitizeFilename(input, options?)`

Reduces arbitrary text to a single flat filename safe on POSIX and Windows. Removes separators, control characters, bidirectional overrides, trailing dots and spaces, and neutralizes reserved device names. The input is compatibility normalized (NFKC) first, so a fullwidth slash can never become a separator after the call, and the fallback value is scrubbed exactly like the input.

```js
sanitizeFilename('../../CON.txt');        // => '_CON.txt'
sanitizeFilename('a/b/report?.txt');      // => 'report_.txt'
sanitizeFilename('file.txt:hidden');      // => 'file.txt_hidden'
sanitizeFilename('', { fallback: 'CON' });// => '_CON'
```

Options: `replacement` (default `'_'`), `fallback`, `maxLength` (default `255`), `decodeCheck`, `maxPathLength` (default `4096`).

### `validateArchiveEntry(entry, options?)`

Validates one archive entry before extraction. Accepts a path string or an object:

```js
{
  path: 'docs/readme.md',
  type: 'file' | 'directory' | 'symlink' | 'hardlink',
  size: 1048576,
  compressedSize: 32768,
  linkTarget: '../README.md'
}
```

Rejects absolute paths, parent traversal, encoded traversal, backslashes, drive letters, UNC paths, device names, null bytes, link entries pointing outside the archive, entries over `maxFileSize`, totals over `maxTotalSize`, counts over `maxFiles`, compression ratios over `maxCompressionRatio`, and collisions that are visible to case-insensitive or normalization-insensitive filesystems. Sizes must be non-negative safe integers, compressed sizes of zero on non-empty entries are treated as bombs, link targets are length capped, and trailing slashes are folded so `dir` and `dir/` collide.

### `createArchiveGuard(options?)`

Stateful wrapper around `validateArchiveEntry` that tracks cumulative limits and collisions across an entire archive.

```js
import { createArchiveGuard } from 'pathcage';

const guard = createArchiveGuard({
  maxFiles: 10000,
  maxFileSize: 10 * 1024 * 1024,
  maxTotalSize: 100 * 1024 * 1024,
  maxCompressionRatio: 100
});

for (const entry of archiveEntries) {
  const validated = guard.validate(entry);
  await extract(validated.path, entry);
}
```

Methods: `validate(entry)`, `validateBatch(entries)`, `stats()`, `reset()`.

### `createCage(rootDir, options?)`

Creates a cage bound to a root directory. Methods:

- `resolve(input)` lexically resolve an input underneath the root.
- `realpathCheck(candidate)` resolve and verify every existing path component and symlink hop. Absolute and relative candidates are held to the same symlink policy.
- `assertInside(candidate)` alias of `realpathCheck`.
- `validateBatch(inputs)` resolve a batch and reject duplicates or case-insensitive and Unicode-normalization collisions.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `noSymlinks` | `true` | Reject every symlink component. |
| `allowSymlinksInsideRoot` | `false` | When true, allow symlinks whose resolved target stays inside the root. |
| `caseInsensitive` | `true` | Detect colliding paths in `validateBatch`. |
| `mustExist` | `false` | Fail at creation if the root does not exist. |

### `PathCageError`

Every rejection throws a `PathCageError` with:

- `code`: a stable `ERR_PATHCAGE_*` string.
- `reason`: human-readable explanation.
- `input`: the original value that was rejected.
- `toJSON()`: serializable `{ name, code, reason, input }`.

## Framework examples

### Express static file route

```js
import express from 'express';
import { createCage } from 'pathcage';

const app = express();
const cage = createCage('/srv/app/public', { noSymlinks: true });

app.get('/files/*name', async (req, res) => {
  try {
    const file = cage.realpathCheck(req.params.name.join('/'));
    res.sendFile(file);
  } catch (error) {
    if (error.name === 'PathCageError') return res.status(400).json(error.toJSON());
    throw error;
  }
});
```

### Fastify upload

```js
import Fastify from 'fastify';
import { createCage, sanitizeFilename } from 'pathcage';

const app = Fastify();
const cage = createCage('/srv/app/uploads');

app.post('/upload', async (request, reply) => {
  const name = sanitizeFilename(request.body.name);
  const destination = cage.resolve(name);
  await writeFile(destination, request.body.bytes);
  return { ok: true };
});
```

### tar style extraction

```js
import { createArchiveGuard } from 'pathcage';

const guard = createArchiveGuard({
  maxCompressionRatio: 100,
  maxTotalSize: 50 * 1024 * 1024
});

for (const entry of tarEntries) {
  guard.validate({
    path: entry.name,
    type: entry.type,
    size: entry.size,
    compressedSize: entry.packedSize,
    linkTarget: entry.linkname
  });
  await extractEntry(entry);
}
```

### unzipper style extraction

```js
import { createArchiveGuard } from 'pathcage';

const guard = createArchiveGuard();

archive.on('entry', (entry) => {
  guard.validate({
    path: entry.path,
    type: entry.type === 'Directory' ? 'directory' : 'file',
    size: entry.uncompressedSize,
    compressedSize: entry.compressedSize
  });
  entry.pipe(destination());
});
```

### MCP filesystem tool

```js
import { createCage } from 'pathcage';

const cage = createCage(process.env.WORKSPACE_ROOT, {
  allowSymlinksInsideRoot: false,
  caseInsensitive: true
});

function readTool(args) {
  const absolute = cage.assertInside(args.path);
  return fs.readFileSync(absolute, 'utf8');
}
```

## Threat model

`pathcage` defends against:

- Classic and encoded traversal: `../`, `..\`, mixed slashes, `%2e%2e%2f`, up to eight encoding layers, and malformed percent escapes that would otherwise hide an encoded traversal.
- Absolute path injection and prefix confusion: `/app/uploads-evil` is not a child of `/app/uploads`.
- Null bytes, control characters, bidirectional overrides and isolates, trailing dots and spaces.
- Compatibility lookalikes that become separators, parent segments, device names or streams under Unicode NFKC normalization (for example fullwidth slashes and dots). Arbitrary homoglyphs that do not normalize into separators are not separators for any filesystem.
- Windows drive letters, drive-relative paths, UNC paths, extended-length prefixes (`\\?\`, `\\.\`), alternate data streams and reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9`, `LPT1` to `LPT9`).
- Real symlink escapes, including chained symlinks, absolute targets, directory symlinks, dangling links, links reached through a nonexistent tail, sibling-prefix escapes and symlink loops.
- Zip-slip and tar-slip entries, link entries escaping the archive, decompression bombs, unsafe integer sizes and collisions that case-insensitive or normalization-insensitive filesystems would merge.

`pathcage` does not:

- Open files or create directories for you. Validation and I/O are separate; always use the validated path.
- Prevent Time-of-Check to Time-of-Use races on a filesystem writable by an attacker. Use OS-level isolation for that.
- Inspect archive file contents. It validates metadata; your extractor still needs resource limits.
- Decide authorization. It answers one question only: is this path safe to use under this root?

## Security

See [SECURITY.md](SECURITY.md) for supported versions and responsible disclosure.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md).

## License

MIT. See [LICENSE](LICENSE).
