import test from 'node:test';
import assert from 'node:assert/strict';
import { cjs, esm, throwsCode } from './helpers.mjs';

const C = cjs.CODE;

/* ------------------------- Zip-slip path matrix ------------------------- */

test('zip-slip: absolute and parent-traversal entry paths are rejected', () => {
  const vectors = [
    ['/etc/passwd', C.ARCHIVE_PATH],
    ['../evil.sh', C.TRAVERSAL],
    ['../../etc/passwd', C.TRAVERSAL],
    ['a/../../evil.sh', C.TRAVERSAL],
    ['a/..\\..\\evil.sh', C.BACKSLASH_SEPARATOR],
    ['C:\\Windows\\System32\\evil.dll', C.WINDOWS_DRIVE],
    ['\\\\server\\share\\evil.dll', C.WINDOWS_UNC]
  ];
  for (const [vector, code] of vectors) {
    throwsCode(() => cjs.validateArchiveEntry(vector), code, vector);
  }
});

test('zip-slip: rejected vectors always carry a PathCageError code', () => {
  for (const vector of ['../evil.sh', '/etc/passwd', 'a/../../evil.sh']) {
    let error;
    assert.throws(() => cjs.validateArchiveEntry(vector), (e) => {
      error = e;
      return true;
    });
    assert.equal(error.name, 'PathCageError');
    assert.ok(error.code.startsWith('ERR_PATHCAGE_'));
    assert.equal(error.input, vector);
    assert.ok(error.reason.length > 0);
  }
});

test('zip-slip: encoded traversal is rejected by default', () => {
  for (const vector of ['%2e%2e%2fevil.sh', 'a/%2e%2e/%2e%2e/evil.sh']) {
    throwsCode(() => cjs.validateArchiveEntry(vector), C.ENCODED_TRAVERSAL, vector);
  }
});

test('zip-slip: null byte and control characters in entry paths are rejected', () => {
  throwsCode(() => cjs.validateArchiveEntry('safe\u0000.txt'), C.NULL_BYTE);
  throwsCode(() => cjs.validateArchiveEntry('safe\n.txt'), C.CONTROL_CHARACTER);
});

test('zip-slip: benign nested entries are normalized and accepted', () => {
  assert.equal(
    cjs.validateArchiveEntry('docs/readme.md').path,
    'docs/readme.md'
  );
  assert.equal(
    cjs.validateArchiveEntry('a/./b/c.txt').path,
    'a/b/c.txt'
  );
  assert.equal(
    cjs.validateArchiveEntry('a/b/../c.txt').path,
    'a/c.txt'
  );
  assert.equal(cjs.validateArchiveEntry('file.txt').type, 'file');
});

test('archive entry type validation', () => {
  throwsCode(() => cjs.validateArchiveEntry(null), C.ARCHIVE_TYPE);
  throwsCode(() => cjs.validateArchiveEntry(42), C.ARCHIVE_TYPE);
  throwsCode(() => cjs.validateArchiveEntry({ path: 'x', type: 'socket' }), C.ARCHIVE_TYPE);
  throwsCode(() => cjs.validateArchiveEntry({ path: 'x', size: -1 }), C.INVALID_INPUT);
  throwsCode(() => cjs.validateArchiveEntry({}), C.ARCHIVE_PATH);
});

/* ------------------------- Link entries ------------------------- */

test('symlink and hardlink entries are disabled by default', () => {
  throwsCode(
    () => cjs.validateArchiveEntry({ path: 'link', type: 'symlink', linkTarget: 'target' }),
    C.ARCHIVE_LINK
  );
  throwsCode(
    () => cjs.validateArchiveEntry({ path: 'link', type: 'hardlink', linkTarget: 'target' }),
    C.ARCHIVE_LINK
  );
});

test('symlink entries with escaping targets are rejected even when enabled', () => {
  const opts = { allowSymlinks: true };
  for (const target of [
    '/etc/passwd',
    '../../etc/passwd',
    'a/../../../secret',
    'C:\\Windows\\evil.dll'
  ]) {
    throwsCode(
      () => cjs.validateArchiveEntry(
        { path: 'docs/link', type: 'symlink', linkTarget: target },
        opts
      ),
      C.ARCHIVE_LINK,
      target
    );
  }
});

test('symlink entries with internal targets are accepted when enabled', () => {
  const result = cjs.validateArchiveEntry(
    { path: 'docs/link', type: 'symlink', linkTarget: '../README.md' },
    { allowSymlinks: true }
  );
  assert.equal(result.type, 'symlink');
  assert.equal(result.linkTarget, '/README.md');
});

test('hardlink entries with internal targets are accepted when enabled', () => {
  const result = cjs.validateArchiveEntry(
    { path: 'copy.txt', type: 'hardlink', linkTarget: 'file.txt' },
    { allowHardlinks: true }
  );
  assert.equal(result.type, 'hardlink');
  assert.equal(result.linkTarget, '/file.txt');
});

test('link entries without a target are rejected', () => {
  throwsCode(
    () => cjs.validateArchiveEntry({ path: 'l', type: 'symlink' }, { allowSymlinks: true }),
    C.ARCHIVE_LINK
  );
});

/* ------------------------- Limits and bombs ------------------------- */

test('maxFiles limit is enforced by createArchiveGuard', () => {
  const guard = cjs.createArchiveGuard({ maxFiles: 2 });
  guard.validate('a.txt');
  guard.validate('b.txt');
  throwsCode(() => guard.validate('c.txt'), C.ARCHIVE_LIMIT);
  assert.equal(guard.stats().files, 2);
});

test('maxFileSize and maxTotalSize limits are enforced', () => {
  throwsCode(
    () => cjs.validateArchiveEntry({ path: 'big', size: 100 }, { maxFileSize: 50 }),
    C.ARCHIVE_LIMIT
  );
  const guard = cjs.createArchiveGuard({ maxTotalSize: 100 });
  guard.validate({ path: 'a', size: 60 });
  throwsCode(() => guard.validate({ path: 'b', size: 60 }), C.ARCHIVE_LIMIT);
});

test('zip-bomb: compression ratio above the limit is rejected', () => {
  throwsCode(
    () => cjs.validateArchiveEntry(
      { path: 'bomb.txt', size: 10_000_000, compressedSize: 10_000 },
      { maxCompressionRatio: 100, maxFileSize: 20_000_000 }
    ),
    C.ARCHIVE_ZIP_BOMB
  );
  assert.equal(
    cjs.validateArchiveEntry(
      { path: 'ok.txt', size: 9_000, compressedSize: 1_000 },
      { maxCompressionRatio: 10 }
    ).path,
    'ok.txt'
  );
});

test('zip-bomb: non-empty entry with zero compressed size is rejected', () => {
  throwsCode(
    () => cjs.validateArchiveEntry({ path: 'bomb', size: 100, compressedSize: 0 }),
    C.ARCHIVE_ZIP_BOMB
  );
});

test('bad limit options are rejected', () => {
  for (const key of ['maxFiles', 'maxFileSize', 'maxTotalSize']) {
    throwsCode(
      () => cjs.createArchiveGuard({ [key]: -1 }),
      C.INVALID_INPUT
    );
  }
  throwsCode(
    () => cjs.createArchiveGuard({ maxCompressionRatio: 0 }),
    C.INVALID_INPUT
  );
});

/* ------------------------- Collision detection ------------------------- */

test('case-insensitive collisions are detected by default', () => {
  const guard = cjs.createArchiveGuard();
  guard.validate('README.md');
  throwsCode(() => guard.validate('readme.md'), C.ARCHIVE_COLLISION);
  throwsCode(() => guard.validate('README.md'), C.ARCHIVE_COLLISION);
});

test('exact duplicate paths are detected', () => {
  const guard = cjs.createArchiveGuard({ caseInsensitive: false });
  guard.validate('a/b.txt');
  throwsCode(() => guard.validate('a/b.txt'), C.ARCHIVE_COLLISION);
});

test('case-insensitive detection can be disabled', () => {
  const guard = cjs.createArchiveGuard({ caseInsensitive: false });
  guard.validate('README.md');
  assert.equal(guard.validate('readme.md').path, 'readme.md');
});

test('guard reset clears limits and seen paths', () => {
  const guard = cjs.createArchiveGuard({ maxFiles: 1 });
  guard.validate('a.txt');
  guard.reset();
  assert.deepEqual(guard.stats(), { files: 0, totalSize: 0, paths: 0 });
  guard.validate('b.txt');
});

test('validateBatch validates and records an entire archive', () => {
  const guard = cjs.createArchiveGuard();
  const results = guard.validateBatch([
    'src/index.js',
    { path: 'src/util.js', size: 100, compressedSize: 30 },
    'README.md'
  ]);
  assert.deepEqual(results.map((r) => r.path), ['src/index.js', 'src/util.js', 'README.md']);
  assert.equal(guard.stats().files, 3);
  throwsCode(() => guard.validateBatch('not-an-array'), C.INVALID_INPUT);
});

test('standalone validateArchiveEntry with caller-owned state detects collisions', () => {
  const state = { seen: new Set(), files: 0, totalSize: 0 };
  cjs.validateArchiveEntry('a.txt', { state });
  throwsCode(() => cjs.validateArchiveEntry('A.txt', { state }), C.ARCHIVE_COLLISION);
});

test('ESM and CJS archive validation match', () => {
  const cases = [
    { path: 'docs/a.md', size: 100, compressedSize: 40 },
    '../evil',
    { path: 'bomb', size: 100000, compressedSize: 100 },
    { path: 'l', type: 'symlink', linkTarget: '../../secret' }
  ];
  for (const entry of cases) {
    let e1;
    let e2;
    try { cjs.validateArchiveEntry(entry); } catch (e) { e1 = e; }
    try { esm.validateArchiveEntry(entry); } catch (e) { e2 = e; }
    assert.equal(Boolean(e1), Boolean(e2), JSON.stringify(entry));
    if (e1 && e2) {
      assert.equal(e1.code, e2.code);
      assert.equal(e1.reason, e2.reason);
    }
  }
});
