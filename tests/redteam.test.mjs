import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { cjs, esm, ROOT, tempDir, throwsCode } from './helpers.mjs';

const C = cjs.CODE;

function pathThrowsCode(fn, code, label) {
  return throwsCode(fn, code, label);
}

function withTemp(label, fn) {
  const t = tempDir(label);
  try {
    return fn(t.dir);
  } finally {
    t.cleanup();
  }
}

/* ---------------------- Unicode normalization attacks ---------------------- */

test('redteam: fullwidth separators and dots cannot smuggle traversal', () => {
  const vectors = [
    '\uFF0E\uFF0E\uFF0Fetc\uFF0Fpasswd', // ../etc/passwd in fullwidth
    '\uFF0E\uFF0E',
    'a\uFF0F..\uFF0F..\uFF0Fetc',
    'a\uFF3Cb',
    'C\uFF1A\uFF3Csecret'
  ];
  for (const vector of vectors) {
    pathThrowsCode(
      () => cjs.resolveSafePath(vector, { root: ROOT }),
      C.UNICODE_NORMALIZATION,
      JSON.stringify(vector)
    );
  }
});

test('redteam: harmless compatibility forms are still accepted unchanged', () => {
  const name = '\uFF46\uFF49\uFF4C\uFF45.txt'; // fullwidth "file.txt"
  assert.equal(
    cjs.resolveSafePath(name, { root: ROOT }),
    path.join(ROOT, name)
  );
  // NFC and NFD spellings of a composed letter both pass the raw check.
  assert.equal(
    cjs.resolveSafePath('caf\u00E9.txt', { root: ROOT }),
    path.join(ROOT, 'caf\u00E9.txt')
  );
  assert.equal(
    cjs.resolveSafePath('cafe\u0301.txt', { root: ROOT }),
    path.join(ROOT, 'cafe\u0301.txt')
  );
});

test('redteam: fullwidth traversal is rejected in archive paths and link targets', () => {
  pathThrowsCode(
    () => cjs.validateArchiveEntry('\uFF0E\uFF0E\uFF0Fevil.sh'),
    C.UNICODE_NORMALIZATION
  );
  pathThrowsCode(
    () => cjs.validateArchiveEntry(
      { path: 'docs/link', type: 'symlink', linkTarget: '\uFF0E\uFF0E\uFF0F\uFF0E\uFF0E\uFF0Fetc' },
      { allowSymlinks: true }
    ),
    C.UNICODE_NORMALIZATION
  );
});

test('redteam: fullwidth names that normalize to a device name are rejected', () => {
  pathThrowsCode(
    () => cjs.validateArchiveEntry('\uFF23\uFF2F\uFF2E.txt'),
    C.UNICODE_NORMALIZATION
  );
});

/* --------------------------- Bidi control attacks -------------------------- */

test('redteam: bidi overrides and isolates are rejected as control characters', () => {
  const vectors = ['safe\u202Etxt.exe', 'a\u202Db', 'x\u2066y\u2069.txt', 'l\u200Ftr.txt'];
  for (const vector of vectors) {
    pathThrowsCode(
      () => cjs.resolveSafePath(vector, { root: ROOT }),
      C.CONTROL_CHARACTER,
      JSON.stringify(vector)
    );
    pathThrowsCode(
      () => cjs.validateArchiveEntry(vector),
      C.CONTROL_CHARACTER,
      JSON.stringify(vector)
    );
  }
});

test('redteam: sanitizeFilename strips bidi controls and keeps the visible tail', () => {
  assert.equal(cjs.sanitizeFilename('safe\u202Etxt.exe'), 'safe_txt.exe');
  assert.equal(cjs.sanitizeFilename('invoice\u202Efdp.exe'), 'invoice_fdp.exe');
});

/* ------------------------ Malformed percent encoding ----------------------- */

test('redteam: malformed tail cannot hide an encoded traversal', () => {
  pathThrowsCode(
    () => cjs.resolveSafePath('%2e%2e%2f%ZZsecret', { root: ROOT, decodeCheck: true }),
    C.ENCODED_TRAVERSAL
  );
  pathThrowsCode(
    () => cjs.resolveSafePath('x/%2e%2e%2f%', { root: ROOT, decodeCheck: true }),
    C.ENCODED_TRAVERSAL
  );
  pathThrowsCode(
    () => cjs.resolveSafePath('%2e%2e%zz%2fsecret', { root: ROOT, decodeCheck: true }),
    C.ENCODED_TRAVERSAL
  );
});

test('redteam: literal percent text is not an unhandled URIError', () => {
  // decodeURIComponent would throw on these; the library must treat the
  // percent sign as literal text and never leak a URIError.
  for (const vector of ['%ZZ', '100%.txt', 'a%2', '%%%']) {
    const result = cjs.resolveSafePath(vector, { root: ROOT, decodeCheck: true });
    assert.equal(result, path.join(ROOT, vector));
  }
  // Percent escaped bytes that are not UTF-8 are rejected with a PathCageError.
  const error = throwsCode(
    () => cjs.resolveSafePath('a%FFb.txt', { root: ROOT, decodeCheck: true }),
    C.ENCODED_TRAVERSAL
  );
  assert.notEqual(error.name, 'URIError');
});

test('redteam: deeply nested percent encoding cannot outrun the decode loop', () => {
  const fiveLayers = '%252525252e%252525252e%252525252fsecret';
  pathThrowsCode(
    () => cjs.resolveSafePath(fiveLayers, { root: ROOT, decodeCheck: true }),
    C.ENCODED_TRAVERSAL
  );
});

test('redteam: decoded device names, streams and absolute forms are rejected', () => {
  const vectors = [
    ['CON%2E', C.WINDOWS_DEVICE],
    ['%43%4f%4e', C.WINDOWS_DEVICE],
    ['file%3Atxt', C.ALTERNATE_DATA_STREAM],
    ['%2Fetc%2Fpasswd', C.ENCODED_TRAVERSAL],
    ['a%5cb', C.BACKSLASH_SEPARATOR],
    ['a%E2%80%AEb', C.ENCODED_TRAVERSAL],
    ['a%EF%BC%8F..%EF%BC%8Fetc', C.UNICODE_NORMALIZATION]
  ];
  for (const [vector, code] of vectors) {
    pathThrowsCode(
      () => cjs.resolveSafePath(vector, { root: ROOT, decodeCheck: true }),
      code,
      vector
    );
  }
});

/* ------------------------------ Symlink attacks ---------------------------- */

test('redteam: nonexistent leaf through an escaping symlink ancestor is rejected', () => {
  withTemp('redteam-link-ancestor', (dir) => {
    const root = path.join(dir, 'root');
    const outside = path.join(dir, 'outside');
    fs.mkdirSync(root);
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, path.join(root, 'link_out'));
    const cage = cjs.createCage(root, { noSymlinks: false });
    for (const candidate of [
      'link_out/newdir/file.txt',
      path.join(root, 'link_out/newdir/file.txt')
    ]) {
      pathThrowsCode(() => cage.realpathCheck(candidate), C.SYMLINK_ESCAPE, candidate);
    }
  });
});

test('redteam: dangling escaping symlinks are rejected', () => {
  withTemp('redteam-dangling', (dir) => {
    const root = path.join(dir, 'root');
    const outside = path.join(dir, 'outside');
    fs.mkdirSync(root);
    fs.mkdirSync(outside);
    fs.symlinkSync(path.join(outside, 'nope.txt'), path.join(root, 'dangle_out'));
    fs.symlinkSync('../outside/nope2.txt', path.join(root, 'dangle_rel'));
    const cage = cjs.createCage(root, { noSymlinks: false });
    pathThrowsCode(() => cage.realpathCheck('dangle_out'), C.SYMLINK_ESCAPE);
    pathThrowsCode(() => cage.realpathCheck('dangle_out/deeper.txt'), C.SYMLINK_ESCAPE);
    pathThrowsCode(() => cage.realpathCheck('dangle_rel'), C.SYMLINK_ESCAPE);
  });
});

test('redteam: dangling internal symlink stays accepted and contained', () => {
  withTemp('redteam-dangling-inside', (dir) => {
    const root = path.join(dir, 'root');
    fs.mkdirSync(root);
    fs.symlinkSync(path.join(root, 'missing.txt'), path.join(root, 'dangle_in'));
    const cage = cjs.createCage(root, { noSymlinks: false });
    assert.equal(cage.realpathCheck('dangle_in'), path.join(cage.rootReal, 'missing.txt'));
  });
});

test('redteam: symlink loops raise PathCageError instead of a raw ELOOP error', () => {
  withTemp('redteam-loop', (dir) => {
    const root = path.join(dir, 'root');
    fs.mkdirSync(root);
    fs.symlinkSync(path.join(root, 'loop_b'), path.join(root, 'loop_a'));
    fs.symlinkSync(path.join(root, 'loop_a'), path.join(root, 'loop_b'));
    fs.symlinkSync('self', path.join(root, 'self'));
    const cage = cjs.createCage(root, { noSymlinks: false });
    const loop = throwsCode(() => cage.realpathCheck('loop_a'), C.SYMLINK_ESCAPE);
    assert.equal(loop.name, 'PathCageError');
    const self = throwsCode(() => cage.realpathCheck('self'), C.SYMLINK_ESCAPE);
    assert.equal(self.name, 'PathCageError');
  });
});

test('redteam: strict mode applies noSymlinks to absolute candidates too', () => {
  withTemp('redteam-strict-absolute', (dir) => {
    const root = path.join(dir, 'root');
    fs.mkdirSync(path.join(root, 'real'), { recursive: true });
    fs.writeFileSync(path.join(root, 'real', 'f.txt'), 'x');
    fs.symlinkSync(path.join(root, 'real'), path.join(root, 'alias'));
    const strict = cjs.createCage(root);
    const relative = path.posix.join('alias', 'f.txt');
    pathThrowsCode(() => strict.realpathCheck(relative), C.FORBIDDEN_SYMLINK);
    pathThrowsCode(
      () => strict.realpathCheck(path.join(root, 'alias', 'f.txt')),
      C.FORBIDDEN_SYMLINK
    );
    const loose = cjs.createCage(root, { noSymlinks: false });
    assert.equal(
      loose.realpathCheck(path.join(root, 'alias', 'f.txt')),
      fs.realpathSync(path.join(root, 'real', 'f.txt'))
    );
  });
});

test('redteam: a user controlled symlink ancestor cannot be skipped under strict mode', () => {
  withTemp('redteam-ancestor-strict', (dir) => {
    const real = path.join(dir, 'real');
    fs.mkdirSync(path.join(real, 'root'), { recursive: true });
    const link = path.join(dir, 'link');
    fs.symlinkSync(real, link);
    pathThrowsCode(
      () => cjs.createCage(path.join(link, 'root')),
      C.FORBIDDEN_SYMLINK
    );
    assert.equal(
      cjs.createCage(path.join(link, 'root'), { noSymlinks: false }).rootReal,
      fs.realpathSync(path.join(real, 'root'))
    );
  });
});

test('redteam: validateBatch detects Unicode normalization duplicates', () => {
  withTemp('redteam-batch-nfc', (dir) => {
    const cage = cjs.createCage(dir);
    pathThrowsCode(
      () => cage.validateBatch(['caf\u00E9.txt', 'cafe\u0301.txt']),
      C.DUPLICATE_PATH
    );
  });
});

/* ------------------------------ Archive attacks ---------------------------- */

test('redteam: tar hardlink escapes are rejected', () => {
  const opts = { allowHardlinks: true };
  for (const target of ['../outside', '../../etc/passwd', 'a/../../x', '/etc/passwd']) {
    pathThrowsCode(
      () => cjs.validateArchiveEntry({ path: 'copy.txt', type: 'hardlink', linkTarget: target }, opts),
      C.ARCHIVE_LINK,
      target
    );
  }
  assert.equal(
    cjs.validateArchiveEntry(
      { path: 'copy.txt', type: 'hardlink', linkTarget: 'a/../file.txt' },
      opts
    ).linkTarget,
    '/file.txt'
  );
});

test('redteam: symlink target at the archive root cannot climb above it', () => {
  pathThrowsCode(
    () => cjs.validateArchiveEntry(
      { path: 'link', type: 'symlink', linkTarget: '..' },
      { allowSymlinks: true }
    ),
    C.ARCHIVE_LINK
  );
});

test('redteam: oversized link targets are rejected before segment walks', () => {
  pathThrowsCode(
    () => cjs.validateArchiveEntry(
      { path: 'l', type: 'symlink', linkTarget: 'a/'.repeat(5000) + 'x' },
      { allowSymlinks: true }
    ),
    C.LIMIT_EXCEEDED
  );
});

test('redteam: zero compressed size never divides by zero', () => {
  const bomb = throwsCode(
    () => cjs.validateArchiveEntry({ path: 'bomb', size: 1, compressedSize: 0 }),
    C.ARCHIVE_ZIP_BOMB
  );
  assert.doesNotMatch(bomb.message, /NaN|Infinity/);
  const empty = cjs.validateArchiveEntry({ path: 'empty', size: 0, compressedSize: 0 });
  assert.equal(empty.size, 0);
  assert.equal(empty.compressedSize, 0);
});

test('redteam: negative, NaN, Infinity and unsafe integer sizes are rejected', () => {
  for (const size of [-1, -0.5, NaN, Infinity, 1.5, '10', 1e308, Number.MAX_SAFE_INTEGER + 1]) {
    pathThrowsCode(
      () => cjs.validateArchiveEntry({ path: 'f', size, compressedSize: 1 }),
      C.INVALID_INPUT,
      String(size)
    );
    pathThrowsCode(
      () => cjs.validateArchiveEntry({ path: 'g', size: 1, compressedSize: size }),
      C.INVALID_INPUT,
      String(size)
    );
  }
  pathThrowsCode(
    () => cjs.validateArchiveEntry('x', { maxFileSize: 1e308 }),
    C.INVALID_INPUT
  );
});

test('redteam: prototype pollution names are inert archive entries', () => {
  const guard = cjs.createArchiveGuard();
  for (const name of ['__proto__', 'constructor', 'prototype', '__proto__/x.txt']) {
    assert.equal(guard.validate(name).path, name);
  }
  assert.equal({}.polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(cjs.sanitizeFilename('__proto__'), '__proto__');
  assert.equal(cjs.sanitizeFilename('constructor'), 'constructor');
  assert.equal(cjs.resolveSafePath('__proto__', { root: ROOT }), path.join(ROOT, '__proto__'));
});

test('redteam: reserved option keys cannot rewire options through the prototype', () => {
  const vectors = [
    JSON.parse('{"root":"/app/uploads","__proto__":{"decodeCheck":true}}'),
    JSON.parse('{"root":"/app/uploads","constructor":{"prototype":{}}}'),
    JSON.parse('{"root":"/app/uploads","prototype":{"decodeCheck":true}}')
  ];
  for (const options of vectors) {
    pathThrowsCode(() => cjs.resolveSafePath('x.txt', options), C.INVALID_INPUT);
    pathThrowsCode(() => cjs.validateArchiveEntry('x.txt', options), C.INVALID_INPUT);
  }
});

test('redteam: archive state objects are validated', () => {
  pathThrowsCode(
    () => cjs.validateArchiveEntry('x', { state: { seen: [], files: 0, totalSize: 0 } }),
    C.INVALID_INPUT
  );
});

test('redteam: trailing slash and Unicode normalization collisions are rejected', () => {
  const guard = cjs.createArchiveGuard();
  assert.equal(guard.validate('dir/').path, 'dir');
  pathThrowsCode(() => guard.validate('dir'), C.ARCHIVE_COLLISION);
  const second = cjs.createArchiveGuard();
  second.validate('caf\u00E9.txt');
  pathThrowsCode(() => second.validate('cafe\u0301.txt'), C.ARCHIVE_COLLISION);
});

/* ---------------------------- Filename sanitizing -------------------------- */

test('redteam: the fallback value is sanitized like the input', () => {
  assert.equal(cjs.sanitizeFilename('', { fallback: 'CON' }), '_CON');
  assert.equal(cjs.sanitizeFilename('', { fallback: 'a:b' }), 'a_b');
  assert.equal(cjs.sanitizeFilename('', { fallback: 'name ' }), 'name');
  assert.equal(cjs.sanitizeFilename('', { fallback: '../evil.txt' }), 'evil.txt');
  assert.equal(cjs.sanitizeFilename('', { fallback: 'con.txt' }), '_con.txt');
});

test('redteam: truncation can never create a reserved device name', () => {
  const output = cjs.sanitizeFilename('CONSOLE', { maxLength: 3 });
  assert.notEqual(output, 'CON');
  assert.ok(output.length <= 3);
  assert.equal(cjs.sanitizeFilename('LPT1FILE', { maxLength: 4 }).toUpperCase().startsWith('_'), true);
});

test('redteam: sanitizeFilename enforces maxPathLength and normalizes fullwidth text', () => {
  pathThrowsCode(
    () => cjs.sanitizeFilename('x'.repeat(100), { maxPathLength: 5 }),
    C.LIMIT_EXCEEDED
  );
  assert.equal(cjs.sanitizeFilename('a\uFF0Fb.txt'), 'b.txt');
  assert.equal(cjs.sanitizeFilename('cafe\u0301.txt'), 'caf\u00E9.txt');
});

test('redteam: sanitizeFilename rejects an empty or control character replacement', () => {
  pathThrowsCode(
    () => cjs.sanitizeFilename('a<b', { replacement: '\u202E' }),
    C.INVALID_INPUT
  );
  // An empty replacement cannot prefix a reserved device name, so it is
  // rejected instead of returning "CON" unchanged.
  pathThrowsCode(
    () => cjs.sanitizeFilename('CON', { replacement: '' }),
    C.INVALID_INPUT
  );
  pathThrowsCode(
    () => cjs.sanitizeFilename('a<b', { replacement: '' }),
    C.INVALID_INPUT
  );
});

/* --------------------------- Module and typings parity --------------------- */

test('redteam: ESM and CJS default exports expose the same members', () => {
  const esmKeys = Object.keys(esm.default).sort();
  const cjsKeys = Object.keys(cjs).filter((key) => key !== 'default').sort();
  assert.deepEqual(esmKeys, cjsKeys);
  assert.equal(esm.default.isInside, esm.isInside);
  assert.equal(esm.default.assertLexicalInside, esm.assertLexicalInside);
});

test('redteam: typings declare every runtime error code and export', () => {
  const source = fs.readFileSync(new URL('../types/index.d.ts', import.meta.url), 'utf8');
  const declared = new Map();
  for (const match of source.matchAll(/^  ([A-Z][A-Z0-9_]+): '(ERR_PATHCAGE_[A-Z0-9_]+)';$/gm)) {
    declared.set(match[1], match[2]);
  }
  assert.equal(declared.size, Object.keys(C).length);
  for (const [name, value] of Object.entries(C)) {
    assert.equal(declared.get(name), value, name);
  }
  for (const name of Object.keys(cjs)) {
    if (name === 'default') continue;
    assert.ok(source.includes(name), 'typings mention ' + name);
  }
  for (const name of ['isInside', 'assertLexicalInside']) {
    assert.ok(
      source.includes(name + ': typeof ' + name + ';'),
      'default type includes ' + name
    );
  }
  assert.ok(source.includes('export const CODE'));
  assert.ok(source.includes('export declare class PathCageError'));
});
