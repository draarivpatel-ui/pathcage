import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { cjs, esm, ROOT, throwsCode } from './helpers.mjs';

const opts = { root: ROOT };

test('resolveSafePath returns a normalized absolute path inside root', () => {
  assert.equal(cjs.resolveSafePath('file.txt', opts), path.join(ROOT, 'file.txt'));
  assert.equal(cjs.resolveSafePath('a/b/c.txt', opts), path.join(ROOT, 'a/b/c.txt'));
  assert.equal(cjs.resolveSafePath('./a/../b.txt', opts), path.join(ROOT, 'b.txt'));
  assert.equal(cjs.resolveSafePath('a//b', opts), path.join(ROOT, 'a/b'));
});

test('assertSafePath is an alias of resolveSafePath', () => {
  assert.equal(cjs.assertSafePath('x.txt', opts), cjs.resolveSafePath('x.txt', opts));
});

test('classic traversal vectors are rejected', () => {
  const vectors = [
    '..',
    '../',
    '../secret',
    '../../etc/passwd',
    'a/../../secret',
    'a/../..',
    'a/./../../b',
    '....//secret',
    '..;/secret'
  ];
  for (const vector of vectors) {
    throwsCode(() => cjs.resolveSafePath(vector, opts), cjs.CODE.TRAVERSAL, vector);
  }
});

test('backslash and mixed-slash traversal vectors are rejected', () => {
  for (const vector of ['..\\', '..\\secret', 'a\\..\\..\\secret', '..\\/secret']) {
    throwsCode(() => cjs.resolveSafePath(vector, opts), cjs.CODE.BACKSLASH_SEPARATOR, vector);
  }
});

test('absolute paths are rejected on every platform', () => {
  const vectors = ['/etc/passwd', path.join(ROOT, 'file.txt')];
  for (const vector of vectors) {
    throwsCode(() => cjs.resolveSafePath(vector, opts), cjs.CODE.ABSOLUTE_PATH, vector);
  }
});

test('prefix confusion: sibling directory with the root prefix is rejected', () => {
  const sibling = '/app/uploads-evil/secret.txt';
  throwsCode(() => cjs.resolveSafePath(sibling, opts), cjs.CODE.ABSOLUTE_PATH, sibling);
  // Even an absolute path that lexically starts with the root string is rejected.
  const absolute = ROOT + '-evil/x';
  throwsCode(() => cjs.resolveSafePath(absolute, opts), cjs.CODE.ABSOLUTE_PATH, absolute);
  // The cage containment helper itself uses path.relative, never a string prefix.
  assert.equal(cjs.isInside(ROOT, path.join(ROOT, 'a')), true);
  assert.equal(cjs.isInside(ROOT, '/app/uploads-evil/a'), false);
  assert.equal(cjs.isInside(ROOT, '/app/uploads2'), false);
});

test('null bytes and control characters are rejected', () => {
  throwsCode(() => cjs.resolveSafePath('a\u0000b', opts), cjs.CODE.NULL_BYTE);
  throwsCode(() => cjs.resolveSafePath('\u0000', opts), cjs.CODE.NULL_BYTE);
  for (const ch of ['\u0001', '\n', '\r', '\t', '\u007f', '\u009f']) {
    throwsCode(() => cjs.resolveSafePath('a' + ch + 'b', opts), cjs.CODE.CONTROL_CHARACTER, ch);
  }
});

test('percent-encoded traversal is rejected when decodeCheck is enabled', () => {
  const vectors = [
    '%2e%2e%2fsecret',
    '%2E%2E/secret',
    'a%2f..%2f..%2fsecret',
    '%252e%252e%252fsecret'
  ];
  for (const vector of vectors) {
    throwsCode(
      () => cjs.resolveSafePath(vector, { root: ROOT, decodeCheck: true }),
      cjs.CODE.ENCODED_TRAVERSAL,
      vector
    );
  }
  // Double-encoded traversal that starts with a literal .. is rejected
  // earlier by the raw segment check, which is equally safe.
  throwsCode(
    () => cjs.resolveSafePath('..%252fsecret', { root: ROOT, decodeCheck: true }),
    cjs.CODE.TRAVERSAL
  );
});

test('decodeCheck twice-encoded nested traversal cannot slip through', () => {
  const vector = '%252e%252e%252f%252e%252e%252fetc';
  throwsCode(
    () => cjs.resolveSafePath(vector, { root: ROOT, decodeCheck: true }),
    cjs.CODE.ENCODED_TRAVERSAL
  );
});

test('encoded traversal without opt-in is not decoded', () => {
  // Literal percent-encoded text is treated as an ordinary filename.
  assert.equal(
    cjs.resolveSafePath('%2e%2e%2fsecret', opts),
    path.join(ROOT, '%2e%2e%2fsecret')
  );
});

test('invalid inputs are rejected', () => {
  for (const input of ['', 42, null, undefined, {}, []]) {
    throwsCode(() => cjs.resolveSafePath(input, opts), cjs.CODE.INVALID_INPUT, String(input));
  }
  throwsCode(() => cjs.resolveSafePath('x', {}), cjs.CODE.INVALID_ROOT);
  throwsCode(() => cjs.resolveSafePath('x', { root: '' }), cjs.CODE.INVALID_ROOT);
});

test('maxPathLength is enforced', () => {
  throwsCode(
    () => cjs.resolveSafePath('a'.repeat(100), { root: ROOT, maxPathLength: 50 }),
    cjs.CODE.LIMIT_EXCEEDED
  );
  for (const bad of [-1, 1.5, '10', Infinity]) {
    throwsCode(
      () => cjs.resolveSafePath('x', { root: ROOT, maxPathLength: bad }),
      cjs.CODE.INVALID_INPUT
    );
  }
});

test('ESM and CJS entry points behave identically for traversal', () => {
  for (const vector of ['../secret', '/etc/passwd', 'a\u0000b', '..\\windows']) {
    let esmError;
    let cjsError;
    try { esm.resolveSafePath(vector, opts); } catch (e) { esmError = e; }
    try { cjs.resolveSafePath(vector, opts); } catch (e) { cjsError = e; }
    assert.ok(esmError && cjsError, vector);
    assert.equal(esmError.code, cjsError.code, vector);
    assert.equal(esmError.reason, cjsError.reason, vector);
  }
  assert.equal(
    esm.resolveSafePath('ok.txt', opts),
    cjs.resolveSafePath('ok.txt', opts)
  );
});

test('root path resolution is platform independent', () => {
  const withDots = cjs.resolveSafePath('a.txt', { root: ROOT + '/./' });
  assert.equal(withDots, path.join(ROOT, 'a.txt'));
  assert.ok(!ROOT.startsWith(os.homedir()), 'fixture root must not be a personal path');
});
