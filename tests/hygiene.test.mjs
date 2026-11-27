import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { cjs, esm, ROOT, throwsCode } from './helpers.mjs';

const C = cjs.CODE;

test('zero-path hygiene: empty and whitespace-only inputs are rejected', () => {
  throwsCode(() => cjs.resolveSafePath('', { root: ROOT }), C.INVALID_INPUT);
  for (const input of ['   ', '\t', '\n']) {
    let error;
    assert.throws(() => cjs.resolveSafePath(input, { root: ROOT }), (e) => {
      error = e;
      return true;
    });
    assert.equal(error.name, 'PathCageError');
  }
  for (const input of ['', '.', '..', '   ']) {
    let error;
    assert.throws(
      () => cjs.sanitizeFilename(input, { fallback: undefined }),
      (e) => { error = e; return true; }
    );
    assert.equal(error.name, 'PathCageError');
  }
});

test('zero-path hygiene: fallback recovers an empty sanitized filename', () => {
  assert.equal(cjs.sanitizeFilename('', { fallback: 'untitled' }), 'untitled');
  assert.equal(cjs.sanitizeFilename('...', { fallback: 'untitled' }), 'untitled');
  assert.equal(
    cjs.sanitizeFilename('///', { replacement: '_', fallback: 'index' }),
    'index'
  );
});

test('zero-path hygiene: dot and dotdot segments are handled safely', () => {
  assert.equal(cjs.resolveSafePath('.', { root: ROOT }), ROOT);
  assert.equal(cjs.resolveSafePath('a/./b', { root: ROOT }), path.join(ROOT, 'a/b'));
  throwsCode(() => cjs.resolveSafePath('..', { root: ROOT }), C.TRAVERSAL);
  throwsCode(() => cjs.resolveSafePath('./..', { root: ROOT }), C.TRAVERSAL);
});

test('zero-path hygiene: archive entry paths cannot be empty or root', () => {
  for (const input of ['', '.', './', '/']) {
    throwsCode(() => cjs.validateArchiveEntry(input), C.ARCHIVE_PATH, JSON.stringify(input));
  }
});

test('zero-path hygiene: limits of zero reject all entries', () => {
  throwsCode(
    () => cjs.createArchiveGuard({ maxFiles: 0 }).validate('a.txt'),
    C.ARCHIVE_LIMIT
  );
  throwsCode(
    () => cjs.validateArchiveEntry({ path: 'a', size: 1 }, { maxTotalSize: 0 }),
    C.ARCHIVE_LIMIT
  );
});

test('package manifest keeps runtime dependencies empty and fast-check development-only', () => {
  const pkg = JSON.parse(
    fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
  );
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, { 'fast-check': '4.10.3' });
  assert.equal(pkg.name, 'pathcage');
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.exports['.'].import, './src/index.mjs');
  assert.equal(pkg.exports['.'].require, './cjs/index.cjs');
  assert.equal(pkg.exports['.'].types, './types/index.d.ts');
});

test('ESM default export matches named exports', () => {
  assert.equal(esm.default.PathCageError, esm.PathCageError);
  assert.equal(esm.default.resolveSafePath, esm.resolveSafePath);
  assert.equal(esm.default.createCage, esm.createCage);
  assert.equal(esm.default.sanitizeFilename, esm.sanitizeFilename);
});

test('CJS default export matches named exports', () => {
  assert.equal(cjs.default, cjs);
  assert.equal(cjs.default.createArchiveGuard, cjs.createArchiveGuard);
});

test('all ESM exports are present in CJS and vice versa', () => {
  const names = [
    'PathCageError', 'CODE', 'resolveSafePath', 'assertSafePath',
    'sanitizeFilename', 'validateArchiveEntry', 'createArchiveGuard', 'createCage',
    'isInside', 'assertLexicalInside'
  ];
  for (const name of names) {
    assert.equal(typeof esm[name], typeof cjs[name], name);
    assert.ok(esm[name], name);
  }
});

test('deeply nested paths resolve without truncation', () => {
  const segments = Array.from({ length: 50 }, (_, i) => 'd' + i);
  const result = cjs.resolveSafePath(segments.join('/') + '/file.txt', { root: ROOT });
  assert.equal(result, path.join(ROOT, ...segments, 'file.txt'));
});

test('same input always yields the same output', () => {
  for (let i = 0; i < 20; i += 1) {
    assert.equal(
      cjs.resolveSafePath('a/b/../c.txt', { root: ROOT }),
      path.join(ROOT, 'a/c.txt')
    );
    assert.equal(cjs.sanitizeFilename('a/b: c.txt'), 'b_ c.txt');
  }
});

test('path resolution never mutates the supplied options object', () => {
  const options = Object.freeze({ root: ROOT, decodeCheck: true });
  cjs.resolveSafePath('a.txt', options);
  assert.deepEqual(options, { root: ROOT, decodeCheck: true });
});
