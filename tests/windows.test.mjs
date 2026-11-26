import test from 'node:test';
import assert from 'node:assert/strict';
import { cjs, ROOT, throwsCode } from './helpers.mjs';

const opts = { root: ROOT };
const C = cjs.CODE;

test('drive letters and drive-relative paths are rejected', () => {
  for (const vector of ['C:\\secret', 'c:\\secret', 'C:foo', 'D:..\\secret', 'Z:/etc/passwd']) {
    throwsCode(() => cjs.resolveSafePath(vector, opts), C.WINDOWS_DRIVE, vector);
  }
});

test('UNC paths are rejected', () => {
  for (const vector of [
    '\\\\server\\share\\secret',
    '\\\\server\\share',
    '//server/share/secret',
    '//evil.example/share/file.txt'
  ]) {
    throwsCode(() => cjs.resolveSafePath(vector, opts), C.WINDOWS_UNC, vector);
  }
});

test('extended-length and device namespace prefixes are rejected', () => {
  for (const vector of [
    '\\\\?\\C:\\secret',
    '\\\\.\\pipe\\named',
    '\\\\?\\UNC\\server\\share',
    '\\\\.\\PhysicalDrive0'
  ]) {
    throwsCode(() => cjs.resolveSafePath(vector, opts), C.WINDOWS_PREFIX, vector);
  }
});

test('alternate data streams are rejected', () => {
  for (const vector of ['file.txt:hidden', ':stream', 'a/b.txt:$DATA', 'dir/:evil']) {
    throwsCode(() => cjs.resolveSafePath(vector, opts), C.ALTERNATE_DATA_STREAM, vector);
  }
});

test('all reserved Windows device names are rejected with and without extensions', () => {
  const base = ['CON', 'PRN', 'AUX', 'NUL'];
  const numbered = [];
  for (let i = 1; i <= 9; i += 1) {
    numbered.push('COM' + i, 'LPT' + i);
  }
  for (const name of [...base, ...numbered]) {
    for (const vector of [name, name.toLowerCase(), name + '.txt', name + '.']) {
      throwsCode(() => cjs.resolveSafePath(vector, opts), C.WINDOWS_DEVICE, vector);
    }
  }
});

test('non-device names that merely start with a device prefix are allowed', () => {
  for (const vector of ['con.txt.bak', 'COM10', 'LPT0', 'nulified', 'auxiliary.txt']) {
    assert.equal(
      cjs.resolveSafePath(vector, opts),
      ROOT + '/' + vector
    );
  }
});

test('trailing dots and spaces are rejected', () => {
  for (const vector of ['file.', 'file ', 'dir./file', 'dir /file', 'a..', 'a .']) {
    throwsCode(() => cjs.resolveSafePath(vector, opts), C.TRAILING_DOT_OR_SPACE, vector);
  }
});

test('backslash separators are rejected even without traversal', () => {
  for (const vector of ['a\\b', 'dir\\file.txt', 'a/b\\c']) {
    throwsCode(() => cjs.resolveSafePath(vector, opts), C.BACKSLASH_SEPARATOR, vector);
  }
});

test('sanitizeFilename removes Windows hazards and keeps a flat name', () => {
  assert.equal(cjs.sanitizeFilename('CON'), '_CON');
  assert.equal(cjs.sanitizeFilename('con.txt'), '_con.txt');
  assert.equal(cjs.sanitizeFilename('COM1.log'), '_COM1.log');
  assert.equal(cjs.sanitizeFilename('file.txt:hidden'), 'file.txt_hidden');
  assert.equal(cjs.sanitizeFilename('..\\..\\evil.txt'), 'evil.txt');
  assert.equal(cjs.sanitizeFilename('../../evil.txt'), 'evil.txt');
  assert.equal(cjs.sanitizeFilename('a/b/c.txt'), 'c.txt');
  assert.equal(cjs.sanitizeFilename('report?.txt'), 'report_.txt');
  assert.equal(cjs.sanitizeFilename('a<b>c|d"e'), 'a_b_c_d_e');
  assert.equal(cjs.sanitizeFilename('file.txt.'), 'file.txt');
  assert.equal(cjs.sanitizeFilename('file.txt  '), 'file.txt');
});

test('sanitizeFilename honors replacement, fallback and maxLength', () => {
  assert.equal(cjs.sanitizeFilename('a:b', { replacement: '-' }), 'a-b');
  assert.equal(cjs.sanitizeFilename('...', { fallback: 'file' }), '...'.replace(/[. ]+$/g, '') || 'file');
  assert.equal(cjs.sanitizeFilename('x'.repeat(300), { maxLength: 10 }), 'x'.repeat(10));
  assert.equal(cjs.sanitizeFilename('a/b.txt', { maxLength: 3 }), 'a/b.txt'.split('/').pop().slice(0, 3));
  throwsCode(
    () => cjs.sanitizeFilename('a:b', { replacement: '::' }),
    cjs.CODE.INVALID_INPUT
  );
});

test('sanitizeFilename decodes percent-encoded names when requested', () => {
  assert.equal(cjs.sanitizeFilename('%2e%2e%2fevil.txt', { decodeCheck: true }), 'evil.txt');
  assert.equal(cjs.sanitizeFilename('%2e%2e%2fevil.txt'), '%2e%2e%2fevil.txt');
});
