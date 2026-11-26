import test from 'node:test';
import assert from 'node:assert/strict';
import { cjs, esm, throwsCode } from './helpers.mjs';

const C = cjs.CODE;

test('PathCageError is a real Error with name, code, reason and input', () => {
  const error = throwsCode(
    () => cjs.resolveSafePath('../secret', { root: '/app/uploads' }),
    C.TRAVERSAL
  );
  assert.ok(error instanceof Error);
  assert.ok(error instanceof cjs.PathCageError);
  assert.equal(error.name, 'PathCageError');
  assert.equal(error.input, '../secret');
  assert.match(error.message, /^ERR_PATHCAGE_/);
  assert.ok(error.reason.length > 0);
});

test('PathCageError.toJSON returns a stable serializable shape', () => {
  const error = throwsCode(
    () => cjs.resolveSafePath('/etc/passwd', { root: '/app/uploads' }),
    C.ABSOLUTE_PATH
  );
  assert.deepEqual(Object.keys(error.toJSON()).sort(), ['code', 'input', 'name', 'reason']);
  assert.equal(JSON.parse(JSON.stringify(error)).code, C.ABSOLUTE_PATH);
});

test('PathCageError constructor is shared between ESM and CJS', () => {
  assert.equal(esm.PathCageError, cjs.PathCageError);
  const e = new cjs.PathCageError('TEST_CODE', 'test reason', { key: 'value' });
  assert.equal(e.code, 'TEST_CODE');
  assert.deepEqual(e.input, { key: 'value' });
  assert.equal(e.toJSON().reason, 'test reason');
});

test('all documented error codes are exposed', () => {
  const expected = [
    'INVALID_INPUT', 'INVALID_ROOT', 'NULL_BYTE', 'CONTROL_CHARACTER',
    'UNICODE_NORMALIZATION',
    'ABSOLUTE_PATH', 'TRAVERSAL', 'ENCODED_TRAVERSAL', 'WINDOWS_DRIVE',
    'WINDOWS_UNC', 'WINDOWS_PREFIX', 'WINDOWS_DEVICE', 'ALTERNATE_DATA_STREAM',
    'TRAILING_DOT_OR_SPACE', 'BACKSLASH_SEPARATOR', 'OUTSIDE_ROOT',
    'FORBIDDEN_SYMLINK', 'SYMLINK_ESCAPE', 'DUPLICATE_PATH', 'LIMIT_EXCEEDED',
    'ARCHIVE_PATH', 'ARCHIVE_TYPE', 'ARCHIVE_LINK', 'ARCHIVE_LIMIT',
    'ARCHIVE_ZIP_BOMB', 'ARCHIVE_COLLISION'
  ];
  for (const name of expected) {
    assert.equal(C[name], 'ERR_PATHCAGE_' + name, name);
  }
  assert.equal(Object.keys(C).length, expected.length);
});

test('CODE is frozen and cannot be mutated', () => {
  assert.ok(Object.isFrozen(C));
  assert.throws(() => { C.TRAVERSAL = 'nope'; }, TypeError);
});

test('errors from archive guards carry the offending input', () => {
  const guard = cjs.createArchiveGuard({ maxFiles: 1 });
  guard.validate('a.txt');
  const error = throwsCode(() => guard.validate('b.txt'), C.ARCHIVE_LIMIT);
  assert.ok(error.input === 'b.txt' || error.input.path === 'b.txt');
});

test('errors from createCage carry the original rootDir', () => {
  const error = throwsCode(() => cjs.createCage(''), C.INVALID_ROOT);
  assert.equal(error.input, '');
});

test('isInside and assertLexicalInside use segment-aware comparison', () => {
  const root = '/tmp/uploads';
  assert.equal(cjs.isInside(root, '/tmp/uploads'), true);
  assert.equal(cjs.isInside(root, '/tmp/uploads/a/b.txt'), true);
  assert.equal(cjs.isInside(root, '/tmp/uploads-evil'), false);
  assert.equal(cjs.isInside(root, '/tmp/uploads2/x'), false);
  assert.equal(cjs.isInside(root, '/tmp/other/uploads'), false);
  assert.equal(cjs.assertLexicalInside(root, '/tmp/uploads/a.txt'), '/tmp/uploads/a.txt');
  throwsCode(() => cjs.assertLexicalInside(root, '/tmp/uploads-evil/a'), C.OUTSIDE_ROOT);
});
