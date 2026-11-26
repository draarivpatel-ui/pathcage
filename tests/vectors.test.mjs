import test from 'node:test';
import assert from 'node:assert/strict';
import { cjs, ROOT, throwsCode } from './helpers.mjs';

const C = cjs.CODE;

const REJECTED_PATHS = [
  ['../', C.TRAVERSAL],
  ['../etc/passwd', C.TRAVERSAL],
  ['../../etc/passwd', C.TRAVERSAL],
  ['../../../etc/passwd', C.TRAVERSAL],
  ['a/../../secret', C.TRAVERSAL],
  ['a/b/../../../secret', C.TRAVERSAL],
  ['./../secret', C.TRAVERSAL],
  ['..', C.TRAVERSAL],
  ['....//secret', C.TRAVERSAL],
  ['..;/secret', C.TRAVERSAL],
  ['..%2fsecret', C.TRAVERSAL],
  ['..\\secret', C.BACKSLASH_SEPARATOR],
  ['a\\..\\secret', C.BACKSLASH_SEPARATOR],
  ['/etc/passwd', C.ABSOLUTE_PATH],
  ['/app/uploads/file', C.ABSOLUTE_PATH],
  ['/app/uploads-evil/file', C.ABSOLUTE_PATH],
  ['C:\\secret', C.WINDOWS_DRIVE],
  ['C:secret', C.WINDOWS_DRIVE],
  ['D:/secret', C.WINDOWS_DRIVE],
  ['\\\\server\\share\\file', C.WINDOWS_UNC],
  ['//server/share/file', C.WINDOWS_UNC],
  ['\\\\?\\C:\\file', C.WINDOWS_PREFIX],
  ['\\\\.\\pipe\\x', C.WINDOWS_PREFIX],
  ['file.txt:stream', C.ALTERNATE_DATA_STREAM],
  ['a:$DATA', C.ALTERNATE_DATA_STREAM],
  ['file.txt:hidden', C.ALTERNATE_DATA_STREAM],
  ['CON', C.WINDOWS_DEVICE],
  ['PRN', C.WINDOWS_DEVICE],
  ['AUX', C.WINDOWS_DEVICE],
  ['NUL', C.WINDOWS_DEVICE],
  ['COM1', C.WINDOWS_DEVICE],
  ['COM9.txt', C.WINDOWS_DEVICE],
  ['LPT1', C.WINDOWS_DEVICE],
  ['LPT9.log', C.WINDOWS_DEVICE],
  ['file.', C.TRAILING_DOT_OR_SPACE],
  ['file ', C.TRAILING_DOT_OR_SPACE],
  ['dir /file', C.TRAILING_DOT_OR_SPACE],
  ['a\u0000b', C.NULL_BYTE],
  ['a\u0001b', C.CONTROL_CHARACTER],
  ['a\nb', C.CONTROL_CHARACTER],
  ['a\rb', C.CONTROL_CHARACTER],
  ['a\u007fb', C.CONTROL_CHARACTER]
];

// One test per vector, so the suite reports each attack individually.
for (const [vector, code] of REJECTED_PATHS) {
  test('vector rejects: ' + JSON.stringify(vector), () => {
    throwsCode(() => cjs.resolveSafePath(vector, { root: ROOT }), code);
  });
}

const ENCODED_VECTORS = [
  '%2e%2e%2fsecret',
  '%2E%2E%2Fsecret',
  'a%2f%2e%2e%2fsecret',
  '%252e%252e%252fsecret',
  'foo%00.txt'
];

for (const vector of ENCODED_VECTORS) {
  test('encoded vector rejects: ' + vector, () => {
    const expected = vector.includes('%00')
      ? C.ENCODED_TRAVERSAL
      : C.ENCODED_TRAVERSAL;
    throwsCode(
      () => cjs.resolveSafePath(vector, { root: ROOT, decodeCheck: true }),
      expected
    );
  });
}

const ARCHIVE_VECTORS = [
  '/etc/passwd',
  '../evil.sh',
  '../../etc/passwd',
  'a/../../evil.sh',
  'a\\..\\evil.sh',
  'C:\\evil.dll',
  '\\\\server\\share\\evil',
  'file.txt:hidden',
  'CON',
  'file\u0000.txt',
  'file\n.txt'
];

for (const vector of ARCHIVE_VECTORS) {
  test('archive vector rejects: ' + JSON.stringify(vector), () => {
    let error;
    assert.throws(() => cjs.validateArchiveEntry(vector), (e) => {
      error = e;
      return true;
    });
    assert.equal(error.name, 'PathCageError');
    assert.ok(error.code.startsWith('ERR_PATHCAGE_'));
  });
}

const SAFE_PATHS = [
  'index.html',
  'a/b/c.txt',
  'a/./b.txt',
  'assets/img/logo.svg',
  'report-2026.pdf',
  '_hidden',
  'file.name.with.dots.txt',
  'UPPER.TXT',
  'a b c.txt',
  'unicode-é.txt'
];

for (const vector of SAFE_PATHS) {
  test('safe path accepts: ' + JSON.stringify(vector), () => {
    const expected = ROOT + '/' + vector.replace(/\.\//g, '');
    assert.equal(cjs.resolveSafePath(vector, { root: ROOT }), expected);
  });
}

const SAFE_FILENAMES = [
  ['plain.txt', 'plain.txt'],
  ['../../evil.txt', 'evil.txt'],
  ['..\\..\\evil.txt', 'evil.txt'],
  ['a/b/c.txt', 'c.txt'],
  ['file?.txt', 'file_.txt'],
  ['file*.txt', 'file_.txt'],
  ['file<>.txt', 'file__.txt'],
  ['file|pipe.txt', 'file_pipe.txt'],
  ['file"quote.txt', 'file_quote.txt'],
  ['CON', '_CON'],
  ['file.txt:hidden', 'file.txt_hidden'],
  ['file.txt.', 'file.txt']
];

for (const [input, expected] of SAFE_FILENAMES) {
  test('filename sanitizes: ' + JSON.stringify(input), () => {
    assert.equal(cjs.sanitizeFilename(input), expected);
  });
}
