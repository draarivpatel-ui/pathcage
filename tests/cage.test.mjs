import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach } from 'node:test';
import { cjs, esm, tempDir, throwsCode } from './helpers.mjs';

const C = cjs.CODE;
const cleanups = [];

function makeTemp(label) {
  const t = tempDir(label);
  cleanups.push(t.cleanup);
  return t;
}

afterEach(() => {
  while (cleanups.length > 0) {
    try { cleanups.pop()(); } catch { /* ignore cleanup races */ }
  }
});

test('cage exposes root and resolves paths lexically', () => {
  const t = makeTemp('basic');
  fs.mkdirSync(path.join(t.dir, 'sub'));
  const cage = cjs.createCage(t.dir);
  assert.equal(cage.root, path.resolve(t.dir));
  assert.equal(cage.rootReal, fs.realpathSync(t.dir));
  assert.equal(cage.resolve('a.txt'), path.join(cage.root, 'a.txt'));
  assert.equal(cage.resolve('sub/b.txt'), path.join(cage.root, 'sub/b.txt'));
  throwsCode(() => cage.resolve('../secret'), C.TRAVERSAL);
  throwsCode(() => cage.resolve('/etc/passwd'), C.ABSOLUTE_PATH);
});

test('cage requires a valid root', () => {
  throwsCode(() => cjs.createCage(''), C.INVALID_ROOT);
  throwsCode(() => cjs.createCage(42), C.INVALID_ROOT);
  const t = makeTemp('file-root');
  const file = path.join(t.dir, 'root.txt');
  fs.writeFileSync(file, 'x');
  throwsCode(() => cjs.createCage(file), C.INVALID_ROOT);
  const missing = path.join(t.dir, 'missing');
  throwsCode(() => cjs.createCage(missing, { mustExist: true }), C.INVALID_ROOT);
  assert.equal(cjs.createCage(missing).root, missing);
});

test('realpathCheck accepts plain existing and nonexisting paths', () => {
  const t = makeTemp('plain');
  fs.mkdirSync(path.join(t.dir, 'sub'));
  fs.writeFileSync(path.join(t.dir, 'sub', 'file.txt'), 'hello');
  const cage = cjs.createCage(t.dir);
  assert.equal(
    cage.realpathCheck('sub/file.txt'),
    fs.realpathSync(path.join(t.dir, 'sub/file.txt'))
  );
  assert.equal(
    cage.assertInside('sub/new.txt'),
    path.join(fs.realpathSync(t.dir), 'sub/new.txt')
  );
});

test('strict noSymlinks default rejects a leaf symlink inside the root', () => {
  const t = makeTemp('leaf-strict');
  const inside = path.join(t.dir, 'inside.txt');
  const link = path.join(t.dir, 'link.txt');
  fs.writeFileSync(inside, 'safe');
  fs.symlinkSync(inside, link);
  const cage = cjs.createCage(t.dir);
  throwsCode(() => cage.realpathCheck('link.txt'), C.FORBIDDEN_SYMLINK);
  throwsCode(() => cage.assertInside('link.txt'), C.FORBIDDEN_SYMLINK);
});

test('strict noSymlinks default rejects a directory symlink inside the root', () => {
  const t = makeTemp('dir-strict');
  fs.mkdirSync(path.join(t.dir, 'real'));
  fs.symlinkSync(path.join(t.dir, 'real'), path.join(t.dir, 'alias'));
  const cage = cjs.createCage(t.dir);
  throwsCode(() => cage.realpathCheck('alias/file.txt'), C.FORBIDDEN_SYMLINK);
});

test('real symlink escape to an outside file is rejected', () => {
  const t = makeTemp('escape-outside');
  const outside = path.join(t.dir, 'outside.txt');
  const root = path.join(t.dir, 'root');
  fs.mkdirSync(root);
  fs.writeFileSync(outside, 'secret');
  fs.symlinkSync(outside, path.join(root, 'leak.txt'));
  const cage = cjs.createCage(root, { noSymlinks: false });
  throwsCode(() => cage.realpathCheck('leak.txt'), C.SYMLINK_ESCAPE);
  throwsCode(() => cage.assertInside('leak.txt'), C.SYMLINK_ESCAPE);
});

test('real symlink escape to an outside directory is rejected', () => {
  const t = makeTemp('escape-dir');
  const outside = path.join(t.dir, 'outside');
  const root = path.join(t.dir, 'root');
  fs.mkdirSync(outside);
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'secret');
  fs.symlinkSync(outside, path.join(root, 'alias'));
  const cage = cjs.createCage(root, { noSymlinks: false });
  throwsCode(() => cage.realpathCheck('alias/secret.txt'), C.SYMLINK_ESCAPE);
});

test('absolute symlink targets are contained when they point inside the root', () => {
  const t = makeTemp('absolute-link');
  const root = path.join(t.dir, 'root');
  fs.mkdirSync(root);
  const target = path.join(root, 'real.txt');
  fs.writeFileSync(target, 'data');
  fs.symlinkSync(target, path.join(root, 'abs.txt'));
  const cage = cjs.createCage(root, { noSymlinks: false });
  assert.equal(cage.realpathCheck('abs.txt'), fs.realpathSync(target));
  // An absolute target pointing outside is still rejected.
  const outside = path.join(t.dir, 'outside.txt');
  fs.writeFileSync(outside, 'secret');
  fs.symlinkSync(outside, path.join(root, 'leak.txt'));
  throwsCode(() => cage.realpathCheck('leak.txt'), C.SYMLINK_ESCAPE);
});

test('allowSymlinksInsideRoot accepts an internal symlink and returns its real path', () => {
  const t = makeTemp('internal-link');
  const root = path.join(t.dir, 'root');
  fs.mkdirSync(path.join(root, 'sub'), { recursive: true });
  const target = path.join(root, 'sub', 'real.txt');
  fs.writeFileSync(target, 'safe');
  fs.symlinkSync(target, path.join(root, 'alias.txt'));
  const cage = cjs.createCage(root, { allowSymlinksInsideRoot: true });
  assert.equal(
    cage.realpathCheck('alias.txt'),
    fs.realpathSync(target)
  );
  assert.equal(cage.assertInside('alias.txt'), fs.realpathSync(target));
});

test('allowSymlinksInsideRoot still rejects an escaping symlink', () => {
  const t = makeTemp('internal-escape');
  const outside = path.join(t.dir, 'outside.txt');
  const root = path.join(t.dir, 'root');
  fs.mkdirSync(root);
  fs.writeFileSync(outside, 'secret');
  fs.symlinkSync(outside, path.join(root, 'leak.txt'));
  const cage = cjs.createCage(root, { allowSymlinksInsideRoot: true });
  throwsCode(() => cage.realpathCheck('leak.txt'), C.SYMLINK_ESCAPE);
});

test('chained symlinks are followed hop by hop and contained', () => {
  const t = makeTemp('chain');
  const root = path.join(t.dir, 'root');
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, 'real.txt'), 'safe');
  fs.symlinkSync(path.join(root, 'real.txt'), path.join(root, 'a.txt'));
  fs.symlinkSync(path.join(root, 'a.txt'), path.join(root, 'b.txt'));
  const cage = cjs.createCage(root, { allowSymlinksInsideRoot: true });
  assert.equal(cage.realpathCheck('b.txt'), fs.realpathSync(path.join(root, 'real.txt')));
});

test('chained symlinks that escape on a later hop are rejected', () => {
  const t = makeTemp('chain-escape');
  const outside = path.join(t.dir, 'outside.txt');
  const root = path.join(t.dir, 'root');
  fs.mkdirSync(root);
  fs.writeFileSync(outside, 'secret');
  fs.symlinkSync(outside, path.join(root, 'a.txt'));
  fs.symlinkSync(path.join(root, 'a.txt'), path.join(root, 'b.txt'));
  const cage = cjs.createCage(root, { allowSymlinksInsideRoot: true });
  throwsCode(() => cage.realpathCheck('b.txt'), C.SYMLINK_ESCAPE);
});

test('symlink pointing to a sibling with the same prefix is rejected', () => {
  const t = makeTemp('sibling');
  const root = path.join(t.dir, 'uploads');
  const sibling = path.join(t.dir, 'uploads-evil');
  fs.mkdirSync(root);
  fs.mkdirSync(sibling);
  fs.writeFileSync(path.join(sibling, 'secret.txt'), 'secret');
  fs.symlinkSync(path.join(sibling, 'secret.txt'), path.join(root, 'leak.txt'));
  const cage = cjs.createCage(root, { allowSymlinksInsideRoot: true });
  throwsCode(() => cage.realpathCheck('leak.txt'), C.SYMLINK_ESCAPE);
});

test('symlink in cage root itself is rejected under strict default', () => {
  const t = makeTemp('root-link');
  const real = path.join(t.dir, 'real');
  fs.mkdirSync(real);
  const link = path.join(t.dir, 'link');
  fs.symlinkSync(real, link);
  throwsCode(() => cjs.createCage(link), C.FORBIDDEN_SYMLINK);
});

test('symlink in an existing ancestor of the root is rejected under strict default', () => {
  const t = makeTemp('ancestor-link');
  const real = path.join(t.dir, 'real');
  fs.mkdirSync(path.join(real, 'root'), { recursive: true });
  const link = path.join(t.dir, 'link');
  fs.symlinkSync(real, link);
  throwsCode(() => cjs.createCage(path.join(link, 'root')), C.FORBIDDEN_SYMLINK);
});

test('validateBatch rejects case-insensitive collisions and duplicates', () => {
  const t = makeTemp('batch');
  fs.mkdirSync(path.join(t.dir, 'sub'));
  const cage = cjs.createCage(t.dir);
  assert.deepEqual(cage.validateBatch(['a.txt', 'sub/b.txt']), [
    path.join(cage.rootReal, 'a.txt'),
    path.join(cage.rootReal, 'sub/b.txt')
  ]);
  throwsCode(() => cage.validateBatch(['README.md', 'readme.md']), C.DUPLICATE_PATH);
  throwsCode(() => cage.validateBatch(['a.txt', 'a.txt']), C.DUPLICATE_PATH);
  throwsCode(() => cage.validateBatch('not-array'), C.INVALID_INPUT);
  assert.equal(cage.validateBatch(['ONE.txt', 'two.txt'], { caseInsensitive: false }).length, 2);
});

test('cage realpathCheck rejects absolute paths outside the root', () => {
  const t = makeTemp('absolute-candidate');
  const root = path.join(t.dir, 'root');
  fs.mkdirSync(root);
  const cage = cjs.createCage(root);
  assert.throws(
    () => cage.realpathCheck(path.join(t.dir, 'outside.txt')),
    (e) => e.name === 'PathCageError' &&
      [C.OUTSIDE_ROOT, C.SYMLINK_ESCAPE].includes(e.code)
  );
  const inside = path.join(root, 'ok.txt');
  assert.equal(cage.realpathCheck(inside), path.join(fs.realpathSync(root), 'ok.txt'));
});

test('ESM and CJS cages agree on realpaths', () => {
  const t = makeTemp('parity');
  fs.mkdirSync(path.join(t.dir, 'sub'));
  const file = path.join(t.dir, 'sub', 'f.txt');
  fs.writeFileSync(file, 'data');
  assert.equal(
    esm.createCage(t.dir).realpathCheck('sub/f.txt'),
    cjs.createCage(t.dir).realpathCheck('sub/f.txt')
  );
});

test('all test temp directories are under os.tmpdir()', () => {
  const t = makeTemp('location');
  assert.equal(path.dirname(t.dir), os.tmpdir());
  assert.ok(path.basename(t.dir).startsWith('pathcage-'));
});
