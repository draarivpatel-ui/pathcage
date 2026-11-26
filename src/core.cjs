'use strict';

/*
 * pathcage core.
 * Runtime dependencies: node:path, node:fs only.
 * This file is shared by the ESM entry (src/index.mjs) and the CJS entry
 * (cjs/index.cjs) so both module formats have identical behavior.
 */

const path = require('node:path');
const fs = require('node:fs');

const CODE = Object.freeze({
  INVALID_INPUT: 'ERR_PATHCAGE_INVALID_INPUT',
  INVALID_ROOT: 'ERR_PATHCAGE_INVALID_ROOT',
  NULL_BYTE: 'ERR_PATHCAGE_NULL_BYTE',
  CONTROL_CHARACTER: 'ERR_PATHCAGE_CONTROL_CHARACTER',
  ABSOLUTE_PATH: 'ERR_PATHCAGE_ABSOLUTE_PATH',
  TRAVERSAL: 'ERR_PATHCAGE_TRAVERSAL',
  ENCODED_TRAVERSAL: 'ERR_PATHCAGE_ENCODED_TRAVERSAL',
  WINDOWS_DRIVE: 'ERR_PATHCAGE_WINDOWS_DRIVE',
  WINDOWS_UNC: 'ERR_PATHCAGE_WINDOWS_UNC',
  WINDOWS_PREFIX: 'ERR_PATHCAGE_WINDOWS_PREFIX',
  WINDOWS_DEVICE: 'ERR_PATHCAGE_WINDOWS_DEVICE',
  ALTERNATE_DATA_STREAM: 'ERR_PATHCAGE_ALTERNATE_DATA_STREAM',
  TRAILING_DOT_OR_SPACE: 'ERR_PATHCAGE_TRAILING_DOT_OR_SPACE',
  BACKSLASH_SEPARATOR: 'ERR_PATHCAGE_BACKSLASH_SEPARATOR',
  OUTSIDE_ROOT: 'ERR_PATHCAGE_OUTSIDE_ROOT',
  FORBIDDEN_SYMLINK: 'ERR_PATHCAGE_FORBIDDEN_SYMLINK',
  SYMLINK_ESCAPE: 'ERR_PATHCAGE_SYMLINK_ESCAPE',
  DUPLICATE_PATH: 'ERR_PATHCAGE_DUPLICATE_PATH',
  LIMIT_EXCEEDED: 'ERR_PATHCAGE_LIMIT_EXCEEDED',
  ARCHIVE_PATH: 'ERR_PATHCAGE_ARCHIVE_PATH',
  ARCHIVE_TYPE: 'ERR_PATHCAGE_ARCHIVE_TYPE',
  ARCHIVE_LINK: 'ERR_PATHCAGE_ARCHIVE_LINK',
  ARCHIVE_LIMIT: 'ERR_PATHCAGE_ARCHIVE_LIMIT',
  ARCHIVE_ZIP_BOMB: 'ERR_PATHCAGE_ARCHIVE_ZIP_BOMB',
  ARCHIVE_COLLISION: 'ERR_PATHCAGE_ARCHIVE_COLLISION'
});

class PathCageError extends Error {
  constructor(code, reason, input, cause) {
    super(code + ': ' + reason);
    this.name = 'PathCageError';
    this.code = code;
    this.reason = reason;
    this.input = input;
    if (cause !== undefined) this.cause = cause;
  }

  toJSON() {
    return { name: this.name, code: this.code, reason: this.reason, input: this.input };
  }
}

function fail(code, reason, input, cause) {
  throw new PathCageError(code, reason, input, cause);
}

// Reserved device names are matched with or without one extension.
// "con.txt.bak" is a valid file name, so only one dot-isolated suffix counts.
const WINDOWS_DEVICE_RE = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.[^.]*)?$/i;
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
const UNSAFE_FILENAME_RE = /[\\/:*?"<>|\u0000-\u001f\u007f-\u009f]/g;
const DEFAULT_MAX_PATH_LENGTH = 4096;
const MAX_SYMLINK_HOPS = 40;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function asNonNegativeInteger(value, fallback, label) {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
    fail(CODE.INVALID_INPUT, label + ' must be a non-negative integer', value);
  }
  return value;
}

function normalizeOptions(options) {
  if (options === undefined) options = {};
  if (!isPlainObject(options)) {
    fail(CODE.INVALID_INPUT, 'options must be an object', options);
  }
  const merged = Object.assign({}, options);
  merged.maxPathLength = asNonNegativeInteger(
    options.maxPathLength, DEFAULT_MAX_PATH_LENGTH, 'maxPathLength'
  );
  return merged;
}

/*
 * Segment-aware containment. Never use string prefix checks here:
 * /app/uploads-evil must not be accepted as a child of /app/uploads.
 */
function assertLexicalInside(root, candidate, input) {
  const relative = path.relative(root, candidate);
  if (
    relative === '..' ||
    relative.startsWith('..' + path.sep) ||
    path.isAbsolute(relative) ||
    relative.includes('\u0000')
  ) {
    fail(CODE.OUTSIDE_ROOT, 'resolved path escapes the cage root', input, {
      root,
      candidate
    });
  }
  return candidate;
}

function isInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative !== '..' &&
    !relative.startsWith('..' + path.sep) &&
    !path.isAbsolute(relative);
}

function collectSegments(value, input) {
  const normalized = value.replace(/\\/g, '/');
  const segments = normalized.split('/');
  const result = [];
  let depth = 0;
  for (const segment of segments) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      depth -= 1;
      if (depth < 0) {
        fail(CODE.TRAVERSAL, 'parent directory segment is not allowed', input);
      }
    } else {
      // Reject lookalikes such as '..;', '....' and '%2e%2e' tails.
      if (segment.startsWith('..')) {
        fail(CODE.TRAVERSAL, 'parent directory segment is not allowed', input);
      }
      depth += 1;
    }
    result.push(segment);
  }
  return result;
}

function inspectDecodedLayer(decoded, input, depth) {
  const flat = decoded.replace(/\\/g, '/');
  const parts = flat.split('/');
  if (
    parts.includes('..') ||
    /^[a-zA-Z]:/.test(flat) ||
    flat.startsWith('//') ||
    flat.includes('\u0000') ||
    CONTROL_RE.test(decoded) ||
    /[\\/]/.test(decoded) && /%2e|%2f|%5c/i.test(decoded)
  ) {
    fail(
      CODE.ENCODED_TRAVERSAL,
      'encoded traversal or separator detected at decode layer ' + depth,
      input
    );
  }
  return decoded;
}

/*
 * String-level hygiene that is applied on every host platform. Windows attack
 * strings are rejected even when the library runs on POSIX, and vice versa.
 */
function inspectInput(input, options) {
  if (typeof input !== 'string' || input.length === 0) {
    fail(CODE.INVALID_INPUT, 'path must be a non-empty string', input);
  }
  if (input.length > options.maxPathLength) {
    fail(CODE.LIMIT_EXCEEDED, 'path exceeds maxPathLength', input);
  }
  if (input.includes('\u0000')) {
    fail(CODE.NULL_BYTE, 'null byte in path', input);
  }
  if (CONTROL_RE.test(input)) {
    fail(CODE.CONTROL_CHARACTER, 'control character in path', input);
  }
  if (/^[a-zA-Z]:\$/.test(input)) {
    fail(CODE.ALTERNATE_DATA_STREAM, 'alternate data stream is not allowed', input);
  }
  if (/^[a-zA-Z]:/.test(input)) {
    fail(CODE.WINDOWS_DRIVE, 'drive letter or drive-relative path is not allowed', input);
  }
  if (/^\\\\([?.]\\|[^\\])/i.test(input)) {
    fail(
      /^\\\\[?.]/i.test(input) ? CODE.WINDOWS_PREFIX : CODE.WINDOWS_UNC,
      /^\\\\[?.]/i.test(input)
        ? 'extended-length or device namespace prefix is not allowed'
        : 'UNC path is not allowed',
      input
    );
  }
  if (input.startsWith('//')) {
    if (/^\/\/[?./]/i.test(input) || /^\/\/[^/]+[/]/.test(input)) {
      fail(CODE.WINDOWS_UNC, 'UNC path is not allowed', input);
    }
    fail(CODE.WINDOWS_UNC, 'double slash path is not allowed', input);
  }
  if (input.includes('\\')) {
    fail(CODE.BACKSLASH_SEPARATOR, 'backslash separators are not allowed', input);
  }
  const segments = collectSegments(input, input);
  for (const segment of segments) {
    if (segment.includes(':')) {
      fail(CODE.ALTERNATE_DATA_STREAM, 'colon in path segment is not allowed', input);
    }
    if (WINDOWS_DEVICE_RE.test(segment)) {
      fail(CODE.WINDOWS_DEVICE, 'reserved Windows device name is not allowed', input);
    }
    if (segment !== '..' && (segment.endsWith('.') || segment.endsWith(' '))) {
      fail(CODE.TRAILING_DOT_OR_SPACE, 'trailing dot or space in path segment', input);
    }
  }
  if (options.decodeCheck === true) {
    let layer = input;
    const seen = new Set([layer]);
    for (let depth = 1; depth <= 3; depth += 1) {
      let decoded;
      try {
        decoded = decodeURIComponent(layer);
      } catch {
        break;
      }
      if (seen.has(decoded)) break;
      seen.add(decoded);
      inspectDecodedLayer(decoded, input, depth);
      layer = decoded;
    }
  }
  return segments;
}

function normalizeRoot(options) {
  const root = options.root;
  if (typeof root !== 'string' || root.length === 0) {
    fail(CODE.INVALID_ROOT, 'root must be a non-empty string', root);
  }
  return path.resolve(root);
}

/**
 * Resolve a user supplied relative path underneath options.root.
 * The returned absolute path is lexically guaranteed to be inside the root.
 */
function resolveSafePath(input, options) {
  const opts = normalizeOptions(options);
  const root = normalizeRoot(opts);
  if (typeof input !== 'string' || input.length === 0) {
    fail(CODE.INVALID_INPUT, 'path must be a non-empty string', input);
  }
  inspectInput(input, opts);
  if (path.isAbsolute(input)) {
    fail(CODE.ABSOLUTE_PATH, 'absolute paths are not accepted', input);
  }
  const candidate = path.resolve(root, input);
  return assertLexicalInside(root, candidate, input);
}

/** resolveSafePath that throws on any violation, returning the safe path. */
function assertSafePath(input, options) {
  return resolveSafePath(input, options);
}

/**
 * Turn arbitrary text into a single safe, flat filename.
 * Directory components, separators, control characters and Windows hazards
 * are removed or replaced. The result never contains a separator.
 */
function sanitizeFilename(input, options) {
  const opts = normalizeOptions(options);
  if (typeof input !== 'string') {
    fail(CODE.INVALID_INPUT, 'filename must be a string', input);
  }
  if (input.length === 0 && typeof opts.fallback !== 'string') {
    fail(CODE.INVALID_INPUT, 'filename must be a non-empty string', input);
  }
  let value = input;
  if (opts.decodeCheck === true) {
    for (let depth = 0; depth < 3; depth += 1) {
      let decoded;
      try {
        decoded = decodeURIComponent(value);
      } catch {
        break;
      }
      if (decoded === value) break;
      value = decoded;
    }
  }
  const rawSegments = value.split(/[\\/]/).filter((part) => part !== '' && part !== '.' && part !== '..');
  let candidate = rawSegments.length > 0 ? rawSegments[rawSegments.length - 1] : '';
  const replacement = opts.replacement === undefined ? '_' : opts.replacement;
  if (typeof replacement !== 'string' || replacement.length > 1 || replacement.includes('/') || replacement.includes('\\')) {
    fail(CODE.INVALID_INPUT, 'replacement must be a single safe character', replacement);
  }
  candidate = candidate.replace(UNSAFE_FILENAME_RE, replacement);
  candidate = candidate.replace(/[. ]+$/g, '');
  if (WINDOWS_DEVICE_RE.test(candidate)) {
    candidate = replacement + candidate;
  }
  if (candidate === '' || candidate === '.') {
    if (typeof opts.fallback === 'string' && opts.fallback.length > 0) {
      candidate = opts.fallback;
    } else {
      fail(CODE.INVALID_INPUT, 'filename has no safe characters left', input);
    }
  }
  const maxLength = asNonNegativeInteger(opts.maxLength, 255, 'maxLength');
  if (candidate.length > maxLength) {
    candidate = candidate.slice(0, maxLength).replace(/[. ]+$/g, '');
  }
  if (candidate === '' || candidate.includes('/') || candidate.includes('\\') || CONTROL_RE.test(candidate)) {
    fail(CODE.INVALID_INPUT, 'sanitized filename is not safe', input);
  }
  return candidate;
}

/* ------------------------------------------------------------------ *
 * Archive validation
 * ------------------------------------------------------------------ */

const ARCHIVE_DEFAULTS = Object.freeze({
  maxFiles: 10000,
  maxFileSize: 10 * 1024 * 1024,
  maxTotalSize: 100 * 1024 * 1024,
  maxCompressionRatio: 100,
  maxPathLength: DEFAULT_MAX_PATH_LENGTH,
  caseInsensitive: true,
  allowSymlinks: false,
  allowHardlinks: false,
  decodeCheck: true
});

function normalizeArchiveOptions(options) {
  const base = normalizeOptions(options);
  const merged = Object.assign({}, ARCHIVE_DEFAULTS, base);
  merged.maxFiles = asNonNegativeInteger(merged.maxFiles, ARCHIVE_DEFAULTS.maxFiles, 'maxFiles');
  merged.maxFileSize = asNonNegativeInteger(merged.maxFileSize, ARCHIVE_DEFAULTS.maxFileSize, 'maxFileSize');
  merged.maxTotalSize = asNonNegativeInteger(merged.maxTotalSize, ARCHIVE_DEFAULTS.maxTotalSize, 'maxTotalSize');
  if (
    typeof merged.maxCompressionRatio !== 'number' ||
    !Number.isFinite(merged.maxCompressionRatio) ||
    merged.maxCompressionRatio < 1
  ) {
    fail(CODE.INVALID_INPUT, 'maxCompressionRatio must be a finite number >= 1', merged.maxCompressionRatio);
  }
  return merged;
}

function normalizeArchiveEntry(raw) {
  if (typeof raw === 'string') {
    raw = { path: raw, type: 'file', size: 0 };
  }
  if (!isPlainObject(raw)) {
    fail(CODE.ARCHIVE_TYPE, 'archive entry must be an object or path string', raw);
  }
  const type = raw.type === undefined ? 'file' : raw.type;
  if (!['file', 'directory', 'symlink', 'hardlink'].includes(type)) {
    fail(CODE.ARCHIVE_TYPE, 'unsupported archive entry type', raw);
  }
  const size = asNonNegativeInteger(raw.size, 0, 'size');
  const compressedSize = asNonNegativeInteger(raw.compressedSize, size, 'compressedSize');
  return { path: raw.path, type, size, compressedSize, linkTarget: raw.linkTarget };
}

function archiveKey(normalizedPath, options) {
  return options.caseInsensitive === true ? normalizedPath.toLowerCase() : normalizedPath;
}

function validateLinkTarget(entry, normalizedPath, options) {
  const target = entry.linkTarget;
  if (typeof target !== 'string' || target.length === 0) {
    fail(CODE.ARCHIVE_LINK, 'link entry requires a non-empty linkTarget', entry);
  }
  // A relative symlink may legitimately contain '..' as long as it stays
  // inside the subtree containing the link. Resolving from the archive root
  // prevents a link from escaping with enough parent segments.
  if (path.posix.isAbsolute(target.replace(/\\/g, '/')) || /^[a-zA-Z]:/.test(target)) {
    fail(CODE.ARCHIVE_LINK, 'absolute link targets are not allowed', entry);
  }
  const probe = {
    maxPathLength: options.maxPathLength,
    decodeCheck: options.decodeCheck
  };
  if (target.includes('\\')) {
    fail(CODE.BACKSLASH_SEPARATOR, 'backslash separators in link target are not allowed', entry);
  }
  const flatTarget = target.replace(/\\/g, '/');
  // Inspect each ordinary segment with the host hygiene rules. Navigation
  // segments are handled by the explicit depth walk below.
  for (const segment of flatTarget.split('/')) {
    if (segment === '' || segment === '.' || segment === '..') continue;
    inspectInput(segment, normalizeOptions(probe));
  }
  // Resolve the target from the link's own directory. The resolved absolute
  // path must remain strictly under the virtual archive root '/'.
  const base = entry.type === 'hardlink' ? '/' : path.posix.dirname('/' + normalizedPath);
  // Walk segments explicitly: the link may not navigate above its own
  // directory. This rejects ../../etc/passwd from docs/link while allowing
  // ../README.md, and rejects a/../../../secret regardless of normalization.
  let depth = base === '/' ? 0 : base.split('/').filter(Boolean).length;
  for (const segment of flatTarget.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      depth -= 1;
      if (depth < 0) {
        fail(CODE.ARCHIVE_LINK, 'link target escapes the archive root', entry);
      }
    } else {
      depth += 1;
    }
  }
  const resolved = path.posix.resolve(base, flatTarget);
  const relativeToRoot = path.posix.relative('/', resolved);
  if (
    relativeToRoot === '..' ||
    relativeToRoot.startsWith('../') ||
    path.posix.isAbsolute(relativeToRoot)
  ) {
    fail(CODE.ARCHIVE_LINK, 'link target escapes the archive root', entry);
  }
  return resolved;
}

/**
 * Validate one archive entry. Stateful limits and collision detection are
 * supplied through options.state (created by createArchiveGuard), but can also
 * be supplied by any caller that owns its own state object.
 */
function validateArchiveEntry(rawEntry, options) {
  const opts = normalizeArchiveOptions(options);
  const entry = normalizeArchiveEntry(rawEntry);
  const rawPath = entry.path;
  if (typeof rawPath !== 'string' || rawPath.length === 0) {
    fail(CODE.ARCHIVE_PATH, 'archive entry path must be a non-empty string', rawEntry);
  }
  inspectInput(rawPath, opts);
  const normalized = path.posix.normalize(rawPath.replace(/\\/g, '/'));
  if (
    normalized === '.' ||
    normalized === './' ||
    normalized === '/' ||
    normalized.startsWith('/') ||
    normalized === '..' ||
    normalized.startsWith('../')
  ) {
    fail(CODE.ARCHIVE_PATH, 'archive entry path is absolute or empty after normalization', rawEntry);
  }
  if (entry.type === 'symlink' && opts.allowSymlinks !== true) {
    fail(CODE.ARCHIVE_LINK, 'symlink entries are disabled by default', rawEntry);
  }
  if (entry.type === 'hardlink' && opts.allowHardlinks !== true) {
    fail(CODE.ARCHIVE_LINK, 'hardlink entries are disabled by default', rawEntry);
  }
  let linkTarget = null;
  if (entry.type === 'symlink' || entry.type === 'hardlink') {
    linkTarget = validateLinkTarget(entry, normalized, opts);
  }
  if (entry.type === 'directory' && entry.size !== 0) {
    fail(CODE.ARCHIVE_LIMIT, 'directory entries must have size 0', rawEntry);
  }
  const state = opts.state || { seen: new Set(), files: 0, totalSize: 0 };
  if (state.files >= opts.maxFiles) {
    fail(CODE.ARCHIVE_LIMIT, 'archive file count exceeds maxFiles', rawEntry);
  }
  if (entry.size > opts.maxFileSize) {
    fail(CODE.ARCHIVE_LIMIT, 'entry exceeds maxFileSize', rawEntry);
  }
  if (state.totalSize + entry.size > opts.maxTotalSize) {
    fail(CODE.ARCHIVE_LIMIT, 'archive exceeds maxTotalSize', rawEntry);
  }
  if (entry.compressedSize === 0 && entry.size > 0) {
    fail(CODE.ARCHIVE_ZIP_BOMB, 'non-empty entry has zero compressed size', rawEntry);
  }
  if (entry.compressedSize > 0) {
    const ratio = entry.size / entry.compressedSize;
    if (ratio > opts.maxCompressionRatio) {
      fail(CODE.ARCHIVE_ZIP_BOMB, 'compression ratio exceeds maxCompressionRatio', rawEntry);
    }
  }
  const key = archiveKey(normalized, opts);
  if (state.seen.has(key)) {
    fail(CODE.ARCHIVE_COLLISION, 'duplicate or case-insensitive colliding archive path', rawEntry);
  }
  state.seen.add(key);
  state.files += 1;
  state.totalSize += entry.size;
  return {
    path: normalized,
    type: entry.type,
    size: entry.size,
    compressedSize: entry.compressedSize,
    linkTarget,
    key
  };
}

function createArchiveGuard(options) {
  const opts = normalizeArchiveOptions(options);
  const state = { seen: new Set(), files: 0, totalSize: 0 };

  function validate(entry) {
    // validateArchiveEntry updates the supplied state on success.
    return validateArchiveEntry(entry, Object.assign({}, opts, { state }));
  }

  function validateBatch(entries) {
    if (!Array.isArray(entries)) {
      fail(CODE.INVALID_INPUT, 'entries must be an array', entries);
    }
    return entries.map((entry) => validate(entry));
  }

  function stats() {
    return { files: state.files, totalSize: state.totalSize, paths: state.seen.size };
  }

  function reset() {
    state.seen.clear();
    state.files = 0;
    state.totalSize = 0;
  }

  return { validate, validateBatch, stats, reset };
}

/* ------------------------------------------------------------------ *
 * Cage: root containment with real filesystem symlink checks
 * ------------------------------------------------------------------ */

function resolveRealAncestor(target, options) {
  // Check the root itself and every explicit path component from the root up
  // to the first existing ancestor. A symlink in that user-controlled portion
  // is rejected under the strict noSymlinks policy. Ancestors above it (the
  // platform temp directory on macOS is a symlink) are out of scope.
  // Build the chain from the filesystem root down to the target, then start
  // checking at the first component that actually exists.
  const chain = [];
  let cursor = target;
  for (;;) {
    chain.push(cursor);
    if (cursor === path.dirname(cursor)) break;
    cursor = path.dirname(cursor);
  }
  chain.reverse();
  let active = false;
  let skippedPlatformLink = false;
  for (const component of chain) {
    let stat;
    try {
      stat = fs.lstatSync(component);
    } catch {
      continue;
    }
    if (!active) {
      active = true;
      continue;
    }
    // Platform-provided symlinks such as /var -> /private/var on macOS
    // are trusted once. User-controlled symlinks are not.
    if (!skippedPlatformLink && stat.isSymbolicLink()) {
      skippedPlatformLink = true;
      continue;
    }
    if (options.noSymlinks === true && stat.isSymbolicLink()) {
      fail(CODE.FORBIDDEN_SYMLINK, 'symlink in root path is not allowed', target);
    }
  }
  // Resolve the deepest existing ancestor and reattach any missing tail,
  // so nonexistent leaf paths are still canonical underneath their parent.
  let realCursor = target;
  const tail = [];
  for (;;) {
    try {
      let real = fs.realpathSync(realCursor);
      while (tail.length > 0) real = path.join(real, tail.pop());
      return real;
    } catch (error) {
      if (!error || error.code !== 'ENOENT') throw error;
      const parent = path.dirname(realCursor);
      if (parent === realCursor) return target;
      tail.push(path.basename(realCursor));
      realCursor = parent;
    }
  }
}

/*
 * Walk each existing path component below root. Symlinks are checked at every
 * level, including the final target, so a link leaf cannot escape the cage.
 */
function canonicalizeInside(rootReal, relative, options, hops) {
  if (hops > MAX_SYMLINK_HOPS) {
    fail(CODE.LIMIT_EXCEEDED, 'too many symlink hops', relative);
  }
  const queue = relative.split(path.sep).filter((part) => part !== '' && part !== '.');
  let current = rootReal;
  while (queue.length > 0) {
    const segment = queue.shift();
    const next = path.join(current, segment);
    let stat;
    try {
      stat = fs.lstatSync(next);
    } catch (error) {
      if (error && (error.code === 'ENOENT' || error.code === 'ENOTDIR')) {
        current = next;
        continue;
      }
      throw error;
    }
    if (stat.isSymbolicLink()) {
      if (options.noSymlinks === true) {
        fail(CODE.FORBIDDEN_SYMLINK, 'symlink components are disabled', next);
      }
      const link = fs.readlinkSync(next);
      if (/^[a-zA-Z]:/.test(link)) {
        fail(CODE.SYMLINK_ESCAPE, 'drive-letter symlink target is not allowed', link);
      }
      const rawResolved = path.isAbsolute(link)
        ? path.resolve(link)
        : path.resolve(path.dirname(next), link);
      const resolved = resolveRealAncestor(rawResolved, { noSymlinks: false });
      if (!isInside(rootReal, resolved)) {
        fail(CODE.SYMLINK_ESCAPE, 'symlink target resolves outside the cage root', link);
      }
      current = canonicalizeInside(
        rootReal,
        path.relative(rootReal, resolved),
        options,
        hops + 1
      );
      continue;
    }
    current = next;
  }
  return current;
}

function normalizeCageOptions(rootDir, options) {
  const opts = normalizeOptions(options);
  if (typeof rootDir !== 'string' || rootDir.length === 0) {
    fail(CODE.INVALID_ROOT, 'rootDir must be a non-empty string', rootDir);
  }
  if (opts.noSymlinks === undefined) opts.noSymlinks = true;
  if (opts.allowSymlinksInsideRoot === true) opts.noSymlinks = false;
  if (opts.caseInsensitive === undefined) opts.caseInsensitive = true;
  return opts;
}

/** Create a cage bound to a root directory. */
function createCage(rootDir, options) {
  const opts = normalizeCageOptions(rootDir, options);
  const root = path.resolve(rootDir);

  let rootStat;
  try {
    rootStat = fs.lstatSync(root);
  } catch (error) {
    if (!error || (error.code !== 'ENOENT' && error.code !== 'ENOTDIR')) throw error;
    if (opts.mustExist === true) {
      fail(CODE.INVALID_ROOT, 'root directory does not exist', rootDir, error);
    }
  }
  if (rootStat) {
    if (rootStat.isSymbolicLink()) {
      if (opts.noSymlinks === true) {
        fail(CODE.FORBIDDEN_SYMLINK, 'root directory is a symlink', rootDir);
      }
    } else if (!rootStat.isDirectory()) {
      fail(CODE.INVALID_ROOT, 'root is not a directory', rootDir);
    }
  }
  const rootReal = resolveRealAncestor(root, opts);

  function resolve(input, localOptions) {
    return resolveSafePath(input, Object.assign({}, opts, localOptions, { root }));
  }

  function realpathCheck(candidate, localOptions) {
    const merged = Object.assign({}, opts, localOptions, { root });
    let absolute;
    if (typeof candidate === 'string' && path.isAbsolute(candidate)) {
      absolute = path.resolve(candidate);
      assertLexicalInside(root, absolute, candidate);
      const realCandidate = resolveRealAncestor(absolute, {
        noSymlinks: false
      });
      if (!isInside(rootReal, realCandidate)) {
        fail(CODE.SYMLINK_ESCAPE, 'candidate is outside the real root', candidate);
      }
      absolute = realCandidate;
    } else {
      // Resolve relative inputs against the real root so that a symlinked
      // ancestor (for example /var on macOS) is never re-walked below here.
      absolute = resolveSafePath(candidate, Object.assign({}, merged, { root: rootReal }));
    }
    const relative = path.relative(rootReal, absolute);
    return canonicalizeInside(rootReal, relative, merged, 0);
  }

  function assertInside(candidate, localOptions) {
    return realpathCheck(candidate, localOptions);
  }

  function validateBatch(inputs, localOptions) {
    if (!Array.isArray(inputs)) {
      fail(CODE.INVALID_INPUT, 'inputs must be an array', inputs);
    }
    const seen = new Set();
    const sensitive = opts.caseInsensitive === true;
    return inputs.map((input) => {
      const result = assertInside(input, localOptions);
      const key = sensitive ? result.toLowerCase() : result;
      if (seen.has(key)) {
        fail(CODE.DUPLICATE_PATH, 'duplicate or case-insensitive colliding path', input);
      }
      seen.add(key);
      return result;
    });
  }

  return {
    root,
    rootReal,
    resolve,
    realpathCheck,
    assertInside,
    validateBatch
  };
}

module.exports = {
  CODE,
  PathCageError,
  resolveSafePath,
  assertSafePath,
  sanitizeFilename,
  validateArchiveEntry,
  createArchiveGuard,
  createCage,
  isInside,
  assertLexicalInside
};
