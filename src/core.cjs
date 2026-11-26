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
  UNICODE_NORMALIZATION: 'ERR_PATHCAGE_UNICODE_NORMALIZATION',
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
// C0 and C1 controls plus bidirectional formatting characters. Bidi overrides
// (U+202E and friends) are invisible and reverse the rendered order of the
// characters that follow them, which is the classic filename spoofing trick.
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/;
const UNSAFE_FILENAME_RE = /[\\/:*?"<>|\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
const DEFAULT_MAX_PATH_LENGTH = 4096;
const MAX_SYMLINK_HOPS = 40;
const MAX_DECODE_LAYERS = 8;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/*
 * Copy option bags explicitly. Object.assign would invoke the Object.prototype
 * __proto__ setter when a JSON parsed bag carries a "__proto__" key, which lets
 * an option such as decodeCheck or noSymlinks leak in through the prototype
 * chain. Reserved keys are rejected instead of silently rewiring options.
 */
function mergeOptions(...sources) {
  const target = {};
  for (const source of sources) {
    if (source === undefined || source === null) continue;
    if (!isPlainObject(source)) {
      fail(CODE.INVALID_INPUT, 'options must be an object', source);
    }
    for (const key of Object.keys(source)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        fail(CODE.INVALID_INPUT, 'reserved option key is not allowed', key);
      }
      target[key] = source[key];
    }
  }
  return target;
}

function asNonNegativeInteger(value, fallback, label) {
  if (value === undefined) return fallback;
  if (
    typeof value !== 'number' ||
    !Number.isFinite(value) ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    fail(CODE.INVALID_INPUT, label + ' must be a non-negative integer', value);
  }
  return value;
}

function normalizeOptions(options) {
  if (options === undefined) options = {};
  if (!isPlainObject(options)) {
    fail(CODE.INVALID_INPUT, 'options must be an object', options);
  }
  const merged = mergeOptions(options);
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

/*
 * Reject inputs whose Unicode compatibility form (NFKC) would introduce a
 * separator, navigation segment, drive marker, alternate data stream, device
 * name or trailing dot. A fullwidth slash or dot is a literal character for
 * the kernel, but any consumer that normalizes text before joining it into a
 * filesystem path turns it back into a real separator. When the normalized
 * form is still harmless the input is left untouched.
 */
function countSeparators(value) {
  let count = 0;
  for (const char of value) {
    if (char === '/' || char === '\\') count += 1;
  }
  return count;
}

function inspectUnicodeHazards(value, input) {
  const compat = value.normalize('NFKC');
  if (compat === value) return;
  // Normalization can only introduce separators, never remove one, so any
  // change in the total count means a compatibility character (fullwidth
  // slash, reverse solidus) has turned into a real separator.
  if (countSeparators(compat) !== countSeparators(value)) {
    fail(
      CODE.UNICODE_NORMALIZATION,
      'a path separator appears under Unicode NFKC normalization',
      input
    );
  }
  if (/^[a-zA-Z]:/.test(compat)) {
    fail(
      CODE.UNICODE_NORMALIZATION,
      'a drive marker appears under Unicode NFKC normalization',
      input
    );
  }
  if (CONTROL_RE.test(compat)) {
    fail(
      CODE.UNICODE_NORMALIZATION,
      'a control character appears under Unicode NFKC normalization',
      input
    );
  }
  for (const segment of compat.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..' || segment.startsWith('..')) {
      fail(
        CODE.UNICODE_NORMALIZATION,
        'a parent segment appears under Unicode NFKC normalization',
        input
      );
    }
    if (segment.includes(':')) {
      fail(
        CODE.UNICODE_NORMALIZATION,
        'an alternate data stream marker appears under Unicode NFKC normalization',
        input
      );
    }
    if (WINDOWS_DEVICE_RE.test(segment)) {
      fail(
        CODE.UNICODE_NORMALIZATION,
        'a reserved device name appears under Unicode NFKC normalization',
        input
      );
    }
    if (segment.endsWith('.') || segment.endsWith(' ')) {
      fail(
        CODE.UNICODE_NORMALIZATION,
        'a trailing dot or space appears under Unicode NFKC normalization',
        input
      );
    }
  }
}

/*
 * Decode every syntactically valid %HH run in one pass. Invalid UTF-8 inside a
 * run is reported instead of silently aborting the whole layer, which would
 * let "%2e%2e%2f%ZZ" hide a traversal behind a malformed tail.
 */
function decodePercentOnce(value) {
  let malformed = false;
  const text = value.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      malformed = true;
      return run;
    }
  });
  return { text, malformed };
}

function decodePercentLayers(value, input, inspect) {
  let layer = value;
  const seen = new Set([layer]);
  for (let depth = 1; depth <= MAX_DECODE_LAYERS; depth += 1) {
    const decoded = decodePercentOnce(layer);
    if (decoded.malformed) {
      fail(
        CODE.ENCODED_TRAVERSAL,
        'percent-encoded bytes are not valid UTF-8',
        input
      );
    }
    if (decoded.text === layer || seen.has(decoded.text)) break;
    seen.add(decoded.text);
    if (inspect) inspectDecodedLayer(decoded.text, input, depth);
    layer = decoded.text;
  }
  return layer;
}

function inspectDecodedLayer(decoded, input, depth) {
  const flat = decoded.replace(/\\/g, '/');
  const parts = flat.split('/');
  for (const part of parts) {
    // Any parent reference in a decoded layer is hostile. Unlike the raw
    // segment walk there is no legitimate reason to encode one.
    if (part === '..' || part.startsWith('..')) {
      fail(
        CODE.ENCODED_TRAVERSAL,
        'encoded traversal detected at decode layer ' + depth,
        input
      );
    }
  }
  if (/^[a-zA-Z]:/.test(flat)) {
    fail(
      CODE.ENCODED_TRAVERSAL,
      'encoded drive letter detected at decode layer ' + depth,
      input
    );
  }
  if (flat.startsWith('//')) {
    fail(
      CODE.ENCODED_TRAVERSAL,
      'encoded UNC path detected at decode layer ' + depth,
      input
    );
  }
  if (flat.startsWith('/')) {
    fail(
      CODE.ENCODED_TRAVERSAL,
      'encoded absolute path detected at decode layer ' + depth,
      input
    );
  }
  if (flat.includes('\u0000')) {
    fail(
      CODE.ENCODED_TRAVERSAL,
      'encoded null byte detected at decode layer ' + depth,
      input
    );
  }
  if (CONTROL_RE.test(decoded)) {
    fail(
      CODE.ENCODED_TRAVERSAL,
      'encoded control character detected at decode layer ' + depth,
      input
    );
  }
  if (decoded.includes('\\')) {
    fail(
      CODE.BACKSLASH_SEPARATOR,
      'encoded backslash separator detected at decode layer ' + depth,
      input
    );
  }
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part.includes(':')) {
      fail(
        CODE.ALTERNATE_DATA_STREAM,
        'encoded alternate data stream detected at decode layer ' + depth,
        input
      );
    }
    if (WINDOWS_DEVICE_RE.test(part)) {
      fail(
        CODE.WINDOWS_DEVICE,
        'encoded reserved device name detected at decode layer ' + depth,
        input
      );
    }
    if (part.endsWith('.') || part.endsWith(' ')) {
      fail(
        CODE.TRAILING_DOT_OR_SPACE,
        'encoded trailing dot or space detected at decode layer ' + depth,
        input
      );
    }
  }
  inspectUnicodeHazards(decoded, input);
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
  inspectUnicodeHazards(input, input);
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
    decodePercentLayers(input, input, true);
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

function applyDevicePrefix(candidate, replacement) {
  if (candidate === '') return candidate;
  return WINDOWS_DEVICE_RE.test(candidate) ? replacement + candidate : candidate;
}

function scrubFilename(text, replacement) {
  const segments = text
    .split(/[\\/]/)
    .filter((part) => part !== '' && part !== '.' && part !== '..');
  let candidate = segments.length > 0 ? segments[segments.length - 1] : '';
  candidate = candidate.replace(UNSAFE_FILENAME_RE, replacement);
  return candidate.replace(/[. ]+$/g, '');
}

/**
 * Turn arbitrary text into a single safe, flat filename.
 * Directory components, separators, control characters and Windows hazards
 * are removed or replaced. The result never contains a separator.
 *
 * Compatibility normalization runs first so that fullwidth separators and
 * dots cannot become real separators after the value leaves this function.
 * The fallback value goes through the same scrubbing as the input, and the
 * device-name check runs again after truncation, so neither path can return
 * a reserved name.
 */
function sanitizeFilename(input, options) {
  const opts = normalizeOptions(options);
  if (typeof input !== 'string') {
    fail(CODE.INVALID_INPUT, 'filename must be a string', input);
  }
  if (input.length === 0 && typeof opts.fallback !== 'string') {
    fail(CODE.INVALID_INPUT, 'filename must be a non-empty string', input);
  }
  if (input.length > opts.maxPathLength) {
    fail(CODE.LIMIT_EXCEEDED, 'filename exceeds maxPathLength', input);
  }
  const replacement = opts.replacement === undefined ? '_' : opts.replacement;
  if (
    typeof replacement !== 'string' ||
    replacement.length !== 1 ||
    replacement.includes('/') ||
    replacement.includes('\\') ||
    CONTROL_RE.test(replacement)
  ) {
    fail(CODE.INVALID_INPUT, 'replacement must be a single safe character', replacement);
  }
  let value = input.normalize('NFKC');
  if (opts.decodeCheck === true) {
    value = decodePercentLayers(value, input, false);
  }
  const maxLength = asNonNegativeInteger(opts.maxLength, 255, 'maxLength');
  const fallback = typeof opts.fallback === 'string' && opts.fallback.length > 0
    ? opts.fallback.normalize('NFKC')
    : null;
  let candidate = scrubFilename(value, replacement);
  if (candidate === '') {
    if (fallback !== null) candidate = scrubFilename(fallback, replacement);
  }
  if (candidate === '' || candidate === '.') {
    fail(CODE.INVALID_INPUT, 'filename has no safe characters left', input);
  }
  candidate = applyDevicePrefix(candidate, replacement);
  if (candidate.length > maxLength) {
    candidate = candidate.slice(0, maxLength).replace(/[. ]+$/g, '');
    candidate = applyDevicePrefix(candidate, replacement);
    if (candidate.length > maxLength) {
      candidate = candidate.slice(0, maxLength).replace(/[. ]+$/g, '');
    }
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
  const merged = mergeOptions(ARCHIVE_DEFAULTS, base);
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

/*
 * Unicode canonical normalization folds the names that case-insensitive
 * filesystems (APFS, HFS+, NTFS with normalization) treat as the same file,
 * and trailing separators fold "dir" and "dir/". Both would otherwise allow
 * a later entry to silently overwrite an earlier one.
 */
function archiveKey(normalizedPath, options) {
  const canonical = normalizedPath.normalize('NFC');
  return options.caseInsensitive === true ? canonical.toLowerCase() : canonical;
}

function validateLinkTarget(entry, normalizedPath, options) {
  const target = entry.linkTarget;
  if (typeof target !== 'string' || target.length === 0) {
    fail(CODE.ARCHIVE_LINK, 'link entry requires a non-empty linkTarget', entry);
  }
  if (target.length > options.maxPathLength) {
    fail(CODE.LIMIT_EXCEEDED, 'link target exceeds maxPathLength', entry);
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
  const normalized = path.posix
    .normalize(rawPath.replace(/\\/g, '/'))
    .replace(/\/+$/, '');
  if (
    normalized === '' ||
    normalized === '.' ||
    normalized === '..' ||
    normalized.startsWith('/') ||
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
  let state;
  if (opts.state === undefined) {
    state = { seen: new Set(), files: 0, totalSize: 0 };
  } else if (
    isPlainObject(opts.state) &&
    opts.state.seen instanceof Set &&
    typeof opts.state.files === 'number' &&
    typeof opts.state.totalSize === 'number'
  ) {
    state = opts.state;
  } else {
    fail(CODE.INVALID_INPUT, 'state must be an archive state object', opts.state);
  }
  if (state.files >= opts.maxFiles) {
    fail(CODE.ARCHIVE_LIMIT, 'archive file count exceeds maxFiles', rawEntry);
  }
  // Sizes are safe integers, so the sum below cannot silently round and the
  // limits compare exact values.
  if (entry.size > opts.maxFileSize) {
    fail(CODE.ARCHIVE_LIMIT, 'entry exceeds maxFileSize', rawEntry);
  }
  if (state.totalSize > opts.maxTotalSize - entry.size) {
    fail(CODE.ARCHIVE_LIMIT, 'archive exceeds maxTotalSize', rawEntry);
  }
  // Zero compressed size on a non-empty entry is the infinite-ratio bomb and
  // must be rejected before any division happens.
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
    return validateArchiveEntry(entry, mergeOptions(opts, { state }));
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

function lstatOrNull(target, input) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (!error) throw error;
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return null;
    if (error.code === 'ELOOP') {
      fail(CODE.SYMLINK_ESCAPE, 'symlink loop detected while resolving the path', input, error);
    }
    if (error.code === 'ENAMETOOLONG') {
      fail(CODE.LIMIT_EXCEEDED, 'path is too long for the filesystem', input, error);
    }
    throw error;
  }
}

function resolveRealAncestor(target, options) {
  // Walk every existing component from the filesystem root down to the
  // target. A symlink that sits directly under the filesystem root is a
  // platform alias such as /var or /tmp on macOS: no unprivileged principal
  // can create or replace it. Every deeper symlink is user controlled and is
  // rejected under the strict noSymlinks policy, regardless of where it
  // appears in the chain. Trusting only the first symlink seen would let a
  // user controlled ancestor through whenever no platform alias precedes it.
  const chain = [];
  let cursor = target;
  for (;;) {
    chain.push(cursor);
    if (cursor === path.dirname(cursor)) break;
    cursor = path.dirname(cursor);
  }
  chain.reverse();
  for (const component of chain) {
    let stat;
    try {
      stat = fs.lstatSync(component);
    } catch {
      continue;
    }
    if (!stat.isSymbolicLink()) continue;
    if (options.noSymlinks !== true) continue;
    if (path.dirname(component) === path.parse(component).root) continue;
    fail(CODE.FORBIDDEN_SYMLINK, 'symlink in root path is not allowed', target);
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
      if (!error) throw error;
      if (error.code === 'ELOOP') {
        fail(CODE.SYMLINK_ESCAPE, 'symlink loop detected while resolving the path', target, error);
      }
      if (error.code === 'ENAMETOOLONG') {
        fail(CODE.LIMIT_EXCEEDED, 'path is too long for the filesystem', target, error);
      }
      if (error.code !== 'ENOENT') throw error;
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
    const stat = lstatOrNull(next, relative);
    if (stat === null) {
      current = next;
      continue;
    }
    if (stat.isSymbolicLink()) {
      if (options.noSymlinks === true) {
        fail(CODE.FORBIDDEN_SYMLINK, 'symlink components are disabled', next);
      }
      let link;
      try {
        link = fs.readlinkSync(next);
      } catch (error) {
        if (error && error.code === 'ENOENT') {
          // The link disappeared between lstat and readlink; treat the
          // component as nonexistent rather than leaking a system error.
          current = next;
          continue;
        }
        throw error;
      }
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

  const rootStat = lstatOrNull(root, rootDir);
  if (rootStat === null && opts.mustExist === true) {
    fail(CODE.INVALID_ROOT, 'root directory does not exist', rootDir);
  }
  if (rootStat !== null) {
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
    return resolveSafePath(input, mergeOptions(opts, localOptions, { root }));
  }

  function realpathCheck(candidate, localOptions) {
    const merged = mergeOptions(opts, localOptions, { root });
    if (typeof candidate !== 'string' || candidate.length === 0) {
      fail(CODE.INVALID_INPUT, 'path must be a non-empty string', candidate);
    }
    let relative;
    if (path.isAbsolute(candidate)) {
      // Keep the lexical walk for absolute inputs as well. Resolving the
      // candidate with the filesystem first would erase the symlink names
      // and silently bypass the strict noSymlinks policy that relative
      // inputs are held to.
      const absolute = path.resolve(candidate);
      assertLexicalInside(root, absolute, candidate);
      relative = path.relative(root, absolute);
    } else {
      // Resolve relative inputs against the real root so that a symlinked
      // ancestor (for example /var on macOS) is never re-walked below here.
      const absolute = resolveSafePath(candidate, mergeOptions(merged, { root: rootReal }));
      relative = path.relative(rootReal, absolute);
    }
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
      const key = (sensitive ? result.toLowerCase() : result).normalize('NFC');
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
