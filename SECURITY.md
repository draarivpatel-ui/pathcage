# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Please report security issues privately using GitHub's "Report a vulnerability" feature on the repository's Security tab. Do not open a public issue for an exploitable finding.

Include:

- A minimal proof of concept (a path string, archive entry or symlink layout).
- The affected version and Node.js version.
- The expected containment boundary and the observed violation.
- An assessment of impact (for example: escape from an upload root, archive write outside destination).

You should receive an acknowledgement within 7 days. We will work with you on a fix and coordinate disclosure. Please give maintainers a reasonable window to release a patch before public disclosure.

## Scope

The following are in scope:

- Any input that makes a rejected path resolve outside its configured root.
- Any archive entry that causes a write, link or collision outside the extraction root.
- Symlink escapes, including chained, absolute and directory symlinks.
- Bypasses involving Windows path syntax, encoding layers, null bytes or control characters.
- Cumulative-limit bypasses in archive guards (file count, size, ratio, collisions).

The following are generally out of scope:

- Filesystem races where an attacker can freely modify the root after validation. `pathcage` validates paths, it does not lock files. Use OS-level isolation for hostile writable directories.
- Vulnerabilities in an application that ignores `PathCageError` or uses the original unvalidated path instead of the returned value.
- Resource exhaustion in the consuming extractor when it ignores archive metadata limits.

## Security design notes

- Containment is decided on path segments via `path.relative`, never on string prefixes. This prevents sibling-directory confusion.
- Lexical checks and real filesystem checks are separate. `createCage().resolve()` is lexical; `realpathCheck()` / `assertInside()` walk existing ancestors and every symlink hop.
- Archive validation is cumulative and stateful. Use `createArchiveGuard` for whole archives and never reuse a guard across unrelated archives without calling `reset()`.
- All comparisons that matter on case-insensitive filesystems are case-insensitive by default.

## Disclosure history

No published advisories yet. Fixed versions will be listed here with their advisory links.
