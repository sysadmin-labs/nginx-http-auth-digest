# Changelog

## Unreleased

### Fixed

- CI: the Test::Nginx cache is now keyed by the Perl build, not just by
  the runner OS.  When the hosted image moved to Ubuntu 26.04 the cached
  `~/perl5` tree was restored against a new interpreter and every test
  file died before its first assertion with `loadable library and perl
  binaries are mismatched`, taking Build & Test, A/UBSan and Valgrind
  down together.

## 1.0.2 (2026-11-16)

### Fixed

- **A one-byte heap overflow on every unauthenticated request.**
  `ngx_http_auth_digest_send_challenge` sizes the `WWW-Authenticate`
  value, allocates exactly that much, and then filled it with two
  `ngx_cpymem` calls that used `sizeof(...)` instead of
  `sizeof(...) - 1`: the terminator came along, and `challenge.len` does
  not account for one. Measured at run time with a realm of fifteen
  characters: eighty-five bytes allocated, eighty-six written, in both
  the stale and the ordinary branch.

  Any request to a protected location reaches it, so anyone can, and it
  needs no credentials. What it corrupts is whatever the request pool
  handed out next.

  It had been invisible to the sanitizer workflow, because the allocation
  comes from the request pool: `ngx_pnalloc` hands out a slice of a block
  that the allocator sees as one piece, and a write just past the slice
  lands inside memory ASan had handed over whole. Building with
  `-DNGX_DEBUG_PALLOC=1`, which sends every allocation straight to
  malloc, is what brought it out -- ASan then reports
  `heap-buffer-overflow ... 0 bytes after 85-byte region` and takes the
  worker down with it, on the first request.

## 1.0.1 (2026-11-01)

Taken over as a maintained fork of atomx/nginx-http-auth-digest, itself a
fork of the original samizdatco module.  Upstream last changed in 2021 and
its newest tag is 1.0.0; this release is the head of its master branch,
built and tested against current nginx.

- Carries the one fix that sits unreleased on upstream master above the 1.0.0
  tag: `!` is accepted as a valid token character when parsing the
  Authorization header, so a client that sends an unquoted `!` in a field no
  longer fails the parse.

No behaviour of the module itself is changed otherwise; the work in this
release is the build, the test harness and the packaging.

The `t/` suite computes the RFC 2617 digest response itself (core Perl's
Digest::MD5) and asserts the challenge fields, a correct login, and a wrong
password.  `ci/auth_digest.sh` drives the same with curl, which performs the
full two round-trip handshake, and additionally exercises the brute-force
evasion lockout.

Valgrind runs against that end-to-end driver, not the Test::Nginx suite: the
driver starts one foreground nginx under valgrind and stops it with QUIT, so
the pools are freed and a leak report would be the module's own; it is clean.
