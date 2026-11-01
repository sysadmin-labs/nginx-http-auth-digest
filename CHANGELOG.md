# Changelog

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
