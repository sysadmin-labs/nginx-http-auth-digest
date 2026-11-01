# nginx-http-auth-digest

[![Build&Test][build-test-badge]][build-test-link]
[![Digest auth][digest-badge]][digest-link]
[![FreeBSD][freebsd-badge]][freebsd-link]
[![A/UBSan][sanitizers-badge]][sanitizers-link]
[![Valgrind][valgrind-badge]][valgrind-link]
[![Reload][reload-badge]][reload-link]
[![CodeQL][codeql-badge]][codeql-link]
[![Lint][lint-badge]][lint-link]

[build-test-badge]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/build-test.yml/badge.svg
[build-test-link]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/build-test.yml
[digest-badge]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/auth_digest.yml/badge.svg
[digest-link]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/auth_digest.yml
[freebsd-badge]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/freebsd.yml/badge.svg
[freebsd-link]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/freebsd.yml
[sanitizers-badge]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/sanitizers.yml/badge.svg
[sanitizers-link]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/sanitizers.yml
[valgrind-badge]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/valgrind.yml/badge.svg
[valgrind-link]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/valgrind.yml
[reload-badge]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/reload.yml/badge.svg
[reload-link]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/reload.yml
[codeql-badge]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/codeql.yml/badge.svg
[codeql-link]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/codeql.yml
[lint-badge]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/lint.yml/badge.svg
[lint-link]: https://github.com/sysadmin-labs/nginx-http-auth-digest/actions/workflows/lint.yml

This module supplements nginx's built-in Basic authentication with support
for RFC 2617 Digest authentication, so a password never crosses the wire in
the clear.  It is a maintained fork of atomx/nginx-http-auth-digest.

## Synopsis

```nginx
http {
    # optional; this is the default
    auth_digest_shm_size 4m;

    server {
        location /private/ {
            auth_digest_user_file /etc/nginx/htdigest;
            auth_digest "restricted area";   # the realm
        }
    }
}
```

The user file is in the Apache `htdigest` format, one `user:realm:HA1` line
per entry, where `HA1` is `md5(user:realm:password)`.  It can be made with
Apache's `htdigest` tool or with the `htdigest.py` helper in this
repository.

## Directives

- `auth_digest "<realm>"`: protect this location with the given realm; an
  empty string `off` disables it in a nested location.
- `auth_digest_user_file <path>`: the `htdigest` file to check against.
- `auth_digest_shm_size <size>`: shared memory for tracking issued nonces,
  set in the `http` block (default 4m).
- `auth_digest_timeout <time>`: how long a client has to answer a challenge
  (default 60s).
- `auth_digest_expires <time>`: how long a nonce stays valid after the first
  successful authentication (default 10s).
- `auth_digest_replays <number>`: how many requests may reuse one nonce
  (default 20).
- `auth_digest_maxtries <number>`: failed attempts from one address before
  it is locked out (default 3).
- `auth_digest_evasion_time <time>`: how long that lockout lasts (default
  300s).

## Building

```sh
./configure --add-module=/path/to/nginx-http-auth-digest
```

or as a loadable module

```sh
./configure --add-dynamic-module=/path/to/nginx-http-auth-digest
```

with `load_module modules/ngx_http_auth_digest_module.so;` in the main
context.  The module is self-contained and needs no extra libraries.

## Testing

```sh
ci/build.sh 1.30.5 /tmp/nginx-test
TEST_NGINX_BINARY=/tmp/nginx-test/sbin/nginx prove -r t/
ci/auth_digest.sh /tmp/nginx-test/sbin/nginx
ci/reload.sh /tmp/nginx-test/sbin/nginx
```

The `t/` suite computes the digest response itself and needs only core Perl;
the nginx core `Test::Nginx` is vendored under `t/lib`.  `ci/auth_digest.sh`
needs only `curl`, which performs the full digest handshake, and drives a
correct login, a wrong password and the brute-force evasion lockout end to
end.

## License

BSD 2-Clause, see [LICENSE](LICENSE).
