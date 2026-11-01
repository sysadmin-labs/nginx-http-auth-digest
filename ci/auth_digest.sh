#!/bin/sh
#
# Drive the auth_digest module against a running nginx with a real HTTP
# client: the full RFC 2617 digest handshake, end to end.
#
# curl does the two round trips of digest for us (the 401 challenge and the
# authenticated retry), so this exercises what a client-library suite cannot
# express cleanly: a correct login, a wrong password and the brute-force
# evasion lockout.  This is also what the FreeBSD job, the sanitizer job and
# the valgrind job run.
#
# usage: ci/auth_digest.sh <nginx binary>
#
# Set AUTH_DIGEST_LOAD_MODULE to the path of ngx_http_auth_digest_module.so
# to test a loadable build.  Set AUTH_DIGEST_VALGRIND=1 to run one foreground
# nginx under valgrind and fail on any memory finding.

set -eu

NGINX=${1:?path to the nginx binary missing}
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${CI_WORK:-$SRC/ci-work}/auth_digest
PORT=${AUTH_DIGEST_PORT:-18670}

command -v curl > /dev/null || { echo "curl(1) is needed" >&2; exit 2; }

# FreeBSD has md5(1), Linux has md5sum(1); fall back to openssl.  Reads
# stdin, prints the lower-case hex digest only.
md5hex() {
	if command -v md5sum > /dev/null 2>&1; then
		md5sum | cut -d" " -f1
	elif command -v md5 > /dev/null 2>&1; then
		md5 -q
	else
		openssl md5 | sed "s/.*= //"
	fi
}

VG=${AUTH_DIGEST_VALGRIND:-}
vglog="$WORK/logs/valgrind.log"
maxtime=10
daemon_mode=on
master_mode=on
if [ -n "$VG" ]; then
	command -v valgrind > /dev/null || { echo "valgrind(1) is needed" >&2; exit 2; }
	daemon_mode=off
	master_mode=off
	maxtime=60
fi

rm -rf "$WORK"
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/root"

fail=0
note() { echo "  $1" >&2; fail=1; }

realm="restricted area"
user="alice"
pass="secret"
# htdigest file format: user:realm:md5(user:realm:password)
ha1=$(printf '%s:%s:%s' "$user" "$realm" "$pass" | md5hex)
printf '%s:%s:%s\n' "$user" "$realm" "$ha1" > "$WORK/conf/htdigest"

printf 'top secret\n' > "$WORK/root/secret.txt"
printf 'open\n' > "$WORK/root/open.txt"

load=
[ -n "${AUTH_DIGEST_LOAD_MODULE:-}" ] && load="load_module $AUTH_DIGEST_LOAD_MODULE;"

# Run as root (the FreeBSD job does) and nginx workers drop to "nobody";
# pin them to root so the worker can read the user file under $WORK.
ngx_user=
if [ "$(id -u)" = 0 ]; then
	ngx_user="user root $(id -gn);"
fi

cat > "$WORK/conf/nginx.conf" <<CONF
$load
$ngx_user
daemon $daemon_mode;
master_process $master_mode;
worker_processes 1;
pid $WORK/logs/nginx.pid;
error_log $WORK/logs/error.log info;
events { worker_connections 64; }
http {
    access_log off;

    server {
        listen 127.0.0.1:$PORT;
        root $WORK/root;

        location /open/ {
            alias $WORK/root/;
        }

        location / {
            auth_digest_user_file $WORK/conf/htdigest;
            auth_digest "$realm";
        }

        location /evasion/ {
            alias $WORK/root/;
            auth_digest_user_file $WORK/conf/htdigest;
            auth_digest "$realm";
            auth_digest_maxtries 2;
            auth_digest_evasion_time 30s;
        }
    }
}
CONF

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" -t 2> "$WORK/logs/t.log" ||
	{ cat "$WORK/logs/t.log" >&2; echo "ci/auth_digest.sh: config rejected" >&2; exit 1; }

ngxpid=
if [ -n "$VG" ]; then
	valgrind --leak-check=full --show-leak-kinds=definite,indirect \
		--errors-for-leak-kinds=definite,indirect --error-exitcode=99 \
		--log-file="$vglog" --suppressions="$SRC/valgrind.suppress" \
		--trace-children=no \
		"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
	ngxpid=$!
	up=0; i=0
	while [ $i -lt 80 ]; do
		if curl -s -o /dev/null --max-time 5 "http://127.0.0.1:$PORT/open.txt"; then
			up=1; break
		fi
		sleep 0.5; i=$((i + 1))
	done
	[ "$up" = 1 ] || { echo "ci/auth_digest.sh: nginx did not come up under valgrind" >&2; kill "$ngxpid" 2>/dev/null; exit 1; }
else
	"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"
	sleep 1
fi

stop() {
	if [ -n "$ngxpid" ]; then
		kill -QUIT "$ngxpid" 2>/dev/null
		wait "$ngxpid" 2>/dev/null
	elif [ -s "$WORK/logs/nginx.pid" ]; then
		kill -QUIT "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null
	fi
	return 0
}
trap stop EXIT INT TERM

base="http://127.0.0.1:$PORT"

echo "== an unprotected location is served without a challenge"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$maxtime" "$base/open/open.txt")
echo "  GET /open/ $code"; [ "$code" = 200 ] || note "unprotected GET not 200 ($code)"

echo "== a protected location challenges with Digest"
hdr=$(curl -s -D - -o /dev/null --max-time "$maxtime" "$base/secret.txt")
echo "$hdr" | grep -qiE '^HTTP/[0-9.]+ 401' || note "protected GET without credentials not 401"
wa=$(printf '%s' "$hdr" | awk 'tolower($1)=="www-authenticate:"{sub(/^[^:]*:[ ]*/,""); print; exit}' | tr -d '\r')
echo "  WWW-Authenticate: $wa"
printf '%s' "$wa" | grep -qi '^Digest'                  || note "challenge is not Digest"
printf '%s' "$wa" | grep -qi "realm=\"$realm\""          || note "challenge realm wrong"
printf '%s' "$wa" | grep -qi 'qop="auth"'                || note "challenge lacks qop=auth"
printf '%s' "$wa" | grep -qi 'nonce="'                   || note "challenge lacks a nonce"

echo "== the right password gets in"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$maxtime" --digest -u "$user:$pass" "$base/secret.txt")
echo "  GET /secret.txt (good creds) $code"; [ "$code" = 200 ] || note "correct digest login not 200 ($code)"
body=$(curl -s --max-time "$maxtime" --digest -u "$user:$pass" "$base/secret.txt")
[ "$body" = "top secret" ] || note "authenticated body wrong (\"$body\")"

echo "== the wrong password does not"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$maxtime" --digest -u "$user:wrong" "$base/secret.txt")
echo "  GET /secret.txt (bad creds) $code"; [ "$code" = 401 ] || note "wrong password not 401 ($code)"

echo "== repeated failures trip the evasion lockout"
# auth_digest_maxtries 2 on /evasion/: after two failed attempts the source
# is shut out for evasion_time.  The module then refuses every request up
# front with a bare 401 that carries no challenge, so even the right
# password cannot get in and the client has nothing to retry against.
curl -s -o /dev/null --max-time "$maxtime" --digest -u "$user:wrong" "$base/evasion/secret.txt" || true
curl -s -o /dev/null --max-time "$maxtime" --digest -u "$user:wrong" "$base/evasion/secret.txt" || true
h=$(curl -s -D - -o /dev/null --max-time "$maxtime" --digest -u "$user:$pass" "$base/evasion/secret.txt")
code=$(printf '%s' "$h" | awk 'NR==1{print $2}')
echo "  GET /evasion/ after lockout (good creds) $code"
[ "$code" = 401 ] || note "evasion lockout did not refuse the good password ($code)"
if printf '%s' "$h" | grep -qi '^WWW-Authenticate:'; then
	note "the evasion 401 still offered a challenge, so it was not a lockout"
fi

echo "== error log"
if grep -qE '\[(alert|emerg|crit)\]' "$WORK/logs/error.log"; then
	note "alert/emerg/crit in the error log"
	grep -E '\[(alert|emerg|crit)\]' "$WORK/logs/error.log" | head -3 >&2
else
	echo "  clean"
fi

if [ -n "$VG" ]; then
	echo "== valgrind"
	stop
	ngxpid=
	trap - EXIT INT TERM
	errs=$(sed -n 's/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p' "$vglog" | tail -1)
	defl=$(sed -n 's/.*definitely lost: \([0-9,]*\) bytes.*/\1/p' "$vglog" | tr -d , | tail -1)
	indl=$(sed -n 's/.*indirectly lost: \([0-9,]*\) bytes.*/\1/p' "$vglog" | tr -d , | tail -1)
	if [ "${errs:-0}" != 0 ] || [ "${defl:-0}" != 0 ] || [ "${indl:-0}" != 0 ]; then
		note "valgrind: ${errs:-?} errors, definitely lost ${defl:-?}, indirectly lost ${indl:-?}"
		grep -niE "Invalid read|Invalid write|uninitialised|Mismatched free" "$vglog" >&2
	else
		echo "  clean (errors $errs, suppressed shown in log)"
	fi
fi

[ "$fail" -eq 0 ] || { echo "ci/auth_digest.sh: failed" >&2; exit 1; }
echo "ci/auth_digest.sh: ok"
