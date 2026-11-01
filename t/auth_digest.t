#!/usr/bin/perl

# Tests for nginx-http-auth-digest.

###############################################################################

use warnings;
use strict;

use Test::More;
use Digest::MD5 qw/md5_hex/;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(10);

my $realm = 'restricted area';
my $user  = 'alice';
my $pass  = 'secret';

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /open.txt {
            root %%TESTDIR%%/html;
        }

        location / {
            root %%TESTDIR%%/html;
            auth_digest_user_file %%TESTDIR%%/htdigest;
            auth_digest "restricted area";
        }
    }
}

EOF

mkdir $t->testdir() . "/html";
$t->write_file('html/open.txt', 'open');
$t->write_file('html/secret.txt', 'top secret');

# htdigest line: user:realm:md5(user:realm:password)
my $ha1file = md5_hex("$user:$realm:$pass");
$t->write_file('htdigest', "$user:$realm:$ha1file\n");

$t->run();

###############################################################################

# an unprotected location needs no credentials
like(http_get('/open.txt'), qr!^HTTP/\S+ 200!m, 'unprotected location served');

# the protected location challenges
my $c = http_get('/secret.txt');
like($c, qr!^HTTP/\S+ 401!m, 'protected location returns 401');

my ($wa) = $c =~ /WWW-Authenticate:\s*(.+)/i;
$wa = '' unless defined $wa;
like($wa, qr/^Digest/i,                    'challenge is Digest');
like($wa, qr/realm="\Q$realm\E"/,          'challenge carries the realm');
like($wa, qr/qop="auth"/,                  'challenge offers qop=auth');
like($wa, qr/algorithm="MD5"/,             'challenge is algorithm MD5');
like($wa, qr/nonce="[^"]+"/,               'challenge carries a nonce');

# build and send a full qop=auth digest response
sub digest_get {
	my ($uri, $password) = @_;
	my $ch = http_get($uri);
	my ($realm_s) = $ch =~ /realm="([^"]+)"/;
	my ($nonce)   = $ch =~ /nonce="([^"]+)"/;
	my ($qop)     = $ch =~ /qop="([^"]+)"/;
	my $nc     = '00000001';
	my $cnonce = '0a4f113b';
	my $ha1 = md5_hex("$user:$realm_s:$password");
	my $ha2 = md5_hex("GET:$uri");
	my $resp = md5_hex("$ha1:$nonce:$nc:$cnonce:$qop:$ha2");
	my $auth = "Digest username=\"$user\", realm=\"$realm_s\", "
		. "nonce=\"$nonce\", uri=\"$uri\", qop=$qop, nc=$nc, "
		. "cnonce=\"$cnonce\", response=\"$resp\"";
	return http(<<"REQ");
GET $uri HTTP/1.0
Host: localhost
Authorization: $auth

REQ
}

my $good = digest_get('/secret.txt', $pass);
like($good, qr!^HTTP/\S+ 200!m, 'correct digest login is let in');
like($good, qr/top secret/,     'authenticated body is returned');

my $bad = digest_get('/secret.txt', 'wrongpass');
like($bad, qr!^HTTP/\S+ 401!m, 'wrong password is refused');

###############################################################################
