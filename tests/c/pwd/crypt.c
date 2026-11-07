/*
 * crypt and crypt_r: the traditional DES hash and BSDi's extended form beside
 * the $ hashes, and the settings they refuse.
 *
 * The DES hashes of settings in the alphabet are libxcrypt's, from perl's
 * crypt. The two with bytes above 0x7f are the self-test vectors of musl
 * 1.2.5's crypt_des.c, and the MD5 one is libc-test's crypt.c (both MIT).
 */

#include <crypt.h>
#include <string.h>

#include "check.h"

#define TEST_KEY "\x80\xff\x80\x01 \x7f\x81\x80\x80\x0d\x0a\xff\x7f \x81 test"

static int is(const char *got, const char *want)
{
	return got && strcmp(got, want) == 0;
}

int main(void)
{
	CHECK(is(crypt("password", "ab"), "abJnggxhB/yWI"));
	CHECK(is(crypt("", ".."), "..X8NBuQ4l6uQ"));
	CHECK(is(crypt("12345678extra", "Az"), "Azc.VARqxkTMU"));
	CHECK(is(crypt(TEST_KEY, "zZ"), "zZgIU02pSikzc"));
	CHECK(is(crypt(TEST_KEY, "\x80" "x"), "\x80" "x22/wK52ZKGA"));

	/* What a login does: hash under the stored entry and compare. */
	CHECK(is(crypt("password", "abJnggxhB/yWI"), "abJnggxhB/yWI"));
	CHECK(!is(crypt("passwore", "abJnggxhB/yWI"), "abJnggxhB/yWI"));

	CHECK(is(crypt("test", "_J9..CCCC"), "_J9..CCCCZBIc.TMGpK."));
	CHECK(is(crypt(TEST_KEY, "_0.../9Zz"), "_0.../9ZzX7iSJNd21sU"));
	CHECK(is(crypt("123456789", "_1234abcd"), "_1234abcddAJdBhgpNwU"));

	/* The $ hashes still come first. */
	CHECK(is(crypt("", "$1$salt$"), "$1$salt$UsdFqFVB.FsuinRDK5eE.."));
	CHECK(is(crypt("password", "$2a$04$abcdefghijklmnopqrstuv"), "*0"));

	/* A $ setting naming no hash is a DES salt, as musl reads it. */
	const char *dollar = crypt("password", "$9$salt$");
	CHECK(dollar && strlen(dollar) == 13 && strncmp(dollar, "$9", 2) == 0);

	/* Refusals: libxcrypt's "*0", or "*1" for a refused setting beginning
	 * "*0", so that a refusal never equals a locked entry or its setting. */
	CHECK(is(crypt("password", ""), "*0"));
	CHECK(is(crypt("password", "a"), "*0"));
	CHECK(is(crypt("password", "a:"), "*0"));
	CHECK(is(crypt("password", "_...."), "*0"));
	CHECK(is(crypt("password", "_....abcd"), "*0"));
	CHECK(is(crypt("password", "*"), "*0"));
	/* "*0" itself is a DES salt, so it hashes rather than being refused. */
	const char *star0 = crypt("password", "*0");
	CHECK(star0 && strlen(star0) == 13);

	struct crypt_data data;
	memset(&data, 0, sizeof data);
	CHECK(is(crypt_r("password", "ab", &data), "abJnggxhB/yWI"));
	CHECK(is(crypt_r("test", "_J9..CCCC", &data), "_J9..CCCCZBIc.TMGpK."));
	CHECK(is(crypt_r("password", "*", &data), "*0"));

	/* A key past the SHA-crypt limit, hashed under another account's salt
	 * as OpenSSH does for a locked account, never equals "*" (sshhole). */
	char long_key[258];
	memset(long_key, 'A', 257);
	long_key[257] = 0;
	CHECK(is(crypt(long_key, "$6$saltsalt$"), "*0"));
	CHECK(is(crypt(long_key, "$5$saltsalt$"), "*0"));

	return t_status;
}
