/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-dh.c: Test egg-dh.c

   Copyright (C) 2009 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   see <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#undef G_DISABLE_ASSERT

#include "egg/egg-dh.h"
#include "egg/egg-secure-memory.h"
#include "egg/egg-testing.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

static void
test_perform (void)
{
	egg_dh_params *params;
	egg_dh_pubkey *y1;
	egg_dh_privkey *x1;
	egg_dh_pubkey *y2;
	egg_dh_privkey *x2;
	GBytes *k1, *k2;
	gboolean ret;

	/* Load up the parameters */
	params = egg_dh_default_params ("ietf-ike-grp-modp-768");
	if (!params)
		g_assert_not_reached ();

	/* Generate secrets */
	ret = egg_dh_gen_pair (params, 0, &y1, &x1);
	g_assert_true (ret);
	ret = egg_dh_gen_pair (params, 0, &y2, &x2);
	g_assert_true (ret);

	/* Calculate keys */
	k1 = egg_dh_gen_secret (y1, x2, params);
	g_assert_nonnull (k1);
	k2 = egg_dh_gen_secret (y2, x1, params);
	g_assert_nonnull (k2);

	/* Keys must be the same */
	g_assert_cmpmem (g_bytes_get_data (k1, NULL), g_bytes_get_size (k1),
			 g_bytes_get_data (k2, NULL), g_bytes_get_size (k2));

	egg_dh_params_free (params);
	egg_dh_pubkey_free (y1);
	egg_dh_privkey_free (x1);
	egg_secure_free (k1);
	egg_dh_pubkey_free (y2);
	egg_dh_privkey_free (x2);
	egg_secure_free (k2);
}

static void
test_short_pair (void)
{
	egg_dh_params *params;
	egg_dh_pubkey *y1;
	egg_dh_privkey *x1;
	GBytes *bytes;
	gboolean ret;

	/* Load up the parameters */
	params = egg_dh_default_params ("ietf-ike-grp-modp-1024");
	g_assert_nonnull (params);

	/* Generate secrets */
	ret = egg_dh_gen_pair (params, 512, &y1, &x1);
	g_assert_true (ret);
	bytes = egg_dh_pubkey_export (y1);
	g_assert_cmpuint (g_bytes_get_size (bytes), <=, 512);
	g_bytes_unref (bytes);

	egg_dh_params_free (params);
	egg_dh_pubkey_free (y1);
	egg_dh_privkey_free (x1);
}

static void
check_dh_default (const gchar *name, guint bits)
{
	gboolean ret;
	gconstpointer prime, base;
	gsize n_prime, n_base;

	ret = egg_dh_default_params_raw (name, &prime, &n_prime, &base, &n_base);
	g_assert_true (ret);
	g_assert_nonnull (prime);
	egg_assert_cmpsize (n_prime, >, 0);
	g_assert_nonnull (base);
	egg_assert_cmpsize (n_base, >, 0);
}

static void
test_default_768 (void)
{
	check_dh_default ("ietf-ike-grp-modp-768", 768);
}

static void
test_default_1024 (void)
{
	check_dh_default ("ietf-ike-grp-modp-1024", 1024);
}

static void
test_default_1536 (void)
{
	check_dh_default ("ietf-ike-grp-modp-1536", 1536);
}

static void
test_default_2048 (void)
{
	check_dh_default ("ietf-ike-grp-modp-2048", 2048);
}

static void
test_default_3072 (void)
{
	check_dh_default ("ietf-ike-grp-modp-3072", 3072);
}

static void
test_default_4096 (void)
{
	check_dh_default ("ietf-ike-grp-modp-4096", 4096);
}

static void
test_default_8192 (void)
{
	check_dh_default ("ietf-ike-grp-modp-8192", 8192);
}

static void
test_default_bad (void)
{
	egg_dh_params *params;

	params = egg_dh_default_params ("bad-name");
	g_assert_null (params);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	if (!g_test_quick ()) {
		g_test_add_func ("/dh/perform", test_perform);
		g_test_add_func ("/dh/short_pair", test_short_pair);
	}

	g_test_add_func ("/dh/default_768", test_default_768);
	g_test_add_func ("/dh/default_1024", test_default_1024);
	g_test_add_func ("/dh/default_1536", test_default_1536);
	g_test_add_func ("/dh/default_2048", test_default_2048);
	g_test_add_func ("/dh/default_3072", test_default_3072);
	g_test_add_func ("/dh/default_4096", test_default_4096);
	g_test_add_func ("/dh/default_8192", test_default_8192);
	g_test_add_func ("/dh/default_bad", test_default_bad);

	return g_test_run ();
}
