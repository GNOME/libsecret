/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
 * SPDX-FileCopyrightText: (C) 2026 Red Hat (www.redhat.com)
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"

#undef G_DISABLE_ASSERT

#include "egg/egg-dh.h"
#include "egg/egg-fips.h"
#include "egg/egg-secure-memory.h"

#include <glib.h>

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

/* Secrets with leading zero bytes used to come out short about 1 in 256 times.
 * This value is chosen so that a regression bringing that back has better than 99.9%
 * odds of getting caught, while still running in a few seconds. */
#define NUM_TRIALS 2000

static void
test_secret_matches_prime_length (void)
{
	egg_dh_params *params;
	gsize n_prime, n_base;
	gconstpointer prime, base;
	gint ii;
	EggFipsMode fips_mode;

	params = egg_dh_default_params ("ietf-ike-grp-modp-1024");
	g_assert_nonnull (params);

	g_assert_true (egg_dh_default_params_raw ("ietf-ike-grp-modp-1024",
	                                          &prime, &n_prime, &base, &n_base));

	/* just as libsecret itself, disable the FIPS mode, where
	   the key gen is rejected by GnuTLS */
	fips_mode = egg_fips_get_mode ();
	egg_fips_set_mode (EGG_FIPS_MODE_DISABLED);

	for (ii = 0; ii < NUM_TRIALS; ii++) {
		egg_dh_pubkey *y1, *y2;
		egg_dh_privkey *x1, *x2;
		GBytes *k1, *k2;

		g_assert_true (egg_dh_gen_pair (params, 0, &y1, &x1));
		g_assert_true (egg_dh_gen_pair (params, 0, &y2, &x2));

		k1 = egg_dh_gen_secret (y1, x2, params);
		k2 = egg_dh_gen_secret (y2, x1, params);
		g_assert_nonnull (k1);
		g_assert_nonnull (k2);

		g_assert_cmpuint (g_bytes_get_size (k1), ==, n_prime);
		g_assert_cmpuint (g_bytes_get_size (k2), ==, n_prime);

		g_bytes_unref (k1);
		g_bytes_unref (k2);
		egg_dh_pubkey_free (y1);
		egg_dh_privkey_free (x1);
		egg_dh_pubkey_free (y2);
		egg_dh_privkey_free (x2);
	}

	egg_fips_set_mode (fips_mode);

	egg_dh_params_free (params);
}

int
main (int argc,
      char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/dh/secret-matches-prime-length", test_secret_matches_prime_length);

	return g_test_run ();
}
