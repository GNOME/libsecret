/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and
 * the GNU Lesser General Public License along with this program.  If
 * not, see http://www.gnu.org/licenses/.
 *
 * Author: Stef Walter <stefw@thewalter.net>
 */

#include "config.h"

#include "egg-dh.h"

#include <gcrypt.h>
#include "egg-secure-memory.h"

/* Enabling this is a complete security compromise */
#define DEBUG_DH_SECRET 0

EGG_SECURE_DECLARE (dh);

struct egg_dh_params {
	gcry_mpi_t prime;
	gcry_mpi_t base;
};

struct egg_dh_pubkey {
	gcry_mpi_t inner;
};

struct egg_dh_privkey {
	gcry_mpi_t inner;
};

egg_dh_params *
egg_dh_default_params (const gchar *name)
{
	const egg_dh_group *group;
	gcry_error_t gcry;
	gcry_mpi_t prime = NULL, base = NULL;
	egg_dh_params *params = NULL;

	g_return_val_if_fail (name, NULL);

	for (group = egg_dh_groups; group->name; ++group)
		if (g_str_equal (group->name, name))
			break;
	if (!group->name)
		return NULL;

	gcry = gcry_mpi_scan (&prime, GCRYMPI_FMT_USG,
			      group->prime, group->n_prime, NULL);
	g_return_val_if_fail (gcry == 0, NULL);
	g_return_val_if_fail (gcry_mpi_get_nbits (prime) == group->bits, NULL);

	gcry = gcry_mpi_scan (&base, GCRYMPI_FMT_USG,
			      group->base, group->n_base, NULL);
	g_return_val_if_fail (gcry == 0, NULL);

	params = g_new (struct egg_dh_params, 1);
	if (!params)
		goto error;

	params->prime = g_steal_pointer (&prime);
	params->base = g_steal_pointer (&base);

 error:
	gcry_mpi_release (prime);
	gcry_mpi_release (base);
	return params;
}

gboolean
egg_dh_gen_pair (egg_dh_params *params, guint bits,
                 egg_dh_pubkey **pub, egg_dh_privkey **priv)
{
	guint pbits;
	gcry_mpi_t pub_inner = NULL, priv_inner = NULL;

	g_return_val_if_fail (params, FALSE);
	g_return_val_if_fail (pub, FALSE);
	g_return_val_if_fail (priv, FALSE);

	*pub = NULL;
	*priv = NULL;

	pbits = gcry_mpi_get_nbits (params->prime);
	g_return_val_if_fail (pbits > 1, FALSE);

	if (bits == 0) {
		bits = pbits;
	} else if (bits > pbits) {
		g_return_val_if_reached (FALSE);
	}

	/*
	 * Generate a strong random number of bits, and not zero.
	 * gcry_mpi_randomize bumps up to the next byte. Since we
	 * need to have a value less than half of prime, we make sure
	 * we bump down.
	 */
	priv_inner = gcry_mpi_snew (bits);
	g_return_val_if_fail (priv_inner, FALSE);
	while (gcry_mpi_cmp_ui (priv_inner, 0) == 0)
		gcry_mpi_randomize (priv_inner, bits, GCRY_STRONG_RANDOM);

	/* Secret key value must be less than half of p */
	if (gcry_mpi_get_nbits (priv_inner) > bits)
		gcry_mpi_clear_highbit (priv_inner, bits);
	if (gcry_mpi_get_nbits (priv_inner) > pbits - 1)
		gcry_mpi_clear_highbit (priv_inner, pbits - 1);
	g_assert (gcry_mpi_cmp (params->prime, priv_inner) > 0);

	pub_inner = gcry_mpi_new (gcry_mpi_get_nbits (priv_inner));
	if (!pub_inner)
		goto error;
	gcry_mpi_powm (pub_inner, params->base, priv_inner, params->prime);

	*priv = g_new0 (struct egg_dh_privkey, 1);
	if (!*priv)
		goto error;
	(*priv)->inner = g_steal_pointer (&priv_inner);

	*pub = g_new0 (struct egg_dh_pubkey, 1);
	if (!*pub)
		goto error;
	(*pub)->inner = g_steal_pointer (&pub_inner);

	return TRUE;
 error:
	egg_dh_privkey_free (*priv);
	egg_dh_pubkey_free (*pub);

	gcry_mpi_release (priv_inner);
	gcry_mpi_release (pub_inner);

	g_return_val_if_reached (FALSE);
}

GBytes *
egg_dh_gen_secret (egg_dh_pubkey *peer, egg_dh_privkey *priv,
                   egg_dh_params *params)
{
	gcry_error_t gcry;
	guchar *value;
	gsize n_prime;
	gsize n_value;
	gcry_mpi_t k;
	gint bits;

	g_return_val_if_fail (peer, NULL);
	g_return_val_if_fail (priv, NULL);
	g_return_val_if_fail (params, NULL);

	bits = gcry_mpi_get_nbits (params->prime);
	g_return_val_if_fail (bits >= 0, NULL);

	k = gcry_mpi_snew (bits);
	g_return_val_if_fail (k, NULL);
	gcry_mpi_powm (k, peer->inner, priv->inner, params->prime);

	/* Write out the secret */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &n_prime, params->prime);
	g_return_val_if_fail (gcry == 0, NULL);

	value = egg_secure_alloc (n_prime);
	if (!value)
		return NULL;

	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, value, n_prime, &n_value, k);
	g_return_val_if_fail (gcry == 0, NULL);

	/* Pad the secret with zero bytes to match length of prime in bytes. */
	if (n_value < n_prime) {
		memmove (value + (n_prime - n_value), value, n_value);
		memset (value, 0, (n_prime - n_value));
	}

#if DEBUG_DH_SECRET
	g_printerr ("DH SECRET: ");
	gcry_mpi_dump (k);
#endif
	gcry_mpi_release (k);

#if DEBUG_DH_SECRET
	gcry_mpi_scan (&k, GCRYMPI_FMT_USG, value, n_prime, NULL);
	g_printerr ("RAW SECRET: ");
	gcry_mpi_dump (k);
	gcry_mpi_release (k);
#endif

	return g_bytes_new_with_free_func (value, n_prime,
					   (GDestroyNotify)egg_secure_free,
					   value);
}

void
egg_dh_params_free (egg_dh_params *params)
{
	if (!params)
		return;
	gcry_mpi_release (params->prime);
	gcry_mpi_release (params->base);
	g_free (params);
}

void
egg_dh_pubkey_free (egg_dh_pubkey *pubkey)
{
	if (!pubkey)
		return;
	if (pubkey->inner)
		gcry_mpi_release (pubkey->inner);
	g_free (pubkey);
}

void
egg_dh_privkey_free (egg_dh_privkey *privkey)
{
	if (!privkey)
		return;
	if (privkey->inner)
		gcry_mpi_release (privkey->inner);
	g_free (privkey);
}

GBytes *
egg_dh_pubkey_export (const egg_dh_pubkey *pubkey)
{
	gcry_error_t gcry;
	unsigned char *buffer;
	size_t n_buffer;

	gcry = gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer, &n_buffer,
				pubkey->inner);
	g_return_val_if_fail (gcry == 0, NULL);

	return g_bytes_new_with_free_func (buffer, n_buffer,
					   gcry_free, buffer);
}

egg_dh_pubkey *
egg_dh_pubkey_new_from_bytes (const egg_dh_params *params,
			      GBytes *bytes)
{
	gcry_error_t gcry;
	gcry_mpi_t inner;
	egg_dh_pubkey *pub;

	gcry = gcry_mpi_scan (&inner, GCRYMPI_FMT_USG,
			      g_bytes_get_data (bytes, NULL),
			      g_bytes_get_size (bytes),
			      NULL);
	if (gcry != 0)
		return NULL;

	pub = g_new (struct egg_dh_pubkey, 1);
	if (!pub) {
		gcry_mpi_release (inner);
		return NULL;
	}

	pub->inner = inner;
	return pub;
}
