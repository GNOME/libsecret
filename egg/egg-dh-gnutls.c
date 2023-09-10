/*
 * libsecret
 *
 * Copyright (C) 2023 Daiki Ueno
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
 * Author: Daiki Ueno
 */

#include "config.h"

#include "egg-dh.h"

/* Enabling this is a complete security compromise */
#define DEBUG_DH_SECRET 0

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

struct egg_dh_params {
	gnutls_dh_params_t inner;
	guint bits;
};

struct egg_dh_pubkey {
	gnutls_pubkey_t inner;
};

struct egg_dh_privkey {
	gnutls_privkey_t inner;
};

egg_dh_params *
egg_dh_default_params (const gchar *name)
{
	const egg_dh_group *group;
	egg_dh_params *params;

	g_return_val_if_fail (name, NULL);

	for (group = egg_dh_groups; group->name; ++group) {
		if (g_str_equal (group->name, name)) {
			gnutls_dh_params_t inner;
			gnutls_datum_t prime, generator;
			int ret;

			ret = gnutls_dh_params_init (&inner);
			if (ret < 0)
				return NULL;

			prime.data = (void *)group->prime;
			prime.size = group->n_prime;
			generator.data = (void *)group->base;
			generator.size = group->n_base;

			ret = gnutls_dh_params_import_raw (inner,
							   &prime,
							   &generator);
			if (ret < 0) {
				gnutls_dh_params_deinit (inner);
				return NULL;
			}

			params = g_new (struct egg_dh_params, 1);
			if (!params) {
				gnutls_dh_params_deinit (inner);
				return NULL;
			}
			params->inner = g_steal_pointer (&inner);
			params->bits = group->bits;
			return params;
		}
	}

	return NULL;
}

gboolean
egg_dh_gen_pair (egg_dh_params *params, guint bits,
                 egg_dh_pubkey **pub, egg_dh_privkey **priv)
{
	gnutls_pubkey_t pub_inner = NULL;
	gnutls_privkey_t priv_inner = NULL;
	egg_dh_pubkey *pub_outer = NULL;
	egg_dh_privkey *priv_outer = NULL;
	gnutls_keygen_data_st data;
	gboolean ok = FALSE;
	int ret;

	g_return_val_if_fail (params, FALSE);
	g_return_val_if_fail (pub, FALSE);
	g_return_val_if_fail (priv, FALSE);

	if (bits == 0)
		bits = params->bits;
	else if (bits > params->bits)
		g_return_val_if_reached (FALSE);

	ret = gnutls_privkey_init (&priv_inner);
	if (ret < 0)
		goto out;

	data.type = GNUTLS_KEYGEN_DH;
	data.data = (void *)params->inner;

	ret = gnutls_privkey_generate2 (priv_inner, GNUTLS_PK_DH, bits, 0,
					&data, 1);
	if (ret < 0)
		goto out;

	ret = gnutls_pubkey_init (&pub_inner);
	if (ret < 0)
		goto out;

	ret = gnutls_pubkey_import_privkey (pub_inner, priv_inner, 0, 0);
	if (ret < 0)
		goto out;

	pub_outer = g_new0 (struct egg_dh_pubkey, 1);
	if (!pub_outer)
		goto out;
	pub_outer->inner = g_steal_pointer (&pub_inner);

	priv_outer = g_new0 (struct egg_dh_privkey, 1);
	if (!priv_outer)
		goto out;
	priv_outer->inner = g_steal_pointer (&priv_inner);

	*pub = g_steal_pointer (&pub_outer);
	*priv = g_steal_pointer (&priv_outer);

	ok = TRUE;

 out:
	if (priv_inner)
		gnutls_privkey_deinit (priv_inner);
	if (pub_inner)
		gnutls_pubkey_deinit (pub_inner);

	egg_dh_privkey_free (priv_outer);
	egg_dh_pubkey_free (pub_outer);

	return ok;
}

GBytes *
egg_dh_gen_secret (egg_dh_pubkey *peer, egg_dh_privkey *priv,
                   egg_dh_params *params)
{
	int ret;
	gnutls_datum_t k;
#if DEBUG_DH_SECRET
	gnutls_datum_t h;
#endif

	g_return_val_if_fail (peer, NULL);
	g_return_val_if_fail (priv, NULL);
	g_return_val_if_fail (params, NULL);

	ret = gnutls_privkey_derive_secret (priv->inner, peer->inner,
					    NULL, &k, 0);
	if (ret < 0)
		return NULL;

#if DEBUG_DH_SECRET
	ret = gnutls_hex_encode2 (&k, &h);
	g_assert (ret >= 0);
	g_printerr ("DH SECRET: %s\n", h.data);
	gnutls_free (h.data);
#endif

	return g_bytes_new_with_free_func (k.data, k.size,
					   (GDestroyNotify)gnutls_free,
					   k.data);
}

void
egg_dh_params_free (egg_dh_params *params)
{
	gnutls_dh_params_deinit (params->inner);
	g_free (params);
}

void
egg_dh_pubkey_free (egg_dh_pubkey *pubkey)
{
	if (!pubkey)
		return;
	if (pubkey->inner)
		gnutls_pubkey_deinit (pubkey->inner);
	g_free (pubkey);
}

void
egg_dh_privkey_free (egg_dh_privkey *privkey)
{
	if (!privkey)
		return;
	if (privkey->inner)
		gnutls_privkey_deinit (privkey->inner);
	g_free (privkey);
}

GBytes *
egg_dh_pubkey_export (const egg_dh_pubkey *pubkey)
{
	gnutls_datum_t data;
	int ret;

	ret = gnutls_pubkey_export_dh_raw (pubkey->inner, NULL, &data, 0);
	if (ret < 0)
		return NULL;

	return g_bytes_new_with_free_func (data.data, data.size,
					   (GDestroyNotify)gnutls_free,
					   data.data);
}

egg_dh_pubkey *
egg_dh_pubkey_new_from_bytes (const egg_dh_params *params, GBytes *bytes)
{
	egg_dh_pubkey *pub;
	gnutls_pubkey_t inner;
	gnutls_datum_t data;
	int ret;

	ret = gnutls_pubkey_init (&inner);
	if (ret < 0)
		return NULL;

	data.data = (void *)g_bytes_get_data (bytes, NULL);
	data.size = g_bytes_get_size (bytes);

	ret = gnutls_pubkey_import_dh_raw (inner, params->inner, &data);
	if (ret < 0) {
		gnutls_pubkey_deinit (inner);
		return NULL;
	}

	pub = g_new (struct egg_dh_pubkey, 1);
	if (!pub) {
		gnutls_pubkey_deinit (inner);
		return NULL;
	}

	pub->inner = g_steal_pointer (&inner);
	return pub;
}
