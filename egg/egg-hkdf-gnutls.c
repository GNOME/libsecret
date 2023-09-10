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

#include "egg-hkdf.h"

#include "egg-secure-memory.h"
#include <gnutls/crypto.h>

EGG_SECURE_DECLARE (hkdf);

gboolean
egg_hkdf_perform (const gchar *hash_algo, gconstpointer input, gsize n_input,
                  gconstpointer salt, gsize n_salt, gconstpointer info,
                  gsize n_info, gpointer output, gsize n_output)
{
	static const struct {
		gchar *name;
		gnutls_mac_algorithm_t algo;
	} hash_algos[] = {
		{ "sha1", GNUTLS_MAC_SHA1 },
		{ "sha256", GNUTLS_MAC_SHA256 },
		{ NULL, }
	};
	gnutls_mac_algorithm_t algo = GNUTLS_MAC_UNKNOWN;
	gnutls_datum_t input_datum, salt_datum, info_datum;
	gpointer alloc = NULL;
	gpointer buffer = NULL;
	guint hash_len;
	gsize i;
	int ret;
	gboolean result = TRUE;

	for (i = 0; hash_algos[i].name; i++) {
		if (g_str_equal (hash_algos[i].name, hash_algo)) {
			algo = hash_algos[i].algo;
			break;
		}
	}
	g_return_val_if_fail (algo != GNUTLS_MAC_UNKNOWN, FALSE);

	hash_len = gnutls_hmac_get_len (algo);
	g_return_val_if_fail (hash_len != 0, FALSE);
	g_return_val_if_fail (n_output <= 255 * hash_len, FALSE);

	/* Buffer we need to for intermediate stuff */
	buffer = egg_secure_alloc (hash_len);
	g_return_val_if_fail (buffer, FALSE);

	/* Salt defaults to hash_len zeros */
	if (!salt) {
		alloc = g_malloc0 (hash_len);
		if (!alloc) {
			result = FALSE;
			goto out;
		}
		salt = alloc;
		n_salt = hash_len;
	}

	/* Step 1: Extract */
	input_datum.data = (void *)input;
	input_datum.size = n_input;
	salt_datum.data = (void *)salt;
	salt_datum.size = n_salt;

	ret = gnutls_hkdf_extract (algo, &input_datum, &salt_datum, buffer);
	if (ret < 0) {
		result = FALSE;
		goto out;
	}

	/* Step 2: Expand */
	input_datum.data = buffer;
	input_datum.size = hash_len;
	info_datum.data = (void *)info;
	info_datum.size = n_info;

	ret = gnutls_hkdf_expand (algo, &input_datum, &info_datum,
				  output, n_output);
	if (ret < 0) {
		result = FALSE;
		goto out;
	}

 out:
	g_free (alloc);
	egg_secure_free (buffer);
	return result;
}
