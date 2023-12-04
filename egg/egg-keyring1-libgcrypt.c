/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2019 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Daiki Ueno
 */

#include "config.h"

#include "egg-keyring1.h"

#include "egg/egg-secure-memory.h"

EGG_SECURE_DECLARE (egg_keyring1);

#include <gcrypt.h>

#define PBKDF2_HASH_ALGO GCRY_MD_SHA256
#define MAC_ALGO GCRY_MAC_HMAC_SHA256
#define CIPHER_ALGO GCRY_CIPHER_AES128

void
egg_keyring1_create_nonce (guint8 *nonce,
			   gsize nonce_size)
{
	gcry_create_nonce (nonce, nonce_size);
}

GBytes *
egg_keyring1_derive_key (const gchar *password,
			 gsize n_password,
			 GBytes *salt,
			 guint32 iteration_count)
{
	guint8 *buffer;
	gcry_error_t gcry;

	buffer = egg_secure_alloc (KEY_SIZE);
	g_return_val_if_fail (buffer, NULL);

	gcry = gcry_kdf_derive (password,
				n_password,
				GCRY_KDF_PBKDF2, PBKDF2_HASH_ALGO,
				g_bytes_get_data (salt, NULL),
				g_bytes_get_size (salt),
				iteration_count,
				KEY_SIZE, buffer);
	if (gcry != 0) {
		egg_secure_free (buffer);
		return NULL;
	}

	return g_bytes_new_with_free_func (buffer,
					   KEY_SIZE,
					   egg_secure_free,
					   buffer);
}

gboolean
egg_keyring1_calculate_mac (GBytes *key,
			    const guint8 *value,
			    gsize n_value,
			    guint8 *buffer)
{
	gcry_mac_hd_t hd;
	gcry_error_t gcry;
	gconstpointer secret;
	gsize n_secret;
	gboolean ret = FALSE;

	gcry = gcry_mac_open (&hd, MAC_ALGO, 0, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	secret = g_bytes_get_data (key, &n_secret);
	gcry = gcry_mac_setkey (hd, secret, n_secret);
	if (gcry != 0)
		goto out;

	gcry = gcry_mac_write (hd, value, n_value);
	if (gcry != 0)
		goto out;

	n_value = MAC_SIZE;
	gcry = gcry_mac_read (hd, buffer, &n_value);
	if (gcry != 0)
		goto out;

	if (n_value != MAC_SIZE)
		goto out;

	ret = TRUE;
 out:
	gcry_mac_close (hd);
	return ret;
}

gboolean
egg_keyring1_verify_mac (GBytes *key,
			 const guint8 *value,
			 gsize n_value,
			 const guint8 *data)
{
	guint8 buffer[MAC_SIZE];
	guint8 status = 0;
	gsize i;

	if (!egg_keyring1_calculate_mac (key, value, n_value, buffer)) {
		return FALSE;
	}

	for (i = 0; i < MAC_SIZE; i++) {
		status |= data[i] ^ buffer[i];
	}

	return status == 0;
}

gboolean
egg_keyring1_decrypt (GBytes *key,
		      guint8 *data,
		      gsize n_data)
{
	gcry_cipher_hd_t hd;
	gcry_error_t gcry;
	gconstpointer secret;
	gsize n_secret;
	gboolean ret = FALSE;

	gcry = gcry_cipher_open (&hd, CIPHER_ALGO, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry != 0)
		goto out;

	secret = g_bytes_get_data (key, &n_secret);
	gcry = gcry_cipher_setkey (hd, secret, n_secret);
	if (gcry != 0)
		goto out;

	gcry = gcry_cipher_setiv (hd, data + n_data, IV_SIZE);
	if (gcry != 0)
		goto out;

	gcry = gcry_cipher_decrypt (hd, data, n_data, NULL, 0);
	if (gcry != 0)
		goto out;

	ret = TRUE;
 out:
	gcry_cipher_close (hd);
	return ret;
}

gboolean
egg_keyring1_encrypt (GBytes *key,
		      guint8 *data,
		      gsize n_data)
{
	gcry_cipher_hd_t hd;
	gcry_error_t gcry;
	gconstpointer secret;
	gsize n_secret;
	gboolean ret = FALSE;

	gcry = gcry_cipher_open (&hd, CIPHER_ALGO, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry != 0)
		goto out;

	secret = g_bytes_get_data (key, &n_secret);
	gcry = gcry_cipher_setkey (hd, secret, n_secret);
	if (gcry != 0)
		goto out;

	egg_keyring1_create_nonce (data + n_data, IV_SIZE);

	gcry = gcry_cipher_setiv (hd, data + n_data, IV_SIZE);
	if (gcry != 0)
		goto out;

	gcry = gcry_cipher_encrypt (hd, data, n_data, NULL, 0);
	if (gcry != 0)
		goto out;

	ret = TRUE;
 out:
	gcry_cipher_close (hd);
	return ret;
}
