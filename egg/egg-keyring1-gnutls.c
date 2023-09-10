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

#include <gnutls/crypto.h>
#define PBKDF2_HASH_ALGO GNUTLS_MAC_SHA256
#define MAC_ALGO GNUTLS_MAC_SHA256
#define CIPHER_ALGO GNUTLS_CIPHER_AES_128_CBC

void
egg_keyring1_create_nonce (guint8 *nonce,
			   gsize nonce_size)
{
	(void)gnutls_rnd (GNUTLS_RND_NONCE, nonce, nonce_size);
}

GBytes *
egg_keyring1_derive_key (const char *password,
			 gsize n_password,
			 GBytes *salt,
			 guint32 iteration_count)
{
	gnutls_datum_t password_datum, salt_datum;
	guint8 *buffer;
	int ret;

	password_datum.data = (void *)password;
	password_datum.size = n_password;

	salt_datum.data = (void *)g_bytes_get_data (salt, NULL);
	salt_datum.size = g_bytes_get_size (salt);

	buffer = egg_secure_alloc (KEY_SIZE);
	g_return_val_if_fail (buffer, NULL);

	ret = gnutls_pbkdf2 (PBKDF2_HASH_ALGO, &password_datum, &salt_datum,
			     iteration_count,
			     buffer, KEY_SIZE);
	if (ret < 0) {
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
	return gnutls_hmac_fast (MAC_ALGO,
				 g_bytes_get_data (key, NULL),
				 g_bytes_get_size (key),
				 value, n_value,
				 buffer) >= 0;
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
	gnutls_cipher_hd_t hd = NULL;
	int ret;
	gsize n_secret;
	gnutls_datum_t key_datum, iv_datum;

	key_datum.data = (void *)g_bytes_get_data (key, &n_secret);
	key_datum.size = n_secret;

	iv_datum.data = data + n_data;
	iv_datum.size = IV_SIZE;

	ret = gnutls_cipher_init (&hd, CIPHER_ALGO, &key_datum, &iv_datum);
	if (ret < 0) {
		return FALSE;
	}

	ret = gnutls_cipher_decrypt2 (hd, data, n_data, data, n_data);
	if (ret < 0) {
		gnutls_cipher_deinit (hd);
		return FALSE;
	}

	gnutls_cipher_deinit (hd);
	return TRUE;
}

gboolean
egg_keyring1_encrypt (GBytes *key,
		      guint8 *data,
		      gsize n_data)
{
	gnutls_cipher_hd_t hd = NULL;
	int ret;
	gsize n_secret;
	gnutls_datum_t key_datum, iv_datum;

	key_datum.data = (void *)g_bytes_get_data (key, &n_secret);
	key_datum.size = n_secret;

	iv_datum.data = data + n_data;
	iv_datum.size = IV_SIZE;
	egg_keyring1_create_nonce (iv_datum.data, iv_datum.size);

	ret = gnutls_cipher_init (&hd, CIPHER_ALGO, &key_datum, &iv_datum);
	g_return_val_if_fail (ret >= 0, FALSE);

	ret = gnutls_cipher_encrypt2 (hd, data, n_data, data, n_data);
	gnutls_cipher_deinit (hd);
	return ret < 0 ? FALSE : TRUE;
}
