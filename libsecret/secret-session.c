/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 * Copyright 2012 Red Hat Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "secret-private.h"

#ifdef WITH_CRYPTO
#include "egg/egg-dh.h"
#include "egg/egg-fips.h"
#include "egg/egg-hkdf.h"
#endif

#ifdef WITH_GCRYPT
#include "egg/egg-libgcrypt.h"
#include <gcrypt.h>
#endif

#ifdef WITH_GNUTLS
#include <gnutls/crypto.h>
#endif

#include "egg/egg-hex.h"
#include "egg/egg-secure-memory.h"

#include <glib/gi18n-lib.h>

EGG_SECURE_DECLARE (secret_session);

#define ALGORITHMS_AES    "dh-ietf1024-sha256-aes128-cbc-pkcs7"
#define ALGORITHMS_PLAIN  "plain"

struct _SecretSession {
	gchar *path;
	const gchar *algorithms;
#ifdef WITH_CRYPTO
	egg_dh_params *params;
	egg_dh_privkey *privat;
	egg_dh_pubkey *publi;
#endif
	gpointer key;
	gsize n_key;
};

void
_secret_session_free (gpointer data)
{
	SecretSession *session = data;

	if (session == NULL)
		return;

	g_free (session->path);
#ifdef WITH_CRYPTO
	egg_dh_pubkey_free (session->publi);
	egg_dh_privkey_free (session->privat);
	egg_dh_params_free (session->params);
#endif
	egg_secure_free (session->key);
	g_free (session);
}

#ifdef WITH_CRYPTO

static GVariant *
request_open_session_aes (SecretSession *session)
{
	GBytes *buffer;
	GVariant *argument;
	EggFipsMode fips_mode;

	g_assert (session->params == NULL);
	g_assert (session->privat == NULL);
	g_assert (session->publi == NULL);

#ifdef WITH_GCRYPT
	egg_libgcrypt_initialize ();
#endif

	/* Initialize our local parameters and values */
	session->params = egg_dh_default_params ("ietf-ike-grp-modp-1024");
	if (!session->params)
		g_return_val_if_reached (NULL);

#if 0
	g_printerr ("\n lib params: ");
	egg_dh_params_dump (session->params);
	g_printerr ("\n");
#endif

	fips_mode = egg_fips_get_mode ();
	egg_fips_set_mode (EGG_FIPS_MODE_DISABLED);
	if (!egg_dh_gen_pair (session->params, 0,
	                      &session->publi, &session->privat))
		g_return_val_if_reached (NULL);
	egg_fips_set_mode (fips_mode);

	buffer = egg_dh_pubkey_export (session->publi);
	g_return_val_if_fail (buffer != NULL, NULL);
	argument = g_variant_new_from_bytes (G_VARIANT_TYPE ("ay"),
					     buffer,
					     TRUE);
	g_bytes_unref (buffer);

	return g_variant_new ("(sv)", ALGORITHMS_AES, argument);
}

static gboolean
response_open_session_aes (SecretSession *session,
                           GVariant *response)
{
	GBytes *buffer;
	GVariant *argument;
	const gchar *sig;
	egg_dh_pubkey *peer;
	GBytes *ikm;
	EggFipsMode fips_mode;

	sig = g_variant_get_type_string (response);
	g_return_val_if_fail (sig != NULL, FALSE);

	if (!g_str_equal (sig, "(vo)")) {
		g_warning ("invalid OpenSession() response from daemon with signature: %s", sig);
		return FALSE;
	}

	g_assert (session->path == NULL);
	g_variant_get (response, "(vo)", &argument, &session->path);

	buffer = g_variant_get_data_as_bytes (argument);
	peer = egg_dh_pubkey_new_from_bytes (session->params, buffer);
	g_bytes_unref (buffer);
	g_return_val_if_fail (peer != NULL, FALSE);
	g_variant_unref (argument);

#if 0
	g_printerr (" lib publi: ");
	egg_dh_pubkey_dump (session->publi);
	g_printerr ("\n  lib peer: ");
	egg_dh_pubkey_dump (peer);
	g_printerr ("\n");
#endif

	fips_mode = egg_fips_get_mode ();
	egg_fips_set_mode (EGG_FIPS_MODE_DISABLED);
	ikm = egg_dh_gen_secret (peer, session->privat, session->params);
	egg_fips_set_mode (fips_mode);
	egg_dh_pubkey_free (peer);

#if 0
	g_printerr ("   lib ikm:  %s\n",
		    egg_hex_encode (g_bytes_get_data (ikm, NULL),
				    g_bytes_get_size (ikm)));
#endif

	if (ikm == NULL) {
		g_warning ("couldn't negotiate a valid AES session key");
		g_free (session->path);
		session->path = NULL;
		return FALSE;
	}

	session->n_key = 16;
	session->key = egg_secure_alloc (session->n_key);
	if (!egg_hkdf_perform ("sha256",
			       g_bytes_get_data (ikm, NULL),
			       g_bytes_get_size (ikm),
			       NULL, 0, NULL, 0,
	                       session->key, session->n_key))
		g_return_val_if_reached (FALSE);
	g_bytes_unref (ikm);

	session->algorithms = ALGORITHMS_AES;
	return TRUE;
}

#endif /* WITH_CRYPTO */

static GVariant *
request_open_session_plain (SecretSession *session)
{
	GVariant *argument = g_variant_new_string ("");
	return g_variant_new ("(sv)", "plain", argument);
}

static gboolean
response_open_session_plain (SecretSession *session,
                             GVariant *response)
{
	GVariant *argument;
	const gchar *sig;

	sig = g_variant_get_type_string (response);
	g_return_val_if_fail (sig != NULL, FALSE);

	if (!g_str_equal (sig, "(vo)")) {
		g_warning ("invalid OpenSession() response from daemon with signature: %s",
		           g_variant_get_type_string (response));
		return FALSE;
	}

	g_assert (session->path == NULL);
	g_variant_get (response, "(vo)", &argument, &session->path);
	g_variant_unref (argument);

	g_assert (session->key == NULL);
	g_assert (session->n_key == 0);

	session->algorithms = ALGORITHMS_PLAIN;
	return TRUE;
}

typedef struct {
	SecretSession *session;
} OpenSessionClosure;

static void
open_session_closure_free (gpointer data)
{
	OpenSessionClosure *closure = data;
	g_assert (closure);
	_secret_session_free (closure->session);
	g_free (closure);
}

static void
on_service_open_session_plain (GObject *source,
                               GAsyncResult *result,
                               gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	OpenSessionClosure *closure = g_task_get_task_data (task);
	SecretService *service = SECRET_SERVICE (source);
	GError *error = NULL;
	GVariant *response;

	response =  g_dbus_proxy_call_finish (G_DBUS_PROXY (service), result, &error);

	/* A successful response, decode it */
	if (response != NULL) {
		if (response_open_session_plain (closure->session, response)) {
			_secret_service_take_session (service, closure->session);
			closure->session = NULL;
			g_task_return_boolean (task, TRUE);

		} else {
			g_task_return_new_error (task, SECRET_ERROR, SECRET_ERROR_PROTOCOL,
			                         _("Couldn’t communicate with the secret storage"));
		}

		g_variant_unref (response);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_object_unref (task);
}

#ifdef WITH_CRYPTO

static void
on_service_open_session_aes (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	OpenSessionClosure * closure = g_task_get_task_data (task);
	SecretService *service = SECRET_SERVICE (source);
	GError *error = NULL;
	GVariant *response;

	response =  g_dbus_proxy_call_finish (G_DBUS_PROXY (service), result, &error);

	/* A successful response, decode it */
	if (response != NULL) {
		if (response_open_session_aes (closure->session, response)) {
			_secret_service_take_session (service, closure->session);
			closure->session = NULL;
			g_task_return_boolean (task, TRUE);

		} else {
			g_task_return_new_error (task, SECRET_ERROR, SECRET_ERROR_PROTOCOL,
			                         _("Couldn’t communicate with the secret storage"));
		}

		g_variant_unref (response);

	} else {
		/* AES session not supported, request a plain session */
		if (g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_NOT_SUPPORTED)) {
			g_dbus_proxy_call (G_DBUS_PROXY (source), "OpenSession",
			                   request_open_session_plain (closure->session),
			                   G_DBUS_CALL_FLAGS_NONE, -1,
			                   g_task_get_cancellable (task),
			                   on_service_open_session_plain,
			                   g_object_ref (task));
			g_error_free (error);

		/* Other errors result in a failure */
		} else {
			g_task_return_error (task, g_steal_pointer (&error));
		}
	}

	g_object_unref (task);
}

#endif /* WITH_CRYPTO */


void
_secret_session_open (SecretService *service,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
	GTask *task;
	OpenSessionClosure *closure;

	task = g_task_new (service, cancellable, callback, user_data);
	g_task_set_source_tag (task, _secret_session_open);
	closure = g_new (OpenSessionClosure, 1);
	closure->session = g_new0 (SecretSession, 1);
	g_task_set_task_data (task, closure, open_session_closure_free);

	g_dbus_proxy_call (G_DBUS_PROXY (service), "OpenSession",
#ifdef WITH_CRYPTO
	                   request_open_session_aes (closure->session),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   cancellable, on_service_open_session_aes,
#else
	                   request_open_session_plain (closure->session),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   cancellable, on_service_open_session_plain,
#endif
	                   g_object_ref (task));

	g_object_unref (task);
}

gboolean
_secret_session_open_finish (GAsyncResult *result,
                              GError **error)
{
	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

#ifdef WITH_CRYPTO

static gboolean
pkcs7_unpad_bytes_in_place (guchar *padded,
                            gsize *n_padded)
{
	gsize n_pad, i;

	if (*n_padded == 0)
		return FALSE;

	n_pad = padded[*n_padded - 1];

	/* Validate the padding */
	if (n_pad == 0 || n_pad > 16)
		return FALSE;
	if (n_pad > *n_padded)
		return FALSE;
	for (i = *n_padded - n_pad; i < *n_padded; ++i) {
		if (padded[i] != n_pad)
			return FALSE;
	}

	/* The last bit of data */
	*n_padded -= n_pad;

	/* Null teriminate as a courtesy */
	padded[*n_padded] = 0;

	return TRUE;
}

#ifdef WITH_GCRYPT

static SecretValue *
service_decode_aes_secret (SecretSession *session,
                           gconstpointer param,
                           gsize n_param,
                           gconstpointer value,
                           gsize n_value,
                           const gchar *content_type)
{
	gcry_cipher_hd_t cih;
	gsize n_padded;
	gcry_error_t gcry;
	guchar *padded;
	gsize pos;

	if (n_param != 16) {
		g_info ("received an encrypted secret structure with invalid parameter");
		return NULL;
	}

	if (n_value == 0 || n_value % 16 != 0) {
		g_info ("received an encrypted secret structure with bad secret length");
		return NULL;
	}

	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry != 0) {
		g_warning ("couldn't create AES cipher: %s", gcry_strerror (gcry));
		return NULL;
	}

#if 0
	g_printerr ("    lib iv:  %s\n", egg_hex_encode (param, n_param));
#endif

	gcry = gcry_cipher_setiv (cih, param, n_param);
	g_return_val_if_fail (gcry == 0, NULL);

#if 0
	g_printerr ("   lib key:  %s\n", egg_hex_encode (session->key, session->n_key));
#endif

	gcry = gcry_cipher_setkey (cih, session->key, session->n_key);
	g_return_val_if_fail (gcry == 0, NULL);

	/* Copy the memory buffer */
	n_padded = n_value;
	padded = egg_secure_alloc (n_padded);
	memcpy (padded, value, n_padded);

	/* Perform the decryption */
	for (pos = 0; pos < n_padded; pos += 16) {
		gcry = gcry_cipher_decrypt (cih, (guchar*)padded + pos, 16, NULL, 0);
		g_return_val_if_fail (gcry == 0, FALSE);
	}

	gcry_cipher_close (cih);

	/* Unpad the resulting value */
	if (!pkcs7_unpad_bytes_in_place (padded, &n_padded)) {
		egg_secure_clear (padded, n_padded);
		egg_secure_free (padded);
		g_info ("received an invalid or unencryptable secret");
		return FALSE;
	}

	return secret_value_new_full ((gchar *)padded, n_padded, content_type, egg_secure_free);
}

#endif /* WITH_GCRYPT */

#ifdef WITH_GNUTLS

static SecretValue *
service_decode_aes_secret (SecretSession *session,
                           gconstpointer param,
                           gsize n_param,
                           gconstpointer value,
                           gsize n_value,
                           const gchar *content_type)
{
	gnutls_cipher_hd_t cih;
	gnutls_datum_t iv, key;
	gsize n_padded;
	int ret;
	guchar *padded;

	if (n_param != 16) {
		g_info ("received an encrypted secret structure with invalid parameter");
		return NULL;
	}

	if (n_value == 0 || n_value % 16 != 0) {
		g_info ("received an encrypted secret structure with bad secret length");
		return NULL;
	}

#if 0
	g_printerr ("    lib iv:  %s\n", egg_hex_encode (param, n_param));
#endif

#if 0
	g_printerr ("   lib key:  %s\n", egg_hex_encode (session->key, session->n_key));
#endif

	iv.data = (void *)param;
	iv.size = n_param;
	key.data = session->key;
	key.size = session->n_key;
	ret = gnutls_cipher_init (&cih, GNUTLS_CIPHER_AES_128_CBC, &key, &iv);
	if (ret != 0) {
		g_warning ("couldn't create AES cipher: %s", gnutls_strerror (ret));
		return NULL;
	}

	/* Copy the memory buffer */
	n_padded = n_value;
	padded = egg_secure_alloc (n_padded);
	if (!padded) {
		gnutls_cipher_deinit (cih);
		return NULL;
	}
	memcpy (padded, value, n_padded);

	/* Perform the decryption */
	ret = gnutls_cipher_decrypt2 (cih, padded, n_padded, padded, n_padded);
	if (ret < 0) {
		egg_secure_clear (padded, n_padded);
		egg_secure_free (padded);
		gnutls_cipher_deinit (cih);
		return NULL;
	}

	gnutls_cipher_deinit (cih);

	/* Unpad the resulting value */
	if (!pkcs7_unpad_bytes_in_place (padded, &n_padded)) {
		egg_secure_clear (padded, n_padded);
		egg_secure_free (padded);
		g_info ("received an invalid or unencryptable secret");
		return FALSE;
	}

	return secret_value_new_full ((gchar *)padded, n_padded, content_type, egg_secure_free);
}

#endif /* WITH_GNUTLS */

#endif /* WITH_CRYPTO */

static SecretValue *
service_decode_plain_secret (SecretSession *session,
                             gconstpointer param,
                             gsize n_param,
                             gconstpointer value,
                             gsize n_value,
                             const gchar *content_type)
{
	if (n_param != 0) {
		g_info ("received a plain secret structure with invalid parameter");
		return NULL;
	}

	return secret_value_new (value, n_value, content_type);
}

SecretValue *
_secret_session_decode_secret (SecretSession *session,
                               GVariant *encoded)
{
	SecretValue *result;
	gconstpointer param;
	gconstpointer value;
	gchar *session_path;
	gchar *content_type;
	gsize n_param;
	gsize n_value;
	GVariant *vparam;
	GVariant *vvalue;

	g_return_val_if_fail (session != NULL, NULL);
	g_return_val_if_fail (encoded != NULL, NULL);

	/* Parsing (oayays) */
	g_variant_get_child (encoded, 0, "o", &session_path);

	if (session_path == NULL || !g_str_equal (session_path, session->path)) {
		g_info ("received a secret encoded with wrong session: %s != %s",
		        session_path, session->path);
		g_free (session_path);
		return NULL;
	}

	vparam = g_variant_get_child_value (encoded, 1);
	param = g_variant_get_fixed_array (vparam, &n_param, sizeof (guchar));
	vvalue = g_variant_get_child_value (encoded, 2);
	value = g_variant_get_fixed_array (vvalue, &n_value, sizeof (guchar));
	g_variant_get_child (encoded, 3, "s", &content_type);

#ifdef WITH_CRYPTO
	if (session->key != NULL)
		result = service_decode_aes_secret (session, param, n_param,
		                                    value, n_value, content_type);
	else
#endif
		result = service_decode_plain_secret (session, param, n_param,
		                                      value, n_value, content_type);

	g_variant_unref (vparam);
	g_variant_unref (vvalue);
	g_free (content_type);
	g_free (session_path);

	return result;
}

#ifdef WITH_CRYPTO

static guchar*
pkcs7_pad_bytes_in_secure_memory (gconstpointer secret,
                                  gsize length,
                                  gsize *n_padded)
{
	gsize n_pad;
	guchar *padded;

	/* Pad the secret */
	*n_padded = ((length + 16) / 16) * 16;
	g_assert (length < *n_padded);
	g_assert (*n_padded > 0);
	n_pad = *n_padded - length;
	g_assert (n_pad > 0 && n_pad <= 16);
	padded = egg_secure_alloc (*n_padded);
	memcpy (padded, secret, length);
	memset (padded + length, n_pad, n_pad);
	return padded;
}

#ifdef WITH_GCRYPT

static gboolean
service_encode_aes_secret (SecretSession *session,
                           SecretValue *value,
                           GVariantBuilder *builder)
{
	gcry_cipher_hd_t cih;
	guchar *padded;
	gsize n_padded, pos;
	gcry_error_t gcry;
	gpointer iv;
	gconstpointer secret;
	gsize n_secret;
	GVariant *child;

	g_variant_builder_add (builder, "o", session->path);

	/* Create the cipher */
	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry != 0) {
		g_warning ("couldn't create AES cipher: %s", gcry_strerror (gcry));
		return FALSE;
	}

	secret = secret_value_get (value, &n_secret);

	/* Perform the encoding here */
	padded = pkcs7_pad_bytes_in_secure_memory (secret, n_secret, &n_padded);
	g_assert (padded != NULL);

	/* Setup the IV */
	iv = g_malloc0 (16);
	gcry_create_nonce (iv, 16);
	gcry = gcry_cipher_setiv (cih, iv, 16);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Setup the key */
	gcry = gcry_cipher_setkey (cih, session->key, session->n_key);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Perform the encryption */
	for (pos = 0; pos < n_padded; pos += 16) {
		gcry = gcry_cipher_encrypt (cih, (guchar*)padded + pos, 16, NULL, 0);
		g_return_val_if_fail (gcry == 0, FALSE);
	}

	gcry_cipher_close (cih);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), iv, 16, TRUE, g_free, iv);
	g_variant_builder_add_value (builder, child);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), padded, n_padded, TRUE, egg_secure_free, padded);
	g_variant_builder_add_value (builder, child);

	g_variant_builder_add (builder, "s", secret_value_get_content_type (value));
	return TRUE;
}

#endif /* WITH_GCRYPT */

#ifdef WITH_GNUTLS

static gboolean
service_encode_aes_secret (SecretSession *session,
                           SecretValue *value,
                           GVariantBuilder *builder)
{
	gnutls_cipher_hd_t cih = NULL;
	guchar *padded;
	gsize n_padded;
	int ret;
	gnutls_datum_t iv, key;
	gpointer iv_data;
	gconstpointer secret;
	gsize n_secret;
	GVariant *child;

	g_variant_builder_add (builder, "o", session->path);

	secret = secret_value_get (value, &n_secret);

	/* Perform the encoding here */
	padded = pkcs7_pad_bytes_in_secure_memory (secret, n_secret, &n_padded);
	g_assert (padded != NULL);

	/* Setup the IV */
	iv_data = g_malloc0 (16);
	iv.data = iv_data;
	iv.size = 16;
	ret = gnutls_rnd (GNUTLS_RND_NONCE, iv.data, iv.size);
	g_return_val_if_fail (ret >= 0, FALSE);

	/* Setup the key */
	key.data = session->key;
	key.size = session->n_key;

	/* Create the cipher */
	ret = gnutls_cipher_init (&cih, GNUTLS_CIPHER_AES_128_CBC, &key, &iv);
	if (ret < 0) {
		g_warning ("couldn't create AES cipher: %s", gnutls_strerror (ret));
		return FALSE;
	}

	/* Perform the encryption */
	ret = gnutls_cipher_encrypt2 (cih, padded, n_padded, padded, n_padded);
	if (ret < 0) {
		gnutls_cipher_deinit (cih);
		return FALSE;
	}

	gnutls_cipher_deinit (cih);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), iv_data, 16, TRUE, g_free, iv_data);
	g_variant_builder_add_value (builder, child);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), padded, n_padded, TRUE, egg_secure_free, padded);
	g_variant_builder_add_value (builder, child);

	g_variant_builder_add (builder, "s", secret_value_get_content_type (value));
	return TRUE;
}

#endif /* WITH_GNUTLS */

#endif /* WITH_CRYPTO */

static gboolean
service_encode_plain_secret (SecretSession *session,
                             SecretValue *value,
                             GVariantBuilder *builder)
{
	gconstpointer secret;
	gsize n_secret;
	GVariant *child;

	g_variant_builder_add (builder, "o", session->path);

	secret = secret_value_get (value, &n_secret);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), "", 0, TRUE, NULL, NULL);
	g_variant_builder_add_value (builder, child);

	child = g_variant_new_from_data (G_VARIANT_TYPE ("ay"), secret, n_secret, TRUE,
	                                 secret_value_unref, secret_value_ref (value));
	g_variant_builder_add_value (builder, child);

	g_variant_builder_add (builder, "s", secret_value_get_content_type (value));
	return TRUE;
}

GVariant *
_secret_session_encode_secret (SecretSession *session,
                               SecretValue *value)
{
	GVariantBuilder *builder;
	GVariant *result = NULL;
	GVariantType *type;
	gboolean ret;

	g_return_val_if_fail (session != NULL, NULL);
	g_return_val_if_fail (value != NULL, NULL);

	type = g_variant_type_new ("(oayays)");
	builder = g_variant_builder_new (type);

#ifdef WITH_CRYPTO
	if (session->key)
		ret = service_encode_aes_secret (session, value, builder);
	else
#endif
		ret = service_encode_plain_secret (session, value, builder);
	if (ret)
		result = g_variant_builder_end (builder);

	g_variant_builder_unref (builder);
	g_variant_type_free (type);
	return result;
}

const gchar *
_secret_session_get_algorithms (SecretSession *session)
{
	g_return_val_if_fail (session != NULL, NULL);
	return session->algorithms;
}

const gchar *
_secret_session_get_path (SecretSession *session)
{
	g_return_val_if_fail (session != NULL, NULL);
	return session->path;
}
