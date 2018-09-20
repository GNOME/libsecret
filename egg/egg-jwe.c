/*
 * libsecret
 *
 * Copyright (C) 2018 Red Hat, Inc.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 *
 * Author: Daiki Ueno
 */

#include "config.h"

#include "egg-jwe.h"
#include "egg-base64.h"

#include <gcrypt.h>

/* IV size is always 12 when GCM */
#define IV_SIZE 12
#define TAG_SIZE 16

static gint
enc_to_cipher (const gchar *enc)
{
	if (g_str_equal (enc, "A128GCM"))
		return GCRY_CIPHER_AES128;
	else if (g_str_equal (enc, "A192GCM"))
		return GCRY_CIPHER_AES192;
	else if (g_str_equal (enc, "A256GCM"))
		return GCRY_CIPHER_AES256;

	/* FIXME: support CBC ciphersuites */
	return -1;
}

JsonNode *
egg_jwe_symmetric_encrypt (const guchar  *input,
                           gsize          n_input,
                           const gchar   *enc,
                           const guchar  *key,
                           gsize          n_key,
                           const guchar   *iv,
                           gsize          n_iv,
                           GError       **error)
{
	gcry_cipher_hd_t cipher;
	gcry_error_t gcry;
	guchar random[IV_SIZE];
	guchar tag[TAG_SIZE];
	JsonBuilder *builder;
	JsonGenerator *generator;
	JsonNode *result;
	gchar *protected;
	gchar *encoded;
	guchar *ciphertext;
	gint algo;
	gsize length;

	algo = enc_to_cipher (enc);
	if (algo < 0) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "unknown encryption algorithm");
		return NULL;
	}

	gcry = gcry_cipher_open (&cipher, algo, GCRY_CIPHER_MODE_GCM, 0);
	if (gcry) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't open cipher");
		return NULL;
	}

	gcry = gcry_cipher_setkey (cipher, key, n_key);
	if (gcry) {
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't set key");
		return NULL;
	}

	if (!iv) {
		gcry_randomize (random, IV_SIZE, GCRY_STRONG_RANDOM);
		iv = random;
		n_iv = IV_SIZE;
	}
	gcry = gcry_cipher_setiv (cipher, iv, n_iv);
	if (gcry) {
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't set IV");
		return NULL;
	}

	/* generate protected header */
	builder = json_builder_new ();
	json_builder_begin_object (builder);
	json_builder_set_member_name (builder, "enc");
	json_builder_add_string_value (builder, enc);
	json_builder_end_object (builder);
	result = json_builder_get_root (builder);
	g_object_unref (builder);

	generator = json_generator_new ();
	json_generator_set_root (generator, result);
	json_node_unref (result);
	protected = json_generator_to_data (generator, &length);
	g_object_unref (generator);
	encoded = egg_base64_encode ((const guchar *) protected, length);
	g_free (protected);
	protected = encoded;

	gcry = gcry_cipher_authenticate (cipher, protected, strlen (protected));
	if (gcry) {
		g_free (protected);
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't set authentication data");
		return NULL;
	}

	ciphertext = g_new (guchar, n_input);
	gcry = gcry_cipher_encrypt (cipher, ciphertext, n_input, input, n_input);
	if (gcry) {
		g_free (protected);
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't encrypt data");
		return NULL;
	}

	gcry = gcry_cipher_gettag (cipher, tag, TAG_SIZE);
	if (gcry) {
		g_free (protected);
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't get tag");
		return NULL;
	}

	gcry_cipher_close (cipher);

	builder = json_builder_new ();
	json_builder_begin_object (builder);

	json_builder_set_member_name (builder, "ciphertext");
	encoded = egg_base64_encode (ciphertext, n_input);
	g_free (ciphertext);
	json_builder_add_string_value (builder, encoded);
	g_free (encoded);

	json_builder_set_member_name (builder, "encrypted_key");
	json_builder_add_string_value (builder, "");

	json_builder_set_member_name (builder, "iv");
	encoded = egg_base64_encode (iv, IV_SIZE);
	json_builder_add_string_value (builder, encoded);
	g_free (encoded);

	json_builder_set_member_name (builder, "tag");
	encoded = egg_base64_encode (tag, TAG_SIZE);
	json_builder_add_string_value (builder, encoded);
	g_free (encoded);

	json_builder_set_member_name (builder, "protected");
	json_builder_add_string_value (builder, protected);
	g_free (protected);

	json_builder_set_member_name (builder, "header");
	json_builder_begin_object (builder);
	json_builder_set_member_name (builder, "alg");
	json_builder_add_string_value (builder, "dir");
	json_builder_end_object (builder);

	json_builder_end_object (builder);
	result = json_builder_get_root (builder);
	g_object_unref (builder);

	return result;
}

guchar *
egg_jwe_symmetric_decrypt (JsonNode      *root,
                           const guchar  *key,
                           gsize          n_key,
                           gsize         *length,
                           GError       **error)
{
	gcry_cipher_hd_t cipher;
	gcry_error_t gcry;
	guchar iv[(IV_SIZE / 3 + 1) *4 + 1];
	guchar tag[(TAG_SIZE / 3 + 1) * 4 + 1];
	JsonParser *parser;
	JsonObject *object;
	const gchar *string;
	const gchar *protected;
	JsonNode *protected_root;
	JsonObject *protected_object;
	gchar *buffer;
	guchar *decoded;
	gsize n_decoded;
	gint algo;
	gboolean ret;

	object = json_node_get_object (root);
	if (!object) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "the root element is not an object");
		return NULL;
	}

	protected = json_object_get_string_member (object, "protected");
	if (!protected) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "the root element doesn't contain \"protected\" element");
		return NULL;
	}

	buffer = g_strdup (protected);
	decoded = egg_base64_decode_inplace (buffer, &n_decoded);
	if (!decoded) {
		g_free (buffer);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "couldn't decode \"protected\" element");
		return NULL;
	}

	parser = json_parser_new ();
	ret = json_parser_load_from_data (parser, (gchar *) decoded, n_decoded, error);
	g_free (buffer);
	if (!ret) {
		g_object_unref (parser);
		return NULL;
	}

	protected_root = json_parser_steal_root (parser);
	g_object_unref (parser);

	protected_object = json_node_get_object (protected_root);
	if (!protected_object) {
		json_node_unref (protected_root);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "the \"protected\" element is not an object");
		return NULL;
	}

	string = json_object_get_string_member (protected_object, "enc");
	if (!string) {
		json_node_unref (protected_root);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "the \"protected\" element doesn't contain \"enc\"");
		return NULL;
	}

	algo = enc_to_cipher (string);
	json_node_unref (protected_root);
	if (algo < 0) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "unknown encryption algorithm");
		return NULL;
	}

	string = json_object_get_string_member (object, "iv");
	if (!string) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "the root element doesn't contain \"iv\" element");
		return NULL;
	}
	if (strlen (string) > sizeof (iv) - 1) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "IV is too large");
		return NULL;
	}

	memset (iv, 0, sizeof (iv));
	memcpy (iv, string, strlen (string));
	decoded = egg_base64_decode_inplace ((gchar *) iv, &n_decoded);
	if (!decoded) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "couldn't decode \"iv\" element");
		return NULL;
	}

	string = json_object_get_string_member (object, "tag");
	if (!string) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "the root element doesn't contain \"tag\" element");
		return NULL;
	}
	if (strlen (string) > sizeof (tag) - 1) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "tag is too large");
		return NULL;
	}

	memset (tag, 0, sizeof (tag));
	memcpy (tag, string, strlen (string));
	decoded = egg_base64_decode_inplace ((gchar *) tag, &n_decoded);
	if (!decoded) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "couldn't decode \"tag\" element");
		return NULL;
	}

	string = json_object_get_string_member (object, "ciphertext");
	if (!string) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "the root element doesn't contain \"ciphertext\"");
		return NULL;
	}

	buffer = g_strdup (string);
	decoded = egg_base64_decode_inplace (buffer, &n_decoded);
	if (!decoded) {
		g_free (buffer);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_INVALID_ARGUMENT,
				     "couldn't decode \"ciphertext\" element");
		return NULL;
	}

	gcry = gcry_cipher_open (&cipher, algo, GCRY_CIPHER_MODE_GCM, 0);
	if (gcry) {
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't open cipher");
		return NULL;
	}

	gcry = gcry_cipher_setkey (cipher, key, n_key);
	if (gcry) {
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't set key");
		return NULL;
	}

	gcry = gcry_cipher_setiv (cipher, iv, IV_SIZE);
	if (gcry) {
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't set IV");
		return NULL;
	}

	gcry = gcry_cipher_authenticate (cipher, protected, strlen (protected));
	if (gcry) {
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't set authentication data");
		return NULL;
	}

	gcry = gcry_cipher_decrypt (cipher, decoded, n_decoded, decoded, n_decoded);
	if (gcry) {
		g_free (decoded);
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't decrypt data");
		return NULL;
	}

	gcry = gcry_cipher_checktag (cipher, tag, TAG_SIZE);
	if (gcry) {
		g_free (decoded);
		gcry_cipher_close (cipher);
		g_set_error_literal (error,
				     G_IO_ERROR,
				     G_IO_ERROR_FAILED,
				     "couldn't check tag");
		return NULL;
	}

	gcry_cipher_close (cipher);

	*length = n_decoded;
	return decoded;
}
