/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#include "config.h"

#include "secret-private.h"
#include "secret-value.h"

#include "egg/egg-secure-memory.h"

#include <string.h>

/**
 * SECTION:secret-value
 * @title: SecretValue
 * @short_description: a value containing a secret
 *
 * A #SecretValue contains a password or other secret value.
 *
 * Use secret_value_get() to get the actual secret data, such as a password.
 * The secret data is not necessarily null-terminated, unless the content type
 * is "text/plain".
 *
 * Each #SecretValue has a content type. For passwords, this is "text/plain".
 * Use secret_value_get_content_type() to look at the content type.
 *
 * #SecretValue is reference counted and immutable. The secret data is only
 * freed when all references have been released via secret_value_unref().
 *
 * @stability: Unstable
 */

/**
 * SecretValue:
 *
 * A secret value, like a password or other binary secret.
 */

EGG_SECURE_DECLARE (secret_value);

struct _SecretValue {
	gint refs;
	gpointer secret;
	gsize length;
	GDestroyNotify destroy;
	gchar *content_type;
};

GType
secret_value_get_type (void)
{
	static gsize initialized = 0;
	static GType type = 0;

	if (g_once_init_enter (&initialized)) {
		type = g_boxed_type_register_static ("SecretValue",
		                                     (GBoxedCopyFunc)secret_value_ref,
		                                     (GBoxedFreeFunc)secret_value_unref);
		g_once_init_leave (&initialized, 1);
	}

	return type;
}

/**
 * secret_value_new_full:
 * @secret: the secret data
 * @length: the length of the data
 * @content_type: the content type of the data
 *
 * Create a #SecretValue for the secret data passed in. The secret data is
 * copied into non-pageable 'secure' memory.
 *
 * If the length is less than zero, then @secret is assumed to be
 * null-terminated.
 *
 * Returns: (transfer full): the new #SecretValue
 */
SecretValue *
secret_value_new (const gchar *secret,
                  gssize length,
                  const gchar *content_type)
{
	gchar *copy;

	g_return_val_if_fail (secret == NULL || length != 0, NULL);
	g_return_val_if_fail (content_type, NULL);

	if (length < 0)
		length = strlen (secret);

	copy = egg_secure_alloc (length + 1);
	memcpy (copy, secret, length);
	copy[length] = 0;
	return secret_value_new_full (copy, length, content_type, egg_secure_free);
}

/**
 * secret_value_new_full:
 * @secret: the secret data
 * @length: the length of the data
 * @content_type: the content type of the data
 * @destroy: function to call to free the secret data
 *
 * Create a #SecretValue for the secret data passed in. The secret data is
 * not copied, and will later be freed with the @destroy function.
 *
 * If the length is less than zero, then @secret is assumed to be
 * null-terminated.
 *
 * Returns: (transfer full): the new #SecretValue
 */
SecretValue *
secret_value_new_full (gchar *secret,
                       gssize length,
                       const gchar *content_type,
                       GDestroyNotify destroy)
{
	SecretValue *value;

	g_return_val_if_fail (secret == NULL || length != 0, NULL);
	g_return_val_if_fail (content_type, NULL);

	if (length < 0)
		length = strlen (secret);

	value = g_slice_new0 (SecretValue);
	value->refs = 1;
	value->content_type = g_strdup (content_type);
	value->destroy = destroy;
	value->length = length;
	value->secret = secret;

	return value;
}

/**
 * secret_value_get:
 * @value: the value
 * @length: (out): the length of the secret
 *
 * Get the secret data in the #SecretValue. The value is not necessarily
 * null-terminated unless it was created with secret_value_new() or a
 * null-terminated string was passed to secret_value_new_full().
 *
 * Returns: (array length=length): the secret data
 */
const gchar *
secret_value_get (SecretValue *value,
                  gsize *length)
{
	g_return_val_if_fail (value, NULL);
	if (length)
		*length = value->length;
	return value->secret;
}

/**
 * secret_value_get_content_type:
 * @value: the value
 *
 * Get the content type of the secret value, such as
 * <literal>text/plain</literal>.
 *
 * Returns: the content type
 */
const gchar *
secret_value_get_content_type (SecretValue *value)
{
	g_return_val_if_fail (value, NULL);
	return value->content_type;
}

/**
 * secret_value_unref:
 * @value: value to reference
 *
 * Add another reference to the #SecretValue. For each reference
 * secret_value_unref() should be called to unreference the value.
 *
 * Returns: (transfer full): the value
 */
SecretValue *
secret_value_ref (SecretValue *value)
{
	g_return_val_if_fail (value, NULL);
	g_atomic_int_inc (&value->refs);
	return value;
}

/**
 * secret_value_unref:
 * @value: (type Secret.Value) (allow-none): value to unreference
 *
 * Unreference a #SecretValue. When the last reference is gone, then
 * the value will be freed.
 */
void
secret_value_unref (gpointer value)
{
	SecretValue *val = value;

	g_return_if_fail (value != NULL);

	if (g_atomic_int_dec_and_test (&val->refs)) {
		g_free (val->content_type);
		if (val->destroy)
			(val->destroy) (val->secret);
		g_slice_free (SecretValue, val);
	}
}

gchar *
_secret_value_unref_to_password (SecretValue *value)
{
	SecretValue *val = value;
	gchar *result;

	g_return_val_if_fail (value != NULL, NULL);

	if (val->content_type && !g_str_equal (val->content_type, "text/plain")) {
		secret_value_unref (value);
		return NULL;
	}

	if (g_atomic_int_dec_and_test (&val->refs)) {
		if (val->destroy == egg_secure_free) {
			result = val->secret;

		} else {
			result = egg_secure_strdup (val->secret);
			if (val->destroy)
				(val->destroy) (val->secret);
		}
		g_free (val->content_type);
		g_slice_free (SecretValue, val);

	} else {
		result = egg_secure_strdup (val->secret);
	}

	return result;
}

gchar *
_secret_value_unref_to_string (SecretValue *value)
{
	SecretValue *val = value;
	gchar *result;

	g_return_val_if_fail (value != NULL, NULL);

	if (val->content_type && !g_str_equal (val->content_type, "text/plain")) {
		secret_value_unref (value);
		return NULL;
	}

	if (g_atomic_int_dec_and_test (&val->refs)) {
		if (val->destroy == g_free) {
			result = val->secret;

		} else {
			result = g_strdup (val->secret);
			if (val->destroy)
				(val->destroy) (val->secret);
		}
		g_free (val->content_type);
		g_slice_free (SecretValue, val);

	} else {
		result = g_strdup (val->secret);
	}

	return result;
}
