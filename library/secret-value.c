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

SecretValue*
secret_value_new (const gchar *secret, gssize length, const gchar *content_type)
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

SecretValue*
secret_value_new_full (gchar *secret, gssize length,
                        const gchar *content_type, GDestroyNotify destroy)
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

const gchar*
secret_value_get (SecretValue *value, gsize *length)
{
	g_return_val_if_fail (value, NULL);
	if (length)
		*length = value->length;
	return value->secret;
}

const gchar*
secret_value_get_content_type (SecretValue *value)
{
	g_return_val_if_fail (value, NULL);
	return value->content_type;
}

SecretValue*
secret_value_ref (SecretValue *value)
{
	g_return_val_if_fail (value, NULL);
	g_atomic_int_inc (&value->refs);
	return value;
}

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
