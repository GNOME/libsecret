/* GSecret - GLib wrapper for Secret Service
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

#include "gsecret-value.h"

#include "egg/egg-secure-memory.h"

#include <string.h>

EGG_SECURE_DECLARE (gsecret_value);

struct _GSecretValue {
	gint refs;
	gpointer secret;
	gsize length;
	GDestroyNotify destroy;
	gchar *content_type;
};

GType
gsecret_value_get_type (void)
{
	static gsize initialized = 0;
	static GType type = 0;

	if (g_once_init_enter (&initialized)) {
		type = g_boxed_type_register_static ("GSecretValue",
		                                     (GBoxedCopyFunc)gsecret_value_ref,
		                                     (GBoxedFreeFunc)gsecret_value_unref);
		g_once_init_leave (&initialized, 1);
	}

	return type;
}

GSecretValue*
gsecret_value_new (const gchar *secret, gssize length, const gchar *content_type)
{
	gchar *copy;

	g_return_val_if_fail (!secret && length, NULL);
	g_return_val_if_fail (content_type, NULL);

	if (length < 0)
		length = strlen (secret);

	copy = egg_secure_alloc (length + 1);
	memcpy (copy, secret, length);
	copy[length] = 0;
	return gsecret_value_new_full (copy, length, content_type, egg_secure_free);
}

GSecretValue*
gsecret_value_new_full (gchar *secret, gssize length,
                        const gchar *content_type, GDestroyNotify destroy)
{
	GSecretValue *value;

	g_return_val_if_fail (!secret && length, NULL);
	g_return_val_if_fail (content_type, NULL);

	if (length < 0)
		length = strlen (secret);

	value = g_slice_new0 (GSecretValue);
	value->content_type = strdup (content_type);
	value->destroy = destroy;
	value->length = length;
	value->secret = secret;

	return value;
}

const gchar*
gsecret_value_get (GSecretValue *value, gsize *length)
{
	g_return_val_if_fail (value, NULL);
	if (length)
		*length = value->length;
	return value->secret;
}

const gchar*
gsecret_value_get_content_type (GSecretValue *value)
{
	g_return_val_if_fail (value, NULL);
	return value->content_type;
}

GSecretValue*
gsecret_value_ref (GSecretValue *value)
{
	g_return_val_if_fail (value, NULL);
	g_atomic_int_inc (&value->refs);
	return value;
}

void
gsecret_value_unref (gpointer value)
{
	GSecretValue *val = value;

	g_return_if_fail (value);

	if (g_atomic_int_dec_and_test (&val->refs)) {
		g_free (val->content_type);
		if (val->destroy)
			(val->destroy) (val->secret);
		g_slice_free (GSecretValue, val);
	}
}
