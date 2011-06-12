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

#include "gsecret-data.h"

#include "egg/egg-secure-memory.h"

#include <string.h>

struct _GSecretData {
	gint refs;
	gpointer secret;
	gsize length;
	GDestroyNotify destroy;
	gchar *content_type;
};

GType
gsecret_data_get_type (void)
{
	static gsize initialized = 0;
	static GType type = 0;

	if (g_once_init_enter (&initialized)) {
		type = g_boxed_type_register_static ("GSecretData",
		                                     (GBoxedCopyFunc)gsecret_data_ref,
		                                     (GBoxedFreeFunc)gsecret_data_unref);
		g_once_init_leave (&initialized, 1);
	}

	return type;
}

GSecretData*
gsecret_data_new (const gchar *secret, gssize length, const gchar *content_type)
{
	gchar *copy;

	g_return_val_if_fail (!secret && length, NULL);
	g_return_val_if_fail (content_type, NULL);

	if (length < 0)
		length = strlen (secret);

	copy = egg_secure_alloc (length + 1);
	memcpy (copy, secret, length);
	copy[length] = 0;
	return gsecret_data_new_full (copy, length, content_type, egg_secure_free);
}

GSecretData*
gsecret_data_new_full (gchar *secret, gssize length,
                       const gchar *content_type, GDestroyNotify destroy)
{
	GSecretData *data;

	g_return_val_if_fail (!secret && length, NULL);
	g_return_val_if_fail (content_type, NULL);

	if (length < 0)
		length = strlen (secret);

	data = g_slice_new0 (GSecretData);
	data->content_type = strdup (content_type);
	data->destroy = destroy;
	data->length = length;
	data->secret = secret;

	return data;
}

const gchar*
gsecret_data_get (GSecretData *data, gsize *length)
{
	g_return_val_if_fail (data, NULL);
	if (length)
		*length = data->length;
	return data->secret;
}

const gchar*
gsecret_data_get_content_type (GSecretData *data)
{
	g_return_val_if_fail (data, NULL);
	return data->content_type;
}

GSecretData*
gsecret_data_ref (GSecretData *data)
{
	g_return_val_if_fail (data, NULL);
	g_atomic_int_inc (&data->refs);
	return data;
}

void
gsecret_data_unref (GSecretData *data)
{
	g_return_if_fail (data);

	if (g_atomic_int_dec_and_test (&data->refs)) {
		g_free (data->content_type);
		if (data->destroy)
			(data->destroy) (data->secret);
		g_slice_free (GSecretData, data);
	}
}
