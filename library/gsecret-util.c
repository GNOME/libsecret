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

#include "gsecret-private.h"
#include "gsecret-types.h"

#include <string.h>

GQuark
gsecret_error_get_quark (void)
{
	static volatile gsize initialized = 0;
	static GQuark quark = 0;

	if (g_once_init_enter (&initialized)) {
		quark = g_quark_from_static_string ("gsecret-error");
		g_once_init_leave (&initialized, 1);
	}

	return quark;
}

GSecretParams *
_gsecret_params_new (GCancellable *cancellable,
                     GVariant *in)
{
	GSecretParams *params;

	params = g_slice_new0 (GSecretParams);
	params->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	params->in = g_variant_ref_sink (in);

	return params;
}

void
_gsecret_params_free (gpointer data)
{
	GSecretParams *params = data;

	g_clear_object (&params->cancellable);
	if (params->in)
		g_variant_unref (params->in);
	if (params->out)
		g_variant_unref (params->out);
	g_slice_free (GSecretParams, params);
}

gchar *
_gsecret_util_parent_path (const gchar *path)
{
	const gchar *pos;

	g_return_val_if_fail (path != NULL, NULL);

	pos = strrchr (path, '/');
	g_return_val_if_fail (pos != NULL, NULL);
	g_return_val_if_fail (pos != path, NULL);

	pos--;
	return g_strndup (path, pos - path);
}

gboolean
_gsecret_util_empty_path (const gchar *path)
{
	g_return_val_if_fail (path != NULL, TRUE);
	return (g_str_equal (path, "") || g_str_equal (path, "/"));
}

GVariant *
_gsecret_util_variant_for_attributes (GHashTable *attributes)
{
	GHashTableIter iter;
	GVariantBuilder builder;
	const gchar *name;
	const gchar *value;

	g_return_val_if_fail (attributes != NULL, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, (gpointer *)&name, (gpointer *)&value))
		g_variant_builder_add (&builder, "{ss}", name, value);

	return g_variant_builder_end (&builder);

}

GHashTable *
_gsecret_util_attributes_for_varargs (const GSecretSchema *schema,
                                      va_list args)
{
	const gchar *attribute_name;
	GSecretSchemaType type;
	GHashTable *attributes;
	const gchar *string;
	gboolean type_found;
	gchar *value = NULL;
	gboolean boolean;
	gint integer;
	gint i;

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	for (;;) {
		attribute_name = va_arg (args, const gchar *);
		if (attribute_name == NULL)
			break;

		type_found = FALSE;
		for (i = 0; i < G_N_ELEMENTS (schema->attributes); ++i) {
			if (!schema->attributes[i].name)
				break;
			if (g_str_equal (schema->attributes[i].name, attribute_name)) {
				type_found = TRUE;
				type = schema->attributes[i].type;
				break;
			}
		}

		if (!type_found) {
			g_warning ("The attribute '%s' was not found in the password schema.", attribute_name);
			g_hash_table_unref (attributes);
			return NULL;
		}

		switch (type) {
		case GSECRET_ATTRIBUTE_BOOLEAN:
			boolean = va_arg (args, gboolean);
			value = g_strdup (boolean ? "true" : "false");
			break;
		case GSECRET_ATTRIBUTE_STRING:
			string = va_arg (args, gchar *);
			if (!g_utf8_validate (string, -1, NULL)) {
				g_warning ("The value for attribute '%s' was not a valid utf-8 string.", attribute_name);
				g_hash_table_unref (attributes);
				return NULL;
			}
			value = g_strdup (string);
			break;
		case GSECRET_ATTRIBUTE_INTEGER:
			integer = va_arg (args, gint);
			value = g_strdup_printf ("%d", integer);
			break;
		default:
			g_warning ("The password attribute '%s' has an invalid type in the password schema.", attribute_name);
			g_hash_table_unref (attributes);
			return NULL;
		}

		g_hash_table_insert (attributes, g_strdup (attribute_name), value);
	}

	return attributes;
}
