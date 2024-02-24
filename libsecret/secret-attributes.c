/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
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

#include "secret-attributes.h"
#include "secret-private.h"

#include <string.h>

GVariant *
_secret_attributes_to_variant (GHashTable *attributes,
                               const gchar *schema_name)
{
	GHashTableIter iter;
	GVariantBuilder builder;
	const gchar *name;
	const gchar *value;

	g_return_val_if_fail (attributes != NULL, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, (gpointer *)&name, (gpointer *)&value)) {
		if (!schema_name || !g_str_equal (name, "xdg:schema"))
			g_variant_builder_add (&builder, "{ss}", name, value);
	}

	if (schema_name)
		g_variant_builder_add (&builder, "{ss}", "xdg:schema", schema_name);

	return g_variant_builder_end (&builder);
}

GHashTable *
_secret_attributes_for_variant (GVariant *variant)
{
	GVariantIter iter;
	GHashTable *attributes;
	gchar *value;
	gchar *key;

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	g_variant_iter_init (&iter, variant);
	while (g_variant_iter_next (&iter, "{ss}", &key, &value))
		g_hash_table_insert (attributes, key, value);

	return attributes;
}

/**
 * secret_attributes_build: (skip)
 * @schema: the schema for the attributes
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Build up a hash table of attribute values.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attributes should be terminated with a %NULL.
 *
 * Returns: (transfer full) (element-type utf8 utf8): a new table of
 *   attributes, to be released with [func@GLib.HashTable.unref]
 */
GHashTable *
secret_attributes_build (const SecretSchema *schema,
                         ...)
{
	GHashTable *attributes;
	va_list va;

	va_start (va, schema);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	return attributes;
}

/**
 * secret_attributes_buildv: (skip)
 * @schema: the schema for the attributes
 * @va: the attribute keys and values, terminated with %NULL
 *
 * Build up a hash table of attribute values.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attributes should be terminated with a %NULL.
 *
 * Returns: (transfer full) (element-type utf8 utf8): a new table of
 *   attributes, to be released with [func@GLib.HashTable.unref]
 */
GHashTable *
secret_attributes_buildv (const SecretSchema *schema,
                          va_list va)
{
	const gchar *attribute_name;
	SecretSchemaAttributeType type;
	GHashTable *attributes;
	const gchar *string;
	gboolean type_found;
	gchar *value = NULL;
	gboolean boolean;
	gint integer;
	gint i;

	g_return_val_if_fail (schema != NULL, NULL);

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	for (;;) {
		attribute_name = va_arg (va, const gchar *);
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
			g_critical ("The attribute '%s' was not found in the password schema.", attribute_name);
			g_hash_table_unref (attributes);
			return NULL;
		}

		switch (type) {
		case SECRET_SCHEMA_ATTRIBUTE_BOOLEAN:
			boolean = va_arg (va, gboolean);
			value = g_strdup (boolean ? "true" : "false");
			break;
		case SECRET_SCHEMA_ATTRIBUTE_STRING:
			string = va_arg (va, gchar *);
			if (string == NULL) {
				g_critical ("The value for attribute '%s' was NULL", attribute_name);
				return NULL;
			}
			if (!g_utf8_validate (string, -1, NULL)) {
				g_critical ("The value for attribute '%s' was not a valid UTF-8 string.", attribute_name);
				g_hash_table_unref (attributes);
				return NULL;
			}
			value = g_strdup (string);
			break;
		case SECRET_SCHEMA_ATTRIBUTE_INTEGER:
			integer = va_arg (va, gint);
			value = g_strdup_printf ("%d", integer);
			break;
		default:
			g_critical ("The password attribute '%s' has an invalid type in the password schema.", attribute_name);
			g_hash_table_unref (attributes);
			return NULL;
		}

		g_hash_table_insert (attributes, g_strdup (attribute_name), value);
	}

	return attributes;
}

/**
 * secret_attributes_validate:
 * @schema: the schema for the attributes
 * @attributes: the attributes to be validated
 * @error: place to report errors encountered
 *
 * Check if attributes are valid according to the provided schema.
 *
 * Verifies schema name if available, attribute names and parsing
 * of attribute values.
 *
 * Returns: whether or not the given attributes table is valid
 *
 * Since: 0.21.2
 */
gboolean
secret_attributes_validate (const SecretSchema *schema,
                            GHashTable *attributes,
			    GError **error)
{
	const SecretSchemaAttribute *attribute;
	GHashTableIter iter;
	gboolean any = FALSE;
	gchar *key;
	gchar *value;
	gchar *end;
	gint i;

	g_return_val_if_fail (schema != NULL, FALSE);

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, (gpointer *)&key, (gpointer *)&value)) {
		any = TRUE;

		/* If the 'xdg:schema' meta-attribute is present,
		   ensure that it is consistent with the schema
		   name. */
		if (g_str_equal (key, "xdg:schema")) {
			if (!g_str_equal (value, schema->name)) {
				g_set_error_literal (error,
						     SECRET_ERROR,
						     SECRET_ERROR_MISMATCHED_SCHEMA,
						     "Schema attribute doesn't match schema name");
				return FALSE;
			}
			continue;
		}

		/* Pass through libgnomekeyring specific attributes */
		if (g_str_has_prefix (key, "gkr:"))
			continue;

		/* Find the attribute */
		attribute = NULL;
		for (i = 0; i < G_N_ELEMENTS (schema->attributes); i++) {
			if (schema->attributes[i].name == NULL)
				break;
			if (g_str_equal (schema->attributes[i].name, key)) {
				attribute = &schema->attributes[i];
				break;
			}
		}

		if (attribute == NULL) {
			g_set_error (error,
				     SECRET_ERROR,
				     SECRET_ERROR_NO_MATCHING_ATTRIBUTE,
				     "Schema does not contain any attributes matching %s",
				     key);
			return FALSE;
		}

		switch (attribute->type) {
		case SECRET_SCHEMA_ATTRIBUTE_BOOLEAN:
			if (!g_str_equal (value, "true") && !g_str_equal (value, "false")) {
				g_set_error (error,
					     SECRET_ERROR,
					     SECRET_ERROR_WRONG_TYPE,
					     "Attribute %s could not be parsed into a boolean",
					     key);
				return FALSE;
			}
			break;
		case SECRET_SCHEMA_ATTRIBUTE_INTEGER:
			end = NULL;
			g_ascii_strtoll (value, &end, 10);
			if (!end || end[0] != '\0') {
				g_set_error (error,
					     SECRET_ERROR,
					     SECRET_ERROR_WRONG_TYPE,
					     "Attribute %s could not be parsed into an integer",
					     key);
				return FALSE;
			}
			break;
		case SECRET_SCHEMA_ATTRIBUTE_STRING:
			if (!g_utf8_validate (value, -1, NULL)) {
				g_set_error (error,
					     SECRET_ERROR,
					     SECRET_ERROR_WRONG_TYPE,
					     "Attribute %s could not be parsed into a string",
					     key);
				return FALSE;
			}
			break;
		default:
			g_set_error (error,
				     SECRET_ERROR,
				     SECRET_ERROR_WRONG_TYPE,
				     "%s: Invalid attribute type",
				     key);
			return FALSE;
		}
	}

	/* Nothing to match on, resulting search would match everything :S */
	if (!any && schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME) {
		g_set_error_literal (error,
				     SECRET_ERROR,
				     SECRET_ERROR_EMPTY_TABLE,
				     "Must have at least one attribute to check");
		return FALSE;
	}

	return TRUE;
}

// Private function to be used internally
gboolean
_secret_attributes_validate (const SecretSchema *schema,
                             GHashTable *attributes,
                             const char *pretty_function,
                             gboolean matching)
{
	GError *error = NULL;

	if (!secret_attributes_validate (schema, attributes, &error)) {
		// if matching is false, an empty table is fine
		if ((!matching) && (error->code == SECRET_ERROR_EMPTY_TABLE)) {
			g_error_free (error);
			return TRUE;
		}
		
		g_warning ("%s: error validating schema: %s", pretty_function, error->message);
		g_error_free (error);
		return FALSE;
	}
	return TRUE;
}


GHashTable *
_secret_attributes_copy (GHashTable *attributes)
{
	GHashTableIter iter;
	GHashTable *copy;
	gchar *key;
	gchar *value;

	if (attributes == NULL)
		return NULL;

	copy = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, (gpointer *)&key, (gpointer *)&value))
		g_hash_table_insert (copy, g_strdup (key), g_strdup (value));

	return copy;
}
