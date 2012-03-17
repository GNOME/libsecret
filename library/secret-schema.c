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

#include "secret-enum-types.h"
#include "secret-password.h"
#include "secret-private.h"
#include "secret-value.h"

#include <egg/egg-secure-memory.h>

/**
 * SECTION:secret-schema
 * @title: SecretSchema
 * @short_description: Schema for defining which attributes are on items
 *
 * Each password is associated with a set of attributes. Attribute values can
 * be either strings, integers or booleans.
 *
 * The names and types of allowed attributes for a given password are defined
 * with a schema. Certain schemas are predefined like %SECRET_SCHEMA_NETWORK.
 *
 * Additional schemas can be defined via the %SecretSchema structure like this:
 *
 * If the schema flags contain the %SECRET_SCHEMA_ALLOW_UNDEFINED flag, then
 * undefined attributes are permitted.
 */

/**
 * SecretSchema:
 * @identifier: the dotted identifer of the schema
 * @flags: flags for the schema
 * @attributes: the attribute names and types of those attributes
 *
 * Represents a set of attributes that are stored with an item. These schemas
 * are used for interoperability between various services storing the same types
 * of items.
 *
 * Each schema has a identifier like "org.gnome.keyring.NetworkPassword", and defines
 * a set of attributes, and types (string, integer, boolean) for those attributes.
 *
 * Attributes are stored as strings in the Secret Service, and the attribute
 * types simply define standard ways to store integer and boolean values as strings.
 *
 * If @flags contains the %SECRET_SCHEMA_ALLOW_UNDEFINED flag, then attributes
 * not listed in @attributes are permitted.
 */

/**
 * SecretSchemaFlags:
 * @SECRET_SCHEMA_NONE: no flags for the schema
 * @SECRET_SCHEMA_ALLOW_UNDEFINED: allow undefined attributes
 *
 * Flags for a #SecretSchema definition.
 */

/**
 * SecretSchemaAttribute:
 * @name: name of the attribute
 * @type: the type of the attribute
 *
 * An attribute in a #SecretSchema.
 */

/**
 * SecretSchemaAttributeType:
 * @SECRET_SCHEMA_ATTRIBUTE_BOOLEAN: a boolean attribute, stored as 'true' or 'false'
 * @SECRET_SCHEMA_ATTRIBUTE_INTEGER: an integer attribute, stored as a decimal
 * @SECRET_SCHEMA_ATTRIBUTE_STRING: a utf-8 string attribute
 *
 * The type of an attribute in a #SecretSchema. Attributes are stored as strings
 * in the Secret Service, and the attribute types simply define standard ways
 * to store integer and boolean values as strings.
 */

static const SecretSchema network_schema = {
	SECRET_SCHEMA_IDENTIFIER_NETWORK,
	SECRET_SCHEMA_NONE,
	{
		{  "user", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "domain", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "object", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "protocol", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "port", SECRET_SCHEMA_ATTRIBUTE_INTEGER },
		{  "server", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{  "NULL", 0 },
	}
};

const SecretSchema *  SECRET_SCHEMA_NETWORK = &network_schema;

static const SecretSchema generic_schema = {
	SECRET_SCHEMA_IDENTIFIER_GENERIC,
	SECRET_SCHEMA_ALLOW_UNDEFINED,
	{
		{  "NULL", 0 },
	}
};

const SecretSchema *  SECRET_SCHEMA_GENERIC = &generic_schema;

static const SecretSchema note_schema = {
	SECRET_SCHEMA_IDENTIFIER_NOTE,
	SECRET_SCHEMA_ALLOW_UNDEFINED,
	{
		{  "NULL", 0 },
	}
};

const SecretSchema *  SECRET_SCHEMA_NOTE = &note_schema;

static SecretSchemaAttribute *
schema_attribute_copy (SecretSchemaAttribute *attribute)
{
	SecretSchemaAttribute *copy;

	copy = g_slice_new0 (SecretSchemaAttribute);
	copy->name = g_strdup (attribute->name);
	copy->type = attribute->type;

	return copy;
}

static void
schema_attribute_free (SecretSchemaAttribute *attribute)
{
	g_free ((gchar *)attribute->name);
	g_slice_free (SecretSchemaAttribute, attribute);
}

G_DEFINE_BOXED_TYPE (SecretSchemaAttribute, secret_schema_attribute,
                     schema_attribute_copy, schema_attribute_free);

/**
 * secret_schema_new:
 * @identifier: the dotted identifier of the schema
 * @flags: the flags for the schema
 * @attributes: (element-type utf8 Secret.SchemaAttributeType): the attribute names and types of those attributes
 *
 * Using this function is not normally necessary from C code. This is useful
 * for constructing #SecretSchema structures in bindings.
 *
 * A schema represents a set of attributes that are stored with an item. These
 * schemas are used for interoperability between various services storing the
 * same types of items.
 *
 * Each schema has an @identifier like "org.gnome.keyring.NetworkPassword", and
 * defines a set of attributes names, and types (string, integer, boolean) for
 * those attributes.
 *
 * Each key in the @attributes table should be a attribute name strings, and
 * the values in the table should be integers from the #SecretSchemaAttributeType
 * enumeration, representing the attribute type for each attribute name.
 *
 * If @flags contains the %SECRET_SCHEMA_ALLOW_UNDEFINED flag, then attributes
 * not listed in @attributes are permitted.
 *
 * Returns: (transfer full): the new schema, which should be unreferenced with
 *          secret_schema_unref() when done
 */
SecretSchema *
secret_schema_new (const gchar *identifier,
                   SecretSchemaFlags flags,
                   GHashTable *attributes)
{
	SecretSchema *schema;
	GHashTableIter iter;
	GEnumClass *enumc;
	gpointer value;
	gpointer key;
	gint type;
	gint ind = 0;

	g_return_val_if_fail (identifier != NULL, NULL);

	schema = g_slice_new0 (SecretSchema);
	schema->identifier = g_strdup (identifier);
	schema->flags = flags;
	schema->reserved = 1;

	if (attributes) {
		g_hash_table_iter_init (&iter, attributes);
		while (g_hash_table_iter_next (&iter, &key, &value)) {

			if (ind >= G_N_ELEMENTS (schema->attributes)) {
				g_warning ("too many attributes for schema, max %d",
				           (gint) G_N_ELEMENTS (schema->attributes));
				break;
			}

			type = GPOINTER_TO_INT (value);

			enumc = G_ENUM_CLASS (g_type_class_ref (SECRET_TYPE_SCHEMA_ATTRIBUTE_TYPE));
			if (!g_enum_get_value (enumc, type)) {
				g_warning ("invalid type for attribute %s", (gchar *)key);
				type = -1;
			}

			g_type_class_unref (enumc);

			if (type >= 0) {
				schema->attributes[ind].name = g_strdup (key);
				schema->attributes[ind].type = type;
			}

			ind++;
		}
	}

	return schema;
}

/**
 * secret_schema_ref:
 * @schema: the schema to reference
 *
 * Adds a reference to the #SecretSchema.
 *
 * It is not normally necessary to call this function from C code, and is
 * mainly present for the sake of bindings. If the @schema was statically
 * allocated, then this function will copy the schema.
 *
 * Returns: (transfer full): the referenced schema, which should be later
 *          unreferenced with secret_schema_unref()
 */
SecretSchema *
secret_schema_ref (SecretSchema *schema)
{
	SecretSchema *result;
	gint i;

	g_return_val_if_fail (schema != NULL, NULL);

	/* If it's static, then copy it */
	if (g_atomic_int_get (&schema->reserved) > 0) {
		g_atomic_int_inc (&schema->reserved);
		result = schema;
	} else {
		result = g_slice_new0 (SecretSchema);
		result->reserved = 1;
		result->identifier = g_strdup (schema->identifier);

		for (i = 0; i < G_N_ELEMENTS (schema->attributes); i++) {
			result->attributes[i].name = g_strdup (schema->attributes[i].name);
			result->attributes[i].type = schema->attributes[i].type;
		}
	}

	return result;
}

const SecretSchema *
_secret_schema_ref_if_nonstatic (const SecretSchema *schema)
{
	if (schema && g_atomic_int_get (&schema->reserved) > 0)
		secret_schema_ref ((SecretSchema *)schema);

	return schema;
}

/**
 * secret_schema_unref:
 * @schema: the schema to reference
 *
 * Releases a reference to the #SecretSchema. If the last reference is
 * released then the schema will be freed.
 *
 * It is not normally necessary to call this function from C code, and is
 * mainly present for the sake of bindings. It is an error to call this for
 * a @schema that was statically allocated.
 */
void
secret_schema_unref (SecretSchema *schema)
{
	gint refs;
	gint i;

	g_return_if_fail (schema != NULL);

	refs = g_atomic_int_add (&schema->reserved, -1);
	if (refs < 0) {
		g_warning ("should not unreference a static or invalid SecretSchema");

	} else if (refs == 0) {
		g_free ((gpointer)schema->identifier);
		for (i = 0; i < G_N_ELEMENTS (schema->attributes); i++)
			g_free ((gpointer)schema->attributes[i].name);
		g_slice_free (SecretSchema, schema);
	}
}

void
_secret_schema_unref_if_nonstatic (const SecretSchema *schema)
{
	if (schema && g_atomic_int_get (&schema->reserved) > 0)
		secret_schema_unref ((SecretSchema *)schema);
}

G_DEFINE_BOXED_TYPE (SecretSchema, secret_schema, secret_schema_ref, secret_schema_unref);
