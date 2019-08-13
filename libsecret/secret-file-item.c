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

#include "secret-file-item.h"
#include "secret-retrievable.h"
#include "secret-value.h"

struct _SecretFileItem
{
	GObject parent;
	GHashTable *attributes;
	gchar *label;
	guint64 created;
	guint64 modified;
	SecretValue *value;
	GVariant *encrypted;
};

static void secret_file_item_retrievable_iface (SecretRetrievableInterface *iface);

G_DEFINE_TYPE_WITH_CODE (SecretFileItem, secret_file_item, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (SECRET_TYPE_RETRIEVABLE, secret_file_item_retrievable_iface);
);

enum {
	PROP_0,
	PROP_ATTRIBUTES,
	PROP_LABEL,
	PROP_CREATED,
	PROP_MODIFIED,
	PROP_VALUE
};

static void
secret_file_item_init (SecretFileItem *self)
{
}

static void
secret_file_item_set_property (GObject *object,
                               guint prop_id,
                               const GValue *value,
                               GParamSpec *pspec)
{
	SecretFileItem *self = SECRET_FILE_ITEM (object);

	switch (prop_id) {
	case PROP_ATTRIBUTES:
		self->attributes = g_value_dup_boxed (value);
		break;
	case PROP_LABEL:
		self->label = g_value_dup_string (value);
		break;
	case PROP_CREATED:
		self->created = g_value_get_uint64 (value);
		break;
	case PROP_MODIFIED:
		self->modified = g_value_get_uint64 (value);
		break;
	case PROP_VALUE:
		self->value = g_value_dup_boxed (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
secret_file_item_get_property (GObject *object,
                               guint prop_id,
                               GValue *value,
                               GParamSpec *pspec)
{
	SecretFileItem *self = SECRET_FILE_ITEM (object);

	switch (prop_id) {
	case PROP_ATTRIBUTES:
		g_value_set_boxed (value, self->attributes);
		break;
	case PROP_LABEL:
		g_value_set_string (value, self->label);
		break;
	case PROP_CREATED:
		g_value_set_uint64 (value, self->created);
		break;
	case PROP_MODIFIED:
		g_value_set_uint64 (value, self->modified);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
secret_file_item_finalize (GObject *object)
{
	SecretFileItem *self = SECRET_FILE_ITEM (object);

	g_hash_table_unref (self->attributes);
	g_free (self->label);
	secret_value_unref (self->value);
	G_OBJECT_CLASS (secret_file_item_parent_class)->finalize (object);
}

static void
secret_file_item_class_init (SecretFileItemClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->set_property = secret_file_item_set_property;
	gobject_class->get_property = secret_file_item_get_property;
	gobject_class->finalize = secret_file_item_finalize;

	g_object_class_override_property (gobject_class, PROP_ATTRIBUTES, "attributes");
	g_object_class_override_property (gobject_class, PROP_LABEL, "label");
	g_object_class_override_property (gobject_class, PROP_CREATED, "created");
	g_object_class_override_property (gobject_class, PROP_MODIFIED, "modified");
	g_object_class_install_property (gobject_class, PROP_VALUE,
		   g_param_spec_boxed ("value", "Value", "Value",
				       SECRET_TYPE_VALUE, G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
}

static void
secret_file_item_retrieve_secret (SecretRetrievable *retrievable,
				  GCancellable *cancellable,
				  GAsyncReadyCallback callback,
				  gpointer user_data)
{
	SecretFileItem *self = SECRET_FILE_ITEM (retrievable);
	GTask *task = g_task_new (retrievable, cancellable, callback, user_data);

	g_task_return_pointer (task,
			       secret_value_ref (self->value),
			       secret_value_unref);
	g_object_unref (task);
}

static SecretValue *
secret_file_item_retrieve_secret_finish (SecretRetrievable *retrievable,
					 GAsyncResult *result,
					 GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, retrievable), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
secret_file_item_retrievable_iface (SecretRetrievableInterface *iface)
{
	iface->retrieve_secret = secret_file_item_retrieve_secret;
	iface->retrieve_secret_finish = secret_file_item_retrieve_secret_finish;
}

static GHashTable *
variant_to_attributes (GVariant *variant)
{
	GVariantIter iter;
	gchar *key;
	gchar *value;
	GHashTable *attributes;

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal,
					    g_free, g_free);

	g_variant_iter_init (&iter, variant);
	while (g_variant_iter_next (&iter, "{ss}", &key, &value))
		g_hash_table_insert (attributes, key, value);

	return attributes;
}

SecretFileItem *
secret_file_item_deserialize (GVariant *serialized)
{
	GVariant *attributes_variant;
	GHashTable *attributes;
	const gchar *label;
	guint64 created;
	guint64 modified;
	GVariant *array;
	const gchar *secret;
	gsize n_secret;
	SecretValue *value;
	SecretFileItem *result;

	g_variant_get (serialized, "(@a{ss}&stt@ay)",
		       &attributes_variant, &label, &created, &modified, &array);

	secret = g_variant_get_fixed_array (array, &n_secret, sizeof(gchar));
	value = secret_value_new (secret, n_secret, "text/plain");

	attributes = variant_to_attributes (attributes_variant);
	g_variant_unref (attributes_variant);

	result = g_object_new (SECRET_TYPE_FILE_ITEM,
			       "attributes", attributes,
			       "label", label,
			       "created", created,
			       "modified", modified,
			       "value", value,
			       NULL);
	g_hash_table_unref (attributes);
	g_variant_unref (array);
	secret_value_unref (value);

	return result;
}

GVariant *
secret_file_item_serialize (SecretFileItem *self)
{
	GVariantBuilder builder;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GVariant *variant;
	const gchar *secret;
	gsize n_secret;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
	g_hash_table_iter_init (&iter, self->attributes);
	while (g_hash_table_iter_next (&iter, &key, &value))
		g_variant_builder_add (&builder, "{ss}", key, value);

	secret = secret_value_get (self->value, &n_secret);
	variant = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
					     secret, n_secret, sizeof(guint8));

	variant = g_variant_new ("(@a{ss}stt@ay)",
				 g_variant_builder_end (&builder),
				 self->label,
				 self->created,
				 self->modified,
				 variant);
	g_variant_get_data (variant); /* force serialize */
	return g_variant_ref_sink (variant);
}
