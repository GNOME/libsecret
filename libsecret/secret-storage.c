/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 * Copyright 2018 Red Hat Inc.
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

#include "secret-storage.h"
#include "secret-private.h"

#include "egg/egg-base64.h"
#include "egg/egg-hkdf.h"
#include "egg/egg-jwe.h"
#include "egg/egg-secure-memory.h"

#define CONTEXT "secret storage key"

EGG_SECURE_DECLARE (secret_storage);

enum {
	PROP_0,
	PROP_FILE,
	PROP_PASSWORD
};

struct _SecretStorage
{
	GObject parent;
	GFile *file;
	gchar *password;
	guchar *key;
	gsize n_key;
	JsonNode *root;
	gchar *etag;
};

struct _SecretStorageClass
{
	GObjectClass parent_class;
};

static void secret_storage_async_initable_iface_init (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (SecretStorage, secret_storage, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, secret_storage_async_initable_iface_init));

static void
secret_storage_set_property (GObject      *object,
                             guint         prop_id,
                             const GValue *value,
                             GParamSpec   *pspec)
{
	SecretStorage *self = SECRET_STORAGE (object);

	switch (prop_id) {
	case PROP_FILE:
		self->file = g_value_dup_object (value);
		break;
	case PROP_PASSWORD:
		self->password = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
secret_storage_finalize (GObject *object)
{
	SecretStorage *self = SECRET_STORAGE (object);

	g_clear_object (&self->file);
	g_free (self->password);

	if (self->key) {
		egg_secure_clear (self->key, self->n_key);
		egg_secure_free (self->key);
	}

	json_node_unref (self->root);

	G_OBJECT_CLASS (secret_storage_parent_class)->finalize (object);
}

static void
secret_storage_class_init (SecretStorageClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->set_property = secret_storage_set_property;
	object_class->finalize = secret_storage_finalize;

	g_object_class_install_property (object_class,
					 PROP_FILE,
					 g_param_spec_object ("file", "File", "Storage file",
							      G_TYPE_FILE,
							      G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (object_class,
					 PROP_PASSWORD,
					 g_param_spec_string ("password", "Password", "Master password of storage",
							      "",
							      G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
}

static void
secret_storage_init (SecretStorage *self)
{
}

static void
on_load_contents (GObject *source_object,
		  GAsyncResult *result,
		  gpointer user_data)
{
	GFile *file = G_FILE (source_object);
	GTask *task = G_TASK (user_data);
	SecretStorage *self = g_task_get_source_object (task);
	GError *error;
	gchar *contents;
	gsize length;
	JsonParser *parser;
	JsonNode *root;
	guchar *plaintext;
	gsize n_plaintext;
	gchar *etag;

	error = NULL;
	if (!g_file_load_contents_finish (file, result, &contents, &length,
					  &etag, &error)) {
		if (error->code == G_IO_ERROR_NOT_FOUND) {
			g_error_free (error);
			self->root = json_node_new (JSON_NODE_ARRAY);
			json_node_take_array (self->root, json_array_new ());
			g_task_return_boolean (task, TRUE);
		} else {
			g_task_return_error (task, error);
		}
		g_object_unref (task);
		return;
	}

	g_free (self->etag);
	self->etag = etag;

	parser = json_parser_new ();
	error = NULL;
	if (!json_parser_load_from_data (parser, contents, length, &error)) {
		g_object_unref (parser);
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}
	root = json_parser_steal_root (parser);
	g_object_unref (parser);

	error = NULL;
	plaintext = egg_jwe_symmetric_decrypt (root, self->key, self->n_key,
					       &n_plaintext, &error);
	json_node_unref (root);
	if (!plaintext) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	parser = json_parser_new ();
	error = NULL;
	if (!json_parser_load_from_data (parser, (gchar *)plaintext, n_plaintext,
					 &error)) {
		g_object_unref (parser);
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}
	self->root = json_parser_steal_root (parser);
	g_object_unref (parser);

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
secret_storage_init_async (GAsyncInitable      *initable,
			   int                  io_priority,
			   GCancellable        *cancellable,
			   GAsyncReadyCallback  callback,
			   gpointer             user_data)
{
	SecretStorage *self = SECRET_STORAGE (initable);
	GTask *task;

	task = g_task_new (initable, cancellable, callback, user_data);

	self->n_key = 16;
	self->key = egg_secure_alloc (self->n_key);

	if (!egg_hkdf_perform ("sha256",
			       self->password,
			       strlen (self->password),
			       NULL,
			       0,
			       CONTEXT,
			       sizeof (CONTEXT)-1,
			       self->key,
			       self->n_key)) {
		egg_secure_free (self->key);
		self->key = NULL;
		g_task_return_new_error (task,
					 G_IO_ERROR,
					 G_IO_ERROR_FAILED,
					 "couldn't derive encryption key");
		g_object_unref (task);
		return;
	}

	g_file_load_contents_async (self->file, cancellable, on_load_contents, task);
}

static gboolean
secret_storage_init_finish (GAsyncInitable  *initable,
                            GAsyncResult    *res,
                            GError         **error)
{
	g_return_val_if_fail (g_task_is_valid (res, initable), FALSE);

	return g_task_propagate_boolean (G_TASK (res), error);
}

static void
secret_storage_async_initable_iface_init (GAsyncInitableIface *iface)
{
	iface->init_async = secret_storage_init_async;
	iface->init_finish = secret_storage_init_finish;
}

static void
on_replace_contents (GObject *source_object,
		     GAsyncResult *result,
		     gpointer user_data)
{
	GFile *file = G_FILE (source_object);
	GTask *task = G_TASK (user_data);
	SecretStorage *self = g_task_get_source_object (task);
	GError *error = NULL;
	gchar *etag;

	if (!g_file_replace_contents_finish (file, result, &etag, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_free (self->etag);
	self->etag = etag;

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static gboolean
node_matches_attributes (JsonNode   *node,
                         GHashTable *attributes)
{
	JsonObject *object;
	GHashTableIter iter;
	gpointer key, val;
	const gchar *attribute_value;

	/* Check if all the attributes are set on node */
	object = json_node_get_object (node);
	if (!object)
		return FALSE;

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, &key, &val)) {
		attribute_value = json_object_get_string_member (object, key);
		if (!attribute_value || !g_str_equal (attribute_value, val))
			return FALSE;
	}

	return TRUE;
}

static JsonNode *
storage_find_item (SecretStorage *storage,
                   GHashTable    *attributes)
{
	JsonArray *array;
	guint length, i;

	array = json_node_get_array (storage->root);
	if (!array)
		return NULL;

	length = json_array_get_length (array);
	for (i = 0; i < length; i++) {
		JsonNode *node = json_array_get_element (array, i);
		if (node_matches_attributes (node, attributes))
			return node;
	}

	return NULL;
}

static JsonNode *
hash_table_to_json (GHashTable *hash_table)
{
	GHashTableIter iter;
	gpointer key, val;
	JsonBuilder *builder;
	JsonNode *result;

	builder = json_builder_new ();
	json_builder_begin_object (builder);
	g_hash_table_iter_init (&iter, hash_table);
	while (g_hash_table_iter_next (&iter, &key, &val)) {
		json_builder_set_member_name (builder, key);
		json_builder_add_string_value (builder, val);
	}
	json_builder_end_object (builder);
	result = json_builder_get_root (builder);
	g_object_unref (builder);
	return result;
}

void
secret_storage_store (SecretStorage *self,
                      const SecretSchema *schema,
                      GHashTable *attributes,
                      const gchar *collection,
                      const gchar *label,
                      SecretValue *value,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
	JsonNode *item;
	JsonNode *root;
	JsonObject *object;
	JsonGenerator *generator;
	const gchar *data;
	gsize length;
	gchar *encoded;
	guchar *plaintext;
	gsize n_plaintext;
	gchar *ciphertext;
	gsize n_ciphertext;
	GTask *task;
	GError *error;

	g_return_if_fail (SECRET_IS_STORAGE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (self, cancellable, callback, user_data);

	/* Warnings raised already */
	if (schema != NULL &&
	    !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE)) {
		g_task_return_new_error (task,
					 G_IO_ERROR,
					 G_IO_ERROR_INVALID_ARGUMENT,
					 "couldn't validate attributes");
		g_object_unref (task);
		return;
	}

	if (!g_str_equal (collection, SECRET_COLLECTION_DEFAULT)) {
		g_task_return_boolean (task, TRUE);
		g_object_unref (task);
		return;
	}

	item = storage_find_item (self, attributes);
	if (!item) {
		item = json_node_new (JSON_NODE_OBJECT);
		object = json_object_new ();
		json_node_take_object (item, object);
		json_object_set_member (object, "attributes",
					hash_table_to_json (attributes));
		json_array_add_element (json_node_get_array (self->root), item);
	}

	object = json_node_get_object (item);
	json_object_set_string_member (object, "content-type",
				       secret_value_get_content_type (value));

	json_object_set_string_member (object, "label", label);

	data = secret_value_get (value, &length);
	encoded = egg_base64_encode ((guchar *) data, length);
	json_object_set_string_member (object, "value", encoded);
	g_free (encoded);

	generator = json_generator_new ();
	json_generator_set_root (generator, self->root);
	plaintext = (guchar *) json_generator_to_data (generator, &n_plaintext);
	g_object_unref (generator);

	error = NULL;
	root = egg_jwe_symmetric_encrypt (plaintext, n_plaintext, "A128GCM",
					  self->key, self->n_key, NULL, 0,
					  &error);
	g_free (plaintext);
	if (!root) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	generator = json_generator_new ();
	json_generator_set_root (generator, root);
	json_node_unref (root);
	ciphertext = json_generator_to_data (generator, &n_ciphertext);
	g_object_unref (generator);

	g_file_replace_contents_async (self->file,
				       ciphertext, n_ciphertext,
				       self->etag, TRUE,
				       G_FILE_CREATE_PRIVATE,
				       cancellable,
				       on_replace_contents,
				       task);
	g_task_set_task_data (task, ciphertext, g_free);
}

gboolean
secret_storage_store_finish (SecretStorage *self,
                             GAsyncResult *result,
                             GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}
