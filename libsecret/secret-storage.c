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
	JsonNode *session_collection;
	JsonNode *default_collection;
	gchar *etag;

	/* Locked by mutex */
	GMutex lock;
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

	json_node_unref (self->session_collection);
	g_clear_pointer (&self->default_collection, json_node_unref);

	g_free (self->etag);

	g_mutex_clear (&self->lock);

	G_OBJECT_CLASS (secret_storage_parent_class)->finalize (object);
}

static void
secret_storage_class_init (SecretStorageClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->set_property = secret_storage_set_property;
	object_class->finalize = secret_storage_finalize;

	g_object_class_install_property (object_class, PROP_FILE,
		 g_param_spec_object ("file", "File", "Storage file",
				      G_TYPE_FILE,
				      G_PARAM_WRITABLE |
				      G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (object_class, PROP_PASSWORD,
		 g_param_spec_string ("password", "Password", "Master password",
				      "",
				      G_PARAM_WRITABLE |
				      G_PARAM_CONSTRUCT_ONLY));
}

static void
secret_storage_init (SecretStorage *self)
{
	self->session_collection = json_node_new (JSON_NODE_ARRAY);
	json_node_take_array (self->session_collection, json_array_new ());
	g_mutex_init (&self->lock);
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
			self->default_collection =
				json_node_new (JSON_NODE_ARRAY);
			json_node_take_array (self->default_collection,
					      json_array_new ());
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
		g_free (contents);
		g_object_unref (parser);
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}
	g_free (contents);
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
		g_free (plaintext);
		g_object_unref (parser);
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}
	g_free (plaintext);
	self->default_collection = json_parser_steal_root (parser);
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

G_LOCK_DEFINE (storage_instance);
static gpointer storage_instance = NULL;

static void
on_new_async (GObject      *source_object,
              GAsyncResult *result,
              gpointer      user_data)
{
	GAsyncInitable *initable = G_ASYNC_INITABLE (source_object);
	GTask *task = G_TASK (user_data);
	GObject *instance;
	GError *error = NULL;

	instance = g_async_initable_new_finish (initable, result, &error);
	if (!instance) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	G_LOCK (storage_instance);
	storage_instance = instance;
	G_UNLOCK (storage_instance);

	g_task_return_pointer (task, instance, NULL);
	g_object_unref (task);
}

void
secret_storage_get_default (int                  io_priority,
			    GCancellable        *cancellable,
			    GAsyncReadyCallback  callback,
			    gpointer             user_data)
{
	SecretStorage *instance = NULL;
	const gchar *envvar;
	const gchar *password;
	GFile *file;
	GFile *dir;
	GTask *task;
	GError *error;

	task = g_task_new (NULL, cancellable, callback, user_data);

	G_LOCK (storage_instance);
	if (storage_instance != NULL)
		instance = g_object_ref (storage_instance);
	G_UNLOCK (storage_instance);

	if (instance != NULL) {
		g_task_return_pointer (task, instance, g_object_unref);
		g_object_unref (task);
		return;
	}

	envvar = g_getenv ("SECRET_STORAGE_PASSWORD");
	if (!envvar || *envvar == '\0') {
		g_task_return_new_error (task,
					 G_IO_ERROR,
					 G_IO_ERROR_INVALID_ARGUMENT,
					 "storage password is not set");
		g_object_unref (task);
		return;
	}
	password = envvar;

	envvar = g_getenv ("SECRET_STORAGE_PATH");
	if (!envvar || *envvar == '\0') {
		gchar *path;

		path = g_build_filename (g_get_user_data_dir (), "keyrings",
					 "default.jwe", NULL);
		file = g_file_new_for_path (path);
		g_free (path);
	} else {
		file = g_file_new_for_path (envvar);
	}

	dir = g_file_get_parent (file);
	if (!g_file_query_exists (file, cancellable)) {
		error = NULL;
		if (!g_file_make_directory_with_parents (dir, cancellable, &error)) {
			g_object_unref (file);
			g_object_unref (dir);
			g_task_return_error (task, error);
			g_object_unref (task);
			return;
		}
	}
	
	g_async_initable_new_async (SECRET_TYPE_STORAGE,
				    io_priority,
				    cancellable,
				    on_new_async,
				    task,
				    "password", password,
				    "file", file,
				    NULL);
}

SecretStorage *
secret_storage_get_default_finish (GAsyncResult  *result,
                                   GError       **error)
{
	g_return_val_if_fail (g_task_is_valid (result, NULL), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

void
_secret_storage_reset_default (void)
{
	G_LOCK (storage_instance);
	g_clear_object (&storage_instance);
	G_UNLOCK (storage_instance);
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
node_matches_attributes (JsonNode    *node,
                         GHashTable  *attributes,
                         const gchar *schema_name)
{
	JsonObject *object;
	GHashTableIter iter;
	gpointer key, val;
	JsonNode *attributes_node;
	JsonObject *attributes_object;

	object = json_node_get_object (node);
	if (!object)
		return FALSE;

	attributes_node = json_object_get_member (object, "attributes");
	if (!attributes_node)
		return FALSE;

	attributes_object = json_node_get_object (attributes_node);
	if (!attributes_object)
		return FALSE;

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, &key, &val)) {
		JsonNode *attribute_node =
			json_object_get_member (attributes_object, key);
		const gchar *attribute_value;
		if (!attribute_node)
			return FALSE;
		attribute_value = json_node_get_string (attribute_node);
		if (!attribute_value || !g_str_equal (attribute_value, val))
			return FALSE;
	}

	if (schema_name) {
		JsonNode *attribute_node =
			json_object_get_member (attributes_object, "xdg:schema");
		const gchar *attribute_value;
		if (!attribute_node)
			return FALSE;
		attribute_value = json_node_get_string (attribute_node);
		if (!attribute_value || !g_str_equal (attribute_value, schema_name))
			return FALSE;
	}

	return TRUE;
}

static JsonNode *
lookup_from_collection (JsonNode    *collection,
                        GHashTable  *attributes,
                        const gchar *schema_name)
{
	JsonArray *array;
	guint length, i;

	array = json_node_get_array (collection);
	if (!array)
		return NULL;

	length = json_array_get_length (array);
	for (i = 0; i < length; i++) {
		JsonNode *node = json_array_get_element (array, i);
		if (node_matches_attributes (node, attributes, schema_name))
			return node;
	}

	return NULL;
}

static gboolean
remove_from_collection (JsonNode    *collection,
                        GHashTable  *attributes,
                        const gchar *schema_name)
{
	JsonArray *array;
	guint length, i;

	array = json_node_get_array (collection);
	if (!array)
		return FALSE;

	length = json_array_get_length (array);
	for (i = 0; i < length; i++) {
		JsonNode *node = json_array_get_element (array, i);
		if (node_matches_attributes (node, attributes, schema_name)) {
			json_array_remove_element (array, i);
			return TRUE;
		}
	}

	return FALSE;
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

static void
store_default_collection (SecretStorage       *self,
                          GCancellable        *cancellable,
                          GAsyncReadyCallback  callback,
                          gpointer             user_data)
{
	JsonGenerator *generator;
	JsonNode *root;
	guchar *plaintext;
	gsize n_plaintext;
	gchar *ciphertext;
	gsize n_ciphertext;
	GError *error;
	GTask *task;

	task = g_task_new (self, cancellable, callback, user_data);

	generator = json_generator_new ();
	json_generator_set_root (generator, self->default_collection);
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

static gboolean
store_default_collection_finish (SecretStorage  *self,
                                 GAsyncResult   *result,
                                 GError        **error)
{
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
on_store_default_collection (GObject *source_object,
			     GAsyncResult *result,
			     gpointer user_data)
{
	SecretStorage *self = SECRET_STORAGE (source_object);
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	g_mutex_unlock (&self->lock);

	if (!store_default_collection_finish (self, result, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

typedef struct {
	SecretSchema *schema;
	GHashTable *attributes;
	gchar *collection;
	gchar *label;
	SecretValue *value;
} StorageClosure;

static void
storage_closure_free (StorageClosure *closure)
{
	g_clear_pointer (&closure->schema, secret_schema_unref);
	g_clear_pointer (&closure->attributes, g_hash_table_unref);
	g_clear_pointer (&closure->collection, g_free);
	g_clear_pointer (&closure->label, g_free);
	g_clear_pointer (&closure->value, secret_value_unref);
	g_free (closure);
}

static void
on_store (GObject *source_object,
	  GAsyncResult *result,
	  gpointer user_data)
{
	SecretStorage *self = SECRET_STORAGE (source_object);
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	if (!secret_storage_store_finish (self, result, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
on_get_default_store (GObject *source_object,
		      GAsyncResult *result,
		      gpointer user_data)
{
	SecretStorage *storage;
	GTask *task = G_TASK (user_data);
	StorageClosure *closure = g_task_get_task_data (task);
	GError *error = NULL;

	storage = secret_storage_get_default_finish (result, &error);
	if (!storage) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	secret_storage_store (storage,
			      closure->schema,
			      closure->attributes,
			      closure->collection,
			      closure->label,
			      closure->value,
			      g_task_get_cancellable (task),
			      on_store,
			      task);
}

void
secret_storage_store (SecretStorage       *self,
                      const SecretSchema  *schema,
                      GHashTable          *attributes,
                      const gchar         *collection,
                      const gchar         *label,
                      SecretValue         *value,
                      GCancellable        *cancellable,
                      GAsyncReadyCallback  callback,
                      gpointer             user_data)
{
	JsonNode *collection_, *item;
	const gchar *schema_name = NULL;
	JsonObject *object;
	const gchar *data;
	gsize length;
	gchar *encoded;
	GTask *task;

	g_return_if_fail (self == NULL || SECRET_IS_STORAGE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (self, cancellable, callback, user_data);

	if (self == NULL) {
		StorageClosure *closure = g_new0 (StorageClosure, 1);
		closure->schema = secret_schema_ref ((SecretSchema *) schema);
		closure->attributes = g_hash_table_ref (attributes);
		closure->collection = g_strdup (collection);
		closure->label = g_strdup (label);
		closure->value = secret_value_ref (value);
		g_task_set_task_data (task, closure,
				      (GDestroyNotify) storage_closure_free);
		secret_storage_get_default (G_PRIORITY_DEFAULT,
					    cancellable,
					    on_get_default_store,
					    task);
		return;
	}

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

	if (g_str_equal (collection, SECRET_COLLECTION_SESSION)) {
		collection_ = self->session_collection;
	} else {
		/* We only support session and default collections */
		collection_ = self->default_collection;
	}

	if (schema != NULL && !(schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME))
		schema_name = schema->name;

	g_mutex_lock (&self->lock);

	item = lookup_from_collection (collection_, attributes, schema_name);
	if (!item) {
		JsonNode *attributes_node;

		item = json_node_new (JSON_NODE_OBJECT);
		object = json_object_new ();
		json_node_take_object (item, object);
		attributes_node = hash_table_to_json (attributes);
		if (schema) {
			JsonObject *attributes_object =
				json_node_get_object (attributes_node);
			json_object_set_string_member (attributes_object,
						       "xdg:schema",
						       schema->name);
		}
		json_object_set_member (object, "attributes", attributes_node);
		json_array_add_element (json_node_get_array (collection_), item);
	}

	object = json_node_get_object (item);
	json_object_set_string_member (object, "content-type",
				       secret_value_get_content_type (value));

	json_object_set_string_member (object, "label", label);

	data = secret_value_get (value, &length);
	encoded = egg_base64_encode ((guchar *) data, length);
	json_object_set_string_member (object, "value", encoded);
	g_free (encoded);

	if (collection_ == self->session_collection) {
		g_mutex_unlock (&self->lock);
		g_task_return_boolean (task, TRUE);
		g_object_unref (task);
		return;
	}

	store_default_collection (self, cancellable,
				  on_store_default_collection, task);
}

gboolean
secret_storage_store_finish (SecretStorage *self,
                             GAsyncResult *result,
                             GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static SecretValue *
json_to_secret_value (JsonNode *node)
{
	JsonObject *object;
	guchar *value = NULL;
	gsize n_value;
	const gchar *content_type;

	object = json_node_get_object (node);
	if (!object)
		return NULL;

	value = (guchar *) g_strdup (json_object_get_string_member (object, "value"));
	if (!value || !egg_base64_decode_inplace ((gchar *) value, &n_value)) {
		g_free (value);
		return NULL;
	}

	content_type = json_object_get_string_member (object, "content-type");
	if (!content_type) {
		g_free (value);
		return NULL;
	}

	return secret_value_new_full ((gchar *) value, n_value, content_type, g_free);
}

static void
on_lookup (GObject *source_object,
	   GAsyncResult *result,
	   gpointer user_data)
{
	SecretStorage *self = SECRET_STORAGE (source_object);
	GTask *task = G_TASK (user_data);
	SecretValue *value;
	GError *error = NULL;

	value = secret_storage_lookup_finish (self, result, &error);
	if (error) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	if (value)
		g_task_return_pointer (task, value, secret_value_unref);
	else
		g_task_return_pointer (task, NULL, NULL);
	g_object_unref (task);
}

static void
on_get_default_lookup (GObject *source_object,
		       GAsyncResult *result,
		       gpointer user_data)
{
	SecretStorage *storage;
	GTask *task = G_TASK (user_data);
	StorageClosure *closure = g_task_get_task_data (task);
	GError *error = NULL;

	storage = secret_storage_get_default_finish (result, &error);
	if (!storage) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	secret_storage_lookup (storage,
			       closure->schema,
			       closure->attributes,
			       g_task_get_cancellable (task),
			       on_lookup,
			       task);
}

void
secret_storage_lookup (SecretStorage *self,
                       const SecretSchema *schema,
                       GHashTable *attributes,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	JsonNode *item;
	const gchar *schema_name = NULL;
	GTask *task;

	g_return_if_fail (self == NULL || SECRET_IS_STORAGE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (self, cancellable, callback, user_data);

	if (self == NULL) {
		StorageClosure *closure = g_new0 (StorageClosure, 1);
		closure->schema = secret_schema_ref ((SecretSchema *) schema);
		closure->attributes = g_hash_table_ref (attributes);
		g_task_set_task_data (task, closure,
				      (GDestroyNotify) storage_closure_free);
		secret_storage_get_default (G_PRIORITY_DEFAULT,
					    cancellable,
					    on_get_default_lookup,
					    task);
		return;
	}

	/* Warnings raised already */
	if (schema != NULL &&
	    !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE)) {
		g_task_return_new_error (task,
					 G_IO_ERROR,
					 G_IO_ERROR_INVALID_ARGUMENT,
					 "couldn't validate attributes");
		g_object_unref (task);
		return;
	}

	if (schema != NULL && !(schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME))
		schema_name = schema->name;

	g_mutex_lock (&self->lock);

	item = lookup_from_collection (self->session_collection, attributes,
				       schema_name);
	if (item) {
		g_mutex_unlock (&self->lock);
		g_task_return_pointer (task, json_to_secret_value (item),
				       secret_value_unref);
		g_object_unref (task);
		return;
	}

	item = lookup_from_collection (self->default_collection, attributes,
				       schema_name);
	if (item) {
		g_mutex_unlock (&self->lock);
		g_task_return_pointer (task, json_to_secret_value (item),
				       secret_value_unref);
		g_object_unref (task);
		return;
	}

	g_mutex_unlock (&self->lock);
	g_task_return_pointer (task, NULL, NULL);
	g_object_unref (task);
}

SecretValue *
secret_storage_lookup_finish (SecretStorage *self,
                              GAsyncResult *result,
                              GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, self), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
on_clear (GObject *source_object,
	  GAsyncResult *result,
	  gpointer user_data)
{
	SecretStorage *self = SECRET_STORAGE (source_object);
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	if (!secret_storage_clear_finish (self, result, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
on_get_default_clear (GObject *source_object,
		      GAsyncResult *result,
		      gpointer user_data)
{
	SecretStorage *storage;
	GTask *task = G_TASK (user_data);
	StorageClosure *closure = g_task_get_task_data (task);
	GError *error = NULL;

	storage = secret_storage_get_default_finish (result, &error);
	if (!storage) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	secret_storage_clear (storage,
			      closure->schema,
			      closure->attributes,
			      g_task_get_cancellable (task),
			      on_clear,
			      task);
}

void
secret_storage_clear (SecretStorage *self,
                      const SecretSchema *schema,
                      GHashTable *attributes,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
	const gchar *schema_name = NULL;
	GTask *task;

	g_return_if_fail (self == NULL || SECRET_STORAGE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (self, cancellable, callback, user_data);

	if (self == NULL) {
		StorageClosure *closure = g_new0 (StorageClosure, 1);
		closure->schema = secret_schema_ref ((SecretSchema *) schema);
		closure->attributes = g_hash_table_ref (attributes);
		g_task_set_task_data (task, closure,
				      (GDestroyNotify) storage_closure_free);
		secret_storage_get_default (G_PRIORITY_DEFAULT,
					    cancellable,
					    on_get_default_clear,
					    task);
		return;
	}

	/* Warnings raised already */
	if (schema != NULL &&
	    !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE)) {
		g_task_return_new_error (task,
					 G_IO_ERROR,
					 G_IO_ERROR_INVALID_ARGUMENT,
					 "couldn't validate attributes");
		g_object_unref (task);
		return;
	}

	if (schema != NULL && !(schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME))
		schema_name = schema->name;

	g_mutex_lock (&self->lock);

	if (remove_from_collection (self->session_collection, attributes,
				    schema_name)) {
		g_mutex_unlock (&self->lock);
		g_task_return_boolean (task, TRUE);
		g_object_unref (task);
		return;
	}

	if (remove_from_collection (self->default_collection, attributes,
				    schema_name)) {
		store_default_collection (self, cancellable,
					  on_store_default_collection, task);
		return;
	}

	g_mutex_unlock (&self->lock);
	g_task_return_boolean (task, FALSE);
	g_object_unref (task);
}

gboolean
secret_storage_clear_finish (SecretStorage *self,
                             GAsyncResult *result,
                             GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}
