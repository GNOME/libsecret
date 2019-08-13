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

#include "secret-backend.h"
#include "secret-file-backend.h"
#include "secret-file-collection.h"
#include "secret-file-item.h"
#include "secret-private.h"
#include "secret-retrievable.h"

static void secret_file_backend_async_initable_iface (GAsyncInitableIface *iface);
static void secret_file_backend_backend_iface (SecretBackendInterface *iface);

struct _SecretFileBackend {
	GObject parent;
	SecretFileCollection *collection;
	SecretServiceFlags init_flags;
};

G_DEFINE_TYPE_WITH_CODE (SecretFileBackend, secret_file_backend, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, secret_file_backend_async_initable_iface);
			 G_IMPLEMENT_INTERFACE (SECRET_TYPE_BACKEND, secret_file_backend_backend_iface);
			 _secret_backend_ensure_extension_point ();
			 g_io_extension_point_implement (SECRET_BACKEND_EXTENSION_POINT_NAME,
							 g_define_type_id,
							 "file",
							 0)
);

enum {
	PROP_0,
	PROP_FLAGS
};

static void
secret_file_backend_init (SecretFileBackend *self)
{
}

static void
secret_file_backend_set_property (GObject *object,
                                  guint prop_id,
                                  const GValue *value,
                                  GParamSpec *pspec)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (object);

	switch (prop_id) {
	case PROP_FLAGS:
		self->init_flags = g_value_get_flags (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
secret_file_backend_get_property (GObject *object,
                                  guint prop_id,
                                  GValue *value,
                                  GParamSpec *pspec)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (object);

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_flags (value, self->init_flags);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
secret_file_backend_finalize (GObject *object)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (object);

	g_clear_object (&self->collection);

	G_OBJECT_CLASS (secret_file_backend_parent_class)->finalize (object);
}

static void
secret_file_backend_class_init (SecretFileBackendClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->set_property = secret_file_backend_set_property;
	object_class->get_property = secret_file_backend_get_property;
	object_class->finalize = secret_file_backend_finalize;

	/**
	 * SecretFileBackend:flags:
	 *
	 * A set of flags describing which parts of the secret file have
	 * been initialized.
	 */
	g_object_class_override_property (object_class, PROP_FLAGS, "flags");
}

static void
on_collection_new_async (GObject *source_object,
			 GAsyncResult *result,
			 gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretFileBackend *self = g_task_get_source_object (task);
	GObject *object;
	GError *error = NULL;

	object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
					      result,
					      &error);
	if (object == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	self->collection = SECRET_FILE_COLLECTION (object);
	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
secret_file_backend_real_init_async (GAsyncInitable *initable,
				     int io_priority,
				     GCancellable *cancellable,
				     GAsyncReadyCallback callback,
				     gpointer user_data)
{
	gchar *path;
	GFile *file;
	GFile *dir;
	SecretValue *password;
	const gchar *envvar;
	GTask *task;
	GError *error = NULL;
	gboolean ret;

	task = g_task_new (initable, cancellable, callback, user_data);

	envvar = g_getenv ("SECRET_FILE_TEST_PATH");
	if (envvar != NULL && *envvar != '\0')
		path = g_strdup (envvar);
	else {
		path = g_build_filename (g_get_user_data_dir (),
					 "keyrings",
					 SECRET_COLLECTION_DEFAULT ".keyring",
					 NULL);
	}

	file = g_file_new_for_path (path);
	g_free (path);

	dir = g_file_get_parent (file);
	if (dir == NULL) {
		g_task_return_new_error (task,
					 G_IO_ERROR,
					 G_IO_ERROR_INVALID_ARGUMENT,
					 "not a valid path");
		g_object_unref (file);
		g_object_unref (task);
		return;
	}

	ret = g_file_make_directory_with_parents (dir, cancellable, &error);
	g_object_unref (dir);
	if (!ret && !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_EXISTS)) {
		g_task_return_error (task, error);
		g_object_unref (file);
		g_object_unref (task);
		return;
	}

	envvar = g_getenv ("SECRET_FILE_TEST_PASSWORD");
	if (envvar != NULL && *envvar != '\0')
		password = secret_value_new (envvar, -1, "text/plain");
	else {
		g_error ("master password is not retrievable");
		return;
	}

	g_async_initable_new_async (SECRET_TYPE_FILE_COLLECTION,
				    io_priority,
				    cancellable,
				    on_collection_new_async,
				    task,
				    "file", file,
				    "password", password,
				    NULL);
	g_object_unref (file);
	secret_value_unref (password);
}

static gboolean
secret_file_collection_real_init_finish (GAsyncInitable *initable,
					 GAsyncResult *result,
					 GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, initable), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
secret_file_backend_async_initable_iface (GAsyncInitableIface *iface)
{
	iface->init_async = secret_file_backend_real_init_async;
	iface->init_finish = secret_file_collection_real_init_finish;
}

static void
on_collection_write (GObject *source_object,
		     GAsyncResult *result,
		     gpointer user_data)
{
	SecretFileCollection *collection =
		SECRET_FILE_COLLECTION (source_object);
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	if (!secret_file_collection_write_finish (collection, result, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
secret_file_backend_real_store (SecretBackend *backend,
				const SecretSchema *schema,
				GHashTable *attributes,
				const gchar *collection,
				const gchar *label,
				SecretValue *value,
				GCancellable *cancellable,
				GAsyncReadyCallback callback,
				gpointer user_data)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (backend);
	GTask *task;
	GError *error = NULL;

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return;

	task = g_task_new (self, cancellable, callback, user_data);

	if (!secret_file_collection_replace (self->collection,
					     attributes,
					     label,
					     value,
					     &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	secret_file_collection_write (self->collection,
				      cancellable,
				      on_collection_write,
				      task);
}

static gboolean
secret_file_backend_real_store_finish (SecretBackend *backend,
				       GAsyncResult *result,
				       GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
on_retrieve_secret (GObject *source_object,
		    GAsyncResult *result,
		    gpointer user_data)
{
	SecretRetrievable *retrievable = SECRET_RETRIEVABLE (source_object);
	GTask *task = G_TASK (user_data);
	SecretValue *value;
	GError *error;

	value = secret_retrievable_retrieve_secret_finish (retrievable,
							   result,
							   &error);
	if (value == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
	}
	g_task_return_pointer (task, value, secret_value_unref);
	g_object_unref (task);
}

static void
secret_file_backend_real_lookup (SecretBackend *backend,
				 const SecretSchema *schema,
				 GHashTable *attributes,
				 GCancellable *cancellable,
				 GAsyncReadyCallback callback,
				 gpointer user_data)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (backend);
	GTask *task;
	GList *matches;
	GVariant *variant;
	SecretFileItem *item;
	GError *error = NULL;

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	task = g_task_new (self, cancellable, callback, user_data);

	matches = secret_file_collection_search (self->collection, attributes);

	if (matches == NULL) {
		g_task_return_pointer (task, NULL, NULL);
		g_object_unref (task);
		return;
	}

	variant = g_variant_ref (matches->data);
	g_list_free_full (matches, (GDestroyNotify)g_variant_unref);

	item = _secret_file_item_decrypt (variant, self->collection, &error);
	if (item == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	secret_retrievable_retrieve_secret (SECRET_RETRIEVABLE (item),
					    cancellable,
					    on_retrieve_secret,
					    task);
}

static SecretValue *
secret_file_backend_real_lookup_finish (SecretBackend *backend,
					GAsyncResult *result,
					GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
secret_file_backend_real_clear (SecretBackend *backend,
				const SecretSchema *schema,
				GHashTable *attributes,
				GCancellable *cancellable,
				GAsyncReadyCallback callback,
				gpointer user_data)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (backend);
	GTask *task;
	GError *error = NULL;

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	task = g_task_new (self, cancellable, callback, user_data);

	if (!secret_file_collection_clear (self->collection, attributes, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	secret_file_collection_write (self->collection,
				      cancellable,
				      on_collection_write,
				      task);
}

static gboolean
secret_file_backend_real_clear_finish (SecretBackend *backend,
				       GAsyncResult *result,
				       GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
unref_objects (gpointer data)
{
	GList *list = data;

	g_list_free_full (list, g_object_unref);
}

static void
secret_file_backend_real_search (SecretBackend *backend,
				 const SecretSchema *schema,
				 GHashTable *attributes,
				 SecretSearchFlags flags,
				 GCancellable *cancellable,
				 GAsyncReadyCallback callback,
				 gpointer user_data)
{
	SecretFileBackend *self = SECRET_FILE_BACKEND (backend);
	GTask *task;
	GList *matches;
	GList *results = NULL;
	GList *l;
	GError *error = NULL;

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return;

	task = g_task_new (self, cancellable, callback, user_data);

	matches = secret_file_collection_search (self->collection, attributes);
	for (l = matches; l; l = g_list_next (l)) {
		SecretFileItem *item = _secret_file_item_decrypt (l->data, self->collection, &error);
		if (item == NULL) {
			g_task_return_error (task, error);
			g_object_unref (task);
			return;
		}
		results = g_list_append (results, item);
	}

	g_task_return_pointer (task, results, unref_objects);
	g_object_unref (task);
}

static GList *
secret_file_backend_real_search_finish (SecretBackend *backend,
					GAsyncResult *result,
					GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
secret_file_backend_backend_iface (SecretBackendInterface *iface)
{
	iface->store = secret_file_backend_real_store;
	iface->store_finish = secret_file_backend_real_store_finish;
	iface->lookup = secret_file_backend_real_lookup;
	iface->lookup_finish = secret_file_backend_real_lookup_finish;
	iface->clear = secret_file_backend_real_clear;
	iface->clear_finish = secret_file_backend_real_clear_finish;
	iface->search = secret_file_backend_real_search;
	iface->search_finish = secret_file_backend_real_search_finish;
}
