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
#include "secret-password.h"
#include "secret-private.h"
#include "secret-retrievable.h"
#include "secret-backend.h"
#include "secret-value.h"

#include <egg/egg-secure-memory.h>

/**
 * secret_password_store: (skip)
 * @schema: the schema for attributes
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *   collection where to store the secret
 * @label: label for the secret
 * @password: the null-terminated password to store
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Store a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the @schema.
 * The list of attributes should be terminated with a %NULL.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * If @collection is %NULL, then the default collection will be
 * used. Use [const@COLLECTION_SESSION] to store the password in the session
 * collection, which doesn't get stored across login sessions.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_password_store (const SecretSchema *schema,
                       const gchar *collection,
                       const gchar *label,
                       const gchar *password,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data,
                       ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (schema != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (password != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return;

	secret_password_storev (schema, attributes, collection, label, password,
	                        cancellable, callback, user_data);

	g_hash_table_unref (attributes);
}

typedef struct {
	const SecretSchema *schema;
	GHashTable *attributes;
	gchar *collection;
	gchar *label;
	SecretValue *value;
} StoreClosure;

static void
store_closure_free (gpointer data)
{
	StoreClosure *store = data;
	_secret_schema_unref_if_nonstatic (store->schema);
	g_hash_table_unref (store->attributes);
	g_free (store->collection);
	g_free (store->label);
	secret_value_unref (store->value);
	g_free (store);
}

static void
on_store (GObject *source,
	  GAsyncResult *result,
	  gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretBackend *backend = SECRET_BACKEND (source);
	SecretBackendInterface *iface;
	GError *error = NULL;

	iface = SECRET_BACKEND_GET_IFACE (backend);
	g_return_if_fail (iface->store_finish != NULL);

	if (!iface->store_finish (backend, result, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
on_store_backend (GObject *source,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	StoreClosure *store = g_task_get_task_data (task);
	SecretBackend *backend;
	SecretBackendInterface *iface;
	GError *error = NULL;

	backend = secret_backend_get_finish (result, &error);
	if (backend == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	iface = SECRET_BACKEND_GET_IFACE (backend);
	g_return_if_fail (iface->store != NULL);

	iface->store (backend, store->schema, store->attributes,
		      store->collection, store->label, store->value,
		      g_task_get_cancellable (task),
		      on_store,
		      task);
}

/**
 * secret_password_storev: (rename-to secret_password_store)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8) (transfer full): the attribute keys and values
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *   collection where to store the secret
 * @label: label for the secret
 * @password: the null-terminated password to store
 * @cancellable: (nullable): optional cancellation object
 * @callback: (scope async): called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Store a password in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * If @collection is %NULL, then the default collection will be
 * used. Use [const@COLLECTION_SESSION] to store the password in the session
 * collection, which doesn't get stored across login sessions.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_password_storev (const SecretSchema *schema,
                        GHashTable *attributes,
                        const gchar *collection,
                        const gchar *label,
                        const gchar *password,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	StoreClosure *store;
	GTask *task;

	g_return_if_fail (label != NULL);
	g_return_if_fail (password != NULL);
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return;

	task = g_task_new (NULL, cancellable, callback, user_data);
	store = g_new0 (StoreClosure, 1);
	store->schema = _secret_schema_ref_if_nonstatic (schema);
	store->attributes = g_hash_table_ref (attributes);
	store->collection = g_strdup (collection);
	store->label = g_strdup (label);
	store->value = secret_value_new (password, -1, "text/plain");
	g_task_set_task_data (task, store, store_closure_free);

	secret_backend_get (SECRET_BACKEND_OPEN_SESSION,
			    cancellable,
			    on_store_backend, task);
}

/**
 * secret_password_store_binary: (skip)
 * @schema: the schema for attributes
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *    collection where to store the secret
 * @label: label for the secret
 * @value: a [struct@Value]
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Store a password in the secret service.
 *
 * This is similar to [func@password_store], but takes a
 * [struct@Value] as the argument instead of a null-terminated password.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Since: 0.19.0
 */
void
secret_password_store_binary (const SecretSchema *schema,
			      const gchar *collection,
			      const gchar *label,
			      SecretValue *value,
			      GCancellable *cancellable,
			      GAsyncReadyCallback callback,
			      gpointer user_data,
			      ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (schema != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return;

	secret_password_storev_binary (schema, attributes, collection, label, value,
				       cancellable, callback, user_data);

	g_hash_table_unref (attributes);
}

/**
 * secret_password_storev_binary: (rename-to secret_password_store_binary)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8) (transfer full): the attribute keys and values
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *   collection where to store the secret
 * @label: label for the secret
 * @value: a [struct@Value]
 * @cancellable: (nullable): optional cancellation object
 * @callback: (scope async): called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Store a password in the secret service.
 *
 * This is similar to [func@password_storev], but takes a
 * [struct@Value] as the argument instead of a null-terminated password.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Since: 0.19.0
 */
void
secret_password_storev_binary (const SecretSchema *schema,
			       GHashTable *attributes,
			       const gchar *collection,
			       const gchar *label,
			       SecretValue *value,
			       GCancellable *cancellable,
			       GAsyncReadyCallback callback,
			       gpointer user_data)
{
	StoreClosure *store;
	GTask *task;

	g_return_if_fail (label != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return;

	task = g_task_new (NULL, cancellable, callback, user_data);
	store = g_new0 (StoreClosure, 1);
	store->schema = _secret_schema_ref_if_nonstatic (schema);
	store->attributes = g_hash_table_ref (attributes);
	store->collection = g_strdup (collection);
	store->label = g_strdup (label);
	store->value = secret_value_ref (value);
	g_task_set_task_data (task, store, store_closure_free);

	secret_backend_get (SECRET_BACKEND_OPEN_SESSION,
			    cancellable,
			    on_store_backend, task);
}

/**
 * secret_password_store_finish:
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to store a password in the secret service.
 *
 * Returns: whether the storage was successful or not
 */
gboolean
secret_password_store_finish (GAsyncResult *result,
                              GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_task_is_valid (result, NULL), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/**
 * secret_password_store_sync:
 * @schema: the schema for attributes
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *   collection where to store the secret
 * @label: label for the secret
 * @password: the null-terminated password to store
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Store a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the @schema.
 * The list of attributes should be terminated with a %NULL.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * If @collection is %NULL, then the default collection will be
 * used. Use [const@COLLECTION_SESSION] to store the password in the session
 * collection, which doesn't get stored across login sessions.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the storage was successful or not
 */
gboolean
secret_password_store_sync (const SecretSchema *schema,
                            const gchar *collection,
                            const gchar *label,
                            const gchar *password,
                            GCancellable *cancellable,
                            GError **error,
                            ...)
{
	GHashTable *attributes;
	va_list va;
	gboolean ret;

	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	va_start (va, error);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return FALSE;

	ret = secret_password_storev_sync (schema, attributes, collection,
	                                   label, password, cancellable, error);

	g_hash_table_unref (attributes);
	return ret;
}

/**
 * secret_password_storev_sync: (rename-to secret_password_store_sync)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *   collection where to store the secret
 * @label: label for the secret
 * @password: the null-terminated password to store
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Store a password in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * If @collection is %NULL, then the default collection will be
 * used. Use [const@COLLECTION_SESSION] to store the password in the session
 * collection, which doesn't get stored across login sessions.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the storage was successful or not
 */
gboolean
secret_password_storev_sync (const SecretSchema *schema,
                             GHashTable *attributes,
                             const gchar *collection,
                             const gchar *label,
                             const gchar *password,
                             GCancellable *cancellable,
                             GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_password_storev (schema, attributes, collection, label, password,
	                        cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_password_store_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

/**
 * secret_password_store_binary_sync:
 * @schema: the schema for attributes
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *   collection where to store the secret
 * @label: label for the secret
 * @value: a [struct@Value]
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Store a password in the secret service.
 *
 * This is similar to [func@password_store_sync], but takes a
 * [struct@Value] as the argument instead of a null terminated password.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the storage was successful or not
 *
 * Since: 0.19.0
 */
gboolean
secret_password_store_binary_sync (const SecretSchema *schema,
				   const gchar *collection,
				   const gchar *label,
				   SecretValue *value,
				   GCancellable *cancellable,
				   GError **error,
				   ...)
{
	GHashTable *attributes;
	va_list va;
	gboolean ret;

	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	va_start (va, error);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return FALSE;

	ret = secret_password_storev_binary_sync (schema, attributes, collection,
						  label, value, cancellable, error);

	g_hash_table_unref (attributes);
	return ret;
}

/**
 * secret_password_storev_binary_sync: (rename-to secret_password_store_binary_sync)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *   collection where to store the secret
 * @label: label for the secret
 * @value: a [struct@Value]
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Store a password in the secret service.
 *
 * This is similar to [func@password_storev_sync], but takes a [struct@Value] as
 * the argument instead of a null-terminated passwords.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the storage was successful or not
 *
 * Since: 0.19.0
 */
gboolean
secret_password_storev_binary_sync (const SecretSchema *schema,
				    GHashTable *attributes,
				    const gchar *collection,
				    const gchar *label,
				    SecretValue *value,
				    GCancellable *cancellable,
				    GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_password_storev_binary (schema, attributes, collection, label, value,
				       cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_password_store_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

/**
 * secret_password_lookup: (skip)
 * @schema: the schema for the attributes
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Lookup a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attributes should be terminated with a %NULL.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_password_lookup (const SecretSchema *schema,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data,
                        ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (schema != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return;

	secret_password_lookupv (schema, attributes, cancellable,
	                         callback, user_data);

	g_hash_table_unref (attributes);
}

typedef struct {
	const SecretSchema *schema;
	GHashTable *attributes;
} LookupClosure;

static void
lookup_closure_free (gpointer data)
{
	LookupClosure *closure = data;
	_secret_schema_unref_if_nonstatic (closure->schema);
	g_hash_table_unref (closure->attributes);
	g_free (closure);
}

static void
on_lookup (GObject *source,
	   GAsyncResult *result,
	   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretBackend *backend = SECRET_BACKEND (source);
	SecretBackendInterface *iface;
	SecretValue *value;
	GError *error = NULL;

	iface = SECRET_BACKEND_GET_IFACE (backend);
	g_return_if_fail (iface->store_finish != NULL);

	value = iface->lookup_finish (backend, result, &error);
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
on_lookup_backend (GObject *source,
		   GAsyncResult *result,
		   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	LookupClosure *lookup = g_task_get_task_data (task);
	SecretBackend *backend;
	SecretBackendInterface *iface;
	GError *error = NULL;

	backend = secret_backend_get_finish (result, &error);
	if (backend == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	iface = SECRET_BACKEND_GET_IFACE (backend);
	g_return_if_fail (iface->store != NULL);

	iface->lookup (backend, lookup->schema, lookup->attributes,
		       g_task_get_cancellable (task),
		       on_lookup,
		       task);
}

/**
 * secret_password_lookupv: (rename-to secret_password_lookup)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8) (transfer full): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @callback: (scope async): called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Lookup a password in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_password_lookupv (const SecretSchema *schema,
                         GHashTable *attributes,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	LookupClosure *lookup;
	GTask *task;

	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	task = g_task_new (NULL, cancellable, callback, user_data);
	lookup = g_new0 (LookupClosure, 1);
	lookup->schema = _secret_schema_ref_if_nonstatic (schema);
	lookup->attributes = g_hash_table_ref (attributes);
	g_task_set_task_data (task, lookup, lookup_closure_free);

	secret_backend_get (SECRET_BACKEND_OPEN_SESSION,
			    cancellable,
			    on_lookup_backend, task);
}

/**
 * secret_password_lookup_nonpageable_finish: (skip)
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish an asynchronous operation to lookup a password in the secret service.
 *
 * Returns: (transfer full): a new password string stored in nonpageable memory
 *   which must be freed with [func@password_free] when done
 */
gchar *
secret_password_lookup_nonpageable_finish (GAsyncResult *result,
                                           GError **error)
{
	SecretValue *value;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_task_is_valid (result, NULL), NULL);

	value = g_task_propagate_pointer (G_TASK (result), error);
	if (value == NULL)
		return NULL;

	return _secret_value_unref_to_password (value);
}

/**
 * secret_password_lookup_binary_finish: (skip)
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish an asynchronous operation to lookup a password in the secret service.
 *
 * Returns: (transfer full): a newly allocated [struct@Value], which should be
 *   released with [method@Value.unref], or %NULL if no secret found
 *
 * Since: 0.19.0
 */
SecretValue *
secret_password_lookup_binary_finish (GAsyncResult *result,
				      GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_task_is_valid (result, NULL), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

/**
 * secret_password_lookup_finish:
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish an asynchronous operation to lookup a password in the secret service.
 *
 * Returns: (transfer full): a new password string which should be freed with
 *   [func@password_free] or may be freed with [func@GLib.free] when done
 */
gchar *
secret_password_lookup_finish (GAsyncResult *result,
                               GError **error)
{
	SecretValue *value;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_task_is_valid (result, NULL), NULL);

	value = g_task_propagate_pointer (G_TASK (result), error);
	if (value == NULL)
		return NULL;

	return _secret_value_unref_to_string (value);
}

/**
 * secret_password_lookup_sync: (skip)
 * @schema: the schema for the attributes
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Lookup a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attributes should be terminated with a %NULL.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a new password string which should be freed with
 *   [func@password_free] or may be freed with [func@GLib.free] when done
 */
gchar *
secret_password_lookup_sync (const SecretSchema *schema,
                             GCancellable *cancellable,
                             GError **error,
                             ...)
{
	GHashTable *attributes;
	gchar *password;
	va_list va;

	g_return_val_if_fail (schema != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	va_start (va, error);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return NULL;

	password = secret_password_lookupv_sync (schema, attributes,
	                                         cancellable, error);

	g_hash_table_unref (attributes);

	return password;
}

/**
 * secret_password_lookup_nonpageable_sync: (skip)
 * @schema: the schema for the attributes
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Lookup a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attributes should be terminated with a %NULL.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a new password string stored in nonpageable memory
 *   which must be freed with [func@password_free] when done
 */
gchar *
secret_password_lookup_nonpageable_sync (const SecretSchema *schema,
                                         GCancellable *cancellable,
                                         GError **error,
                                         ...)
{
	GHashTable *attributes;
	gchar *password;
	va_list va;

	g_return_val_if_fail (schema != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	va_start (va, error);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return NULL;

	password = secret_password_lookupv_nonpageable_sync (schema, attributes,
	                                                     cancellable, error);

	g_hash_table_unref (attributes);

	return password;
}

/**
 * secret_password_lookupv_nonpageable_sync: (skip)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Lookup a password in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a new password string stored in non pageable memory
 *   which should be freed with [func@password_free] when done
 */
gchar *
secret_password_lookupv_nonpageable_sync (const SecretSchema *schema,
                                          GHashTable *attributes,
                                          GCancellable *cancellable,
                                          GError **error)
{
	SecretSync *sync;
	gchar *password;

	g_return_val_if_fail (attributes != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_password_lookupv (schema, attributes, cancellable,
	                         _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	password = secret_password_lookup_nonpageable_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return password;
}

/**
 * secret_password_lookup_binary_sync: (skip)
 * @schema: the schema for the attributes
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Lookup a password in the secret service.
 *
 * This is similar to [func@password_lookup_sync], but returns a
 * [struct@Value] instead of a null-terminated password.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a newly allocated [struct@Value], which should be
 *   released with [method@Value.unref], or %NULL if no secret found
 *
 * Since: 0.19.0
 */
SecretValue *
secret_password_lookup_binary_sync (const SecretSchema *schema,
				    GCancellable *cancellable,
				    GError **error,
				    ...)
{
	GHashTable *attributes;
	SecretValue *value;
	va_list va;

	g_return_val_if_fail (schema != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	va_start (va, error);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return NULL;

	value = secret_password_lookupv_binary_sync (schema, attributes,
						     cancellable, error);

	g_hash_table_unref (attributes);

	return value;
}

/**
 * secret_password_lookupv_binary_sync: (skip)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Lookup a password in the secret service.
 *
 * This is similar to [func@password_lookupv_sync], but returns a
 * [struct@Value] instead of a null-terminated password.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a newly allocated [struct@Value], which should be
 *   released with [method@Value.unref], or %NULL if no secret found
 *
 * Since: 0.19.0
 */
SecretValue *
secret_password_lookupv_binary_sync (const SecretSchema *schema,
				     GHashTable *attributes,
				     GCancellable *cancellable,
				     GError **error)
{
	SecretSync *sync;
	SecretValue *value;

	g_return_val_if_fail (attributes != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_password_lookupv (schema, attributes, cancellable,
	                         _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	value = secret_password_lookup_binary_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return value;
}

/**
 * secret_password_lookupv_sync: (rename-to secret_password_lookup_sync)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Lookup a password in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a new password string which should be freed with
 *   [func@password_free] or may be freed with [func@GLib.free] when done
 */
gchar *
secret_password_lookupv_sync (const SecretSchema *schema,
                              GHashTable *attributes,
                              GCancellable *cancellable,
                              GError **error)
{
	SecretSync *sync;
	gchar *string;

	g_return_val_if_fail (attributes != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_password_lookupv (schema, attributes, cancellable,
	                         _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	string = secret_password_lookup_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return string;
}

/**
 * secret_password_clear:
 * @schema: the schema for the attributes
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Clear unlocked matching passwords from the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attributes should be terminated with a %NULL.
 *
 * All unlocked items that match the attributes will be deleted.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_password_clear (const SecretSchema *schema,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data,
                       ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (schema != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return;

	secret_password_clearv (schema, attributes, cancellable,
	                        callback, user_data);

	g_hash_table_unref (attributes);
}

typedef struct {
	const SecretSchema *schema;
	GHashTable *attributes;
} ClearClosure;

static void
clear_closure_free (gpointer data)
{
	ClearClosure *closure = data;
	_secret_schema_unref_if_nonstatic (closure->schema);
	g_hash_table_unref (closure->attributes);
	g_free (closure);
}

static void
on_clear (GObject *source,
	  GAsyncResult *result,
	  gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretBackend *backend = SECRET_BACKEND (source);
	SecretBackendInterface *iface;
	GError *error = NULL;

	iface = SECRET_BACKEND_GET_IFACE (backend);
	g_return_if_fail (iface->clear_finish != NULL);

	if (!iface->clear_finish (backend, result, &error)) {
		if (error)
			g_task_return_error (task, error);
		else
			g_task_return_boolean (task, FALSE);
		g_object_unref (task);
		return;
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
on_clear_backend (GObject *source,
		  GAsyncResult *result,
		  gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	ClearClosure *clear = g_task_get_task_data (task);
	SecretBackend *backend;
	SecretBackendInterface *iface;
	GError *error = NULL;

	backend = secret_backend_get_finish (result, &error);
	if (backend == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	iface = SECRET_BACKEND_GET_IFACE (backend);
	g_return_if_fail (iface->clear != NULL);

	iface->clear (backend, clear->schema, clear->attributes,
		      g_task_get_cancellable (task),
		      on_clear,
		      task);
}

/**
 * secret_password_clearv: (rename-to secret_password_clear)
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8) (transfer full): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @callback: (scope async): called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Remove unlocked matching passwords from the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * All unlocked items that match the attributes will be deleted.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_password_clearv (const SecretSchema *schema,
                        GHashTable *attributes,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	ClearClosure *clear;
	GTask *task;

	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	task = g_task_new (NULL, cancellable, callback, user_data);
	clear = g_new0 (ClearClosure, 1);
	clear->schema = _secret_schema_ref_if_nonstatic (schema);
	clear->attributes = g_hash_table_ref (attributes);
	g_task_set_task_data (task, clear, clear_closure_free);

	secret_backend_get (SECRET_SERVICE_NONE,
			    cancellable,
			    on_clear_backend, task);
}

/**
 * secret_password_clear_finish:
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish an asynchronous operation to remove passwords from the secret
 * service.
 *
 * Returns: whether any passwords were removed
 */
gboolean
secret_password_clear_finish (GAsyncResult *result,
                              GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_task_is_valid (result, NULL), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/**
 * secret_password_clear_sync:
 * @schema: the schema for the attributes
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Remove unlocked matching passwords from the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attributes should be terminated with a %NULL.
 *
 * All unlocked items that match the attributes will be deleted.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the any passwords were removed
 */
gboolean
secret_password_clear_sync (const SecretSchema* schema,
                            GCancellable *cancellable,
                            GError **error,
                            ...)
{
	GHashTable *attributes;
	gboolean result;
	va_list va;

	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	va_start (va, error);
	attributes = secret_attributes_buildv (schema, va);
	va_end (va);

	/* Precondition failed, already warned */
	if (!attributes)
		return FALSE;

	result = secret_password_clearv_sync (schema, attributes,
	                                      cancellable, error);

	g_hash_table_unref (attributes);

	return result;
}

/**
 * secret_password_clearv_sync: (rename-to secret_password_clear_sync)
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Remove unlocked matching passwords from the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * All unlocked items that match the attributes will be deleted.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether any passwords were removed
 */
gboolean
secret_password_clearv_sync (const SecretSchema *schema,
                             GHashTable *attributes,
                             GCancellable *cancellable,
                             GError **error)
{
	SecretSync *sync;
	gboolean result;

	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_password_clearv (schema, attributes, cancellable,
	                        _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = secret_password_clear_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return result;
}

/**
 * secret_password_search: (skip)
 * @schema: the schema for the attributes
 * @flags: search option flags
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Search for items in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attributes should be terminated with a %NULL.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Since: 0.19.0
 */
void
secret_password_search (const SecretSchema *schema,
                        SecretSearchFlags flags,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data,
                        ...)
{
        GHashTable *attributes;
        va_list va;

        g_return_if_fail (schema != NULL);
        g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

        va_start (va, user_data);
        attributes = secret_attributes_buildv (schema, va);
        va_end (va);

        /* Precondition failed, already warned */
        if (!attributes)
                return;

        secret_password_searchv (schema, attributes, flags, cancellable,
                                 callback, user_data);

        g_hash_table_unref (attributes);
}

typedef struct {
	const SecretSchema *schema;
	GHashTable *attributes;
	SecretSearchFlags flags;
} SearchClosure;

static void
search_closure_free (gpointer data)
{
	SearchClosure *closure = data;
	_secret_schema_unref_if_nonstatic (closure->schema);
	g_hash_table_unref (closure->attributes);
	g_free (closure);
}

static void
object_list_free (gpointer data)
{
	GList *list = data;
	g_list_free_full (list, g_object_unref);
}

static void
on_search (GObject *source,
	   GAsyncResult *result,
	   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretBackend *backend = SECRET_BACKEND (source);
	SecretBackendInterface *iface;
	GError *error = NULL;
	GList *items;

	iface = SECRET_BACKEND_GET_IFACE (backend);
	g_return_if_fail (iface->search_finish != NULL);

	items = iface->search_finish (backend, result, &error);
	if (error) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_task_return_pointer (task, items, object_list_free);
	g_object_unref (task);
}

static void
on_search_backend (GObject *source,
		   GAsyncResult *result,
		   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SearchClosure *search = g_task_get_task_data (task);
	SecretBackend *backend;
	SecretBackendInterface *iface;
	GError *error = NULL;

	backend = secret_backend_get_finish (result, &error);
	if (backend == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	iface = SECRET_BACKEND_GET_IFACE (backend);
	g_return_if_fail (iface->search != NULL);

	iface->search (backend,
		       search->schema, search->attributes, search->flags,
		       g_task_get_cancellable (task),
		       on_search,
		       task);
}

/**
 * secret_password_searchv: (rename-to secret_password_search)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8) (transfer full): the attribute keys and values
 * @flags: search option flags
 * @cancellable: (nullable): optional cancellation object
 * @callback: (scope async): called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Search for items in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Since: 0.19.0
 */
void
secret_password_searchv (const SecretSchema *schema,
                         GHashTable *attributes,
                         SecretSearchFlags flags,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	SearchClosure *search;
	GTask *task;

        g_return_if_fail (attributes != NULL);
        g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

        /* Warnings raised already */
        if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
                return;

	task = g_task_new (NULL, cancellable, callback, user_data);
	search = g_new0 (SearchClosure, 1);
	search->schema = _secret_schema_ref_if_nonstatic (schema);
	search->attributes = g_hash_table_ref (attributes);
	search->flags = flags;
	g_task_set_task_data (task, search, search_closure_free);

        secret_backend_get (SECRET_SERVICE_NONE,
			    cancellable,
			    on_search_backend, task);
}

/**
 * secret_password_search_finish:
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish an asynchronous operation to search for items in the secret service.
 *
 * Returns: (transfer full) (element-type Secret.Retrievable): a list of
 *   [iface@Retrievable] containing attributes of the matched items
 *
 * Since: 0.19.0
 */
GList *
secret_password_search_finish (GAsyncResult *result,
                               GError **error)
{
        g_return_val_if_fail (error == NULL || *error == NULL, NULL);
        g_return_val_if_fail (g_task_is_valid (result, NULL), NULL);

        return g_task_propagate_pointer (G_TASK (result), error);
}

/**
 * secret_password_search_sync: (skip)
 * @schema: the schema for the attributes
 * @flags: search option flags
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Search for items in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attributes should be terminated with a %NULL.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full) (element-type Secret.Retrievable): a list of
 *   [iface@Retrievable] containing attributes of the matched items
 *
 * Since: 0.19.0
 */
GList *
secret_password_search_sync (const SecretSchema *schema,
                             SecretSearchFlags flags,
                             GCancellable *cancellable,
                             GError **error,
                             ...)
{
        GHashTable *attributes;
        GList *items;
        va_list va;

        g_return_val_if_fail (schema != NULL, NULL);
        g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
        g_return_val_if_fail (error == NULL || *error == NULL, NULL);

        va_start (va, error);
        attributes = secret_attributes_buildv (schema, va);
        va_end (va);

        /* Precondition failed, already warned */
        if (!attributes)
                return NULL;

        items = secret_password_searchv_sync (schema, attributes, flags,
                                              cancellable, error);

        g_hash_table_unref (attributes);

        return items;
}

/**
 * secret_password_searchv_sync: (rename-to secret_password_search_sync)
 * @schema: (nullable): the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @flags: search option flags
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Search for items in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full) (element-type Secret.Retrievable): a list of
 *   [iface@Retrievable] containing attributes of the matched items
 *
 * Since: 0.19.0
 */
GList *
secret_password_searchv_sync (const SecretSchema *schema,
                              GHashTable *attributes,
                              SecretSearchFlags flags,
                              GCancellable *cancellable,
                              GError **error)
{
        SecretSync *sync;
        GList *items;

        g_return_val_if_fail (attributes != NULL, NULL);
        g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
        g_return_val_if_fail (error == NULL || *error == NULL, NULL);

        /* Warnings raised already */
        if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
                return NULL;

        sync = _secret_sync_new ();
        g_main_context_push_thread_default (sync->context);

        secret_password_searchv (schema, attributes, flags, cancellable,
                                 _secret_sync_on_result, sync);

        g_main_loop_run (sync->loop);

        items = secret_password_search_finish (sync->result, error);

        g_main_context_pop_thread_default (sync->context);
        _secret_sync_free (sync);

        return items;
}

/**
 * secret_password_free: (skip)
 * @password: (nullable): password to free
 *
 * Clear the memory used by a password, and then free it.
 *
 * This function must be used to free nonpageable memory returned by
 * [func@password_lookup_nonpageable_finish],
 * [func@password_lookup_nonpageable_sync] or
 * [func@password_lookupv_nonpageable_sync].
 */
void
secret_password_free (gchar *password)
{
	if (password == NULL)
		return;

	egg_secure_strfree (password);
}

/**
 * secret_password_wipe:
 * @password: (nullable): password to clear
 *
 * Clear the memory used by a password.
 */
void
secret_password_wipe (gchar *password)
{
	if (password == NULL)
		return;

	egg_secure_strclear (password);
}
