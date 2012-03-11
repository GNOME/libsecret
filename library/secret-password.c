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

#include "secret-password.h"
#include "secret-private.h"
#include "secret-value.h"

#include <egg/egg-secure-memory.h>

/**
 * SECTION:secret-password
 * @title: Password storage
 * @short_description: Simple password storage and lookup
 *
 * This is a simple API for storing passwords and retrieving passwords in the
 * Secret Service.
 *
 * Each password is associated with a set of attributes. Attribute values can
 * be either strings, integers or booleans.
 *
 * The names and types of allowed attributes for a given password are defined
 * with a schema. Certain schemas are predefined. Additional schemas can be
 * defined via the %SecretSchema structure.
 *
 * Each of the functions accept a variable list of attributes names and their
 * values. Include a %NULL to terminate the list of attributes.
 */

typedef struct {
	const SecretSchema *schema;
	GHashTable *attributes;
	gchar *collection_path;
	gchar *label;
	SecretValue *value;
	GCancellable *cancellable;
	gboolean created;
} StoreClosure;

static void
store_closure_free (gpointer data)
{
	StoreClosure *closure = data;
	_secret_schema_unref_if_nonstatic (closure->schema);
	g_hash_table_unref (closure->attributes);
	g_free (closure->collection_path);
	g_free (closure->label);
	secret_value_unref (closure->value);
	g_clear_object (&closure->cancellable);
	g_slice_free (StoreClosure, closure);
}

static void
on_store_complete (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	StoreClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	closure->created = secret_service_store_finish (SECRET_SERVICE (source),
	                                                result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_store_connected (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	StoreClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *service;
	GError *error = NULL;

	service = secret_service_get_finish (result, &error);
	if (error == NULL) {
		secret_service_storev (service, closure->schema,
		                       closure->attributes,
		                       closure->collection_path,
		                       closure->label, closure->value,
		                       closure->cancellable,
		                       on_store_complete,
		                       g_object_ref (res));
		g_object_unref (service);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (res);
}

/**
 * secret_password_store:
 * @schema: the schema for attributes
 * @collection_path: (allow-none): the dbus path to the collection where to store the secret
 * @label: label for the secret
 * @password: the null-terminated password to store
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Store a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the @schema.
 * The list of attribtues should be terminated with a %NULL.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * If @collection_path is %NULL, then the default collection will be
 * used. Use #SECRET_COLLECTION_SESSION to store the password in the session
 * collection, which doesn't get stored across login sessions.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_password_store (const SecretSchema *schema,
                       const gchar *collection_path,
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
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	secret_password_storev (schema, attributes, collection_path, label, password,
	                        cancellable, callback, user_data);

	g_hash_table_unref (attributes);
}

/**
 * secret_password_storev:
 * @schema: the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @collection_path: (allow-none): the dbus path to the collection where to store the secret
 * @label: label for the secret
 * @password: the null-terminated password to store
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Store a password in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * If @collection_path is %NULL, then the default collection will be
 * used. Use #SECRET_COLLECTION_SESSION to store the password in the session
 * collection, which doesn't get stored across login sessions.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Rename to: secret_password_store
 */
void
secret_password_storev (const SecretSchema *schema,
                        GHashTable *attributes,
                        const gchar *collection_path,
                        const gchar *label,
                        const gchar *password,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GSimpleAsyncResult *res;
	StoreClosure *closure;

	g_return_if_fail (schema != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (password != NULL);
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return;

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 secret_password_storev);
	closure = g_slice_new0 (StoreClosure);
	closure->schema = _secret_schema_ref_if_nonstatic (schema);
	closure->collection_path = g_strdup (collection_path);
	closure->label = g_strdup (label);
	closure->value = secret_value_new (password, -1, "text/plain");
	closure->attributes = _secret_util_attributes_copy (attributes);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, store_closure_free);

	secret_service_get (SECRET_SERVICE_OPEN_SESSION, cancellable,
	                    on_store_connected, g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_service_store_finish:
 * @self: the secret service
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
	GSimpleAsyncResult *res;
	StoreClosure *closure;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      secret_password_storev), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->created;
}

/**
 * secret_password_store_sync:
 * @schema: the schema for attributes
 * @collection_path: (allow-none): the dbus path to the collection where to store the secret
 * @label: label for the secret
 * @password: the null-terminated password to store
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Store a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the @schema.
 * The list of attribtues should be terminated with a %NULL.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * If @collection_path is %NULL, then the default collection will be
 * used. Use #SECRET_COLLECTION_SESSION to store the password in the session
 * collection, which doesn't get stored across login sessions.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the storage was successful or not
 */
gboolean
secret_password_store_sync (const SecretSchema *schema,
                            const gchar *collection_path,
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
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	ret = secret_password_storev_sync (schema, attributes, collection_path,
	                                   label, password, cancellable, error);

	g_hash_table_unref (attributes);
	return ret;
}

/**
 * secret_password_storev_sync:
 * @schema: the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @collection_path: (allow-none): the dbus path to the collection where to store the secret
 * @label: label for the secret
 * @password: the null-terminated password to store
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Store a password in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * If @collection_path is %NULL, then the default collection will be
 * used. Use #SECRET_COLLECTION_SESSION to store the password in the session
 * collection, which doesn't get stored across login sessions.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the storage was successful or not
 *
 * Rename to: secret_password_store_sync
 */
gboolean
secret_password_storev_sync (const SecretSchema *schema,
                             GHashTable *attributes,
                             const gchar *collection_path,
                             const gchar *label,
                             const gchar *password,
                             GCancellable *cancellable,
                             GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_password_storev (schema, attributes, collection_path, label, password,
	                        cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_password_store_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

typedef struct {
	GCancellable *cancellable;
	GHashTable *attributes;
	SecretValue *value;
	const SecretSchema *schema;
} LookupClosure;

static void
lookup_closure_free (gpointer data)
{
	LookupClosure *closure = data;
	_secret_schema_unref_if_nonstatic (closure->schema);
	g_clear_object (&closure->cancellable);
	g_hash_table_unref (closure->attributes);
	if (closure->value)
		secret_value_unref (closure->value);
	g_slice_free (LookupClosure, closure);
}

/**
 * secret_password_lookup: (skip)
 * @schema: the schema to for attributes
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Lookup a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attribtues should be terminated with a %NULL.
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
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	secret_password_lookupv (schema, attributes, cancellable,
	                         callback, user_data);

	g_hash_table_unref (attributes);
}

static void
on_lookup_complete (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	LookupClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	closure->value = secret_service_lookup_finish (SECRET_SERVICE (source),
	                                               result, &error);

	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_lookup_connected (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	LookupClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *service;
	GError *error = NULL;

	service = secret_service_get_finish (result, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else {
		secret_service_lookupv (service, closure->schema, closure->attributes,
		                        closure->cancellable, on_lookup_complete,
		                        g_object_ref (res));
		g_object_unref (service);
	}

	g_object_unref (res);
}

/**
 * secret_password_lookupv:
 * @schema: (allow-none): the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Lookup a password in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Rename to: secret_password_lookup
 */
void
secret_password_lookupv (const SecretSchema *schema,
                         GHashTable *attributes,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	GSimpleAsyncResult *res;
	LookupClosure *closure;

	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return;

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 secret_password_lookupv);
	closure = g_slice_new0 (LookupClosure);
	closure->schema = _secret_schema_ref_if_nonstatic (schema);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->attributes = _secret_util_attributes_copy (attributes);
	g_simple_async_result_set_op_res_gpointer (res, closure, lookup_closure_free);

	secret_service_get (SECRET_SERVICE_OPEN_SESSION, cancellable,
	                    on_lookup_connected, g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_password_lookup_nonpageable_finish: (skip)
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish an asynchronous operation to lookup a password in the secret service.
 *
 * Returns: (transfer full): a new password string stored in nonpageable memory
 *          which must be freed with secret_password_free() when done
 */
gchar *
secret_password_lookup_nonpageable_finish (GAsyncResult *result,
                                           GError **error)
{
	GSimpleAsyncResult *res;
	LookupClosure *closure;
	const gchar *content_type;
	gchar *password = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      secret_password_lookupv), NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	if (closure->value == NULL)
		return NULL;

	content_type = secret_value_get_content_type (closure->value);
	if (content_type && g_str_equal (content_type, "text/plain")) {
		password = _secret_value_unref_to_password (closure->value);
		closure->value = NULL;
	}

	return password;
}

/**
 * secret_password_lookup_finish:
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish an asynchronous operation to lookup a password in the secret service.
 *
 * Returns: (transfer full): a new password string which should be freed with
 *          secret_password_free() or may be freed with g_free() when done
 */
gchar *
secret_password_lookup_finish (GAsyncResult *result,
                               GError **error)
{
	GSimpleAsyncResult *res;
	LookupClosure *closure;
	const gchar *content_type;
	gchar *string = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      secret_password_lookupv), NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	if (closure->value == NULL)
		return NULL;

	content_type = secret_value_get_content_type (closure->value);
	if (content_type && g_str_equal (content_type, "text/plain")) {
		string = _secret_value_unref_to_string (closure->value);
		closure->value = NULL;
	}

	return string;
}

/**
 * secret_password_lookup_sync: (skip)
 * @schema: the schema to for attributes
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Lookup a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attribtues should be terminated with a %NULL.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a new password string which should be freed with
 *          secret_password_free() or may be freed with g_free() when done
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
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	password = secret_password_lookupv_sync (schema, attributes,
	                                         cancellable, error);

	g_hash_table_unref (attributes);

	return password;
}

/**
 * secret_password_lookup_nonpageable_sync: (skip)
 * @schema: the schema to for attributes
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Lookup a password in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attribtues should be terminated with a %NULL.
 *
 * If no secret is found then %NULL is returned.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a new password string stored in nonpageable memory
 *          which must be freed with secret_password_free() when done
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
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	password = secret_password_lookupv_nonpageable_sync (schema, attributes,
	                                                     cancellable, error);

	g_hash_table_unref (attributes);

	return password;
}

/**
 * secret_password_lookupv_nonpageable_sync: (skip)
 * @schema: (allow-none): the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: optional cancellation object
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
 *          which should be freed with secret_password_free() when done
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
	if (!_secret_util_attributes_validate (schema, attributes))
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
 * secret_password_lookupv_sync:
 * @schema: (allow-none): the schema for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: optional cancellation object
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
 *          secret_password_free() or may be freed with g_free() when done
 *
 * Rename to: secret_password_lookup_sync
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
	if (!_secret_util_attributes_validate (schema, attributes))
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

typedef struct {
	GCancellable *cancellable;
	GHashTable *attributes;
	gboolean deleted;
	const SecretSchema *schema;
} DeleteClosure;

static void
delete_closure_free (gpointer data)
{
	DeleteClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_hash_table_unref (closure->attributes);
	_secret_schema_unref_if_nonstatic (closure->schema);
	g_slice_free (DeleteClosure, closure);
}

/**
 * secret_password_remove:
 * @schema: the schema to for attributes
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Remove a password from the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attribtues should be terminated with a %NULL.
 *
 * If multiple items match the attributes, then only one will be deleted.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_password_remove (const SecretSchema *schema,
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
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	secret_password_removev (schema, attributes, cancellable,
	                         callback, user_data);

	g_hash_table_unref (attributes);
}

static void
on_delete_complete (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	closure->deleted = secret_service_remove_finish (SECRET_SERVICE (source),
	                                                 result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	g_simple_async_result_complete (res);

	g_object_unref (res);
}

static void
on_delete_connect (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *service;
	GError *error = NULL;

	service = secret_service_get_finish (result, &error);
	if (error == NULL) {
		secret_service_removev (service, closure->schema, closure->attributes,
		                        closure->cancellable, on_delete_complete,
		                        g_object_ref (res));
		g_object_unref (service);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (res);
}

/**
 * secret_password_removev:
 * @schema: (allow-none): the schema to for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Remove a password from the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If multiple items match the attributes, then only one will be deleted.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Rename to: secret_password_remove
 */
void
secret_password_removev (const SecretSchema *schema,
                         GHashTable *attributes,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return;

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 secret_password_removev);
	closure = g_slice_new0 (DeleteClosure);
	closure->schema = _secret_schema_ref_if_nonstatic (schema);
	closure->attributes = _secret_util_attributes_copy (attributes);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, delete_closure_free);

	secret_service_get (SECRET_SERVICE_NONE, cancellable,
	                    on_delete_connect, g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_password_remove_finish
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish an asynchronous operation to remove a password from the secret
 * service.
 *
 * Returns: whether the removal was successful or not
 */
gboolean
secret_password_remove_finish (GAsyncResult *result,
                               GError **error)
{
	DeleteClosure *closure;
	GSimpleAsyncResult *res;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      secret_password_removev), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->deleted;
}

/**
 * secret_password_remove_sync:
 * @schema: the schema to for attributes
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Remove a password from the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attribtues should be terminated with a %NULL.
 *
 * If multiple items match the attributes, then only one will be deleted.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the removal was successful or not
 */
gboolean
secret_password_remove_sync (const SecretSchema* schema,
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
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	result = secret_password_removev_sync (schema, attributes,
	                                       cancellable, error);

	g_hash_table_unref (attributes);

	return result;
}

/**
 * secret_password_removev_sync:
 * @schema: (allow-none): the schema to for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Remove a password from the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If multiple items match the attributes, then only one will be deleted.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the removal was successful or not
 *
 * Rename to: secret_password_remove_sync
 */
gboolean
secret_password_removev_sync (const SecretSchema *schema,
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
	if (!_secret_util_attributes_validate (schema, attributes))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_password_removev (schema, attributes, cancellable,
	                         _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = secret_password_remove_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return result;
}

/**
 * secret_password_free: (skip)
 * @password: (allow-none): password to free
 *
 * Clear the memory used by a password, and then free it.
 *
 * This function must be used to free nonpageable memory returned by
 * secret_password_lookup_nonpageable_finish(),
 * secret_password_lookup_nonpageable_sync() or
 * secret_password_lookupv_nonpageable_sync().
 */
void
secret_password_free (gchar *password)
{
	if (password == NULL)
		return;

	egg_secure_strfree (password);
}
