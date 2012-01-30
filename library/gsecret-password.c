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

#include "gsecret-password.h"
#include "gsecret-private.h"
#include "gsecret-value.h"

#include <egg/egg-secure-memory.h>

typedef struct {
	const GSecretSchema *schema;
	GHashTable *attributes;
	gchar *collection_path;
	gchar *label;
	GSecretValue *value;
	GCancellable *cancellable;
	gboolean created;
} StoreClosure;

static void
store_closure_free (gpointer data)
{
	StoreClosure *closure = data;
	g_hash_table_unref (closure->attributes);
	g_free (closure->collection_path);
	g_free (closure->label);
	gsecret_value_unref (closure->value);
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

	closure->created = gsecret_service_store_finish (GSECRET_SERVICE (source),
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
	GSecretService *service;
	GError *error = NULL;

	service = gsecret_service_get_finish (result, &error);
	if (error == NULL) {
		gsecret_service_storev (service, closure->schema,
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

void
gsecret_password_store (const GSecretSchema *schema,
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
	g_return_if_fail (collection_path != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (password != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	gsecret_password_storev (schema, collection_path, label, password, attributes,
	                         cancellable, callback, user_data);

	g_hash_table_unref (attributes);
}

void
gsecret_password_storev (const GSecretSchema *schema,
                         const gchar *collection_path,
                         const gchar *label,
                         const gchar *password,
                         GHashTable *attributes,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	GSimpleAsyncResult *res;
	StoreClosure *closure;

	g_return_if_fail (schema != NULL);
	g_return_if_fail (collection_path != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (password != NULL);
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 gsecret_password_storev);
	closure = g_slice_new0 (StoreClosure);
	closure->schema = schema;
	closure->collection_path = g_strdup (collection_path);
	closure->label = g_strdup (label);
	closure->value = gsecret_value_new (password, -1, "text/plain");
	closure->attributes = g_hash_table_ref (attributes);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, store_closure_free);

	gsecret_service_get (GSECRET_SERVICE_OPEN_SESSION, cancellable,
	                     on_store_connected, g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_password_store_finish (GAsyncResult *result,
                               GError **error)
{
	GSimpleAsyncResult *res;
	StoreClosure *closure;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      gsecret_password_storev), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->created;
}

gboolean
gsecret_password_store_sync (const GSecretSchema *schema,
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
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	ret = gsecret_password_storev_sync (schema, collection_path, label, password,
	                                    attributes, cancellable, error);

	g_hash_table_unref (attributes);
	return ret;
}

gboolean
gsecret_password_storev_sync (const GSecretSchema *schema,
                              const gchar *collection_path,
                              const gchar *label,
                              const gchar *password,
                              GHashTable *attributes,
                              GCancellable *cancellable,
                              GError **error)
{
	GSecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (collection_path != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_password_storev (schema, collection_path, label, password, attributes,
	                         cancellable, _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = gsecret_password_store_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return ret;
}

typedef struct {
	GCancellable *cancellable;
	GHashTable *attributes;
	GSecretValue *value;
} LookupClosure;

static void
lookup_closure_free (gpointer data)
{
	LookupClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_hash_table_unref (closure->attributes);
	if (closure->value)
		gsecret_value_unref (closure->value);
	g_slice_free (LookupClosure, closure);
}

void
gsecret_password_lookup (const GSecretSchema *schema,
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
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	gsecret_password_lookupv (attributes, cancellable, callback, user_data);

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

	closure->value = gsecret_service_lookup_finish (GSECRET_SERVICE (source),
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
	GSecretService *service;
	GError *error = NULL;

	service = gsecret_service_get_finish (result, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else {
		gsecret_service_lookupv (service, closure->attributes, closure->cancellable,
		                         on_lookup_complete, g_object_ref (res));
		g_object_unref (service);
	}

	g_object_unref (res);
}

void
gsecret_password_lookupv (GHashTable *attributes,
                          GCancellable *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
	GSimpleAsyncResult *res;
	LookupClosure *closure;

	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 gsecret_password_lookupv);
	closure = g_slice_new0 (LookupClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->attributes = g_hash_table_ref (attributes);
	g_simple_async_result_set_op_res_gpointer (res, closure, lookup_closure_free);

	gsecret_service_get (GSECRET_SERVICE_OPEN_SESSION, cancellable,
	                     on_lookup_connected, g_object_ref (res));

	g_object_unref (res);
}

gchar *
gsecret_password_lookup_finish (GAsyncResult *result,
                                GError **error)
{
	GSimpleAsyncResult *res;
	LookupClosure *closure;
	const gchar *content_type;
	gchar *password = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      gsecret_password_lookupv), NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	content_type = gsecret_value_get_content_type (closure->value);
	if (content_type && g_str_equal (content_type, "text/plain")) {
		password = _gsecret_value_unref_to_password (closure->value);
		closure->value = NULL;
	}

	return password;
}

gchar *
gsecret_password_lookup_sync (const GSecretSchema *schema,
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
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	password = gsecret_password_lookupv_sync (attributes, cancellable, error);

	g_hash_table_unref (attributes);

	return password;
}

gchar *
gsecret_password_lookupv_sync (GHashTable *attributes,
                               GCancellable *cancellable,
                               GError **error)
{
	GSecretSync *sync;
	gchar *password;

	g_return_val_if_fail (attributes != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_password_lookupv (attributes, cancellable,
	                          _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	password = gsecret_password_lookup_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return password;
}

typedef struct {
	GCancellable *cancellable;
	GHashTable *attributes;
	gboolean deleted;
} DeleteClosure;

static void
delete_closure_free (gpointer data)
{
	DeleteClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_hash_table_unref (closure->attributes);
	g_slice_free (DeleteClosure, closure);
}

void
gsecret_password_remove (const GSecretSchema *schema,
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
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	gsecret_password_removev (attributes, cancellable,
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

	closure->deleted = gsecret_service_remove_finish (GSECRET_SERVICE (source),
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
	GSecretService *service;
	GError *error = NULL;

	service = gsecret_service_get_finish (result, &error);
	if (error == NULL) {
		gsecret_service_removev (service, closure->attributes,
		                         closure->cancellable, on_delete_complete,
		                         g_object_ref (res));
		g_object_unref (service);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (res);
}

void
gsecret_password_removev (GHashTable *attributes,
                          GCancellable *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 gsecret_password_removev);
	closure = g_slice_new0 (DeleteClosure);
	closure->attributes = g_hash_table_ref (attributes);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, delete_closure_free);

	gsecret_service_get (GSECRET_SERVICE_NONE, cancellable,
	                     on_delete_connect, g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_password_remove_finish (GAsyncResult *result,
                                GError **error)
{
	DeleteClosure *closure;
	GSimpleAsyncResult *res;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      gsecret_password_removev), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->deleted;
}

gboolean
gsecret_password_remove_sync (const GSecretSchema* schema,
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
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	result = gsecret_password_removev_sync (attributes, cancellable, error);

	g_hash_table_unref (attributes);

	return result;
}

gboolean
gsecret_password_removev_sync (GHashTable *attributes,
                               GCancellable *cancellable,
                               GError **error)
{
	GSecretSync *sync;
	gboolean result;

	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_password_removev (attributes, cancellable,
	                          _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = gsecret_password_remove_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return result;
}

void
gsecret_password_free (gpointer password)
{
	if (password == NULL)
		return;

	egg_secure_strfree (password);
}
