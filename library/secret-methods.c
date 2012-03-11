/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 * Copyright 2012 Red Hat Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#include "config.h"

#include "secret-collection.h"
#include "secret-dbus-generated.h"
#include "secret-item.h"
#include "secret-private.h"
#include "secret-service.h"
#include "secret-types.h"
#include "secret-value.h"

static void
on_search_items_complete (GObject *source,
                          GAsyncResult *result,
                          gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;
	GVariant *response;

	response = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	else
		g_simple_async_result_set_op_res_gpointer (res, response,
		                                           (GDestroyNotify)g_variant_unref);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

/**
 * secret_service_search_for_paths:
 * @self: the secret service
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Search for items matching the @attributes. All collections are searched.
 * The @attributes should be a table of string keys and string values.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_service_search_for_paths (SecretService *self,
                                 GHashTable *attributes,
                                 GCancellable *cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 secret_service_search_for_paths);

	g_dbus_proxy_call (G_DBUS_PROXY (self), "SearchItems",
	                   g_variant_new ("(@a{ss})",
	                                  _secret_util_variant_for_attributes (attributes)),
	                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable,
	                   on_search_items_complete, g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_service_search_for_paths_finish:
 * @self: the secret service
 * @result: asynchronous result passed to callback
 * @unlocked: (out) (transfer full) (array zero-terminated=1) (allow-none):
 *            location to place an array of dbus object paths for matching
 *            items which were locked.
 * @locked: (out) (transfer full) (array zero-terminated=1) (allow-none):
 *          location to place an array of dbus object paths for matching
 *          items which were locked.
 * @error: location to place error on failure
 *
 * Complete asynchronous operation to search for items.
 *
 * Matching items that are locked or unlocked, have their dbus paths placed
 * in the @locked or @unlocked arrays respectively.
 *
 * Returns: whether the search was successful or not
 */
gboolean
secret_service_search_for_paths_finish (SecretService *self,
                                        GAsyncResult *result,
                                        gchar ***unlocked,
                                        gchar ***locked,
                                        GError **error)
{
	GVariant *response;
	GSimpleAsyncResult *res;
	gchar **dummy = NULL;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      secret_service_search_for_paths), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	if (unlocked || locked) {
		if (!unlocked)
			unlocked = &dummy;
		else if (!locked)
			locked = &dummy;
		response = g_simple_async_result_get_op_res_gpointer (res);
		g_variant_get (response, "(^ao^ao)", unlocked, locked);
	}

	g_strfreev (dummy);
	return TRUE;
}

/**
 * secret_service_search_for_paths_sync:
 * @self: the secret service
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @cancellable: optional cancellation object
 * @unlocked: (out) (transfer full) (array zero-terminated=1) (allow-none):
 *            location to place an array of dbus object paths for matching
 *            items which were locked.
 * @locked: (out) (transfer full) (array zero-terminated=1) (allow-none):
 *          location to place an array of dbus object paths for matching
 *          items which were locked.
 * @error: location to place error on failure
 *
 * Search for items matching the @attributes. All collections are searched.
 * The @attributes should be a table of string keys and string values.
 *
 * This function may block indefinetely. Use the asynchronous version
 * in user interface threads.
 *
 * Matching items that are locked or unlocked, have their dbus paths placed
 * in the @locked or @unlocked arrays respectively.
 *
 * Returns: whether the search was successful or not
 */
gboolean
secret_service_search_for_paths_sync (SecretService *self,
                                      GHashTable *attributes,
                                      GCancellable *cancellable,
                                      gchar ***unlocked,
                                      gchar ***locked,
                                      GError **error)
{
	gchar **dummy = NULL;
	GVariant *response;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	response = g_dbus_proxy_call_sync (G_DBUS_PROXY (self), "SearchItems",
	                                   g_variant_new ("(@a{ss})",
	                                                  _secret_util_variant_for_attributes (attributes)),
	                                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable, error);

	if (response != NULL) {
		if (unlocked || locked) {
			if (!unlocked)
				unlocked = &dummy;
			else if (!locked)
				locked = &dummy;
			g_variant_get (response, "(^ao^ao)", unlocked, locked);
		}

		g_variant_unref (response);
	}

	g_strfreev (dummy);

	return response != NULL;
}

typedef struct {
	GCancellable *cancellable;
	GHashTable *items;
	gchar **unlocked;
	gchar **locked;
	guint loading;
} SearchClosure;

static void
search_closure_free (gpointer data)
{
	SearchClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_hash_table_unref (closure->items);
	g_strfreev (closure->unlocked);
	g_strfreev (closure->locked);
	g_slice_free (SearchClosure, closure);
}

static void
search_closure_take_item (SearchClosure *closure,
                          SecretItem *item)
{
	const gchar *path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (item));
	g_hash_table_insert (closure->items, (gpointer)path, item);
}

static void
on_search_loaded (GObject *source,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	SearchClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;
	SecretItem *item;

	closure->loading--;

	item = secret_item_new_finish (result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	if (item != NULL)
		search_closure_take_item (closure, item);
	if (closure->loading == 0)
		g_simple_async_result_complete (res);

	g_object_unref (res);
}

static void
search_load_item_async (SecretService *self,
                        GSimpleAsyncResult *res,
                        SearchClosure *closure,
                        const gchar *path)
{
	SecretItem *item;

	item = _secret_service_find_item_instance (self, path);
	if (item == NULL) {
		secret_item_new (self, path, closure->cancellable,
		                  on_search_loaded, g_object_ref (res));
		closure->loading++;
	} else {
		search_closure_take_item (closure, item);
	}
}

static void
on_search_paths (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	SearchClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (source);
	GError *error = NULL;
	guint i;

	if (!secret_service_search_for_paths_finish (self, result, &closure->unlocked,
	                                              &closure->locked, &error)) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	for (i = 0; closure->unlocked[i] != NULL; i++)
		search_load_item_async (self, res, closure, closure->unlocked[i]);
	for (i = 0; closure->locked[i] != NULL; i++)
		search_load_item_async (self, res, closure, closure->locked[i]);

	if (closure->loading == 0)
		g_simple_async_result_complete (res);

	g_object_unref (res);
}

/**
 * secret_service_search:
 * @self: the secret service
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Search for items matching the @attributes. All collections are searched.
 * The @attributes should be a table of string keys and string values.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_service_search (SecretService *self,
                       GHashTable *attributes,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	GSimpleAsyncResult *res;
	SearchClosure *closure;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 secret_service_search);
	closure = g_slice_new0 (SearchClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->items = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
	g_simple_async_result_set_op_res_gpointer (res, closure, search_closure_free);

	secret_service_search_for_paths (self, attributes, cancellable,
	                                 on_search_paths, g_object_ref (res));

	g_object_unref (res);
}

static GList *
search_finish_build (gchar **paths,
                     SearchClosure *closure)
{
	GList *results = NULL;
	SecretItem *item;
	guint i;

	for (i = 0; paths[i]; i++) {
		item = g_hash_table_lookup (closure->items, paths[i]);
		if (item != NULL)
			results = g_list_prepend (results, g_object_ref (item));
	}

	return g_list_reverse (results);
}

/**
 * secret_service_search_finish:
 * @self: the secret service
 * @result: asynchronous result passed to callback
 * @unlocked: (out) (transfer full) (element-type Secret.Item) (allow-none):
 *            location to place a list of matching items which were not locked.
 * @locked: (out) (transfer full) (element-type Secret.Item) (allow-none):
 *          location to place a list of matching items which were locked.
 * @error: location to place error on failure
 *
 * Complete asynchronous operation to search for items.
 *
 * Matching items that are locked or unlocked are placed
 * in the @locked or @unlocked lists respectively.
 *
 * Returns: whether the search was successful or not
 */
gboolean
secret_service_search_finish (SecretService *self,
                              GAsyncResult *result,
                              GList **unlocked,
                              GList **locked,
                              GError **error)
{
	GSimpleAsyncResult *res;
	SearchClosure *closure;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      secret_service_search), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	if (unlocked)
		*unlocked = search_finish_build (closure->unlocked, closure);
	if (locked)
		*locked = search_finish_build (closure->locked, closure);

	return TRUE;
}

static gboolean
service_load_items_sync (SecretService *self,
                         GCancellable *cancellable,
                         gchar **paths,
                         GList **items,
                         GError **error)
{
	SecretItem *item;
	GList *result = NULL;
	guint i;

	for (i = 0; paths[i] != NULL; i++) {
		item = _secret_service_find_item_instance (self, paths[i]);
		if (item == NULL)
			item = secret_item_new_sync (self, paths[i], cancellable, error);
		if (item == NULL) {
			g_list_free_full (result, g_object_unref);
			return FALSE;
		} else {
			result = g_list_prepend (result, item);
		}
	}

	*items = g_list_reverse (result);
	return TRUE;
}

/**
 * secret_service_search_sync:
 * @self: the secret service
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @cancellable: optional cancellation object
 * @unlocked: (out) (transfer full) (element-type Secret.Item) (allow-none):
 *            location to place a list of matching items which were not locked.
 * @locked: (out) (transfer full) (element-type Secret.Item) (allow-none):
 *          location to place a list of matching items which were locked.
 * @error: location to place error on failure
 *
 * Search for items matching the @attributes. All collections are searched.
 * The @attributes should be a table of string keys and string values.
 *
 * This function may block indefinetely. Use the asynchronous version
 * in user interface threads.
 *
 * Matching items that are locked or unlocked are placed
 * in the @locked or @unlocked lists respectively.
 *
 * Returns: whether the search was successful or not
 */
gboolean
secret_service_search_sync (SecretService *self,
                            GHashTable *attributes,
                            GCancellable *cancellable,
                            GList **unlocked,
                            GList **locked,
                            GError **error)
{
	gchar **unlocked_paths = NULL;
	gchar **locked_paths = NULL;
	gboolean ret;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!secret_service_search_for_paths_sync (self, attributes, cancellable,
	                                           unlocked ? &unlocked_paths : NULL,
	                                           locked ? &locked_paths : NULL, error))
		return FALSE;

	ret = TRUE;

	if (unlocked)
		ret = service_load_items_sync (self, cancellable, unlocked_paths, unlocked, error);
	if (ret && locked)
		ret = service_load_items_sync (self, cancellable, locked_paths, locked, error);

	g_strfreev (unlocked_paths);
	g_strfreev (locked_paths);

	return ret;
}

typedef struct {
	GCancellable *cancellable;
	GVariant *in;
	GVariant *out;
	GHashTable *items;
} GetClosure;

static void
get_closure_free (gpointer data)
{
	GetClosure *closure = data;
	if (closure->in)
		g_variant_unref (closure->in);
	if (closure->out)
		g_variant_unref (closure->out);
	g_clear_object (&closure->cancellable);
	g_slice_free (GetClosure, closure);
}

static void
on_get_secrets_complete (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GetClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	closure->out = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	g_simple_async_result_complete (res);

	g_object_unref (res);
}

static void
on_get_secrets_session (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GetClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;
	const gchar *session;

	session = secret_service_ensure_session_finish (SECRET_SERVICE (source),
	                                                result, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	} else {
		g_dbus_proxy_call (G_DBUS_PROXY (source), "GetSecrets",
		                   g_variant_new ("(@aoo)", closure->in, session),
		                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
		                   closure->cancellable, on_get_secrets_complete,
		                   g_object_ref (res));
	}

	g_object_unref (res);
}

/**
 * secret_service_get_secret_for_path:
 * @self: the secret service
 * @item_path: the dbus path to item to retrieve secret for
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Get the secret value for an secret item stored in the service.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_service_get_secret_for_path (SecretService *self,
                                    const gchar *item_path,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (item_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 secret_service_get_secret_for_path);

	closure = g_slice_new0 (GetClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->in = g_variant_ref_sink (g_variant_new_objv (&item_path, 1));
	g_simple_async_result_set_op_res_gpointer (res, closure, get_closure_free);

	secret_service_ensure_session (self, cancellable,
	                               on_get_secrets_session,
	                               g_object_ref (res));

	g_object_unref (res);
}

static SecretValue *
service_decode_get_secrets_first (SecretService *self,
                                  GVariant *out)
{
	SecretSession *session;
	SecretValue *value = NULL;
	GVariantIter *iter;
	GVariant *variant;
	const gchar *path;

	g_variant_get (out, "(a{o(oayays)})", &iter);
	while (g_variant_iter_next (iter, "{&o@(oayays)}", &path, &variant)) {
		session = _secret_service_get_session (self);
		value = _secret_session_decode_secret (session, variant);
		g_variant_unref (variant);
		break;
	}
	g_variant_iter_free (iter);
	return value;
}

static GHashTable *
service_decode_get_secrets_all (SecretService *self,
                                GVariant *out)
{
	SecretSession *session;
	GVariantIter *iter;
	GVariant *variant;
	GHashTable *values;
	SecretValue *value;
	gchar *path;

	session = _secret_service_get_session (self);
	values = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                g_free, secret_value_unref);
	g_variant_get (out, "(a{o(oayays)})", &iter);
	while (g_variant_iter_loop (iter, "{o@(oayays)}", &path, &variant)) {
		value = _secret_session_decode_secret (session, variant);
		if (value && path)
			g_hash_table_insert (values, g_strdup (path), value);
	}
	g_variant_iter_free (iter);
	return values;
}

/**
 * secret_service_get_secret_for_path_finish:
 * @self: the secret service
 * @result: asynchronous result passed to callback
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to get the secret value for an
 * secret item stored in the service.
 *
 * Will return %NULL if the item is locked.
 *
 * Returns: (transfer full) (allow-none): the newly allocated secret value
 *          for the item, which should be released with secret_value_unref()
 */
SecretValue *
secret_service_get_secret_for_path_finish (SecretService *self,
                                           GAsyncResult *result,
                                           GError **error)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      secret_service_get_secret_for_path), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return service_decode_get_secrets_first (self, closure->out);
}

/**
 * secret_service_get_secret_for_path_sync:
 * @self: the secret service
 * @item_path: the dbus path to item to retrieve secret for
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Get the secret value for an secret item stored in the service.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Will return %NULL if the item is locked.
 *
 * Returns: (transfer full) (allow-none): the newly allocated secret value
 *          for the item, which should be released with secret_value_unref()
 */
SecretValue *
secret_service_get_secret_for_path_sync (SecretService *self,
                                         const gchar *item_path,
                                         GCancellable *cancellable,
                                         GError **error)
{
	SecretSync *sync;
	SecretValue *value;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (item_path != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_get_secret_for_path (self, item_path, cancellable,
	                                    _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	value = secret_service_get_secret_for_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return value;
}

/**
 * secret_service_get_secrets_for_paths:
 * @self: the secret service
 * @item_paths: the dbus paths to items to retrieve secrets for
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Get the secret values for an secret items stored in the service.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_service_get_secrets_for_paths (SecretService *self,
                                      const gchar **item_paths,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (item_paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 secret_service_get_secret_for_path);

	closure = g_slice_new0 (GetClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->in = g_variant_ref_sink (g_variant_new_objv (item_paths, -1));
	g_simple_async_result_set_op_res_gpointer (res, closure, get_closure_free);

	secret_service_ensure_session (self, cancellable,
	                               on_get_secrets_session,
	                               g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_service_get_secrets_for_paths_finish:
 * @self: the secret service
 * @result: asynchronous result passed to callback
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to get the secret values for an
 * secret items stored in the service.
 *
 * Items that are locked will not be included the results.
 *
 * Returns: (transfer full): a newly allocated hash table of item_path keys to
 *          #SecretValue values.
 */
GHashTable *
secret_service_get_secrets_for_paths_finish (SecretService *self,
                                             GAsyncResult *result,
                                             GError **error)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      secret_service_get_secret_for_path), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return service_decode_get_secrets_all (self, closure->out);
}

/**
 * secret_service_get_secrets_for_paths_sync:
 * @self: the secret service
 * @item_paths: the dbus paths to items to retrieve secrets for
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Get the secret values for an secret items stored in the service.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Items that are locked will not be included the results.
 *
 * Returns: (transfer full): a newly allocated hash table of item_path keys to
 *          #SecretValue values.
 */
GHashTable *
secret_service_get_secrets_for_paths_sync (SecretService *self,
                                           const gchar **item_paths,
                                           GCancellable *cancellable,
                                           GError **error)
{
	SecretSync *sync;
	GHashTable *secrets;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (item_paths != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_get_secrets_for_paths (self, item_paths, cancellable,
	                                      _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	secrets = secret_service_get_secrets_for_paths_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return secrets;
}

/**
 * secret_service_get_secrets:
 * @self: the secret service
 * @items: (element-type Secret.Item): the items to retrieve secrets for
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Get the secret values for an secret items stored in the service.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_service_get_secrets (SecretService *self,
                            GList *items,
                            GCancellable *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;
	GPtrArray *paths;
	const gchar *path;
	GList *l;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 secret_service_get_secrets);
	closure = g_slice_new0 (GetClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->items = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                        g_free, g_object_unref);

	paths = g_ptr_array_new ();
	for (l = items; l != NULL; l = g_list_next (l)) {
		path = g_dbus_proxy_get_object_path (l->data);
		g_hash_table_insert (closure->items, g_strdup (path), g_object_ref (l->data));
		g_ptr_array_add (paths, (gpointer)path);
	}

	closure->in = g_variant_new_objv ((const gchar * const *)paths->pdata, paths->len);
	g_variant_ref_sink (closure->in);

	g_ptr_array_free (paths, TRUE);
	g_simple_async_result_set_op_res_gpointer (res, closure, get_closure_free);

	secret_service_ensure_session (self, cancellable,
	                                on_get_secrets_session,
	                                g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_service_get_secrets_finish:
 * @self: the secret service
 * @result: asynchronous result passed to callback
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to get the secret values for an
 * secret items stored in the service.
 *
 * Items that are locked will not be included the results.
 *
 * Returns: (transfer full): a newly allocated hash table of #SecretItem keys
 *          to #SecretValue values.
 */
GHashTable *
secret_service_get_secrets_finish (SecretService *self,
                                   GAsyncResult *result,
                                   GError **error)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;
	GHashTable *with_paths;
	GHashTable *with_items;
	GHashTableIter iter;
	const gchar *path;
	SecretValue *value;
	SecretItem *item;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      secret_service_get_secrets), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	with_paths = service_decode_get_secrets_all (self, closure->out);
	g_return_val_if_fail (with_paths != NULL, NULL);

	with_items = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                    g_object_unref, secret_value_unref);

	g_hash_table_iter_init (&iter, with_paths);
	while (g_hash_table_iter_next (&iter, (gpointer *)&path, (gpointer *)&value)) {
		item = g_hash_table_lookup (closure->items, path);
		if (item != NULL)
			g_hash_table_insert (with_items, g_object_ref (item),
			                     secret_value_ref (value));
	}

	g_hash_table_unref (with_paths);
	return with_items;
}

/**
 * secret_service_get_secrets_sync:
 * @self: the secret service
 * @items: (element-type Secret.Item): the items to retrieve secrets for
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Get the secret values for an secret items stored in the service.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Items that are locked will not be included the results.
 *
 * Returns: (transfer full): a newly allocated hash table of #SecretItem keys
 *          to #SecretValue values.
 */
GHashTable *
secret_service_get_secrets_sync (SecretService *self,
                                 GList *items,
                                 GCancellable *cancellable,
                                 GError **error)
{
	SecretSync *sync;
	GHashTable *secrets;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_get_secrets (self, items, cancellable,
	                             _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	secrets = secret_service_get_secrets_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return secrets;
}

typedef struct {
	GCancellable *cancellable;
	SecretPrompt *prompt;
	GHashTable *objects;
	GPtrArray *xlocked;
} XlockClosure;

static void
xlock_closure_free (gpointer data)
{
	XlockClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_clear_object (&closure->prompt);
	if (closure->xlocked)
		g_ptr_array_unref (closure->xlocked);
	if (closure->objects)
		g_hash_table_unref (closure->objects);
	g_slice_free (XlockClosure, closure);
}

static void
on_xlock_prompted (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	XlockClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (source);
	GError *error = NULL;
	GVariantIter iter;
	GVariant *retval;
	gchar *path;
	gboolean ret;

	ret = secret_service_prompt_finish (self, result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	if (ret) {
		retval = secret_prompt_get_result_value (closure->prompt, G_VARIANT_TYPE ("ao"));
		g_variant_iter_init (&iter, retval);
		while (g_variant_iter_loop (&iter, "o", &path))
			g_ptr_array_add (closure->xlocked, g_strdup (path));
		g_variant_unref (retval);
	}

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_xlock_called (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	XlockClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (g_async_result_get_source_object (user_data));
	const gchar *prompt = NULL;
	gchar **xlocked = NULL;
	GError *error = NULL;
	GVariant *retval;
	guint i;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else {
		g_variant_get (retval, "(^ao&o)", &xlocked, &prompt);

		if (_secret_util_empty_path (prompt)) {
			for (i = 0; xlocked[i]; i++)
				g_ptr_array_add (closure->xlocked, g_strdup (xlocked[i]));
			g_simple_async_result_complete (res);

		} else {
			closure->prompt = _secret_prompt_instance (self, prompt);
			secret_service_prompt (self, closure->prompt, closure->cancellable,
			                        on_xlock_prompted, g_object_ref (res));
		}

		g_strfreev (xlocked);
		g_variant_unref (retval);
	}

	g_object_unref (self);
	g_object_unref (res);
}

static GSimpleAsyncResult *
service_xlock_paths_async (SecretService *self,
                           const gchar *method,
                           const gchar **paths,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	GSimpleAsyncResult *res;
	XlockClosure *closure;

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 service_xlock_paths_async);
	closure = g_slice_new0 (XlockClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : cancellable;
	closure->xlocked = g_ptr_array_new_with_free_func (g_free);
	g_simple_async_result_set_op_res_gpointer (res, closure, xlock_closure_free);

	g_dbus_proxy_call (G_DBUS_PROXY (self), method,
	                   g_variant_new ("(@ao)", g_variant_new_objv (paths, -1)),
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                   cancellable, on_xlock_called, g_object_ref (res));

	return res;
}

static gint
service_xlock_paths_finish (SecretService *self,
                            GAsyncResult *result,
                            gchar ***xlocked,
                            GError **error)
{
	GSimpleAsyncResult *res;
	XlockClosure *closure;
	gint count;

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return -1;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	count = closure->xlocked->len;

	if (xlocked != NULL) {
		g_ptr_array_add (closure->xlocked, NULL);
		*xlocked = (gchar **)g_ptr_array_free (closure->xlocked, FALSE);
		closure->xlocked = NULL;
	}

	return count;
}

static void
service_xlock_async (SecretService *self,
                     const gchar *method,
                     GList *objects,
                     GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	GSimpleAsyncResult *res;
	XlockClosure *closure;
	GHashTable *table;
	GPtrArray *paths;
	const gchar *path;
	GList *l;

	table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
	paths = g_ptr_array_new ();

	for (l = objects; l != NULL; l = g_list_next (l)) {
		path = g_dbus_proxy_get_object_path (l->data);
		g_ptr_array_add (paths, (gpointer)path);
		g_hash_table_insert (table, g_strdup (path), g_object_ref (l->data));
	}
	g_ptr_array_add (paths, NULL);

	res = service_xlock_paths_async (self, "Lock", (const gchar **)paths->pdata,
	                                 cancellable, callback, user_data);

	closure = g_simple_async_result_get_op_res_gpointer (res);
	closure->objects = table;

	g_ptr_array_free (paths, TRUE);
	g_object_unref (res);
}

static gint
service_xlock_finish (SecretService *self,
                      GAsyncResult *result,
                      GList **xlocked,
                      GError **error)
{
	XlockClosure *closure;
	gchar **paths = NULL;
	GObject *object;
	gint count;
	guint i;

	count = service_xlock_paths_finish (self, result,
	                                    xlocked ? &paths : NULL,
	                                    error);

	if (count > 0 && xlocked) {
		closure = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (result));
		*xlocked = NULL;

		for (i = 0; paths[i] != NULL; i++) {
			object = g_hash_table_lookup (closure->objects, paths[i]);
			if (object != NULL)
				*xlocked = g_list_prepend (*xlocked, g_object_ref (object));
		}

		*xlocked = g_list_reverse (*xlocked);
	}

	return count;

}

/**
 * secret_service_lock:
 * @self: the secret service
 * @objects: (element-type GLib.DBusProxy): the items or collections to lock
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Lock items or collections in the secret service.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * This method returns immediately and completes asynchronously. The secret
 * service may prompt the user. secret_service_prompt() will be used to handle
 * any prompts that show up.
 */
void
secret_service_lock (SecretService *self,
                     GList *objects,
                     GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	service_xlock_async (self, "Lock", objects, cancellable, callback, user_data);
}

/**
 * secret_service_lock_finish:
 * @self: the secret service
 * @result: asynchronous result passed to the callback
 * @locked: (out) (element-type GLib.DBusProxy) (transfer full) (allow-none):
 *          location to place list of items or collections that were locked
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to lock items or collections in the secret
 * service.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * Returns: the number of items or collections that were locked
 */
gint
secret_service_lock_finish (SecretService *self,
                            GAsyncResult *result,
                            GList **locked,
                            GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	return service_xlock_finish (self, result, locked, error);
}

/**
 * secret_service_lock_sync:
 * @self: the secret service
 * @objects: (element-type GLib.DBusProxy): the items or collections to lock
 * @cancellable: optional cancellation object
 * @locked: (out) (element-type GLib.DBusProxy) (transfer full) (allow-none):
 *          location to place list of items or collections that were locked
 * @error: location to place an error on failure
 *
 * Lock items or collections in the secret service.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * secret_service_prompt() will be used to handle any prompts that show up.
 *
 * Returns: the number of items or collections that were locked
 */
gint
secret_service_lock_sync (SecretService *self,
                          GList *objects,
                          GCancellable *cancellable,
                          GList **locked,
                          GError **error)
{
	SecretSync *sync;
	gint count;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_lock (self, objects, cancellable,
	                      _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = secret_service_lock_finish (self, sync->result, locked, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return count;
}

/**
 * secret_service_lock_paths_sync:
 * @self: the secret service
 * @paths: the dbus paths for items or collections to lock
 * @cancellable: optional cancellation object
 * @locked: (out) (array zero-terminated=1) (transfer full) (allow-none):
 *          location to place array of dbus paths of items or collections
 *          that were locked
 * @error: location to place an error on failure
 *
 * Lock items or collections in the secret service.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * secret_service_prompt() will be used to handle any prompts that show up.
 *
 * Returns: the number of items or collections that were locked
 */
gint
secret_service_lock_paths_sync (SecretService *self,
                                const gchar **paths,
                                GCancellable *cancellable,
                                gchar ***locked,
                                GError **error)
{
	SecretSync *sync;
	gint count;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (paths != NULL, -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_lock_paths (self, paths, cancellable,
	                            _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = secret_service_lock_paths_finish (self, sync->result,
	                                           locked, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return count;
}

/**
 * secret_service_lock_paths:
 * @self: the secret service
 * @paths: the dbus paths for items or collections to lock
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Lock items or collections in the secret service.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * This method returns immediately and completes asynchronously. The secret
 * service may prompt the user. secret_service_prompt() will be used to handle
 * any prompts that show up.
 */
void
secret_service_lock_paths (SecretService *self,
                           const gchar **paths,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = service_xlock_paths_async (self, "Lock", paths, cancellable,
	                                 callback, user_data);

	g_object_unref (res);
}

/**
 * secret_service_lock_paths_finish:
 * @self: the secret service
 * @result: asynchronous result passed to the callback
 * @locked: (out) (array zero-terminated=1) (transfer full) (allow-none):
 *          location to place array of dbus paths of items or collections
 *          that were locked
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to lock items or collections in the secret
 * service.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * Returns: the number of items or collections that were locked
 */
gint
secret_service_lock_paths_finish (SecretService *self,
                                  GAsyncResult *result,
                                  gchar ***locked,
                                  GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (locked != NULL, -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	return service_xlock_paths_finish (self, result, locked, error);
}

/**
 * secret_service_unlock_paths_sync:
 * @self: the secret service
 * @paths: the dbus paths for items or collections to unlock
 * @cancellable: optional cancellation object
 * @unlocked: (out) (array zero-terminated=1) (transfer full) (allow-none):
 *            location to place array of dbus paths of items or collections
 *            that were unlocked
 * @error: location to place an error on failure
 *
 * Unlock items or collections in the secret service.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * secret_service_prompt() will be used to handle any prompts that show up.
 *
 * Returns: the number of items or collections that were unlocked
 */
gint
secret_service_unlock_paths_sync (SecretService *self,
                                  const gchar **paths,
                                  GCancellable *cancellable,
                                  gchar ***unlocked,
                                  GError **error)
{
	SecretSync *sync;
	gint count;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (paths != NULL, -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (unlocked != NULL, -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_unlock_paths (self, paths, cancellable,
	                              _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = secret_service_unlock_paths_finish (self, sync->result,
	                                             unlocked, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return count;
}

/**
 * secret_service_unlock_paths:
 * @self: the secret service
 * @paths: the dbus paths for items or collections to unlock
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Unlock items or collections in the secret service.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * This method returns immediately and completes asynchronously. The secret
 * service may prompt the user. secret_service_prompt() will be used to handle
 * any prompts that show up.
 */
void
secret_service_unlock_paths (SecretService *self,
                             const gchar **paths,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = service_xlock_paths_async (self, "Unlock",
	                                 paths, cancellable,
	                                 callback, user_data);

	g_object_unref (res);
}

/**
 * secret_service_unlock_paths_finish:
 * @self: the secret service
 * @result: asynchronous result passed to the callback
 * @unlocked: (out) (array zero-terminated=1) (transfer full) (allow-none):
 *            location to place array of dbus paths of items or collections
 *            that were unlocked
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to unlock items or collections in the secret
 * service.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * Returns: the number of items or collections that were unlocked
 */
gint
secret_service_unlock_paths_finish (SecretService *self,
                                    GAsyncResult *result,
                                    gchar ***unlocked,
                                    GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	return service_xlock_paths_finish (self, result,
	                                   unlocked, error);
}

/**
 * secret_service_unlock:
 * @self: the secret service
 * @objects: (element-type GLib.DBusProxy): the items or collections to unlock
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Unlock items or collections in the secret service.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * secret_service_prompt() will be used to handle any prompts that show up.
 */
void
secret_service_unlock (SecretService *self,
                       GList *objects,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	service_xlock_async (self, "Unlock", objects, cancellable, callback, user_data);
}

/**
 * secret_service_unlock_finish:
 * @self: the secret service
 * @result: asynchronous result passed to the callback
 * @unlocked: (out) (element-type GLib.DBusProxy) (transfer full) (allow-none):
 *            location to place list of items or collections that were unlocked
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to unlock items or collections in the secret
 * service.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * Returns: the number of items or collections that were unlocked
 */
gint
secret_service_unlock_finish (SecretService *self,
                              GAsyncResult *result,
                              GList **unlocked,
                              GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      service_xlock_paths_async), -1);

	return service_xlock_finish (self, result, unlocked, error);
}

/**
 * secret_service_unlock_sync:
 * @self: the secret service
 * @objects: (element-type GLib.DBusProxy): the items or collections to unlock
 * @cancellable: optional cancellation object
 * @unlocked: (out) (element-type GLib.DBusProxy) (transfer full) (allow-none):
 *            location to place list of items or collections that were unlocked
 * @error: location to place an error on failure
 *
 * Unlock items or collections in the secret service.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * secret_service_prompt() will be used to handle any prompts that show up.
 *
 * Returns: the number of items or collections that were unlocked
 */
gint
secret_service_unlock_sync (SecretService *self,
                            GList *objects,
                            GCancellable *cancellable,
                            GList **unlocked,
                            GError **error)
{
	SecretSync *sync;
	gint count;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_unlock (self, objects, cancellable,
	                        _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = secret_service_unlock_finish (self, sync->result,
	                                       unlocked, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return count;
}

/**
 * secret_service_store:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @collection_path: the dbus path to the collection where to store the secret
 * @label: label for the secret
 * @value: the secret value
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Store a secret value in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attribtues should be terminated with a %NULL.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_store (SecretService *self,
                      const SecretSchema *schema,
                      const gchar *collection_path,
                      const gchar *label,
                      SecretValue *value,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data,
                      ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (collection_path != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (value != NULL);

	va_start (va, user_data);
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	secret_service_storev (self, schema, attributes, collection_path,
	                        label, value, cancellable, callback, user_data);

	g_hash_table_unref (attributes);
}

/**
 * secret_service_storev:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @collection_path: the dbus path to the collection where to store the secret
 * @label: label for the secret
 * @value: the secret value
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Store a secret value in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_storev (SecretService *self,
                       const SecretSchema *schema,
                       GHashTable *attributes,
                       const gchar *collection_path,
                       const gchar *label,
                       SecretValue *value,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	GHashTable *properties;
	GVariant *propval;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (collection_path != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return;

	properties = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
	                                    (GDestroyNotify)g_variant_unref);

	propval = g_variant_new_string (label);
	g_hash_table_insert (properties,
	                     SECRET_ITEM_INTERFACE ".Label",
	                     g_variant_ref_sink (propval));

	propval = g_variant_new_string (schema->identifier);
	g_hash_table_insert (properties,
	                     SECRET_ITEM_INTERFACE ".Schema",
	                     g_variant_ref_sink (propval));

	propval = _secret_util_variant_for_attributes (attributes);
	g_hash_table_insert (properties,
	                     SECRET_ITEM_INTERFACE ".Attributes",
	                     g_variant_ref_sink (propval));

	secret_service_create_item_path (self, collection_path, properties, value,
	                                  TRUE, cancellable, callback, user_data);

	g_hash_table_unref (properties);
}

/**
 * secret_service_store_finish:
 * @self: the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to store a secret value in the secret service.
 *
 * Returns: whether the storage was successful or not
 */
gboolean
secret_service_store_finish (SecretService *self,
                             GAsyncResult *result,
                             GError **error)
{
	gchar *path;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	path = secret_service_create_item_path_finish (self, result, error);

	g_free (path);
	return path != NULL;
}

/**
 * secret_service_store_sync:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @collection_path: the dbus path to the collection where to store the secret
 * @label: label for the secret
 * @value: the secret value
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Store a secret value in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attribtues should be terminated with a %NULL.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the storage was successful or not
 */
gboolean
secret_service_store_sync (SecretService *self,
                           const SecretSchema *schema,
                           const gchar *collection_path,
                           const gchar *label,
                           SecretValue *value,
                           GCancellable *cancellable,
                           GError **error,
                           ...)
{
	GHashTable *attributes;
	gboolean ret;
	va_list va;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (collection_path != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	va_start (va, error);
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	ret = secret_service_storev_sync (self, schema, attributes, collection_path,
	                                   label, value, cancellable, error);

	g_hash_table_unref (attributes);

	return ret;
}

/**
 * secret_service_storev_sync:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @collection_path: the dbus path to the collection where to store the secret
 * @label: label for the secret
 * @value: the secret value
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Store a secret value in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If the attributes match a secret item already stored in the collection, then
 * the item will be updated with these new values.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the storage was successful or not
 */
gboolean
secret_service_storev_sync (SecretService *self,
                            const SecretSchema *schema,
                            GHashTable *attributes,
                            const gchar *collection_path,
                            const gchar *label,
                            SecretValue *value,
                            GCancellable *cancellable,
                            GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (collection_path != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_storev (self, schema, attributes, collection_path,
	                        label, value, cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_service_store_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

typedef struct {
	SecretValue *value;
	GCancellable *cancellable;
} LookupClosure;

static void
lookup_closure_free (gpointer data)
{
	LookupClosure *closure = data;
	if (closure->value)
		secret_value_unref (closure->value);
	g_clear_object (&closure->cancellable);
	g_slice_free (LookupClosure, closure);
}

/**
 * secret_service_lookup:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Lookup a secret value in the secret service.
 *
 * The variable argument list should contain pairs of a) The attribute name as
 * a null-terminated string, followed by b) attribute value, either a character
 * string, an int number, or a gboolean value, as defined in the password
 * @schema. The list of attribtues should be terminated with a %NULL.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_lookup (SecretService *self,
                       const SecretSchema *schema,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data,
                       ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	secret_service_lookupv (self, schema, attributes, cancellable,
	                        callback, user_data);

	g_hash_table_unref (attributes);
}

static void
on_lookup_get_secret (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	LookupClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (source);
	GError *error = NULL;

	closure->value = secret_service_get_secret_for_path_finish (self, result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_lookup_unlocked (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	LookupClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (source);
	GError *error = NULL;
	gchar **unlocked = NULL;

	secret_service_unlock_paths_finish (SECRET_SERVICE (source),
	                                     result, &unlocked, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else if (unlocked && unlocked[0]) {
		secret_service_get_secret_for_path (self, unlocked[0],
		                                    closure->cancellable,
		                                    on_lookup_get_secret,
		                                    g_object_ref (res));

	} else {
		g_simple_async_result_complete (res);
	}

	g_strfreev (unlocked);
	g_object_unref (res);
}

static void
on_lookup_searched (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	LookupClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (source);
	GError *error = NULL;
	gchar **unlocked = NULL;
	gchar **locked = NULL;

	secret_service_search_for_paths_finish (self, result, &unlocked, &locked, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else if (unlocked && unlocked[0]) {
		secret_service_get_secret_for_path (self, unlocked[0],
		                                    closure->cancellable,
		                                    on_lookup_get_secret,
		                                    g_object_ref (res));

	} else if (locked && locked[0]) {
		const gchar *paths[] = { locked[0], NULL };
		secret_service_unlock_paths (self, paths,
		                             closure->cancellable,
		                             on_lookup_unlocked,
		                             g_object_ref (res));

	} else {
		g_simple_async_result_complete (res);
	}

	g_strfreev (unlocked);
	g_strfreev (locked);
	g_object_unref (res);
}

/**
 * secret_service_lookupv:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Lookup a secret value in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_lookupv (SecretService *self,
                        const SecretSchema *schema,
                        GHashTable *attributes,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GSimpleAsyncResult *res;
	LookupClosure *closure;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return;

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 secret_service_lookupv);
	closure = g_slice_new0 (LookupClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, lookup_closure_free);

	secret_service_search_for_paths (self, attributes, cancellable,
	                                 on_lookup_searched, g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_service_lookup_finish:
 * @self: the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to lookup a secret value in the secret service.
 *
 * If no secret is found then %NULL is returned.
 *
 * Returns: (transfer full): a newly allocated #SecretValue, which should be
 *          released with secret_value_unref(), or %NULL if no secret found
 */
SecretValue *
secret_service_lookup_finish (SecretService *self,
                              GAsyncResult *result,
                              GError **error)
{
	GSimpleAsyncResult *res;
	LookupClosure *closure;
	SecretValue *value;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      secret_service_lookupv), NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	value = closure->value;
	closure->value = NULL;
	return value;
}

/**
 * secret_service_lookup_sync:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Lookup a secret value in the secret service.
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
 * Returns: (transfer full): a newly allocated #SecretValue, which should be
 *          released with secret_value_unref(), or %NULL if no secret found
 */
SecretValue *
secret_service_lookup_sync (SecretService *self,
                            const SecretSchema *schema,
                            GCancellable *cancellable,
                            GError **error,
                            ...)
{
	GHashTable *attributes;
	SecretValue *value;
	va_list va;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (schema != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);

	va_start (va, error);
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	value = secret_service_lookupv_sync (self, schema, attributes, cancellable, error);

	g_hash_table_unref (attributes);

	return value;
}

/**
 * secret_service_lookupv_sync:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Lookup a secret value in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a newly allocated #SecretValue, which should be
 *          released with secret_value_unref(), or %NULL if no secret found
 */
SecretValue *
secret_service_lookupv_sync (SecretService *self,
                             const SecretSchema *schema,
                             GHashTable *attributes,
                             GCancellable *cancellable,
                             GError **error)
{
	SecretSync *sync;
	SecretValue *value;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (schema != NULL, NULL);
	g_return_val_if_fail (attributes != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return NULL;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_lookupv (self, schema, attributes, cancellable,
	                        _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	value = secret_service_lookup_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return value;
}

typedef struct {
	GCancellable *cancellable;
	SecretPrompt *prompt;
	gboolean deleted;
} DeleteClosure;

static void
delete_closure_free (gpointer data)
{
	DeleteClosure *closure = data;
	g_clear_object (&closure->prompt);
	g_clear_object (&closure->cancellable);
	g_slice_free (DeleteClosure, closure);
}

static void
on_delete_prompted (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	secret_service_prompt_finish (SECRET_SERVICE (source), result, &error);

	if (error == NULL)
		closure->deleted = TRUE;
	else
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_delete_complete (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (g_async_result_get_source_object (user_data));
	const gchar *prompt_path;
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o)", &prompt_path);

		if (_secret_util_empty_path (prompt_path)) {
			closure->deleted = TRUE;
			g_simple_async_result_complete (res);

		} else {
			closure->prompt = _secret_prompt_instance (self, prompt_path);

			secret_service_prompt (self, closure->prompt,
			                       closure->cancellable,
			                       on_delete_prompted,
			                       g_object_ref (res));
		}

		g_variant_unref (retval);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (self);
	g_object_unref (res);
}

void
_secret_service_delete_path (SecretService *self,
                             const gchar *object_path,
                             gboolean is_an_item,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (object_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 _secret_service_delete_path);
	closure = g_slice_new0 (DeleteClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, delete_closure_free);

	g_dbus_connection_call (g_dbus_proxy_get_connection (G_DBUS_PROXY (self)),
	                        g_dbus_proxy_get_name (G_DBUS_PROXY (self)), object_path,
	                        is_an_item ? SECRET_ITEM_INTERFACE : SECRET_COLLECTION_INTERFACE,
	                        "Delete", g_variant_new ("()"), G_VARIANT_TYPE ("(o)"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                        cancellable, on_delete_complete, g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_service_delete_path:
 * @self: the secret service
 * @item_path: dbus path of item to delete
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Delete a secret item from the secret service.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_delete_path (SecretService *self,
                            const gchar *item_path,
                            GCancellable *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (item_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	_secret_service_delete_path (self, item_path, TRUE, cancellable, callback, user_data);
}

/**
 * secret_service_delete_path_finish:
 * @self: the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Complete an asynchronous operation to delete a secret item from the secret
 * service.
 *
 * Returns: whether the deletion was successful or not
 */
gboolean
secret_service_delete_path_finish (SecretService *self,
                                   GAsyncResult *result,
                                   GError **error)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      _secret_service_delete_path), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->deleted;
}

/**
 * secret_service_delete_path_sync:
 * @self: the secret service
 * @item_path: dbus path of item to delete
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Delete a secret item from the secret service.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the deletion was successful or not
 */
gboolean
secret_service_delete_path_sync (SecretService *self,
                                 const gchar *item_path,
                                 GCancellable *cancellable,
                                 GError **error)
{
	SecretSync *sync;
	gboolean result;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (item_path != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_delete_path (self, item_path, cancellable,
	                            _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = secret_service_delete_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return result;
}

static void
on_delete_password_complete (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	SecretService *self = SECRET_SERVICE (g_async_result_get_source_object (user_data));
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	closure->deleted = secret_service_delete_path_finish (self, result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);

	g_object_unref (self);
	g_object_unref (res);
}

static void
on_search_delete_password (GObject *source,
                           GAsyncResult *result,
                           gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (g_async_result_get_source_object (user_data));
	const gchar *path = NULL;
	GError *error = NULL;
	gchar **locked;
	gchar **unlocked;

	secret_service_search_for_paths_finish (self, result, &unlocked, &locked, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else {
		/* Choose the first path */
		if (unlocked && unlocked[0])
			path = unlocked[0];
		else if (locked && locked[0])
			path = locked[0];

		/* Nothing to delete? */
		if (path == NULL) {
			closure->deleted = FALSE;
			g_simple_async_result_complete (res);

		/* Delete the first path */
		} else {
			closure->deleted = TRUE;
			_secret_service_delete_path (self, path, TRUE,
			                             closure->cancellable,
			                             on_delete_password_complete,
			                             g_object_ref (res));
		}
	}

	g_strfreev (locked);
	g_strfreev (unlocked);
	g_object_unref (self);
	g_object_unref (res);
}

/**
 * secret_service_remove:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Remove a secret value from the secret service.
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
secret_service_remove (SecretService *self,
                       const SecretSchema *schema,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data,
                       ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (SECRET_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	secret_service_removev (self, schema, attributes, cancellable,
	                        callback, user_data);

	g_hash_table_unref (attributes);
}

/**
 * secret_service_removev:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Remove a secret value from the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If multiple items match the attributes, then only one will be deleted.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_removev (SecretService *self,
                        const SecretSchema *schema,
                        GHashTable *attributes,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_if_fail (SECRET_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return;

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 secret_service_remove);
	closure = g_slice_new0 (DeleteClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, delete_closure_free);

	secret_service_search_for_paths (self, attributes, cancellable,
	                                 on_search_delete_password, g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_service_remove_finish:
 * @self: the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to remove a secret value from the secret
 * service.
 *
 * Returns: whether the removal was successful or not
 */
gboolean
secret_service_remove_finish (SecretService *self,
                              GAsyncResult *result,
                              GError **error)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      secret_service_remove), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->deleted;
}

/**
 * secret_service_remove_sync:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 * @...: the attribute keys and values, terminated with %NULL
 *
 * Remove a secret value from the secret service.
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
secret_service_remove_sync (SecretService *self,
                            const SecretSchema* schema,
                            GCancellable *cancellable,
                            GError **error,
                            ...)
{
	GHashTable *attributes;
	gboolean result;
	va_list va;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	va_start (va, error);
	attributes = _secret_util_attributes_for_varargs (schema, va);
	va_end (va);

	result = secret_service_removev_sync (self, schema, attributes, cancellable, error);

	g_hash_table_unref (attributes);

	return result;
}

/**
 * secret_service_removev_sync:
 * @self: the secret service
 * @schema: the schema to for attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Remove a secret value from the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If multiple items match the attributes, then only one will be deleted.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the removal was successful or not
 */
gboolean
secret_service_removev_sync (SecretService *self,
                             const SecretSchema *schema,
                             GHashTable *attributes,
                             GCancellable *cancellable,
                             GError **error)
{
	SecretSync *sync;
	gboolean result;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Warnings raised already */
	if (!_secret_util_attributes_validate (schema, attributes))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_removev (self, schema, attributes, cancellable,
	                        _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = secret_service_remove_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return result;
}

typedef struct {
	GCancellable *cancellable;
	SecretPrompt *prompt;
	gchar *collection_path;
} CollectionClosure;

static void
collection_closure_free (gpointer data)
{
	CollectionClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_clear_object (&closure->prompt);
	g_slice_free (CollectionClosure, closure);
}

static void
on_create_collection_prompt (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	CollectionClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;
	gboolean created;
	GVariant *value;

	created = secret_service_prompt_finish (SECRET_SERVICE (source), result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	if (created) {
		value = secret_prompt_get_result_value (closure->prompt, G_VARIANT_TYPE ("o"));
		closure->collection_path = g_variant_dup_string (value, NULL);
		g_variant_unref (value);
	}

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_create_collection_called (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	CollectionClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (g_async_result_get_source_object (user_data));
	const gchar *prompt_path = NULL;
	const gchar *collection_path = NULL;
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o&o)", &collection_path, &prompt_path);
		if (!_secret_util_empty_path (prompt_path)) {
			closure->prompt = _secret_prompt_instance (self, prompt_path);
			secret_service_prompt (self, closure->prompt,
			                       closure->cancellable, on_create_collection_prompt,
			                       g_object_ref (res));

		} else {
			closure->collection_path = g_strdup (collection_path);
			g_simple_async_result_complete (res);
		}

		g_variant_unref (retval);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (self);
	g_object_unref (res);
}

/**
 * secret_service_create_collection_path:
 * @self: a secret service object
 * @properties: hash table of properties for the new collection
 * @alias: (allow-none): an alias to check for before creating the new
 *         collection, or to assign to the new collection
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Create a new collection in the secret service.
 *
 * If a collection with the @alias already exists, then instead of creating a
 * new collection, the existing collection will be returned. If no collection
 * with this alias exists, then a new collection will be created and this
 * alias will be assigned to it.
 *
 * @properties is a set of properties for the new collection. The keys in the
 * hash table should be interface.property strings like
 * <literal>org.freedesktop.Secret.Collection.Label</literal>. The values
 * in the hash table should be #GVariant values of the properties.
 *
 * This method will return immediately and complete asynchronously. The secret
 * service may prompt the user. secret_service_prompt() will be used to handle
 * any prompts that are required.
 */
void
secret_service_create_collection_path (SecretService *self,
                                       GHashTable *properties,
                                       const gchar *alias,
                                       GCancellable *cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
	GSimpleAsyncResult *res;
	CollectionClosure *closure;
	GVariant *params;
	GVariant *props;
	GDBusProxy *proxy;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (properties != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	if (alias == NULL)
		alias = "";

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 secret_service_create_collection_path);
	closure = g_slice_new0 (CollectionClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, collection_closure_free);

	props = _secret_util_variant_for_properties (properties);
	params = g_variant_new ("(@a{sv}s)", props, alias);
	proxy = G_DBUS_PROXY (self);

	g_dbus_connection_call (g_dbus_proxy_get_connection (proxy),
	                        g_dbus_proxy_get_name (proxy),
	                        g_dbus_proxy_get_object_path (proxy),
	                        SECRET_SERVICE_INTERFACE,
	                        "CreateCollection", params, G_VARIANT_TYPE ("(oo)"),
	                        G_DBUS_CALL_FLAGS_NONE, -1,
	                        closure->cancellable,
	                        on_create_collection_called,
	                        g_object_ref (res));

	g_object_unref (res);

}

/**
 * secret_service_create_collection_path_finish:
 * @self: a secret service object
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to create a new collection in the secret
 * service.
 *
 * Returns: (transfer full): a new string containing the dbus object path
 *          of the collection
 */
gchar *
secret_service_create_collection_path_finish (SecretService *self,
                                              GAsyncResult *result,
                                              GError **error)
{
	GSimpleAsyncResult *res;
	CollectionClosure *closure;
	gchar *path;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      secret_service_create_collection_path), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	path = closure->collection_path;
	closure->collection_path = NULL;
	return path;
}

/**
 * secret_service_create_collection_path_sync:
 * @self: a secret service object
 * @properties: hash table of properties for the new collection
 * @alias: (allow-none): an alias to check for before creating the new
 *         collection, or to assign to the new collection
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Create a new collection in the secret service.
 *
 * If a collection with the @alias already exists, then instead of creating a
 * new collection, the existing collection will be returned. If no collection
 * with this alias exists, then a new collection will be created and this
 * alias will be assigned to it.
 *
 * @properties is a set of properties for the new collection. The keys in the
 * hash table should be interface.property strings like
 * <literal>org.freedesktop.Secret.Collection.Label</literal>. The values
 * in the hash table should be #GVariant values of the properties.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads. The secret service may prompt the user. secret_service_prompt()
 * will be used to handle any prompts that are required.
 *
 * Returns: (transfer full): a new string containing the dbus object path
 *          of the collection
 */
gchar *
secret_service_create_collection_path_sync (SecretService *self,
                                            GHashTable *properties,
                                            const gchar *alias,
                                            GCancellable *cancellable,
                                            GError **error)
{
	SecretSync *sync;
	gchar *path;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (properties != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_create_collection_path (self, properties, alias, cancellable,
	                                       _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	path = secret_service_create_collection_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return path;
}

typedef struct {
	GCancellable *cancellable;
	GVariant *properties;
	SecretValue *value;
	gboolean replace;
	gchar *collection_path;
	SecretPrompt *prompt;
	gchar *item_path;
} ItemClosure;

static void
item_closure_free (gpointer data)
{
	ItemClosure *closure = data;
	g_variant_unref (closure->properties);
	secret_value_unref (closure->value);
	g_clear_object (&closure->cancellable);
	g_free (closure->collection_path);
	g_clear_object (&closure->prompt);
	g_slice_free (ItemClosure, closure);
}

static void
on_create_item_prompt (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	ItemClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;
	gboolean created;
	GVariant *value;

	created = secret_service_prompt_finish (SECRET_SERVICE (source), result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	if (created) {
		value = secret_prompt_get_result_value (closure->prompt, G_VARIANT_TYPE ("o"));
		closure->item_path = g_variant_dup_string (value, NULL);
		g_variant_unref (value);
	}

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_create_item_called (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	ItemClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (g_async_result_get_source_object (user_data));
	const gchar *prompt_path = NULL;
	const gchar *item_path = NULL;
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o&o)", &item_path, &prompt_path);
		if (!_secret_util_empty_path (prompt_path)) {
			closure->prompt = _secret_prompt_instance (self, prompt_path);
			secret_service_prompt (self, closure->prompt,
			                       closure->cancellable, on_create_item_prompt,
			                       g_object_ref (res));

		} else {
			closure->item_path = g_strdup (item_path);
			g_simple_async_result_complete (res);
		}

		g_variant_unref (retval);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (self);
	g_object_unref (res);
}

static void
on_create_item_session (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	ItemClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	SecretService *self = SECRET_SERVICE (source);
	SecretSession *session;
	GVariant *params;
	GError *error = NULL;
	GDBusProxy *proxy;

	secret_service_ensure_session_finish (self, result, &error);
	if (error == NULL) {
		session = _secret_service_get_session (self);
		params = g_variant_new ("(@a{sv}@(oayays)b)",
		                        closure->properties,
		                        _secret_session_encode_secret (session, closure->value),
		                        closure->replace);

		proxy = G_DBUS_PROXY (self);
		g_dbus_connection_call (g_dbus_proxy_get_connection (proxy),
		                        g_dbus_proxy_get_name (proxy),
		                        closure->collection_path,
		                        SECRET_COLLECTION_INTERFACE,
		                        "CreateItem", params, G_VARIANT_TYPE ("(oo)"),
		                        G_DBUS_CALL_FLAGS_NONE, -1,
		                        closure->cancellable,
		                        on_create_item_called,
		                        g_object_ref (res));
	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_object_unref (res);
}

/**
 * secret_service_create_item_path:
 * @self: a secret service object
 * @collection_path: dbus path to collection in which to create item
 * @properties: hash table of properties for the new collection
 * @value: the secret value to store in the item
 * @replace: whether to replace an item with the matching attributes
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Create a new item in a secret service collection.
 *
 * It is often easier to use secret_password_store() or secret_item_create()
 * rather than using this function.
 *
 * If @replace is set to %TRUE, and an item already in the collection matches
 * the attributes (specified in @properties) then the item will be updated
 * instead of creating a new item.
 *
 * @properties is a set of properties for the new collection. The keys in the
 * hash table should be interface.property strings like
 * <literal>org.freedesktop.Secret.Item.Label</literal>. The values
 * in the hash table should be #GVariant values of the properties.
 *
 * This method will return immediately and complete asynchronously. The secret
 * service may prompt the user. secret_service_prompt() will be used to handle
 * any prompts that are required.
 */
void
secret_service_create_item_path (SecretService *self,
                                 const gchar *collection_path,
                                 GHashTable *properties,
                                 SecretValue *value,
                                 gboolean replace,
                                 GCancellable *cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
	GSimpleAsyncResult *res;
	ItemClosure *closure;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (properties != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 secret_service_create_item_path);
	closure = g_slice_new0 (ItemClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->properties = _secret_util_variant_for_properties (properties);
	g_variant_ref_sink (closure->properties);
	closure->replace = replace;
	closure->value = secret_value_ref (value);
	closure->collection_path = g_strdup (collection_path);
	g_simple_async_result_set_op_res_gpointer (res, closure, item_closure_free);

	secret_service_ensure_session (self, cancellable,
	                               on_create_item_session,
	                               g_object_ref (res));

	g_object_unref (res);
}

/**
 * secret_service_create_item_path_finish:
 * @self: a secret service object
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to create a new item in the secret
 * service.
 *
 * Returns: (transfer full): a new string containing the dbus object path
 *          of the item
 */
gchar *
secret_service_create_item_path_finish (SecretService *self,
                                        GAsyncResult *result,
                                        GError **error)
{
	GSimpleAsyncResult *res;
	ItemClosure *closure;
	gchar *path;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      secret_service_create_item_path), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	path = closure->item_path;
	closure->item_path = NULL;
	return path;
}

/**
 * secret_service_create_item_path_sync:
 * @self: a secret service object
 * @collection_path: dbus path to collection in which to create item
 * @properties: hash table of properties for the new collection
 * @value: the secret value to store in the item
 * @replace: whether to replace an item with the matching attributes
 * @cancellable: optional cancellation object
 * @error: location to place an error on failure
 *
 * Create a new item in a secret service collection.
 *
 * It is often easier to use secret_password_store_sync() or secret_item_create_sync()
 * rather than using this function.
 *
 * If @replace is set to %TRUE, and an item already in the collection matches
 * the attributes (specified in @properties) then the item will be updated
 * instead of creating a new item.
 *
 * @properties is a set of properties for the new collection. The keys in the
 * hash table should be interface.property strings like
 * <literal>org.freedesktop.Secret.Item.Label</literal>. The values
 * in the hash table should be #GVariant values of the properties.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads. The secret service may prompt the user. secret_service_prompt()
 * will be used to handle any prompts that are required.
 *
 * Returns: (transfer full): a new string containing the dbus object path
 *          of the item
 */
gchar *
secret_service_create_item_path_sync (SecretService *self,
                                      const gchar *collection_path,
                                      GHashTable *properties,
                                      SecretValue *value,
                                      gboolean replace,
                                      GCancellable *cancellable,
                                      GError **error)
{
	SecretSync *sync;
	gchar *path;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (properties != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_create_item_path (self, collection_path, properties, value, replace,
	                                 cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	path = secret_service_create_item_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return path;
}
