/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 * Copyright 2012 Red Hat Inc.
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

#include "secret-dbus-generated.h"
#include "secret-paths.h"
#include "secret-private.h"
#include "secret-service.h"
#include "secret-types.h"
#include "secret-value.h"


/**
 * secret_collection_new_for_dbus_path: (skip)
 * @service: (nullable): a secret service object
 * @collection_path: the D-Bus path of the collection
 * @flags: options for the collection initialization
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Get a new collection proxy for a collection in the secret service.
 *
 * If @service is %NULL, then [func@Service.get] will be called to get
 * the default [class@Service] proxy.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Stability: Unstable
 */
void
secret_collection_new_for_dbus_path (SecretService *service,
                                     const gchar *collection_path,
                                     SecretCollectionFlags flags,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	GDBusProxy *proxy;

	g_return_if_fail (service == NULL || SECRET_IS_SERVICE (service));
	g_return_if_fail (collection_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	proxy = G_DBUS_PROXY (service);

	g_async_initable_new_async (secret_service_get_collection_gtype (service),
	                            G_PRIORITY_DEFAULT, cancellable, callback, user_data,
	                            "g-flags", G_DBUS_CALL_FLAGS_NONE,
	                            "g-interface-info", _secret_gen_collection_interface_info (),
	                            "g-name", g_dbus_proxy_get_name (proxy),
	                            "g-connection", g_dbus_proxy_get_connection (proxy),
	                            "g-object-path", collection_path,
	                            "g-interface-name", SECRET_COLLECTION_INTERFACE,
	                            "service", service,
	                            "flags", flags,
	                            NULL);
}

/**
 * secret_collection_new_for_dbus_path_finish: (skip)
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to get a new collection proxy for a
 * collection in the secret service.
 *
 * Returns: (transfer full): the new collection, which should be unreferenced
 *   with [method@GObject.Object.unref]
 */
SecretCollection *
secret_collection_new_for_dbus_path_finish (GAsyncResult *result,
                                            GError **error)
{
	GObject *source_object;
	GObject *object;

	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	source_object = g_async_result_get_source_object (result);
	object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
	                                      result, error);
	g_object_unref (source_object);

	if (object == NULL)
		return NULL;

	return SECRET_COLLECTION (object);
}

/**
 * secret_collection_new_for_dbus_path_sync: (skip)
 * @service: (nullable): a secret service object
 * @collection_path: the D-Bus path of the collection
 * @flags: options for the collection initialization
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Get a new collection proxy for a collection in the secret service.
 *
 * If @service is %NULL, then [func@Service.get_sync] will be called to get
 * the default [class@Service] proxy.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full): the new collection, which should be unreferenced
 *   with [method@GObject.Object.unref]
 */
SecretCollection *
secret_collection_new_for_dbus_path_sync (SecretService *service,
                                          const gchar *collection_path,
                                          SecretCollectionFlags flags,
                                          GCancellable *cancellable,
                                          GError **error)
{
	GDBusProxy *proxy;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (collection_path != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	proxy = G_DBUS_PROXY (service);

	return g_initable_new (secret_service_get_collection_gtype (service),
	                       cancellable, error,
	                       "g-flags", G_DBUS_CALL_FLAGS_NONE,
	                       "g-interface-info", _secret_gen_collection_interface_info (),
	                       "g-name", g_dbus_proxy_get_name (proxy),
	                       "g-connection", g_dbus_proxy_get_connection (proxy),
	                       "g-object-path", collection_path,
	                       "g-interface-name", SECRET_COLLECTION_INTERFACE,
	                       "service", service,
	                       "flags", flags,
	                       NULL);
}

/**
 * secret_item_new_for_dbus_path: (skip)
 * @service: (nullable): a secret service object
 * @item_path: the D-Bus path of the collection
 * @flags: initialization flags for the new item
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Get a new item proxy for a secret item in the secret service.
 *
 * If @service is %NULL, then [func@Service.get] will be called to get
 * the default [class@Service] proxy.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Stability: Unstable
 */
void
secret_item_new_for_dbus_path (SecretService *service,
                               const gchar *item_path,
                               SecretItemFlags flags,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GDBusProxy *proxy;

	g_return_if_fail (service == NULL || SECRET_IS_SERVICE (service));
	g_return_if_fail (item_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	proxy = G_DBUS_PROXY (service);

	g_async_initable_new_async (secret_service_get_item_gtype (service),
	                            G_PRIORITY_DEFAULT, cancellable, callback, user_data,
	                            "g-flags", G_DBUS_CALL_FLAGS_NONE,
	                            "g-interface-info", _secret_gen_item_interface_info (),
	                            "g-name", g_dbus_proxy_get_name (proxy),
	                            "g-connection", g_dbus_proxy_get_connection (proxy),
	                            "g-object-path", item_path,
	                            "g-interface-name", SECRET_ITEM_INTERFACE,
	                            "service", service,
	                            "flags", flags,
	                            NULL);
}

/**
 * secret_item_new_for_dbus_path_finish: (skip)
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to get a new item proxy for a secret
 * item in the secret service.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full): the new item, which should be unreferenced
 *   with [method@GObject.Object.unref]
 */
SecretItem *
secret_item_new_for_dbus_path_finish (GAsyncResult *result,
                                      GError **error)
{
	GObject *object;
	GObject *source_object;

	source_object = g_async_result_get_source_object (result);
	object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
	                                      result, error);
	g_object_unref (source_object);

	if (object == NULL)
		return NULL;

	return SECRET_ITEM (object);
}

/**
 * secret_item_new_for_dbus_path_sync: (skip)
 * @service: (nullable): a secret service object
 * @item_path: the D-Bus path of the item
 * @flags: initialization flags for the new item
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Get a new item proxy for a secret item in the secret service.
 *
 * If @service is %NULL, then [func@Service.get_sync] will be called to get
 * the default [class@Service] proxy.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full): the new item, which should be unreferenced
 *   with [method@GObject.Object.unref]
 */
SecretItem *
secret_item_new_for_dbus_path_sync (SecretService *service,
                                    const gchar *item_path,
                                    SecretItemFlags flags,
                                    GCancellable *cancellable,
                                    GError **error)
{
	GDBusProxy *proxy;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (item_path != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	proxy = G_DBUS_PROXY (service);

	return g_initable_new (secret_service_get_item_gtype (service),
	                       cancellable, error,
	                       "g-flags", G_DBUS_CALL_FLAGS_NONE,
	                       "g-interface-info", _secret_gen_item_interface_info (),
	                       "g-name", g_dbus_proxy_get_name (proxy),
	                       "g-connection", g_dbus_proxy_get_connection (proxy),
	                       "g-object-path", item_path,
	                       "g-interface-name", SECRET_ITEM_INTERFACE,
	                       "service", service,
	                       "flags", flags,
	                       NULL);
}

static void
on_search_items_complete (GObject *source,
                          GAsyncResult *result,
                          gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GError *error = NULL;
	GVariant *response;

	response = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
	} else {
		g_task_return_pointer (task,
		                       g_steal_pointer (&response),
		                       (GDestroyNotify) g_variant_unref);
	}

	g_object_unref (task);
}

/**
 * secret_collection_search_for_dbus_paths: (skip)
 * @collection: the secret collection
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Search for items in @collection matching the @attributes, and return their
 * DBus object paths.
 *
 * Only the specified collection is searched. The @attributes should be a table
 * of string keys and string values.
 *
 * This function returns immediately and completes asynchronously.
 *
 * When your callback is called use [method@Collection.search_for_dbus_paths_finish]
 * to get the results of this function. Only the DBus object paths of the
 * items will be returned. If you would like [class@Item] objects to be returned
 * instead, then use the [method@Collection.search] function.
 *
 * Stability: Unstable
 */
void
secret_collection_search_for_dbus_paths (SecretCollection *collection,
                                         const SecretSchema *schema,
                                         GHashTable *attributes,
                                         GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
	GTask *task = NULL;
	const gchar *schema_name = NULL;

	g_return_if_fail (SECRET_IS_COLLECTION (collection));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	if (schema != NULL && !(schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME))
		schema_name = schema->name;

	task = g_task_new (collection, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_collection_search_for_dbus_paths);

	g_dbus_proxy_call (G_DBUS_PROXY (collection), "SearchItems",
	                   g_variant_new ("(@a{ss})",
	                   _secret_attributes_to_variant (attributes, schema_name)),
	                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable,
	                   on_search_items_complete, g_steal_pointer (&task));

	g_clear_object (&task);
}

/**
 * secret_collection_search_for_dbus_paths_finish: (skip)
 * @collection: the secret collection
 * @result: asynchronous result passed to callback
 * @error: location to place error on failure
 *
 * Complete asynchronous operation to search for items in a collection.
 *
 * DBus object paths of the items will be returned. If you would to have
 * [class@Item] objects to be returned instead, then use the
 * [method@Collection.search] and [method@Collection.search_finish] functions.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (array zero-terminated=1): an array of DBus object
 *   paths for matching items.
 */
gchar **
secret_collection_search_for_dbus_paths_finish (SecretCollection *collection,
                                                GAsyncResult *result,
                                                GError **error)
{
	GVariant *retval = NULL;
	gchar **paths = NULL;

	g_return_val_if_fail (g_task_is_valid (result, collection), NULL);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                      secret_collection_search_for_dbus_paths, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	retval = g_task_propagate_pointer (G_TASK (result), error);
	if (retval == NULL) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	g_variant_get (retval, "(^ao)", &paths);
	g_clear_pointer (&retval, g_variant_unref);
	return g_steal_pointer (&paths);
}

/**
 * secret_collection_search_for_dbus_paths_sync: (skip)
 * @collection: the secret collection
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place error on failure
 *
 * Search for items matching the @attributes in @collection, and return their
 * DBus object paths.
 *
 * The @attributes should be a table of string keys and string values.
 *
 * This function may block indefinitely. Use the asynchronous version
 * in user interface threads.
 *
 * DBus object paths of the items will be returned. If you would to have
 * [class@Item] objects to be returned instead, then use the
 * [method@Collection.search_sync] function.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (array zero-terminated=1): an array of DBus object
 *   paths for matching items.
 */
gchar **
secret_collection_search_for_dbus_paths_sync (SecretCollection *collection,
                                              const SecretSchema *schema,
                                              GHashTable *attributes,
                                              GCancellable *cancellable,
                                              GError **error)
{
	SecretSync *sync;
	gchar **paths;

	g_return_val_if_fail (SECRET_IS_COLLECTION (collection), NULL);
	g_return_val_if_fail (attributes != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_collection_search_for_dbus_paths (collection, schema, attributes, cancellable,
	                                         _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	paths = secret_collection_search_for_dbus_paths_finish (collection, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return paths;
}

/**
 * secret_service_search_for_dbus_paths: (skip)
 * @self: the secret service
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Search for items matching the @attributes, and return their D-Bus object paths.
 *
 * All collections are searched. The @attributes should be a table of string keys
 * and string values.
 *
 * This function returns immediately and completes asynchronously.
 *
 * When your callback is called use [method@Service.search_for_dbus_paths_finish]
 * to get the results of this function. Only the D-Bus object paths of the
 * items will be returned. If you would like [class@Item] objects to be returned
 * instead, then use the [method@Service.search] function.
 *
 * Stability: Unstable
 */
void
secret_service_search_for_dbus_paths (SecretService *self,
                                      const SecretSchema *schema,
                                      GHashTable *attributes,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
	const gchar *schema_name = NULL;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	if (schema != NULL && !(schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME))
		schema_name = schema->name;

	_secret_service_search_for_paths_variant (self, _secret_attributes_to_variant (attributes, schema_name),
	                                          cancellable, callback, user_data);
}

void
_secret_service_search_for_paths_variant (SecretService *self,
                                          GVariant *attributes,
                                          GCancellable *cancellable,
                                          GAsyncReadyCallback callback,
                                          gpointer user_data)
{
	GTask *task = NULL;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_search_for_dbus_paths);

	g_dbus_proxy_call (G_DBUS_PROXY (self), "SearchItems",
	                   g_variant_new ("(@a{ss})", attributes),
	                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable,
	                   on_search_items_complete, g_steal_pointer (&task));

	g_clear_object (&task);
}

/**
 * secret_service_search_for_dbus_paths_finish: (skip)
 * @self: the secret service
 * @result: asynchronous result passed to callback
 * @unlocked: (out) (transfer full) (array zero-terminated=1) (optional) (nullable):
 *   location to place an array of D-Bus object paths for matching
 *   items which were locked.
 * @locked: (out) (transfer full) (array zero-terminated=1) (optional) (nullable):
 *   location to place an array of D-Bus object paths for matching
 *   items which were locked.
 * @error: location to place error on failure
 *
 * Complete asynchronous operation to search for items, and return their
 * D-Bus object paths.
 *
 * Matching items that are locked or unlocked, have their D-Bus paths placed
 * in the @locked or @unlocked arrays respectively.
 *
 * D-Bus object paths of the items will be returned in the @unlocked or
 * @locked arrays. If you would to have [class@Item] objects to be returned
 * instead, then us the [method@Service.search] and
 * [method@Service.search_finish] functions.
 *
 * Stability: Unstable
 *
 * Returns: whether the search was successful or not
 */
gboolean
secret_service_search_for_dbus_paths_finish (SecretService *self,
                                             GAsyncResult *result,
                                             gchar ***unlocked,
                                             gchar ***locked,
                                             GError **error)
{
	GVariant *response;
	gchar **unlocked_ret = NULL, **locked_ret = NULL;

	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                      secret_service_search_for_dbus_paths, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	response = g_task_propagate_pointer (G_TASK (result), error);
	if (response == NULL) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	g_variant_get (response, "(^ao^ao)", &unlocked_ret, &locked_ret);

	if (unlocked)
		*unlocked = g_steal_pointer (&unlocked_ret);
	if (locked)
		*locked = g_steal_pointer (&locked_ret);

	g_strfreev (unlocked_ret);
	g_strfreev (locked_ret);
	g_variant_unref (response);

	return TRUE;
}

/**
 * secret_service_search_for_dbus_paths_sync: (skip)
 * @self: the secret service
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @cancellable: (nullable): optional cancellation object
 * @unlocked: (out) (transfer full) (array zero-terminated=1) (optional) (nullable):
 *   location to place an array of D-Bus object paths for matching
 *   items which were locked.
 * @locked: (out) (transfer full) (array zero-terminated=1) (optional) (nullable):
 *   location to place an array of D-Bus object paths for matching
 *   items which were locked.
 * @error: location to place error on failure
 *
 * Search for items matching the @attributes, and return their D-Bus object
 * paths.
 *
 * All collections are searched. The @attributes should be a table of string
 * keys and string values.
 *
 * This function may block indefinitely. Use the asynchronous version
 * in user interface threads.
 *
 * Matching items that are locked or unlocked, have their D-Bus paths placed
 * in the @locked or @unlocked arrays respectively.
 *
 * D-Bus object paths of the items will be returned in the @unlocked or
 * @locked arrays. If you would to have [class@Item] objects to be returned
 * instead, then use the [method@Service.search_sync] function.
 *
 * Stability: Unstable
 *
 * Returns: whether the search was successful or not
 */
gboolean
secret_service_search_for_dbus_paths_sync (SecretService *self,
                                           const SecretSchema *schema,
                                           GHashTable *attributes,
                                           GCancellable *cancellable,
                                           gchar ***unlocked,
                                           gchar ***locked,
                                           GError **error)
{
	const gchar *schema_name = NULL;
	GVariant *response;
	gchar **unlocked_ret = NULL, **locked_ret = NULL;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return FALSE;

	if (schema != NULL && !(schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME))
		schema_name = schema->name;

	response = g_dbus_proxy_call_sync (G_DBUS_PROXY (self), "SearchItems",
	                                   g_variant_new ("(@a{ss})",
	                                   _secret_attributes_to_variant (attributes, schema_name)),
	                                   G_DBUS_CALL_FLAGS_NONE, -1,
	                                   cancellable, error);

	if (response == NULL)
		return FALSE;

	g_variant_get (response, "(^ao^ao)", &unlocked_ret, &locked_ret);
	if (unlocked)
		*unlocked = g_steal_pointer (&unlocked_ret);
	if (locked)
		*locked = g_steal_pointer (&locked_ret);
	g_variant_unref (response);

	g_strfreev (unlocked_ret);
	g_strfreev (locked_ret);

	return TRUE;
}

static void
on_get_secrets_complete (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GVariant *ret;
	GError *error = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
	} else {
		g_task_return_pointer (task, ret, (GDestroyNotify) g_variant_unref);
	}

	g_clear_object (&task);
}

static void
on_get_secrets_session (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GVariant *item_paths = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;
	const gchar *session;

	secret_service_ensure_session_finish (SECRET_SERVICE (source), result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
	} else {
		session = secret_service_get_session_dbus_path (SECRET_SERVICE (source));
		g_dbus_proxy_call (G_DBUS_PROXY (source), "GetSecrets",
		                   g_variant_new ("(@aoo)", item_paths, session),
		                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
		                   cancellable, on_get_secrets_complete,
		                   g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

/**
 * secret_service_get_secret_for_dbus_path: (skip)
 * @self: the secret service
 * @item_path: the D-Bus path to item to retrieve secret for
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Get the secret value for a secret item stored in the service.
 *
 * The item is represented by its D-Bus object path. If you already have a
 * [class@Item] proxy object, use use [method@Item.get_secret] to more simply
 * get its secret value.
 *
 * This function returns immediately and completes asynchronously.
 *
 * Stability: Unstable
 */
void
secret_service_get_secret_for_dbus_path (SecretService *self,
                                         const gchar *item_path,
                                         GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
	GTask *task;
	GVariant *path_variant;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (item_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	path_variant = g_variant_ref_sink (g_variant_new_objv (&item_path, 1));

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_get_secret_for_dbus_path);
	g_task_set_task_data (task, path_variant, (GDestroyNotify) g_variant_unref);

	secret_service_ensure_session (self, cancellable,
	                               on_get_secrets_session,
	                               g_steal_pointer (&task));

	g_clear_object (&task);
}

/**
 * secret_service_get_secret_for_dbus_path_finish: (skip)
 * @self: the secret service
 * @result: asynchronous result passed to callback
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to get the secret value for an
 * secret item stored in the service.
 *
 * Will return %NULL if the item is locked.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (nullable): the newly allocated secret value
 *   for the item, which should be released with [method@Value.unref]
 */
SecretValue *
secret_service_get_secret_for_dbus_path_finish (SecretService *self,
                                                GAsyncResult *result,
                                                GError **error)
{
	GVariant *ret;
	SecretValue *value;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_task_is_valid (result, self), NULL);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                      secret_service_get_secret_for_dbus_path, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	ret = g_task_propagate_pointer (G_TASK (result), error);
	if (ret == NULL) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	value = _secret_service_decode_get_secrets_first (self, ret);
	g_variant_unref (ret);
	return value;
}

/**
 * secret_service_get_secret_for_dbus_path_sync: (skip)
 * @self: the secret service
 * @item_path: the D-Bus path to item to retrieve secret for
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Get the secret value for a secret item stored in the service.
 *
 * The item is represented by its D-Bus object path. If you already have a
 * [class@Item] proxy object, use use [method@Item.load_secret_sync] to more simply
 * get its secret value.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Will return %NULL if the item is locked.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (nullable): the newly allocated secret value
 *   the item, which should be released with [method@Value.unref]
 */
SecretValue *
secret_service_get_secret_for_dbus_path_sync (SecretService *self,
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

	secret_service_get_secret_for_dbus_path (self, item_path, cancellable,
	                                         _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	value = secret_service_get_secret_for_dbus_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return value;
}

/**
 * secret_service_get_secrets_for_dbus_paths: (skip)
 * @self: the secret service
 * @item_paths: the D-Bus paths to items to retrieve secrets for
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Get the secret values for a secret item stored in the service.
 *
 * The items are represented by their D-Bus object paths. If you already have
 * [class@Item] proxy objects, use use [func@Item.load_secrets] to more simply
 * get their secret values.
 *
 * This function returns immediately and completes asynchronously.
 *
 * Stability: Unstable
 */
void
secret_service_get_secrets_for_dbus_paths (SecretService *self,
                                           const gchar **item_paths,
                                           GCancellable *cancellable,
                                           GAsyncReadyCallback callback,
                                           gpointer user_data)
{
	GTask *task;
	GVariant *paths_variant;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (item_paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	paths_variant = g_variant_ref_sink (g_variant_new_objv (item_paths, -1));

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_get_secret_for_dbus_path);
	g_task_set_task_data (task, paths_variant, (GDestroyNotify) g_variant_unref);

	secret_service_ensure_session (self, cancellable,
	                               on_get_secrets_session,
	                               g_steal_pointer (&task));

	g_clear_object (&task);
}

/**
 * secret_service_get_secrets_for_dbus_paths_finish: (skip)
 * @self: the secret service
 * @result: asynchronous result passed to callback
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to get the secret values for an
 * secret items stored in the service.
 *
 * Items that are locked will not be included the results.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (element-type utf8 Secret.Value): a newly
 *   allocated hash table of item path keys to [struct@Value]
 *   values.
 */
GHashTable *
secret_service_get_secrets_for_dbus_paths_finish (SecretService *self,
                                                  GAsyncResult *result,
                                                  GError **error)
{
	GVariant *ret;
	GHashTable *values;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_task_is_valid (result, self), NULL);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                      secret_service_get_secret_for_dbus_path, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	ret = g_task_propagate_pointer (G_TASK (result), error);
	if (ret == NULL) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	values = _secret_service_decode_get_secrets_all (self, ret);
	g_variant_unref (ret);
	return values;
}

/**
 * secret_service_get_secrets_for_dbus_paths_sync: (skip)
 * @self: the secret service
 * @item_paths: the D-Bus paths to items to retrieve secrets for
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Get the secret values for a secret item stored in the service.
 *
 * The items are represented by their D-Bus object paths. If you already have
 * [class@Item] proxy objects, use use [func@Item.load_secrets_sync] to more
 * simply get their secret values.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Items that are locked will not be included the results.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (element-type utf8 Secret.Value): a newly
 *   allocated hash table of item_path keys to [struct@Value]
 *   values.
 */
GHashTable *
secret_service_get_secrets_for_dbus_paths_sync (SecretService *self,
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

	secret_service_get_secrets_for_dbus_paths (self, item_paths, cancellable,
	                                           _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	secrets = secret_service_get_secrets_for_dbus_paths_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return secrets;
}


typedef struct {
	SecretPrompt *prompt;
} XlockClosure;

static void
xlock_closure_free (gpointer data)
{
	XlockClosure *closure = data;
	g_clear_object (&closure->prompt);
	g_free (closure);
}

static void
on_xlock_prompted (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretService *self = SECRET_SERVICE (source);
	GPtrArray *xlocked_array;
	GError *error = NULL;
	GVariantIter iter;
	GVariant *retval;
	gchar *path;

	retval = secret_service_prompt_finish (self, result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));

	} else {
		xlocked_array = g_ptr_array_new_with_free_func (g_free);
		g_variant_iter_init (&iter, retval);
		while (g_variant_iter_loop (&iter, "o", &path))
			g_ptr_array_add (xlocked_array, g_strdup (path));
		g_variant_unref (retval);

		g_task_return_pointer (task,
		                       xlocked_array,
		                       (GDestroyNotify) g_ptr_array_unref);
	}

	g_clear_object (&task);
}

static void
on_xlock_called (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	XlockClosure *closure = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	SecretService *self = SECRET_SERVICE (g_task_get_source_object (task));
	const gchar *prompt = NULL;
	gchar **xlocked = NULL;
	GError *error = NULL;
	GVariant *retval;
	guint i;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));

	} else {
		g_variant_get (retval, "(^ao&o)", &xlocked, &prompt);

		if (_secret_util_empty_path (prompt)) {
			GPtrArray *xlocked_array;

			xlocked_array = g_ptr_array_new_with_free_func (g_free);

			for (i = 0; xlocked[i]; i++)
				g_ptr_array_add (xlocked_array, g_strdup (xlocked[i]));

			g_task_return_pointer (task,
			                       xlocked_array,
			                       (GDestroyNotify) g_ptr_array_unref);

		} else {
			closure->prompt = _secret_prompt_instance (self, prompt);
			secret_service_prompt (self, closure->prompt, G_VARIANT_TYPE ("ao"),
			                       cancellable,
			                       on_xlock_prompted, g_steal_pointer (&task));
		}

		g_strfreev (xlocked);
		g_variant_unref (retval);
	}

	g_clear_object (&task);
}

void
_secret_service_xlock_paths_async (SecretService *self,
                                   const gchar *method,
                                   const gchar **paths,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
	GTask *task = NULL;
	XlockClosure *closure;

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, _secret_service_xlock_paths_async);
	closure = g_new0 (XlockClosure, 1);
	g_task_set_task_data (task, closure, xlock_closure_free);

	g_dbus_proxy_call (G_DBUS_PROXY (self), method,
	                   g_variant_new ("(@ao)", g_variant_new_objv (paths, -1)),
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                   cancellable, on_xlock_called, g_steal_pointer (&task));

	g_clear_object (&task);
}

gint
_secret_service_xlock_paths_finish (SecretService *self,
                                    GAsyncResult *result,
                                    gchar ***xlocked,
                                    GError **error)
{
	GPtrArray *xlocked_array = NULL;
	gchar **xlocked_ret = NULL;
	gint count;

	xlocked_array = g_task_propagate_pointer (G_TASK (result), error);
	if (xlocked_array == NULL) {
		_secret_util_strip_remote_error (error);
		return -1;
	}

	count = xlocked_array->len;
	/* Add NULL-terminator after storing the count,
	 * but before getting out the raw pointer */
	g_ptr_array_add (xlocked_array, NULL);
	xlocked_ret = (gchar **) g_ptr_array_free (xlocked_array, FALSE);

	if (xlocked != NULL)
		*xlocked = g_steal_pointer (&xlocked_ret);

	g_strfreev (xlocked_ret);

	return count;
}

/**
 * secret_service_lock_dbus_paths_sync: (skip)
 * @self: the secret service
 * @paths: (array zero-terminated=1): the D-Bus object paths of the items or collections to lock
 * @cancellable: (nullable): optional cancellation object
 * @locked: (out) (array zero-terminated=1) (transfer full) (optional) (nullable):
 *   location to place array of D-Bus paths of items or collections
 *   that were locked
 * @error: location to place an error on failure
 *
 * Lock items or collections in the secret service.
 *
 * The items or collections are represented by their D-Bus object paths. If you
 * already have [class@Item] and [class@Collection] proxy objects, use use
 * [method@Service.lock_sync] instead.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * [method@Service.prompt] will be used to handle any prompts that show up.
 *
 * Stability: Unstable
 *
 * Returns: the number of items or collections that were locked
 */
gint
secret_service_lock_dbus_paths_sync (SecretService *self,
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

	secret_service_lock_dbus_paths (self, paths, cancellable,
	                                _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = secret_service_lock_dbus_paths_finish (self, sync->result,
	                                               locked, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return count;
}

/**
 * secret_service_lock_dbus_paths: (skip)
 * @self: the secret service
 * @paths: (array zero-terminated=1): the D-Bus paths for items or collections to lock
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Lock items or collections in the secret service.
 *
 * The items or collections are represented by their D-Bus object paths. If you
 * already have [class@Item] and [class@Collection] proxy objects, use use
 * [method@Service.lock] instead.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * This method returns immediately and completes asynchronously. The secret
 * service may prompt the user. [method@Service.prompt] will be used to handle
 * any prompts that show up.
 *
 * Stability: Unstable
 */
void
secret_service_lock_dbus_paths (SecretService *self,
                                const gchar **paths,
                                GCancellable *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	_secret_service_xlock_paths_async (self, "Lock", paths, cancellable,
	                                   callback, user_data);
}

/**
 * secret_service_lock_dbus_paths_finish: (skip)
 * @self: the secret service
 * @result: asynchronous result passed to the callback
 * @locked: (out) (array zero-terminated=1) (transfer full) (optional) (nullable):
 *   location to place array of D-Bus paths of items or collections
 *   that were locked
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to lock items or collections in the secret
 * service.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * Stability: Unstable
 *
 * Returns: the number of items or collections that were locked
 */
gint
secret_service_lock_dbus_paths_finish (SecretService *self,
                                       GAsyncResult *result,
                                       gchar ***locked,
                                       GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (locked != NULL, -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	return _secret_service_xlock_paths_finish (self, result, locked, error);
}

/**
 * secret_service_unlock_dbus_paths_sync: (skip)
 * @self: the secret service
 * @paths: (array zero-terminated=1): the D-Bus object paths of the items or
 *   collections to unlock
 * @cancellable: (nullable): optional cancellation object
 * @unlocked: (out) (array zero-terminated=1) (transfer full) (optional) (nullable):
 *   location to place array of D-Bus paths of items or collections
 *   that were unlocked
 * @error: location to place an error on failure
 *
 * Unlock items or collections in the secret service.
 *
 * The items or collections are represented by their D-Bus object paths. If you
 * already have [class@Item] and [class@Collection] proxy objects, use use
 * [method@Service.unlock_sync] instead.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * [method@Service.prompt] will be used to handle any prompts that show up.
 *
 * Stability: Unstable
 *
 * Returns: the number of items or collections that were unlocked
 */
gint
secret_service_unlock_dbus_paths_sync (SecretService *self,
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
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_unlock_dbus_paths (self, paths, cancellable,
	                                  _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = secret_service_unlock_dbus_paths_finish (self, sync->result,
	                                                 unlocked, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return count;
}

/**
 * secret_service_unlock_dbus_paths: (skip)
 * @self: the secret service
 * @paths: (array zero-terminated=1): the D-Bus paths for items or
 *   collections to unlock
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Unlock items or collections in the secret service.
 *
 * The items or collections are represented by their D-Bus object paths. If you
 * already have [class@Item] and [class@Collection] proxy objects, use use
 * [method@Service.unlock] instead.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * This method returns immediately and completes asynchronously. The secret
 * service may prompt the user. [method@Service.prompt] will be used to handle
 * any prompts that show up.
 *
 * Stability: Unstable
 */
void
secret_service_unlock_dbus_paths (SecretService *self,
                                  const gchar **paths,
                                  GCancellable *cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	_secret_service_xlock_paths_async (self, "Unlock",
	                                   paths, cancellable,
	                                   callback, user_data);
}

/**
 * secret_service_unlock_dbus_paths_finish: (skip)
 * @self: the secret service
 * @result: asynchronous result passed to the callback
 * @unlocked: (out) (array zero-terminated=1) (transfer full) (optional) (nullable):
 *   location to place array of D-Bus paths of items or collections
 *   that were unlocked
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to unlock items or collections in the secret
 * service.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * Stability: Unstable
 *
 * Returns: the number of items or collections that were unlocked
 */
gint
secret_service_unlock_dbus_paths_finish (SecretService *self,
                                         GAsyncResult *result,
                                         gchar ***unlocked,
                                         GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	return _secret_service_xlock_paths_finish (self, result,
	                                           unlocked, error);
}

typedef struct {
	SecretPrompt *prompt;
} DeleteClosure;

static void
delete_closure_free (gpointer data)
{
	DeleteClosure *closure = data;
	g_clear_object (&closure->prompt);
	g_free (closure);
}

static void
on_delete_prompted (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GError *error = NULL;
	GVariant *retval;

	retval = secret_service_prompt_finish (SECRET_SERVICE (source), result,
	                                       &error);
	if (retval != NULL)
		g_variant_unref (retval);

	if (error == NULL)
		g_task_return_boolean (task, TRUE);
	else
		g_task_return_error (task, g_steal_pointer (&error));

	g_object_unref (task);
}

static void
on_delete_complete (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	DeleteClosure *closure = g_task_get_task_data (task);
	SecretService *self = SECRET_SERVICE (g_task_get_source_object (task));
	GCancellable *cancellable = g_task_get_cancellable (task);
	const gchar *prompt_path;
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o)", &prompt_path);

		if (_secret_util_empty_path (prompt_path)) {
			g_task_return_boolean (task, TRUE);

		} else {
			closure->prompt = _secret_prompt_instance (self, prompt_path);

			secret_service_prompt (self, closure->prompt, NULL,
			                       cancellable,
			                       on_delete_prompted,
			                       g_steal_pointer (&task));
		}

		g_variant_unref (retval);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

void
_secret_service_delete_path (SecretService *self,
                             const gchar *object_path,
                             gboolean is_an_item,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	GTask *task = NULL;
	DeleteClosure *closure;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (object_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, _secret_service_delete_path);
	closure = g_new0 (DeleteClosure, 1);
	g_task_set_task_data (task, closure, delete_closure_free);

	g_dbus_connection_call (g_dbus_proxy_get_connection (G_DBUS_PROXY (self)),
	                        g_dbus_proxy_get_name (G_DBUS_PROXY (self)),
	                        object_path,
	                        is_an_item ? SECRET_ITEM_INTERFACE : SECRET_COLLECTION_INTERFACE,
	                        "Delete", g_variant_new ("()"), G_VARIANT_TYPE ("(o)"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                        cancellable,
	                        on_delete_complete, g_steal_pointer (&task));

	g_clear_object (&task);
}

gboolean
_secret_service_delete_path_finish (SecretService *self,
                                    GAsyncResult *result,
                                    GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                      _secret_service_delete_path, FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

/**
 * secret_service_delete_item_dbus_path: (skip)
 * @self: the secret service
 * @item_path: the D-Bus path of item to delete
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Delete a secret item from the secret service.
 *
 * The item is represented by its D-Bus object path. If you already have a
 * [class@Item] proxy objects, use use [method@Item.delete] instead.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Stability: Unstable
 */
void
secret_service_delete_item_dbus_path (SecretService *self,
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
 * secret_service_delete_item_dbus_path_finish: (skip)
 * @self: the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Complete an asynchronous operation to delete a secret item from the secret
 * service.
 *
 * Stability: Unstable
 *
 * Returns: whether the deletion was successful or not
 */
gboolean
secret_service_delete_item_dbus_path_finish (SecretService *self,
                                             GAsyncResult *result,
                                             GError **error)
{
	return _secret_service_delete_path_finish (self, result, error);
}

/**
 * secret_service_delete_item_dbus_path_sync: (skip)
 * @self: the secret service
 * @item_path: the D-Bus path of item to delete
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Delete a secret item from the secret service.
 *
 * The item is represented by its D-Bus object path. If you already have a
 * [class@Item] proxy objects, use use [method@Item.delete_sync] instead.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Stability: Unstable
 *
 * Returns: whether the deletion was successful or not
 */
gboolean
secret_service_delete_item_dbus_path_sync (SecretService *self,
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

	secret_service_delete_item_dbus_path (self, item_path, cancellable,
	                                      _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = secret_service_delete_item_dbus_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return result;
}

typedef struct {
	SecretPrompt *prompt;
} CollectionClosure;

static void
collection_closure_free (gpointer data)
{
	CollectionClosure *closure = data;
	g_clear_object (&closure->prompt);
	g_free (closure);
}

static void
on_create_collection_prompt (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GError *error = NULL;
	GVariant *value;
	gchar *collection_path;

	value = secret_service_prompt_finish (SECRET_SERVICE (source), result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
	} else {
		collection_path = g_variant_dup_string (value, NULL);
		g_task_return_pointer (task, collection_path, g_free);
		g_variant_unref (value);
	}

	g_clear_object (&task);
}

static void
on_create_collection_called (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	CollectionClosure *closure = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	SecretService *self = SECRET_SERVICE (g_task_get_source_object (task));
	const gchar *prompt_path = NULL;
	const gchar *collection_path = NULL;
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o&o)", &collection_path, &prompt_path);
		if (!_secret_util_empty_path (prompt_path)) {
			closure->prompt = _secret_prompt_instance (self, prompt_path);
			secret_service_prompt (self, closure->prompt, G_VARIANT_TYPE ("o"),
			                       cancellable, on_create_collection_prompt,
			                       g_steal_pointer (&task));

		} else {
			g_task_return_pointer (task, g_strdup (collection_path), g_free);
		}

		g_variant_unref (retval);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

/**
 * secret_service_create_collection_dbus_path: (skip)
 * @self: a secret service object
 * @properties: (element-type utf8 GLib.Variant): hash table of properties for
 *   the new collection
 * @alias: (nullable): an alias to check for before creating the new
 *   collection, or to assign to the new collection
 * @flags: not currently used
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Create a new collection in the secret service, and return its path.
 *
 * Using this method requires that you setup a correct hash table of D-Bus
 * properties for the new collection. You may prefer to use
 * [func@Collection.create] which does handles this for you.
 *
 * An @alias is a well-known tag for a collection, such as 'default' (ie: the
 * default collection to store items in). This allows other applications to
 * easily identify and share a collection. If a collection with the @alias
 * already exists, then instead of creating a new collection, the existing
 * collection will be returned. If no collection with this alias exists, then a
 * new collection will be created and this alias will be assigned to it.
 *
 * @properties is a set of properties for the new collection. The keys in the
 * hash table should be interface.property strings like
 * `org.freedesktop.Secret.Collection.Label`. The values
 * in the hash table should be [struct@GLib.Variant] values of the properties.
 *
 * If you wish to have a
 *
 * This method will return immediately and complete asynchronously. The secret
 * service may prompt the user. [method@Service.prompt] will be used to handle
 * any prompts that are required.
 *
 * Stability: Unstable
 */
void
secret_service_create_collection_dbus_path (SecretService *self,
                                            GHashTable *properties,
                                            const gchar *alias,
                                            SecretCollectionCreateFlags flags,
                                            GCancellable *cancellable,
                                            GAsyncReadyCallback callback,
                                            gpointer user_data)
{
	GTask *task = NULL;
	CollectionClosure *closure;
	GVariant *params;
	GVariant *props;
	GDBusProxy *proxy;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (properties != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	if (alias == NULL)
		alias = "";

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_create_collection_dbus_path);
	closure = g_new0 (CollectionClosure, 1);
	g_task_set_task_data (task, closure, collection_closure_free);

	props = _secret_util_variant_for_properties (properties);
	params = g_variant_new ("(@a{sv}s)", props, alias);
	proxy = G_DBUS_PROXY (self);

	g_dbus_connection_call (g_dbus_proxy_get_connection (proxy),
	                        g_dbus_proxy_get_name (proxy),
	                        g_dbus_proxy_get_object_path (proxy),
	                        SECRET_SERVICE_INTERFACE,
	                        "CreateCollection", params, G_VARIANT_TYPE ("(oo)"),
	                        G_DBUS_CALL_FLAGS_NONE, -1,
	                        cancellable,
	                        on_create_collection_called,
	                        g_steal_pointer (&task));

	g_clear_object (&task);
}

/**
 * secret_service_create_collection_dbus_path_finish: (skip)
 * @self: a secret service object
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to create a new collection in the secret
 * service.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full): a new string containing the D-Bus object path
 *   of the collection
 */
gchar *
secret_service_create_collection_dbus_path_finish (SecretService *self,
                                                   GAsyncResult *result,
                                                   GError **error)
{
	gchar *path;

	g_return_val_if_fail (g_task_is_valid (result, self), NULL);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                      secret_service_create_collection_dbus_path, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	path = g_task_propagate_pointer (G_TASK (result), error);
	if (path == NULL) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	return g_steal_pointer (&path);
}

/**
 * secret_service_create_collection_dbus_path_sync: (skip)
 * @self: a secret service object
 * @properties: (element-type utf8 GLib.Variant): hash table of D-Bus properties
 *   for the new collection
 * @alias: (nullable): an alias to check for before creating the new
 *   collection, or to assign to the new collection
 * @flags: not currently used
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Create a new collection in the secret service and return its path.
 *
 * Using this method requires that you setup a correct hash table of D-Bus
 * properties for the new collection. You may prefer to use
 * [func@Collection.create] which does handles this for you.
 *
 * An @alias is a well-known tag for a collection, such as 'default' (ie: the
 * default collection to store items in). This allows other applications to
 * easily identify and share a collection. If a collection with the @alias
 * already exists, then instead of creating a new collection, the existing
 * collection will be returned. If no collection with this alias exists, then
 * a new collection will be created and this alias will be assigned to it.
 *
 * @properties is a set of properties for the new collection. The keys in the
 * hash table should be interface.property strings like
 * `org.freedesktop.Secret.Collection.Label`. The values
 * in the hash table should be [struct@GLib.Variant] values of the properties.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads. The secret service may prompt the user. [method@Service.prompt]
 * will be used to handle any prompts that are required.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full): a new string containing the D-Bus object path
 *   of the collection
 */
gchar *
secret_service_create_collection_dbus_path_sync (SecretService *self,
                                                 GHashTable *properties,
                                                 const gchar *alias,
                                                 SecretCollectionCreateFlags flags,
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

	secret_service_create_collection_dbus_path (self, properties, alias, flags, cancellable,
	                                            _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	path = secret_service_create_collection_dbus_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return path;
}

typedef struct {
	GVariant *properties;
	SecretValue *value;
	gboolean replace;
	gchar *collection_path;
	SecretPrompt *prompt;
} ItemClosure;

static void
item_closure_free (gpointer data)
{
	ItemClosure *closure = data;
	g_variant_unref (closure->properties);
	secret_value_unref (closure->value);
	g_free (closure->collection_path);
	g_clear_object (&closure->prompt);
	g_free (closure);
}

static void
on_create_item_prompt (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GError *error = NULL;
	GVariant *value;
	gchar *item_path;

	value = secret_service_prompt_finish (SECRET_SERVICE (source), result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
	} else {
		item_path = g_variant_dup_string (value, NULL);
		g_variant_unref (value);
		g_task_return_pointer (task, item_path, g_free);
	}

	g_clear_object (&task);
}

static void
on_create_item_called (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	ItemClosure *closure = g_task_get_task_data (task);
	SecretService *self = SECRET_SERVICE (g_task_get_source_object (task));
	GCancellable *cancellable = g_task_get_cancellable (task);
	const gchar *prompt_path = NULL;
	const gchar *item_path = NULL;
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o&o)", &item_path, &prompt_path);
		if (!_secret_util_empty_path (prompt_path)) {
			closure->prompt = _secret_prompt_instance (self, prompt_path);
			secret_service_prompt (self, closure->prompt, G_VARIANT_TYPE ("o"),
			                       cancellable, on_create_item_prompt,
			                       g_steal_pointer (&task));

		} else {
			g_task_return_pointer (task, g_strdup (item_path), g_free);
		}

		g_variant_unref (retval);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

static void
on_create_item_session (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	ItemClosure *closure = g_task_get_task_data (task);
	SecretService *self = SECRET_SERVICE (source);
	GCancellable *cancellable = g_task_get_cancellable (task);
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
		                        cancellable,
		                        on_create_item_called,
		                        g_steal_pointer (&task));
	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

/**
 * secret_service_create_item_dbus_path: (skip)
 * @self: a secret service object
 * @collection_path: the D-Bus object path of the collection in which to create item
 * @properties: (element-type utf8 GLib.Variant): hash table of D-Bus properties
 *   for the new collection
 * @value: the secret value to store in the item
 * @flags: flags for the creation of the new item
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Create a new item in a secret service collection and return its D-Bus
 * object path.
 *
 * It is often easier to use [func@password_store] or [func@Item.create]
 * rather than using this function. Using this method requires that you setup
 * a correct hash table of D-Bus @properties for the new collection.
 *
 * If the @flags contains %SECRET_ITEM_CREATE_REPLACE, then the secret
 * service will search for an item matching the @attributes, and update that item
 * instead of creating a new one.
 *
 * @properties is a set of properties for the new collection. The keys in the
 * hash table should be interface.property strings like
 * `org.freedesktop.Secret.Item.Label`. The values
 * in the hash table should be [struct@GLib.Variant] values of the properties.
 *
 * This method will return immediately and complete asynchronously. The secret
 * service may prompt the user. [method@Service.prompt] will be used to handle
 * any prompts that are required.
 *
 * Stability: Unstable
 */
void
secret_service_create_item_dbus_path (SecretService *self,
                                      const gchar *collection_path,
                                      GHashTable *properties,
                                      SecretValue *value,
                                      SecretItemCreateFlags flags,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
	GTask *task = NULL;
	ItemClosure *closure;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (collection_path != NULL && g_variant_is_object_path (collection_path));
	g_return_if_fail (properties != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_create_item_dbus_path);
	closure = g_new0 (ItemClosure, 1);
	closure->properties = _secret_util_variant_for_properties (properties);
	g_variant_ref_sink (closure->properties);
	closure->replace = flags & SECRET_ITEM_CREATE_REPLACE;
	closure->value = secret_value_ref (value);
	closure->collection_path = g_strdup (collection_path);
	g_task_set_task_data (task, closure, item_closure_free);

	secret_service_ensure_session (self, cancellable,
	                               on_create_item_session,
	                               g_steal_pointer (&task));

	g_clear_object (&task);
}

/**
 * secret_service_create_item_dbus_path_finish: (skip)
 * @self: a secret service object
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to create a new item in the secret
 * service.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full): a new string containing the D-Bus object path
 *   of the item
 */
gchar *
secret_service_create_item_dbus_path_finish (SecretService *self,
                                             GAsyncResult *result,
                                             GError **error)
{
	gchar *path;

	g_return_val_if_fail (g_task_is_valid (result, self), NULL);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                      secret_service_create_item_dbus_path, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	path = g_task_propagate_pointer (G_TASK (result), error);
	if (path == NULL) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	return g_steal_pointer (&path);
}

/* Same as the function above, but doesn't strip the remote error and throws
 * away the result */
void
_secret_service_create_item_dbus_path_finish_raw (GAsyncResult *result,
                                                  GError **error)
{
	gchar *path;

	g_return_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                  secret_service_create_item_dbus_path);
	g_return_if_fail (error == NULL || *error == NULL);

	path = g_task_propagate_pointer (G_TASK (result), error);

	g_free (path);
}

/**
 * secret_service_create_item_dbus_path_sync:
 * @self: a secret service object
 * @collection_path: the D-Bus path of the collection in which to create item
 * @properties: (element-type utf8 GLib.Variant): hash table of D-Bus properties
 *   for the new collection
 * @value: the secret value to store in the item
 * @flags: flags for the creation of the new item
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Create a new item in a secret service collection and return its D-Bus
 * object path.
 *
 * It is often easier to use [func@password_store_sync] or [func@Item.create_sync]
 * rather than using this function. Using this method requires that you setup
 * a correct hash table of D-Bus @properties for the new collection.
 *
 * If the @flags contains %SECRET_ITEM_CREATE_REPLACE, then the secret
 * service will search for an item matching the @attributes, and update that item
 * instead of creating a new one.
 *
 * @properties is a set of properties for the new collection. The keys in the
 * hash table should be interface.property strings like
 * `org.freedesktop.Secret.Item.Label`. The values
 * in the hash table should be [struct@GLib.Variant] values of the properties.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads. The secret service may prompt the user. [method@Service.prompt]
 * will be used to handle any prompts that are required.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full): a new string containing the D-Bus object path
 *   of the item
 */
gchar *
secret_service_create_item_dbus_path_sync (SecretService *self,
                                           const gchar *collection_path,
                                           GHashTable *properties,
                                           SecretValue *value,
                                           SecretItemCreateFlags flags,
                                           GCancellable *cancellable,
                                           GError **error)
{
	SecretSync *sync;
	gchar *path;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (collection_path != NULL && g_variant_is_object_path (collection_path), NULL);
	g_return_val_if_fail (properties != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_create_item_dbus_path (self, collection_path, properties, value, flags,
	                                      cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	path = secret_service_create_item_dbus_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return path;
}

/**
 * secret_service_read_alias_dbus_path: (skip)
 * @self: a secret service object
 * @alias: the alias to lookup
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Lookup which collection is assigned to this alias.
 *
 * Aliases help determine well known collections, such as 'default'. This method
 * looks up the dbus object path of the well known collection.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Stability: Unstable
 */
void
secret_service_read_alias_dbus_path (SecretService *self,
                                     const gchar *alias,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (alias != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	g_dbus_proxy_call (G_DBUS_PROXY (self), "ReadAlias",
	                   g_variant_new ("(s)", alias),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   cancellable, callback, user_data);
}

/**
 * secret_service_read_alias_dbus_path_finish: (skip)
 * @self: a secret service object
 * @result: asynchronous result passed to callback
 * @error: location to place error on failure
 *
 * Finish an asynchronous operation to lookup which collection is assigned
 * to an alias.
 *
 * This method returns the DBus object path of the collection
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (nullable): the collection dbus object path,
 *   or %NULL if none assigned to the alias
 */
gchar *
secret_service_read_alias_dbus_path_finish (SecretService *self,
                                            GAsyncResult *result,
                                            GError **error)
{
	gchar *collection_path;
	GVariant *retval;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (self), result, error);

	_secret_util_strip_remote_error (error);
	if (retval == NULL)
		return NULL;

	g_variant_get (retval, "(o)", &collection_path);
	g_variant_unref (retval);

	if (g_str_equal (collection_path, "/")) {
		g_free (collection_path);
		collection_path = NULL;
	}

	return collection_path;
}

/**
 * secret_service_read_alias_dbus_path_sync: (skip)
 * @self: a secret service object
 * @alias: the alias to lookup
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place error on failure
 *
 * Lookup which collection is assigned to this alias.
 *
 * Aliases help determine well known collections, such as 'default'. This method
 * returns the dbus object path of the collection.
 *
 * This method may block and should not be used in user interface threads.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (nullable): the collection dbus object path,
 *          or %NULL if none assigned to the alias
 */
gchar *
secret_service_read_alias_dbus_path_sync (SecretService *self,
                                          const gchar *alias,
                                          GCancellable *cancellable,
                                          GError **error)
{
	SecretSync *sync;
	gchar *collection_path;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (alias != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_read_alias_dbus_path (self, alias, cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	collection_path = secret_service_read_alias_dbus_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return collection_path;
}

/**
 * secret_service_set_alias_to_dbus_path: (skip)
 * @self: a secret service object
 * @alias: the alias to assign the collection to
 * @collection_path: (nullable): the dbus object path of the collection to assign to the alias
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Assign a collection to this alias. Aliases help determine
 * well known collections, such as 'default'. This method takes the dbus object
 * path of the collection to assign to the alias.
 *
 * This method will return immediately and complete asynchronously.
 *
 * Stability: Unstable
 */
void
secret_service_set_alias_to_dbus_path (SecretService *self,
                                       const gchar *alias,
                                       const gchar *collection_path,
                                       GCancellable *cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (alias != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	if (collection_path == NULL)
		collection_path = "/";
	else
		g_return_if_fail (g_variant_is_object_path (collection_path));

	g_dbus_proxy_call (G_DBUS_PROXY (self), "SetAlias",
	                   g_variant_new ("(so)", alias, collection_path),
	                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable,
	                   callback, user_data);
}

/**
 * secret_service_set_alias_to_dbus_path_finish: (skip)
 * @self: a secret service object
 * @result: asynchronous result passed to callback
 * @error: location to place error on failure
 *
 * Finish an asynchronous operation to assign a collection to an alias.
 *
 * Stability: Unstable
 *
 * Returns: %TRUE if successful
 */
gboolean
secret_service_set_alias_to_dbus_path_finish (SecretService *self,
                                              GAsyncResult *result,
                                              GError **error)
{
	GVariant *retval;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (self), result, error);

	_secret_util_strip_remote_error (error);
	if (retval == NULL)
		return FALSE;

	g_variant_unref (retval);
	return TRUE;
}

/**
 * secret_service_set_alias_to_dbus_path_sync: (skip)
 * @self: a secret service object
 * @alias: the alias to assign the collection to
 * @collection_path: (nullable): the D-Bus object path of the collection to
 *   assign to the alias
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place error on failure
 *
 * Assign a collection to this alias.
 *
 * Aliases help determine well known collections, such as 'default'. This method
 * takes the dbus object path of the collection to assign to the alias.
 *
 * This method may block and should not be used in user interface threads.
 *
 * Stability: Unstable
 *
 * Returns: %TRUE if successful
 */
gboolean
secret_service_set_alias_to_dbus_path_sync (SecretService *self,
                                            const gchar *alias,
                                            const gchar *collection_path,
                                            GCancellable *cancellable,
                                            GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (alias != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (collection_path == NULL)
		collection_path = "/";
	else
		g_return_val_if_fail (g_variant_is_object_path (collection_path), FALSE);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_set_alias_to_dbus_path (self, alias, collection_path,
	                                       cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_service_set_alias_to_dbus_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

/**
 * secret_service_prompt_at_dbus_path_sync: (skip)
 * @self: the secret service
 * @prompt_path: the D-Bus object path of the prompt
 * @cancellable: (nullable): optional cancellation object
 * @return_type: (nullable): the variant type of the prompt result
 * @error: location to place error on failure
 *
 * Perform prompting for a [class@Prompt].
 *
 * Override the #SecretServiceClass [vfunc@Service.prompt_async] virtual method
 * to change the behavior of the propmting. The default behavior is to simply
 * run [method@Prompt.perform] on the prompt.
 *
 * Returns a variant result if the prompt was completed and not dismissed. The
 * type of result depends on the action the prompt is completing, and is defined
 * in the Secret Service DBus API specification.
 *
 * This method may block and should not be used in user interface threads.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (nullable): %NULL if the prompt was dismissed or an
 *   error occurred, a variant result if the prompt was successful
 */
GVariant *
secret_service_prompt_at_dbus_path_sync (SecretService *self,
                                         const gchar *prompt_path,
                                         GCancellable *cancellable,
                                         const GVariantType *return_type,
                                         GError **error)
{
	SecretPrompt *prompt;
	GVariant *retval;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (prompt_path != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	prompt = _secret_prompt_instance (self, prompt_path);
	retval = secret_service_prompt_sync (self, prompt, cancellable, return_type, error);
	g_object_unref (prompt);

	return retval;
}

/**
 * secret_service_prompt_at_dbus_path: (skip)
 * @self: the secret service
 * @prompt_path: the D-Bus object path of the prompt
 * @return_type: (nullable): the variant type of the prompt result
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Perform prompting for a [class@Prompt].
 *
 * This function is called by other parts of this library to handle prompts
 * for the various actions that can require prompting.
 *
 * Override the #SecretServiceClass [vfunc@Service.prompt_async] virtual method
 * to change the behavior of the propmting. The default behavior is to simply
 * run [method@Prompt.perform] on the prompt.
 *
 * Stability: Unstable
 */
void
secret_service_prompt_at_dbus_path (SecretService *self,
                                    const gchar *prompt_path,
                                    const GVariantType *return_type,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	SecretPrompt *prompt;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (prompt_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	prompt = _secret_prompt_instance (self, prompt_path);
	secret_service_prompt (self, prompt, return_type, cancellable, callback, user_data);
	g_object_unref (prompt);
}

/**
 * secret_service_prompt_at_dbus_path_finish: (skip)
 * @self: the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to perform prompting for a [class@Prompt].
 *
 * Returns a variant result if the prompt was completed and not dismissed. The
 * type of result depends on the action the prompt is completing, and is defined
 * in the Secret Service DBus API specification.
 *
 * Stability: Unstable
 *
 * Returns: (transfer full) (nullable): %NULL if the prompt was dismissed or an
 *   error occurred, a variant result if the prompt was successful
 */
GVariant *
secret_service_prompt_at_dbus_path_finish (SecretService *self,
                                           GAsyncResult *result,
                                           GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	return secret_service_prompt_finish (self, result, error);
}

/**
 * secret_service_encode_dbus_secret:
 * @service: the service
 * @value: the secret value
 *
 * Encodes a [struct@Value] into [struct@GLib.Variant] for use with the Secret
 * Service DBus API.
 *
 * The resulting [struct@GLib.Variant] will have a `(oayays)` signature.
 *
 * A session must have already been established by the [class@Service].
 *
 * Returns: (transfer floating): the encoded secret
 */
GVariant *
secret_service_encode_dbus_secret (SecretService *service,
                                   SecretValue *value)
{
	SecretSession *session;

	g_return_val_if_fail (service != NULL, NULL);
	g_return_val_if_fail (value != NULL, NULL);

	session = _secret_service_get_session (service);
	g_return_val_if_fail (session != NULL, NULL);

	return _secret_session_encode_secret (session, value);
}

/**
 * secret_service_decode_dbus_secret:
 * @service: the service
 * @value: the encoded secret
 *
 * Decode a [struct@Value] into [struct@GLib.Variant] received with the Secret Service
 * DBus API.
 *
 * The [struct@GLib.Variant] should have a `(oayays)` signature.
 *
 * A session must have already been established by the [class@Service], and
 * the encoded secret must be valid for that session.
 *
 * Returns: (transfer full): the decoded secret value
 */
SecretValue *
secret_service_decode_dbus_secret (SecretService *service,
                                   GVariant *value)
{
	SecretSession *session;

	g_return_val_if_fail (service != NULL, NULL);
	g_return_val_if_fail (value != NULL, NULL);

	session = _secret_service_get_session (service);
	g_return_val_if_fail (session != NULL, NULL);

	return _secret_session_decode_secret (session, value);
}
