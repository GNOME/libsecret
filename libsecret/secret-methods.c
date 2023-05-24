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

#include "secret-collection.h"
#include "secret-dbus-generated.h"
#include "secret-item.h"
#include "secret-paths.h"
#include "secret-private.h"
#include "secret-service.h"
#include "secret-types.h"
#include "secret-value.h"

#include <glib/gi18n-lib.h>

/**
 * SecretSearchFlags:
 * @SECRET_SEARCH_NONE: no flags
 * @SECRET_SEARCH_ALL: all the items matching the search will be returned, instead of just the first one
 * @SECRET_SEARCH_UNLOCK: unlock locked items while searching
 * @SECRET_SEARCH_LOAD_SECRETS: while searching load secrets for items that are not locked
 *
 * Various flags to be used with [method@Service.search] and [method@Service.search_sync].
 */

typedef struct {
	SecretService *service;
	GHashTable *items;
	gchar **unlocked;
	gchar **locked;
	guint loading;
	SecretSearchFlags flags;
	GVariant *attributes;
} SearchClosure;

static void
search_closure_free (gpointer data)
{
	SearchClosure *closure = data;
	g_clear_object (&closure->service);
	g_hash_table_unref (closure->items);
	g_variant_unref (closure->attributes);
	g_strfreev (closure->unlocked);
	g_strfreev (closure->locked);
	g_free (closure);
}

static void
search_closure_take_item (SearchClosure *closure,
                          SecretItem *item)
{
	const gchar *path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (item));
	g_hash_table_insert (closure->items, (gpointer)path, item);
}

static GList *
search_closure_build_items (SearchClosure *closure,
                            gchar **paths)
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

static void
on_search_secrets (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (user_data);

	/* Note that we ignore any unlock failure */
	secret_item_load_secrets_finish (result, NULL);
	g_task_return_boolean (task, TRUE);

	g_clear_object (&task);
}

static void
secret_search_load_or_complete (GTask *task,
                                SearchClosure *search)
{
	GCancellable *cancellable = g_task_get_cancellable (task);
	GList *items;

	/* If loading secrets ... locked items automatically ignored */
	if (search->flags & SECRET_SEARCH_LOAD_SECRETS) {
		items = g_hash_table_get_values (search->items);
		secret_item_load_secrets (items, cancellable,
		                          on_search_secrets, g_object_ref (task));
		g_list_free (items);

	/* No additional options, just complete */
	} else {
		g_task_return_boolean (task, TRUE);
	}
}

static void
on_search_loaded (GObject *source,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SearchClosure *closure = g_task_get_task_data (task);
	GError *error = NULL;
	SecretItem *item;

	closure->loading--;

	item = secret_item_new_for_dbus_path_finish (result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
		g_clear_object (&task);
		return;
	}

	if (item != NULL)
		search_closure_take_item (closure, item);

	/* We're done loading, lets go to the next step */
	if (closure->loading == 0)
		secret_search_load_or_complete (task, closure);

	g_clear_object (&task);
}

static void
search_load_item_async (SecretService *self,
                        GTask *task,
                        SearchClosure *closure,
                        const gchar *path)
{
	GCancellable *cancellable = g_task_get_cancellable (task);
	SecretItem *item;

	item = _secret_service_find_item_instance (self, path);
	if (item == NULL) {
		secret_item_new_for_dbus_path (self, path, SECRET_ITEM_NONE, cancellable,
		                               on_search_loaded, g_object_ref (task));
		closure->loading++;
	} else {
		search_closure_take_item (closure, item);
	}
}

static void
load_items (SearchClosure *closure,
            GTask *task)
{
	SecretService *self = closure->service;
	gint want = 1;
	gint count = 0;
	gint i;

	if (closure->flags & SECRET_SEARCH_ALL)
		want = G_MAXINT;

	for (i = 0; count < want && closure->unlocked[i] != NULL; i++, count++)
		search_load_item_async (self, task, closure, closure->unlocked[i]);
	for (i = 0; count < want && closure->locked[i] != NULL; i++, count++)
		search_load_item_async (self, task, closure, closure->locked[i]);

	/* No items loading, complete operation now */
	if (closure->loading == 0)
		secret_search_load_or_complete (task, closure);
}

static void
on_unlock_paths (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SearchClosure *closure = g_task_get_task_data (task);
	SecretService *self = closure->service;

	/* Note that we ignore any unlock failure */
	secret_service_unlock_dbus_paths_finish (self, result, NULL, NULL);

	load_items (closure, task);
	g_clear_object (&task);
}

static void
on_search_paths (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SearchClosure *closure = g_task_get_task_data (task);
	SecretService *self = closure->service;
	GError *error = NULL;

	secret_service_search_for_dbus_paths_finish (self, result, &closure->unlocked,
	                                             &closure->locked, &error);
	if (error == NULL) {
		/* If unlocking then unlock all the locked items */
		if (closure->flags & SECRET_SEARCH_UNLOCK) {
			GCancellable *cancellable = g_task_get_cancellable (task);
			const gchar **const_locked = (const gchar**) closure->locked;

			secret_service_unlock_dbus_paths (self, const_locked, cancellable,
			                                  on_unlock_paths,
			                                  g_steal_pointer (&task));
		} else {
			load_items (closure, task);
		}
	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

static void
on_search_service (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SearchClosure *search = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;

	search->service = secret_service_get_finish (result, &error);
	if (error == NULL) {
		_secret_service_search_for_paths_variant (search->service, search->attributes,
		                                          cancellable, on_search_paths,
		                                          g_steal_pointer (&task));

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

/**
 * secret_service_search:
 * @service: (nullable): the secret service
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @flags: search option flags
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Search for items matching the @attributes.
 *
 * All collections are searched. The @attributes should be a table of string
 * keys and string values.
 *
 * If @service is %NULL, then [func@Service.get] will be called to get
 * the default [class@Service] proxy.
 *
 * If %SECRET_SEARCH_ALL is set in @flags, then all the items matching the
 * search will be returned. Otherwise only the first item will be returned.
 * This is almost always the unlocked item that was most recently stored.
 *
 * If %SECRET_SEARCH_UNLOCK is set in @flags, then items will be unlocked
 * if necessary. In either case, locked and unlocked items will match the
 * search and be returned. If the unlock fails, the search does not fail.
 *
 * If %SECRET_SEARCH_LOAD_SECRETS is set in @flags, then the items will have
 * their secret values loaded and available via [method@Item.get_secret].
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_service_search (SecretService *service,
                       const SecretSchema *schema,
                       GHashTable *attributes,
                       SecretSearchFlags flags,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	GTask *task;
	SearchClosure *closure;
	const gchar *schema_name = NULL;

	g_return_if_fail (service == NULL || SECRET_IS_SERVICE (service));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	if (schema != NULL && !(schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME))
		schema_name = schema->name;

	task = g_task_new (service, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_search);
	closure = g_new0 (SearchClosure, 1);
	closure->items = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
	closure->flags = flags;
	closure->attributes = _secret_attributes_to_variant (attributes, schema_name);
	g_variant_ref_sink (closure->attributes);
	g_task_set_task_data (task, closure, search_closure_free);

	if (service) {
		closure->service = g_object_ref (service);
		_secret_service_search_for_paths_variant (closure->service, closure->attributes,
		                                          cancellable, on_search_paths,
		                                          g_steal_pointer (&task));

	} else {
		secret_service_get (SECRET_SERVICE_NONE, cancellable,
		                    on_search_service, g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

/**
 * secret_service_search_finish:
 * @service: (nullable): the secret service
 * @result: asynchronous result passed to callback
 * @error: location to place error on failure
 *
 * Complete asynchronous operation to search for items.
 *
 * Returns: (transfer full) (element-type Secret.Item):
 *   a list of items that matched the search
 */
GList *
secret_service_search_finish (SecretService *service,
                              GAsyncResult *result,
                              GError **error)
{
	SearchClosure *closure;
	GList *items = NULL;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_task_is_valid (result, service), NULL);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	closure = g_task_get_task_data (G_TASK (result));
	if (closure->unlocked)
		items = search_closure_build_items (closure, closure->unlocked);
	if (closure->locked)
		items = g_list_concat (items, search_closure_build_items (closure, closure->locked));
	return items;
}

static gboolean
service_load_items_sync (SecretService *service,
                         GCancellable *cancellable,
                         gchar **paths,
                         GList **items,
                         gint want,
                         gint *have,
                         GError **error)
{
	SecretItem *item;
	guint i;

	for (i = 0; *have < want && paths[i] != NULL; i++) {
		item = _secret_service_find_item_instance (service, paths[i]);
		if (item == NULL)
			item = secret_item_new_for_dbus_path_sync (service, paths[i], SECRET_ITEM_NONE,
			                                           cancellable, error);
		if (item == NULL) {
			return FALSE;

		} else {
			*items = g_list_prepend (*items, item);
			(*have)++;
		}
	}

	return TRUE;
}

/**
 * secret_service_search_sync:
 * @service: (nullable): the secret service
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): search for items matching these attributes
 * @flags: search option flags
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place error on failure
 *
 * Search for items matching the @attributes.
 *
 * All collections are searched. The @attributes should be a table of string
 * keys and string values.
 *
 * If @service is %NULL, then [func@Service.get_sync] will be called to get
 * the default [class@Service] proxy.
 *
 * If %SECRET_SEARCH_ALL is set in @flags, then all the items matching the
 * search will be returned. Otherwise only the first item will be returned.
 * This is almost always the unlocked item that was most recently stored.
 *
 * If %SECRET_SEARCH_UNLOCK is set in @flags, then items will be unlocked
 * if necessary. In either case, locked and unlocked items will match the
 * search and be returned. If the unlock fails, the search does not fail.
 *
 * If %SECRET_SEARCH_LOAD_SECRETS is set in @flags, then the items' secret
 * values will be loaded for any unlocked items. Loaded item secret values
 * are available via [method@Item.get_secret]. If the load of a secret values
 * fail, then the
 *
 * This function may block indefinitely. Use the asynchronous version
 * in user interface threads.
 *
 * Returns: (transfer full) (element-type Secret.Item):
 *   a list of items that matched the search
 */
GList *
secret_service_search_sync (SecretService *service,
                            const SecretSchema *schema,
                            GHashTable *attributes,
                            SecretSearchFlags flags,
                            GCancellable *cancellable,
                            GError **error)
{
	gchar **unlocked_paths = NULL;
	gchar **locked_paths = NULL;
	GList *items = NULL;
	GList *locked = NULL;
	GList *unlocked = NULL;
	gboolean ret;
	gint want;
	gint have;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return NULL;

	if (service == NULL) {
		service = secret_service_get_sync (SECRET_SERVICE_NONE, cancellable, error);
		if (service == NULL)
			return NULL;
	} else {
		g_object_ref (service);
	}

	if (!secret_service_search_for_dbus_paths_sync (service, schema, attributes, cancellable,
	                                                &unlocked_paths, &locked_paths, error)) {
		g_object_unref (service);
		return NULL;
	}

	if (flags & SECRET_SEARCH_UNLOCK)
		secret_service_unlock_dbus_paths_sync (service, (const gchar**) locked_paths,
						       cancellable, NULL, NULL);

	ret = TRUE;

	want = 1;
	if (flags & SECRET_SEARCH_ALL)
		want = G_MAXINT;
	have = 0;

	/* Remember, we're adding to the list backwards */

	if (unlocked_paths) {
		ret = service_load_items_sync (service, cancellable, unlocked_paths,
		                               &unlocked, want, &have, error);
	}

	if (ret && locked_paths) {
		ret = service_load_items_sync (service, cancellable, locked_paths,
		                               &locked, want, &have, error);
	}

	g_strfreev (unlocked_paths);
	g_strfreev (locked_paths);

	if (!ret) {
		g_list_free_full (unlocked, g_object_unref);
		g_list_free_full (locked, g_object_unref);
		g_object_unref (service);
		return NULL;
	}

	/* The lists are backwards at this point ... */
	items = g_list_concat (items, g_list_copy (locked));
	items = g_list_concat (items, g_list_copy (unlocked));
	items = g_list_reverse (items);

	if (flags & SECRET_SEARCH_LOAD_SECRETS)
		secret_item_load_secrets_sync (items, NULL, NULL);

	g_list_free (locked);
	g_list_free (unlocked);
	g_object_unref (service);
	return items;
}

SecretValue *
_secret_service_decode_get_secrets_first (SecretService *self,
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

GHashTable *
_secret_service_decode_get_secrets_all (SecretService *self,
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

typedef struct {
	GPtrArray *paths;
	GHashTable *objects;
	gchar **xlocked;
	gboolean locking;
} XlockClosure;

static void
xlock_closure_free (gpointer data)
{
	XlockClosure *closure = data;
	g_ptr_array_free (closure->paths, TRUE);
	g_strfreev (closure->xlocked);
	g_hash_table_unref (closure->objects);
	g_free (closure);
}

static void
on_xlock_paths (GObject *source,
                GAsyncResult *result,
                gpointer user_data)
{
	SecretService *service = SECRET_SERVICE (source);
	GTask *task = G_TASK (user_data);
	XlockClosure *xlock = g_task_get_task_data (task);
	GVariant *lockval;
	GDBusProxy *object;
	GError *error = NULL;
	gint count;
	gint i;

	count = _secret_service_xlock_paths_finish (service, result,
	                                            &xlock->xlocked, &error);

	if (error == NULL) {
		/*
		 * After a lock or unlock we want the Locked property to immediately
		 * reflect the new state, and not have to wait for a PropertiesChanged
		 * signal to be processed later.
		 */

		lockval = g_variant_ref_sink (g_variant_new_boolean (xlock->locking));
		for (i = 0; xlock->xlocked[i] != NULL; i++) {
			object =  g_hash_table_lookup (xlock->objects, xlock->xlocked[i]);
			if (object != NULL)
				g_dbus_proxy_set_cached_property (object, "Locked", lockval);
		}
		g_variant_unref (lockval);
		g_task_return_int (task, count);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

static void
on_xlock_service (GObject *source,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	XlockClosure *xlock = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;
	SecretService *service;

	service = secret_service_get_finish (result, &error);
	if (error == NULL) {
		_secret_service_xlock_paths_async (service, xlock->locking ? "Lock" : "Unlock",
		                                   (const gchar **)xlock->paths->pdata,
		                                   cancellable, on_xlock_paths,
		                                   g_steal_pointer (&task));
		g_object_unref (service);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

static void
service_xlock_async (SecretService *service,
                     gboolean locking,
                     GList *objects,
                     GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	GTask *task;
	XlockClosure *xlock;
	const gchar *path;
	GList *l;

	task = g_task_new (service, cancellable, callback, user_data);
	g_task_set_source_tag (task, service_xlock_async);
	xlock = g_new0 (XlockClosure, 1);
	xlock->objects = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
	xlock->locking = locking;
	xlock->paths = g_ptr_array_new ();

	for (l = objects; l != NULL; l = g_list_next (l)) {
		path = g_dbus_proxy_get_object_path (l->data);
		g_ptr_array_add (xlock->paths, (gpointer)path);
		g_hash_table_insert (xlock->objects, g_strdup (path), g_object_ref (l->data));
	}
	g_ptr_array_add (xlock->paths, NULL);

	g_task_set_task_data (task, xlock, xlock_closure_free);

	if (service == NULL) {
		secret_service_get (SECRET_SERVICE_NONE, cancellable,
		                    on_xlock_service, g_steal_pointer (&task));
	} else {
		_secret_service_xlock_paths_async (service, xlock->locking ? "Lock" : "Unlock",
		                                   (const gchar **)xlock->paths->pdata,
		                                   cancellable, on_xlock_paths,
		                                   g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

static gint
service_xlock_finish (SecretService *service,
                      GAsyncResult *result,
                      GList **xlocked,
                      GError **error)
{
	XlockClosure *xlock;
	GDBusProxy *object;
	gint count;
	gint i;

	g_return_val_if_fail (g_task_is_valid (result, service), -1);

	count = g_task_propagate_int (G_TASK (result), error);
	if (count == -1) {
		_secret_util_strip_remote_error (error);
		return -1;
	}

	xlock = g_task_get_task_data (G_TASK (result));
	if (xlocked) {
		*xlocked = NULL;
		for (i = 0; xlock->xlocked[i] != NULL; i++) {
			object = g_hash_table_lookup (xlock->objects, xlock->xlocked[i]);
			if (object != NULL)
				*xlocked = g_list_prepend (*xlocked, g_object_ref (object));
		}
	}

	return count;
}

/**
 * secret_service_lock:
 * @service: (nullable): the secret service
 * @objects: (element-type Gio.DBusProxy): the items or collections to lock
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Lock items or collections in the secret service.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * If @service is %NULL, then [func@Service.get] will be called to get
 * the default [class@Service] proxy.
 *
 * This method returns immediately and completes asynchronously. The secret
 * service may prompt the user. [method@Service.prompt] will be used to handle
 * any prompts that show up.
 */
void
secret_service_lock (SecretService *service,
                     GList *objects,
                     GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	g_return_if_fail (service == NULL || SECRET_IS_SERVICE (service));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	service_xlock_async (service, TRUE, objects, cancellable, callback, user_data);
}

/**
 * secret_service_lock_finish:
 * @service: (nullable): the secret service
 * @result: asynchronous result passed to the callback
 * @locked: (out) (element-type Gio.DBusProxy) (transfer full) (nullable) (optional):
 *   location to place list of items or collections that were locked
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
secret_service_lock_finish (SecretService *service,
                            GAsyncResult *result,
                            GList **locked,
                            GError **error)
{
	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	return service_xlock_finish (service, result, locked, error);
}

/**
 * secret_service_lock_sync:
 * @service: (nullable): the secret service
 * @objects: (element-type Gio.DBusProxy): the items or collections to lock
 * @cancellable: (nullable): optional cancellation object
 * @locked: (out) (element-type Gio.DBusProxy) (transfer full) (nullable) (optional):
 *   location to place list of items or collections that were locked
 * @error: location to place an error on failure
 *
 * Lock items or collections in the secret service.
 *
 * The secret service may not be able to lock items individually, and may
 * lock an entire collection instead.
 *
 * If @service is %NULL, then [func@Service.get_sync] will be called to get
 * the default [class@Service] proxy.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * [method@Service.prompt] will be used to handle any prompts that show up.
 *
 * Returns: the number of items or collections that were locked
 */
gint
secret_service_lock_sync (SecretService *service,
                          GList *objects,
                          GCancellable *cancellable,
                          GList **locked,
                          GError **error)
{
	SecretSync *sync;
	gint count;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_lock (service, objects, cancellable,
	                     _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = secret_service_lock_finish (service, sync->result, locked, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return count;
}

/**
 * secret_service_unlock:
 * @service: (nullable): the secret service
 * @objects: (element-type Gio.DBusProxy): the items or collections to unlock
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Unlock items or collections in the secret service.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * If @service is %NULL, then [func@Service.get] will be called to get
 * the default [class@Service] proxy.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * [method@Service.prompt] will be used to handle any prompts that show up.
 */
void
secret_service_unlock (SecretService *service,
                       GList *objects,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	g_return_if_fail (service == NULL || SECRET_IS_SERVICE (service));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	service_xlock_async (service, FALSE, objects, cancellable, callback, user_data);
}

/**
 * secret_service_unlock_finish:
 * @service: (nullable): the secret service
 * @result: asynchronous result passed to the callback
 * @unlocked: (out) (element-type Gio.DBusProxy) (transfer full) (nullable) (optional):
 *   location to place list of items or collections that were unlocked
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
secret_service_unlock_finish (SecretService *service,
                              GAsyncResult *result,
                              GList **unlocked,
                              GError **error)
{
	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	return service_xlock_finish (service, result, unlocked, error);
}

/**
 * secret_service_unlock_sync:
 * @service: (nullable): the secret service
 * @objects: (element-type Gio.DBusProxy): the items or collections to unlock
 * @cancellable: (nullable): optional cancellation object
 * @unlocked: (out) (element-type Gio.DBusProxy) (transfer full) (nullable) (optional):
 *   location to place list of items or collections that were unlocked
 * @error: location to place an error on failure
 *
 * Unlock items or collections in the secret service.
 *
 * The secret service may not be able to unlock items individually, and may
 * unlock an entire collection instead.
 *
 * If @service is %NULL, then [func@Service.get_sync] will be called to get
 * the default [class@Service] proxy.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * [method@Service.prompt] will be used to handle any prompts that show up.
 *
 * Returns: the number of items or collections that were unlocked
 */
gint
secret_service_unlock_sync (SecretService *service,
                            GList *objects,
                            GCancellable *cancellable,
                            GList **unlocked,
                            GError **error)
{
	SecretSync *sync;
	gint count;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_unlock (service, objects, cancellable,
	                       _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = secret_service_unlock_finish (service, sync->result, unlocked, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return count;
}

typedef struct {
	gchar *collection_path;
	SecretValue *value;
	GHashTable *properties;
	gboolean created_collection;
	gboolean unlocked_collection;
} StoreClosure;

static void
store_closure_free (gpointer data)
{
	StoreClosure *store = data;
	g_free (store->collection_path);
	secret_value_unref (store->value);
	g_hash_table_unref (store->properties);
	g_free (store);
}

static void
on_store_create (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data);

static void
on_store_keyring (GObject *source,
                  GAsyncResult *result,
                  gpointer user_data)
{
	SecretService *service = SECRET_SERVICE (source);
	GTask *task = G_TASK (user_data);
	StoreClosure *store = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;
	gchar *path;

	path = secret_service_create_collection_dbus_path_finish (service, result, &error);
	if (error == NULL) {
		store->created_collection = TRUE;
		secret_service_create_item_dbus_path (service, store->collection_path,
		                                      store->properties, store->value,
		                                      SECRET_ITEM_CREATE_REPLACE,
		                                      cancellable,
		                                      on_store_create,
		                                      g_steal_pointer (&task));
	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_free (path);
	g_clear_object (&task);
}

static void
on_store_unlock (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	SecretService *service = SECRET_SERVICE (source);
	GTask *task = G_TASK (user_data);
	StoreClosure *store = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;

	secret_service_unlock_dbus_paths_finish (service, result, NULL, &error);
	if (error == NULL) {
		store->unlocked_collection = TRUE;
		secret_service_create_item_dbus_path (service, store->collection_path,
		                                      store->properties, store->value,
		                                      SECRET_ITEM_CREATE_REPLACE,
		                                      cancellable,
		                                      on_store_create,
		                                      g_steal_pointer (&task));
	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

static void
on_store_create (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	SecretService *service = SECRET_SERVICE (source);
	GTask *task = G_TASK (user_data);
	StoreClosure *store = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;
	GHashTable *properties;

	_secret_service_create_item_dbus_path_finish_raw (result, &error);

	/*
	 * This happens when the collection doesn't exist. If the collection is
	 * the default alias, we should try and create it
	 */

	if (!store->created_collection &&
	    (g_error_matches (error, SECRET_ERROR, SECRET_ERROR_NO_SUCH_OBJECT) ||
	     g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD) ||
	     g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_OBJECT)) &&
	    g_strcmp0 (store->collection_path, SECRET_ALIAS_PREFIX "default") == 0) {
		properties = _secret_collection_properties_new (_("Default keyring"));
		secret_service_create_collection_dbus_path (service, properties, "default",
		                                            SECRET_COLLECTION_CREATE_NONE,
		                                            cancellable,
		                                            on_store_keyring,
		                                            g_steal_pointer (&task));
		g_hash_table_unref (properties);
		g_error_free (error);
		g_clear_object (&task);
		return;
	}

	if (!store->unlocked_collection &&
	           g_error_matches (error, SECRET_ERROR, SECRET_ERROR_IS_LOCKED)) {
		const gchar *paths[2] = { store->collection_path, NULL };
		secret_service_unlock_dbus_paths (service, paths, cancellable,
		                                  on_store_unlock, g_steal_pointer (&task));
		g_error_free (error);
		g_clear_object (&task);
		return;
	}

	if (error != NULL)
		g_task_return_error (task, g_steal_pointer (&error));
	else
		g_task_return_boolean (task, TRUE);

	g_clear_object (&task);
}

static void
on_store_service (GObject *source,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	StoreClosure *store = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	SecretService *service;
	GError *error = NULL;

	service = secret_service_get_finish (result, &error);
	if (error == NULL) {
		secret_service_create_item_dbus_path (service, store->collection_path,
		                                      store->properties, store->value,
		                                      SECRET_ITEM_CREATE_REPLACE,
		                                      cancellable,
		                                      on_store_create,
		                                      g_steal_pointer (&task));
		g_object_unref (service);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

/**
 * secret_service_store:
 * @service: (nullable): the secret service
 * @schema: (nullable): the schema to use to check attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *   collection where to store the secret
 * @label: label for the secret
 * @value: the secret value
 * @cancellable: (nullable): optional cancellation object
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
 * If @service is %NULL, then [func@Service.get] will be called to get
 * the default [class@Service] proxy.
 *
 * If @collection is not specified, then the default collection will be
 * used. Use [const@COLLECTION_SESSION] to store the password in the session
 * collection, which doesn't get stored across login sessions.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_store (SecretService *service,
                      const SecretSchema *schema,
                      GHashTable *attributes,
                      const gchar *collection,
                      const gchar *label,
                      SecretValue *value,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
	GTask *task;
	StoreClosure *store;
	const gchar *schema_name;
	GVariant *propval;

	g_return_if_fail (service == NULL || SECRET_IS_SERVICE (service));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return;

	task = g_task_new (service, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_store);
	store = g_new0 (StoreClosure, 1);
	store->collection_path = _secret_util_collection_to_path (collection);
	store->value = secret_value_ref (value);
	store->properties = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
	                                           (GDestroyNotify)g_variant_unref);

	propval = g_variant_new_string (label);
	g_hash_table_insert (store->properties,
	                     SECRET_ITEM_INTERFACE ".Label",
	                     g_variant_ref_sink (propval));

	/* Always store the schema name in the attributes */
	schema_name = (schema == NULL) ? NULL : schema->name;
	propval = _secret_attributes_to_variant (attributes, schema_name);
	g_hash_table_insert (store->properties,
	                     SECRET_ITEM_INTERFACE ".Attributes",
	                     g_variant_ref_sink (propval));

	g_task_set_task_data (task, store, store_closure_free);

	if (service == NULL) {
		secret_service_get (SECRET_SERVICE_OPEN_SESSION, cancellable,
		                    on_store_service, g_steal_pointer (&task));

	} else {
		secret_service_create_item_dbus_path (service, store->collection_path,
		                                      store->properties, store->value,
		                                      SECRET_ITEM_CREATE_REPLACE,
		                                      cancellable,
		                                      on_store_create,
		                                      g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

/**
 * secret_service_store_finish:
 * @service: (nullable): the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to store a secret value in the secret service.
 *
 * Returns: whether the storage was successful or not
 */
gboolean
secret_service_store_finish (SecretService *service,
                             GAsyncResult *result,
                             GError **error)
{
	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), FALSE);
	g_return_val_if_fail (g_task_is_valid (result, service), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

/**
 * secret_service_store_sync:
 * @service: (nullable): the secret service
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @collection: (nullable): a collection alias, or D-Bus object path of the
 *   collection where to store the secret
 * @label: label for the secret
 * @value: the secret value
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Store a secret value in the secret service.
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
 * If @service is %NULL, then [func@Service.get_sync] will be called to get
 * the default [class@Service] proxy.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the storage was successful or not
 */
gboolean
secret_service_store_sync (SecretService *service,
                           const SecretSchema *schema,
                           GHashTable *attributes,
                           const gchar *collection,
                           const gchar *label,
                           SecretValue *value,
                           GCancellable *cancellable,
                           GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_store (service, schema, attributes, collection,
	                      label, value, cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_service_store_finish (service, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

static void
on_lookup_get_secret (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretService *self = SECRET_SERVICE (source);
	SecretValue *value;
	GError *error = NULL;

	value = secret_service_get_secret_for_dbus_path_finish (self, result, &error);
	if (error != NULL)
		g_task_return_error (task, g_steal_pointer (&error));
	else
		g_task_return_pointer (task, value, secret_value_unref);

	g_clear_object (&task);
}

static void
on_lookup_unlocked (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	SecretService *self = SECRET_SERVICE (source);
	GTask *task = G_TASK (user_data);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;
	gchar **unlocked = NULL;

	secret_service_unlock_dbus_paths_finish (self, result, &unlocked, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));

	} else if (unlocked && unlocked[0]) {
		secret_service_get_secret_for_dbus_path (self, unlocked[0],
		                                         cancellable,
		                                         on_lookup_get_secret,
		                                         g_steal_pointer (&task));

	} else {
		g_task_return_pointer (task, NULL, NULL);
	}

	g_strfreev (unlocked);
	g_clear_object (&task);
}

static void
on_lookup_searched (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	SecretService *self = SECRET_SERVICE (source);
	GTask *task = G_TASK (user_data);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;
	gchar **unlocked = NULL;
	gchar **locked = NULL;

	secret_service_search_for_dbus_paths_finish (self, result, &unlocked, &locked, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));

	} else if (unlocked && unlocked[0]) {
		secret_service_get_secret_for_dbus_path (self, unlocked[0],
		                                         cancellable,
		                                         on_lookup_get_secret,
		                                         g_steal_pointer (&task));

	} else if (locked && locked[0]) {
		const gchar *paths[] = { locked[0], NULL };
		secret_service_unlock_dbus_paths (self, paths,
		                                  cancellable,
		                                  on_lookup_unlocked,
		                                  g_steal_pointer (&task));

	} else {
		g_task_return_pointer (task, NULL, NULL);
	}

	g_strfreev (unlocked);
	g_strfreev (locked);
	g_clear_object (&task);
}

static void
on_lookup_service (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GVariant *attributes = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	SecretService *service;
	GError *error = NULL;

	service = secret_service_get_finish (result, &error);
	if (error == NULL) {
		_secret_service_search_for_paths_variant (service, attributes,
		                                          cancellable,
		                                          on_lookup_searched,
		                                          g_steal_pointer (&task));
		g_object_unref (service);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

/**
 * secret_service_lookup:
 * @service: (nullable): the secret service
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Lookup a secret value in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If @service is %NULL, then [func@Service.get] will be called to get
 * the default [class@Service] proxy.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_lookup (SecretService *service,
                       const SecretSchema *schema,
                       GHashTable *attributes,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	const gchar *schema_name = NULL;
	GTask *task;
	GVariant *attributes_v;

	g_return_if_fail (service == NULL || SECRET_IS_SERVICE (service));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	if (schema != NULL && !(schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME))
		schema_name = schema->name;

	task = g_task_new (service, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_lookup);

	attributes_v = _secret_attributes_to_variant (attributes, schema_name);
	g_variant_ref_sink (attributes_v);
	g_task_set_task_data (task, attributes_v, (GDestroyNotify) g_variant_unref);

	if (service == NULL) {
		secret_service_get (SECRET_SERVICE_OPEN_SESSION, cancellable,
		                    on_lookup_service, g_steal_pointer (&task));
	} else {
		_secret_service_search_for_paths_variant (service, attributes_v,
		                                          cancellable,
		                                          on_lookup_searched,
		                                          g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

/**
 * secret_service_lookup_finish:
 * @service: (nullable): the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to lookup a secret value in the secret service.
 *
 * If no secret is found then %NULL is returned.
 *
 * Returns: (transfer full): a newly allocated [struct@Value], which should be
 *   released with [method@Value.unref], or %NULL if no secret found
 */
SecretValue *
secret_service_lookup_finish (SecretService *service,
                              GAsyncResult *result,
                              GError **error)
{
	SecretValue *value;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_task_is_valid (result, service), NULL);

	value = g_task_propagate_pointer (G_TASK (result), error);
	if (!value) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	return value;
}

/**
 * secret_service_lookup_sync:
 * @service: (nullable): the secret service
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Lookup a secret value in the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If @service is %NULL, then [func@Service.get_sync] will be called to get
 * the default [class@Service] proxy.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a newly allocated [struct@Value], which should be
 *   released with [method@Value.unref], or %NULL if no secret found
 */
SecretValue *
secret_service_lookup_sync (SecretService *service,
                            const SecretSchema *schema,
                            GHashTable *attributes,
                            GCancellable *cancellable,
                            GError **error)
{
	SecretSync *sync;
	SecretValue *value;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (attributes != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return NULL;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_lookup (service, schema, attributes, cancellable,
	                       _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	value = secret_service_lookup_finish (service, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return value;
}

typedef struct {
	SecretService *service;
	GVariant *attributes;
	gint deleted;
	gint deleting;
} DeleteClosure;

static void
delete_closure_free (gpointer data)
{
	DeleteClosure *closure = data;
	if (closure->service)
		g_object_unref (closure->service);
	g_variant_unref (closure->attributes);
	g_free (closure);
}

static void
on_delete_password_complete (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	SecretService *service = SECRET_SERVICE (source);
	GTask *task = G_TASK (user_data);
	DeleteClosure *closure = g_task_get_task_data (task);
	GError *error = NULL;
	gboolean deleted;

	closure->deleting--;

	deleted = _secret_service_delete_path_finish (service, result, &error);
	if (error != NULL)
		g_task_return_error (task, g_steal_pointer (&error));
	if (deleted)
		closure->deleted++;

	if (closure->deleting <= 0)
		g_task_return_boolean (task, TRUE);

	g_clear_object (&task);
}

static void
on_delete_searched (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	SecretService *service = SECRET_SERVICE (source);
	GTask *task = G_TASK (user_data);
	DeleteClosure *closure = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;
	gchar **unlocked = NULL;
	gint i;

	secret_service_search_for_dbus_paths_finish (service, result, &unlocked, NULL, &error);
	if (error == NULL) {
		for (i = 0; unlocked[i] != NULL; i++) {
			_secret_service_delete_path (closure->service, unlocked[i], TRUE,
			                             cancellable,
			                             on_delete_password_complete,
			                             g_object_ref (task));
			closure->deleting++;
		}

		if (closure->deleting == 0)
			g_task_return_boolean (task, FALSE);
	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_strfreev (unlocked);
	g_clear_object (&task);
}

static void
on_delete_service (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	DeleteClosure *closure = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	GError *error = NULL;

	closure->service = secret_service_get_finish (result, &error);
	if (error == NULL) {
		_secret_service_search_for_paths_variant (closure->service, closure->attributes,
		                                          cancellable,
		                                          on_delete_searched, g_steal_pointer (&task));

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

/**
 * secret_service_clear:
 * @service: (nullable): the secret service
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Remove unlocked items which match the attributes from the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If @service is %NULL, then [func@Service.get] will be called to get
 * the default [class@Service] proxy.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_clear (SecretService *service,
                      const SecretSchema *schema,
                      GHashTable *attributes,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
	const gchar *schema_name = NULL;
	GTask *task;
	DeleteClosure *closure;

	g_return_if_fail (service == NULL || SECRET_SERVICE (service));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return;

	if (schema != NULL && !(schema->flags & SECRET_SCHEMA_DONT_MATCH_NAME))
		schema_name = schema->name;

	task = g_task_new (service, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_clear);
	closure = g_new0 (DeleteClosure, 1);
	closure->attributes = _secret_attributes_to_variant (attributes, schema_name);
	g_variant_ref_sink (closure->attributes);
	g_task_set_task_data (task, closure, delete_closure_free);

	/* A double check to make sure we don't delete everything, should have been checked earlier */
	g_assert (g_variant_n_children (closure->attributes) > 0);

	if (service == NULL) {
		secret_service_get (SECRET_SERVICE_NONE, cancellable,
		                    on_delete_service, g_steal_pointer (&task));
	} else {
		closure->service = g_object_ref (service);
		_secret_service_search_for_paths_variant (closure->service, closure->attributes,
		                                          cancellable,
		                                          on_delete_searched, g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

/**
 * secret_service_clear_finish:
 * @service: (nullable): the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish asynchronous operation to remove items from the secret
 * service.
 *
 * Returns: whether items were removed or not
 */
gboolean
secret_service_clear_finish (SecretService *service,
                             GAsyncResult *result,
                             GError **error)
{
	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_task_is_valid (result, service), FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

/**
 * secret_service_clear_sync:
 * @service: (nullable): the secret service
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): the attribute keys and values
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Remove unlocked items which match the attributes from the secret service.
 *
 * The @attributes should be a set of key and value string pairs.
 *
 * If @service is %NULL, then [func@Service.get_sync] will be called to get
 * the default [class@Service] proxy.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether items were removed or not
 */
gboolean
secret_service_clear_sync (SecretService *service,
                           const SecretSchema *schema,
                           GHashTable *attributes,
                           GCancellable *cancellable,
                           GError **error)
{
	SecretSync *sync;
	gboolean result;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, TRUE))
		return FALSE;

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_clear (service, schema, attributes, cancellable,
	                      _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = secret_service_clear_finish (service, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return result;
}

typedef struct {
	gchar *alias;
	gchar *collection_path;
} SetClosure;

static void
set_closure_free (gpointer data)
{
	SetClosure *set = data;
	g_free (set->alias);
	g_free (set->collection_path);
	g_free (set);
}

static void
on_set_alias_done (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretService *service = SECRET_SERVICE (source);
	GError *error = NULL;

	if (secret_service_set_alias_to_dbus_path_finish (service, result, &error)) {
		g_task_return_boolean (task, TRUE);
	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

static void
on_set_alias_service (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SetClosure *set = g_task_get_task_data (task);
	GCancellable *cancellable = g_task_get_cancellable (task);
	SecretService *service;
	GError *error = NULL;

	service = secret_service_get_finish (result, &error);
	if (error == NULL) {
		secret_service_set_alias_to_dbus_path (service, set->alias,
		                                       set->collection_path,
		                                       cancellable,
		                                       on_set_alias_done,
		                                       g_steal_pointer (&task));
		g_object_unref (service);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

/**
 * secret_service_set_alias:
 * @service: (nullable): a secret service object
 * @alias: the alias to assign the collection to
 * @collection: (nullable): the collection to assign to the alias
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Assign a collection to this alias.
 *
 * Aliases help determine well known collections, such as 'default'.
 *
 * If @service is %NULL, then [func@Service.get] will be called to get
 * the default [class@Service] proxy.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_set_alias (SecretService *service,
                          const gchar *alias,
                          SecretCollection *collection,
                          GCancellable *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
	GTask *task;
	SetClosure *set;
	const gchar *path;

	g_return_if_fail (service == NULL || SECRET_IS_SERVICE (service));
	g_return_if_fail (alias != NULL);
	g_return_if_fail (collection == NULL || SECRET_IS_COLLECTION (collection));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (service, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_set_alias);
	set = g_new0 (SetClosure, 1);
	set->alias = g_strdup (alias);

	if (collection) {
		path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (collection));
		g_return_if_fail (path != NULL);
	} else {
		path = NULL;
	}

	set->collection_path = g_strdup (path);
	g_task_set_task_data (task, set, set_closure_free);

	if (service == NULL) {
		secret_service_get (SECRET_SERVICE_NONE, cancellable,
		                    on_set_alias_service, g_steal_pointer (&task));
	} else {
		secret_service_set_alias_to_dbus_path (service, set->alias,
		                                       set->collection_path,
		                                       cancellable,
		                                       on_set_alias_done,
		                                       g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

/**
 * secret_service_set_alias_finish:
 * @service: (nullable): a secret service object
 * @result: asynchronous result passed to callback
 * @error: location to place error on failure
 *
 * Finish an asynchronous operation to assign a collection to an alias.
 *
 * Returns: %TRUE if successful
 */
gboolean
secret_service_set_alias_finish (SecretService *service,
                                 GAsyncResult *result,
                                 GError **error)
{
	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), FALSE);
	g_return_val_if_fail (g_task_is_valid (result, service), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

/**
 * secret_service_set_alias_sync:
 * @service: (nullable): a secret service object
 * @alias: the alias to assign the collection to
 * @collection: (nullable): the collection to assign to the alias
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place error on failure
 *
 * Assign a collection to this alias. Aliases help determine
 * well known collections, such as 'default'.
 *
 * If @service is %NULL, then [func@Service.get_sync] will be called to get
 * the default [class@Service] proxy.
 *
 * This method may block and should not be used in user interface threads.
 *
 * Returns: %TRUE if successful
 */
gboolean
secret_service_set_alias_sync (SecretService *service,
                               const gchar *alias,
                               SecretCollection *collection,
                               GCancellable *cancellable,
                               GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (service == NULL || SECRET_IS_SERVICE (service), FALSE);
	g_return_val_if_fail (alias != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_set_alias (service, alias, collection, cancellable,
	                          _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_service_set_alias_finish (service, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}
