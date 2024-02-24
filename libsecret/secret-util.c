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

#include "secret-private.h"
#include "secret-types.h"

#include <string.h>

/**
 * SecretError:
 * @SECRET_ERROR_PROTOCOL: received an invalid data or message from the Secret
 *   Service
 * @SECRET_ERROR_IS_LOCKED: the item or collection is locked and the operation
 *   cannot be performed
 * @SECRET_ERROR_NO_SUCH_OBJECT: no such item or collection found in the Secret
 *   Service
 * @SECRET_ERROR_ALREADY_EXISTS: a relevant item or collection already exists
 * @SECRET_ERROR_INVALID_FILE_FORMAT: the file format is not valid
 *
 * Errors returned by the Secret Service.
 *
 * None of the errors are appropriate for display to the user. It is up to the
 * application to handle them appropriately.
 *
 * Stability: Stable
 */
/**
 * SECRET_ERROR_MISMATCHED_SCHEMA:
 *
 * the xdg:schema attribute of the table does not match the schema name
 *
 * Since: 0.21.2
 */
/**
 * SECRET_ERROR_NO_MATCHING_ATTRIBUTE:
 *
 * attribute contained in table not found in corresponding schema
 *
 * Since: 0.21.2
 */
/**
 * SECRET_ERROR_WRONG_TYPE:
 *
 * attribute could not be parsed according to its type reported in the table's
 * schema
 *
 * Since: 0.21.2
 */
/**
 * SECRET_ERROR_EMPTY_TABLE:
 *
 * attribute list passed to secret_attributes_validate has no elements to
 * validate
 *
 * Since: 0.21.2
 */

static void
list_unref_free (GList *reflist)
{
	GList *l;
	for (l = reflist; l; l = g_list_next (l)) {
		g_return_if_fail (G_IS_OBJECT (l->data));
		g_object_unref (l->data);
	}
	g_list_free (reflist);
}

static GList *
list_ref_copy (GList *reflist)
{
	GList *l, *copy = g_list_copy (reflist);
	for (l = copy; l; l = g_list_next (l)) {
		g_return_val_if_fail (G_IS_OBJECT (l->data), NULL);
		g_object_ref (l->data);
	}
	return copy;
}

GType
_secret_list_get_type (void)
{
	static GType type = 0;
	if (!type)
		type = g_boxed_type_register_static ("SecretObjectList",
		                                     (GBoxedCopyFunc)list_ref_copy,
		                                     (GBoxedFreeFunc)list_unref_free);
	return type;

}

/**
 * secret_error_get_quark:
 *
 * Get the error quark.
 *
 * Returns: the quark
 */
GQuark
secret_error_get_quark (void)
{
	static gsize quark = 0;

	static const GDBusErrorEntry entries[] = {
		{ SECRET_ERROR_IS_LOCKED, "org.freedesktop.Secret.Error.IsLocked", },
		{ SECRET_ERROR_NO_SUCH_OBJECT, "org.freedesktop.Secret.Error.NoSuchObject", },
		{ SECRET_ERROR_ALREADY_EXISTS, "org.freedesktop.Secret.Error.AlreadyExists" },
	};

	g_dbus_error_register_error_domain ("secret-error", &quark,
	                                    entries, G_N_ELEMENTS (entries));

	return quark;
}

void
_secret_util_strip_remote_error (GError **error)
{
	gchar *remote;

	if (error == NULL || *error == NULL)
		return;

	remote = g_dbus_error_get_remote_error (*error);
	if (remote) {
		if (g_dbus_error_strip_remote_error (*error)) {
			g_info ("Remote error from secret service: %s: %s", remote, (*error)->message);
		}
		g_free (remote);
	}
}

gchar *
_secret_util_parent_path (const gchar *path)
{
	const gchar *pos;

	g_return_val_if_fail (path != NULL, NULL);

	pos = strrchr (path, '/');
	g_return_val_if_fail (pos != NULL, NULL);
	g_return_val_if_fail (pos != path, NULL);

	return g_strndup (path, pos - path);
}

gboolean
_secret_util_empty_path (const gchar *path)
{
	g_return_val_if_fail (path != NULL, TRUE);
	return (g_str_equal (path, "") || g_str_equal (path, "/"));
}

gchar *
_secret_util_collection_to_path (const gchar *collection)
{
	if (collection == NULL)
		collection = SECRET_COLLECTION_DEFAULT;
	if (strchr (collection, '/') == NULL)
		return g_strdup_printf ("/org/freedesktop/secrets/aliases/%s", collection);
	return g_strdup (collection);
}

GVariant *
_secret_util_variant_for_properties (GHashTable *properties)
{
	GHashTableIter iter;
	GVariantBuilder builder;
	const gchar *name;
	GVariant *value;

	g_return_val_if_fail (properties != NULL, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	g_hash_table_iter_init (&iter, properties);
	while (g_hash_table_iter_next (&iter, (gpointer *)&name, (gpointer *)&value))
		g_variant_builder_add (&builder, "{sv}", name, value);

	return g_variant_builder_end (&builder);
}

static void
process_get_all_reply (GDBusProxy *proxy,
                       GVariant *retval)
{
	const gchar *invalidated_properties[1] = { NULL };
	GVariant *changed_properties;
	GVariantIter *iter;
	GVariant *value;
	gchar *key;

	if (!g_variant_is_of_type (retval, G_VARIANT_TYPE ("(a{sv})"))) {
		g_warning ("Value for GetAll reply with type `%s' does not match `(a{sv})'",
		           g_variant_get_type_string (retval));
		return;
	}

	g_variant_get (retval, "(a{sv})", &iter);
	while (g_variant_iter_loop (iter, "{sv}", &key, &value))
		g_dbus_proxy_set_cached_property (proxy, key, value);
	g_variant_iter_free (iter);

	g_variant_get (retval, "(@a{sv})", &changed_properties);
	g_signal_emit_by_name (proxy, "g-properties-changed",
	                       changed_properties, invalidated_properties);
	g_variant_unref (changed_properties);
}

static void
on_get_properties (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GDBusProxy *proxy = G_DBUS_PROXY (g_task_get_source_object (task));
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	if (error == NULL) {
		process_get_all_reply (proxy, retval);
		g_task_return_boolean (task, TRUE);
	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}
	if (retval != NULL)
		g_variant_unref (retval);

	g_clear_object (&task);
}

void
_secret_util_get_properties (GDBusProxy *proxy,
                             gpointer result_tag,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	GTask *task;

	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (proxy, cancellable, callback, user_data);
	g_task_set_source_tag (task, result_tag);

	g_dbus_connection_call (g_dbus_proxy_get_connection (proxy),
	                        g_dbus_proxy_get_name (proxy),
	                        g_dbus_proxy_get_object_path (proxy),
	                        "org.freedesktop.DBus.Properties", "GetAll",
	                        g_variant_new ("(s)", g_dbus_proxy_get_interface_name (proxy)),
	                        G_VARIANT_TYPE ("(a{sv})"),
	                        G_DBUS_CALL_FLAGS_NONE, -1,
	                        cancellable, on_get_properties,
	                        g_steal_pointer (&task));

	g_clear_object (&task);
}

gboolean
_secret_util_get_properties_finish (GDBusProxy *proxy,
                                    gpointer result_tag,
                                    GAsyncResult *result,
                                    GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, proxy), FALSE);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) == result_tag, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

typedef struct {
	gchar *property;
	GVariant *value;
	gboolean result;
} SetClosure;

static void
set_closure_free (gpointer data)
{
	SetClosure *closure = data;
	g_free (closure->property);
	g_variant_unref (closure->value);
	g_free (closure);
}

static void
on_set_property (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SetClosure *closure = g_task_get_task_data (task);
	GDBusProxy *proxy = G_DBUS_PROXY (g_task_get_source_object (user_data));
	GError *error = NULL;
	GVariant *retval;
	gboolean success = FALSE;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source),
	                                        result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
	} else {
		success = (retval != NULL);

		if (success) {
			g_dbus_proxy_set_cached_property (proxy, closure->property, closure->value);
			g_variant_unref (retval);
		}

		g_task_return_boolean (task, success);
	}

	g_clear_object (&task);
}

void
_secret_util_set_property (GDBusProxy *proxy,
                           const gchar *property,
                           GVariant *value,
                           gpointer result_tag,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	GTask *task;
	SetClosure *closure;

	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (proxy, cancellable, callback, user_data);
	g_task_set_source_tag (task, result_tag);
	closure = g_new0 (SetClosure, 1);
	closure->property = g_strdup (property);
	closure->value = g_variant_ref_sink (value);
	g_task_set_task_data (task, closure, set_closure_free);

	g_dbus_connection_call (g_dbus_proxy_get_connection (proxy),
	                        g_dbus_proxy_get_name (proxy),
	                        g_dbus_proxy_get_object_path (proxy),
	                        SECRET_PROPERTIES_INTERFACE,
	                        "Set",
	                        g_variant_new ("(ssv)",
	                                       g_dbus_proxy_get_interface_name (proxy),
	                                       property,
	                                       closure->value),
	                        G_VARIANT_TYPE ("()"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                        cancellable, on_set_property,
	                        g_steal_pointer (&task));

	g_clear_object (&task);
}

gboolean
_secret_util_set_property_finish (GDBusProxy *proxy,
                                  gpointer result_tag,
                                  GAsyncResult *result,
                                  GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, proxy), FALSE);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) == result_tag, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

gboolean
_secret_util_set_property_sync (GDBusProxy *proxy,
                                const gchar *property,
                                GVariant *value,
                                GCancellable *cancellable,
                                GError **error)
{
	gboolean result = FALSE;
	GVariant *retval;

	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	g_variant_ref_sink (value);

	retval = g_dbus_connection_call_sync (g_dbus_proxy_get_connection (proxy),
	                                      g_dbus_proxy_get_name (proxy),
	                                      g_dbus_proxy_get_object_path (proxy),
	                                      SECRET_PROPERTIES_INTERFACE,
	                                      "Set",
	                                      g_variant_new ("(ssv)",
	                                                     g_dbus_proxy_get_interface_name (proxy),
	                                                     property,
	                                                     value),
	                                      G_VARIANT_TYPE ("()"),
	                                      G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                                      cancellable, error);

	if (retval != NULL) {
		result = TRUE;
		g_variant_unref (retval);
		g_dbus_proxy_set_cached_property (proxy, property, value);
	}

	g_variant_unref (value);

	return result;
}

gboolean
_secret_util_have_cached_properties (GDBusProxy *proxy)
{
	gchar **names;

	names = g_dbus_proxy_get_cached_property_names (proxy);
	g_strfreev (names);

	return names != NULL;
}

SecretSync *
_secret_sync_new (void)
{
	SecretSync *sync;

	sync = g_new0 (SecretSync, 1);

	sync->context = g_main_context_new ();
	sync->loop = g_main_loop_new (sync->context, FALSE);

	return sync;
}

void
_secret_sync_free (gpointer data)
{
	SecretSync *sync = data;

	while (g_main_context_iteration (sync->context, FALSE));

	g_clear_object (&sync->result);
	g_main_loop_unref (sync->loop);
	g_main_context_unref (sync->context);
	g_free (sync);
}

void
_secret_sync_on_result (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	SecretSync *sync = user_data;
	g_assert (sync->result == NULL);
	sync->result = g_object_ref (result);
	g_main_loop_quit (sync->loop);
}
