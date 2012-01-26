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

#include "gsecret-private.h"
#include "gsecret-types.h"

#include <string.h>

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
_gsecret_list_get_type (void)
{
	static GType type = 0;
	if (!type)
		type = g_boxed_type_register_static ("GSecretObjectList",
		                                     (GBoxedCopyFunc)list_ref_copy,
		                                     (GBoxedFreeFunc)list_unref_free);
	return type;

}

GQuark
gsecret_error_get_quark (void)
{
	static volatile gsize initialized = 0;
	static GQuark quark = 0;

	if (g_once_init_enter (&initialized)) {
		quark = g_quark_from_static_string ("gsecret-error");
		g_once_init_leave (&initialized, 1);
	}

	return quark;
}

gchar *
_gsecret_util_parent_path (const gchar *path)
{
	const gchar *pos;

	g_return_val_if_fail (path != NULL, NULL);

	pos = strrchr (path, '/');
	g_return_val_if_fail (pos != NULL, NULL);
	g_return_val_if_fail (pos != path, NULL);

	return g_strndup (path, pos - path);
}

gboolean
_gsecret_util_empty_path (const gchar *path)
{
	g_return_val_if_fail (path != NULL, TRUE);
	return (g_str_equal (path, "") || g_str_equal (path, "/"));
}

GVariant *
_gsecret_util_variant_for_properties (GHashTable *properties)
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

GVariant *
_gsecret_util_variant_for_attributes (GHashTable *attributes)
{
	GHashTableIter iter;
	GVariantBuilder builder;
	const gchar *name;
	const gchar *value;

	g_return_val_if_fail (attributes != NULL, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, (gpointer *)&name, (gpointer *)&value))
		g_variant_builder_add (&builder, "{ss}", name, value);

	return g_variant_builder_end (&builder);
}

GHashTable *
_gsecret_util_attributes_for_variant (GVariant *variant)
{
	GVariantIter iter;
	GHashTable *attributes;
	gchar *value;
	gchar *key;

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	g_variant_iter_init (&iter, variant);
	while (g_variant_iter_next (&iter, "{ss}", &key, &value))
		g_hash_table_insert (attributes, key, value);

	return attributes;
}

GHashTable *
_gsecret_util_attributes_for_varargs (const GSecretSchema *schema,
                                      va_list args)
{
	const gchar *attribute_name;
	GSecretSchemaType type;
	GHashTable *attributes;
	const gchar *string;
	gboolean type_found;
	gchar *value = NULL;
	gboolean boolean;
	gint integer;
	gint i;

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	for (;;) {
		attribute_name = va_arg (args, const gchar *);
		if (attribute_name == NULL)
			break;

		type_found = FALSE;
		for (i = 0; i < G_N_ELEMENTS (schema->attributes); ++i) {
			if (!schema->attributes[i].name)
				break;
			if (g_str_equal (schema->attributes[i].name, attribute_name)) {
				type_found = TRUE;
				type = schema->attributes[i].type;
				break;
			}
		}

		if (!type_found) {
			g_warning ("The attribute '%s' was not found in the password schema.", attribute_name);
			g_hash_table_unref (attributes);
			return NULL;
		}

		switch (type) {
		case GSECRET_ATTRIBUTE_BOOLEAN:
			boolean = va_arg (args, gboolean);
			value = g_strdup (boolean ? "true" : "false");
			break;
		case GSECRET_ATTRIBUTE_STRING:
			string = va_arg (args, gchar *);
			if (!g_utf8_validate (string, -1, NULL)) {
				g_warning ("The value for attribute '%s' was not a valid utf-8 string.", attribute_name);
				g_hash_table_unref (attributes);
				return NULL;
			}
			value = g_strdup (string);
			break;
		case GSECRET_ATTRIBUTE_INTEGER:
			integer = va_arg (args, gint);
			value = g_strdup_printf ("%d", integer);
			break;
		default:
			g_warning ("The password attribute '%s' has an invalid type in the password schema.", attribute_name);
			g_hash_table_unref (attributes);
			return NULL;
		}

		g_hash_table_insert (attributes, g_strdup (attribute_name), value);
	}

	return attributes;
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
	g_signal_emit_by_name (proxy, "properties-changed",
	                       changed_properties, invalidated_properties);
	g_variant_unref (changed_properties);
}

static void
on_get_properties (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (result);
	GDBusProxy *proxy = G_DBUS_PROXY (g_async_result_get_source_object (user_data));
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	if (error == NULL)
		process_get_all_reply (proxy, retval);
	else
		g_simple_async_result_take_error (res, error);
	if (retval != NULL)
		g_variant_unref (retval);

	g_simple_async_result_complete (res);
	g_object_unref (proxy);
	g_object_unref (res);
}

void
_gsecret_util_get_properties (GDBusProxy *proxy,
                              gpointer result_tag,
                              GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (proxy), callback, user_data, result_tag);

	g_dbus_connection_call (g_dbus_proxy_get_connection (proxy),
	                        g_dbus_proxy_get_name (proxy),
	                        g_dbus_proxy_get_object_path (proxy),
	                        "org.freedesktop.DBus.Properties", "GetAll",
	                        g_variant_new ("(s)", g_dbus_proxy_get_interface_name (proxy)),
	                        G_VARIANT_TYPE ("(a{sv})"),
	                        G_DBUS_CALL_FLAGS_NONE, -1,
	                        cancellable, on_get_properties,
	                        g_object_ref (res));

	g_object_unref (res);
}

gboolean
_gsecret_util_get_properties_finish (GDBusProxy *proxy,
                                     gpointer result_tag,
                                     GAsyncResult *result,
                                     GError **error)
{
	GSimpleAsyncResult *res;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (proxy), result_tag), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

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
	g_slice_free (SetClosure, closure);
}

static void
on_set_property (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	SetClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GDBusProxy *proxy = G_DBUS_PROXY (g_async_result_get_source_object (user_data));
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source),
	                                        result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	if (retval != NULL)
		g_variant_unref (retval);

	closure->result = retval != NULL;
	if (closure->result)
		g_dbus_proxy_set_cached_property (proxy, closure->property, closure->value);

	g_simple_async_result_complete (res);
	g_object_unref (proxy);
	g_object_unref (res);
}

void
_gsecret_util_set_property (GDBusProxy *proxy,
                            const gchar *property,
                            GVariant *value,
                            gpointer result_tag,
                            GCancellable *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
	GSimpleAsyncResult *res;
	SetClosure *closure;

	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (proxy), callback, user_data, result_tag);
	closure = g_slice_new0 (SetClosure);
	closure->property = g_strdup (property);
	closure->value = g_variant_ref_sink (value);
	g_simple_async_result_set_op_res_gpointer (res, closure, set_closure_free);

	g_dbus_connection_call (g_dbus_proxy_get_connection (proxy),
	                        g_dbus_proxy_get_name (proxy),
	                        g_dbus_proxy_get_object_path (proxy),
	                        GSECRET_PROPERTIES_INTERFACE,
	                        "Set",
	                        g_variant_new ("(ssv)",
	                                       g_dbus_proxy_get_interface_name (proxy),
	                                       property,
	                                       closure->value),
	                        G_VARIANT_TYPE ("()"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                        cancellable, on_set_property,
	                        g_object_ref (res));

	g_object_unref (res);
}

gboolean
_gsecret_util_set_property_finish (GDBusProxy *proxy,
                                   gpointer result_tag,
                                   GAsyncResult *result,
                                   GError **error)
{
	GSimpleAsyncResult *res;
	SetClosure *closure;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (proxy), result_tag), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->result;
}

gboolean
_gsecret_util_set_property_sync (GDBusProxy *proxy,
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
	                                      GSECRET_PROPERTIES_INTERFACE,
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
_gsecret_util_have_cached_properties (GDBusProxy *proxy)
{
	gchar **names;

	names = g_dbus_proxy_get_cached_property_names (proxy);
	g_strfreev (names);

	return names != NULL;
}

GSecretSync *
_gsecret_sync_new (void)
{
	GSecretSync *sync;

	sync = g_new0 (GSecretSync, 1);

	sync->context = g_main_context_new ();
	sync->loop = g_main_loop_new (sync->context, FALSE);

	return sync;
}

void
_gsecret_sync_free (gpointer data)
{
	GSecretSync *sync = data;

	g_clear_object (&sync->result);
	g_main_loop_unref (sync->loop);
	g_main_context_unref (sync->context);
}

void
_gsecret_sync_on_result (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	GSecretSync *sync = user_data;
	g_assert (sync->result == NULL);
	sync->result = g_object_ref (result);
	g_main_loop_quit (sync->loop);
}
