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
	GAsyncResult *result;
	GMainContext *context;
	GMainLoop *loop;
} SyncClosure;

static SyncClosure *
sync_closure_new (void)
{
	SyncClosure *closure;

	closure = g_new0 (SyncClosure, 1);

	closure->context = g_main_context_new ();
	closure->loop = g_main_loop_new (closure->context, FALSE);

	return closure;
}

static void
sync_closure_free (gpointer data)
{
	SyncClosure *closure = data;

	g_clear_object (&closure->result);
	g_main_loop_unref (closure->loop);
	g_main_context_unref (closure->context);
}

static void
on_sync_result (GObject *source,
                GAsyncResult *result,
                gpointer user_data)
{
	SyncClosure *closure = user_data;
	closure->result = g_object_ref (result);
	g_main_loop_quit (closure->loop);
}

#if 0

typedef struct {
	GVariant *properties;
	gchar *collection_path;
	GSecretValue *secret;
	GCancellable *cancellable;
} StoreClosure;

static void
store_closure_free (gpointer data)
{
	StoreClosure *closure = data;
	g_variant_unref (closure->properties);
	g_free (closure->collection_path);
	gsecret_value_unref (closure->secret);
	g_clear_object (closure->cancellable);
	g_free (closure);
}

static void
on_create_item_reply (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o&o)", &item_path, &prompt_path);
		if (prompt_path xxx)
			gsecret_prompt_perform (self, "", closure->cancellable,
			                        on_store_prompt_complete, NULL);

		if (g_strcmp0 (item_path, "/") != 0)
			xxx complete!
	}

	g_object_unref (res);
}

static void
on_store_service_connected (GObject *source,
                            GAsyncResult *result,
                            gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	StoreClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretService *service;
	GError *error = NULL;
	GDBusProxy *proxy;
	GVariant *params;

	service = _gsecret_service_bare_connect_finish (result, &error);
	if (error == NULL) {
		params = g_variant_new ("(&a{sv}&(oayays)b)",
		                        closure->properties,
		                        _gsecret_service_encode_secret (service, closure->secret),
		                        TRUE);

		proxy = G_DBUS_PROXY (service);
		g_dbus_connection_call (g_dbus_proxy_get_connection (proxy),
		                        g_dbus_proxy_get_name (proxy),
		                        closure->collection_path,
		                        GSECRET_COLLECTION_INTERFACE,
		                        "CreateItem", params, G_VARIANT_TYPE ("(oo)"),
		                        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
		                        closure->cancellable, on_create_item_reply,
		                        g_object_ref (res));
	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

		<arg name="item" type="o" direction="out"/>
		<arg name="prompt" type="o" direction="out"/>
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
	GSimpleAsyncResult *res;
	GVariant *attributes;
	StoreClosure *closure;
	GVariantBuilder builder;
	va_list va;

	g_return_if_fail (schema != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (password != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Build up the attributes */
	va_start (va, user_data);
	attributes = build_attributes (schema, va);
	va_end (va);
	g_return_if_fail (attributes != NULL);

	/* Build up the various properties */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&builder, "{sv}", GSECRET_SERVICE_INTERFACE "Attributes", attributes);
	g_variant_builder_add (&builder, "{sv}", GSECRET_SERVICE_INTERFACE "Label", g_variant_new_string ("label"));
	g_variant_builder_add (&builder, "{sv}", GSECRET_SERVICE_INTERFACE "Schema", g_variant_new_string (schema->schema_name));

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 gsecret_password_store_finish);
	closure = g_new0 (StoreClosure, 1);
	closure->properties = g_variant_ref_sink (g_variant_builder_end (&builder));
	closure->collection_path = g_strdup (collection_path);
	closure->secret = gsecret_value_new (password, -1, "text/plain");
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, store_closure_free);

	_gsecret_service_bare_connect_with_session (cancellable, on_store_service_connected,
	                                            g_object_ref (res));

	g_object_unref (res);
}

#if 0
gboolean
gsecret_password_store_finish (GAsyncResult *result,
                               GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

}

gboolean
gsecret_password_store_sync (const GSecretPasswordSchema *schema,
                             const gchar *collection,
                             const gchar *label,
                             const gchar *password,
                             GCancellable *cancellable,
                             GError **error,
                             const gchar *attribute_name,
                             ...)
{
	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (display_name != NULL, FALSE);
	g_return_val_if_fail (password != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

}

void
gsecret_password_lookup (const GSecretPasswordSchema *schema,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data,
                         const gchar *attribute_name,
                         ...)
{
	g_return_if_fail (schema != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

}

gchar *
gsecret_password_lookup_finish (GAsyncResult *result,
                                GError **error)
{
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

}

gchar *
gsecret_password_lookup_sync (const GSecretPasswordSchema *schema,
                              GCancellable *cancellable,
                              GError **error,
                              const gchar *attribute_name,
                              ...)
{
	g_return_val_if_fail (schema != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

}

#endif
#endif

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
gsecret_password_delete (const GSecretSchema *schema,
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

	gsecret_password_deletev (attributes, cancellable,
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

	closure->deleted = gsecret_service_delete_password_finish (GSECRET_SERVICE (source),
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

	service = _gsecret_service_bare_connect_finish (result, &error);
	if (error == NULL) {
		gsecret_service_delete_passwordv (service, closure->attributes,
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
gsecret_password_deletev (GHashTable *attributes,
                          GCancellable *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (NULL, callback, user_data,
	                                 gsecret_password_deletev);
	closure = g_slice_new0 (DeleteClosure);
	closure->attributes = g_hash_table_ref (attributes);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, delete_closure_free);

	_gsecret_service_bare_connect (NULL, FALSE, cancellable,
	                               on_delete_connect,
	                               g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_password_delete_finish (GAsyncResult *result,
                                GError **error)
{
	DeleteClosure *closure;
	GSimpleAsyncResult *res;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL,
	                      gsecret_password_deletev), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->deleted;
}

gboolean
gsecret_password_delete_sync (const GSecretSchema* schema,
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

	result = gsecret_password_deletev_sync (attributes, cancellable, error);

	g_hash_table_unref (attributes);

	return result;
}

gboolean
gsecret_password_deletev_sync (GHashTable *attributes,
                               GCancellable *cancellable,
                               GError **error)
{
	SyncClosure *closure;
	gboolean result;

	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	closure = sync_closure_new ();
	g_main_context_push_thread_default (closure->context);

	gsecret_password_deletev (attributes, cancellable,
	                          on_sync_result, closure);

	g_main_loop_run (closure->loop);

	result = gsecret_password_delete_finish (closure->result, error);

	g_main_context_pop_thread_default (closure->context);
	sync_closure_free (closure);

	return result;
}

void
gsecret_password_free (gpointer password)
{
	if (password == NULL)
		return;

	egg_secure_strfree (password);
}

