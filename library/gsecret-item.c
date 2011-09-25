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

#include "gsecret-item.h"
#include "gsecret-private.h"
#include "gsecret-service.h"
#include "gsecret-types.h"
#include "gsecret-value.h"

#include <glib/gi18n-lib.h>

struct _GSecretItemPrivate {
	GSecretService *service;
};

G_DEFINE_TYPE (GSecretItem, gsecret_item, G_TYPE_DBUS_PROXY);

static void
gsecret_item_init (GSecretItem *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GSECRET_TYPE_ITEM, GSecretItemPrivate);
}

static void
gsecret_item_class_init (GSecretItemClass *klass)
{

}

static void
on_item_delete_ready (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;
	GVariant *ret;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source),
	                                     result, &error);
	if (ret == NULL)
		g_simple_async_result_take_error (res, error);
	else
		g_variant_unref (ret);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

void
gsecret_item_delete (GSecretItem *self, GCancellable *cancellable,
                     GAsyncReadyCallback callback, gpointer user_data)
{
	const gchar *object_path;
	gchar *collection_path;
	GSimpleAsyncResult *res;

	g_return_if_fail (GSECRET_IS_ITEM (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));
	res = g_simple_async_result_new (G_OBJECT (self), callback,
	                                 user_data, gsecret_item_delete);

	object_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (self));
	collection_path = _gsecret_util_parent_path (object_path);

	g_dbus_connection_call (g_dbus_proxy_get_connection (G_DBUS_PROXY (self)),
	                        g_dbus_proxy_get_name (G_DBUS_PROXY (self)),
	                        collection_path, GSECRET_COLLECTION_INTERFACE,
	                        "Delete", NULL, NULL,
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                        cancellable, on_item_delete_ready, res);

	g_free (collection_path);
}

gboolean
gsecret_item_delete_finish (GSecretItem *self, GAsyncResult *result,
                            GError **error)
{
	g_return_val_if_fail (GSECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result,
	                      G_OBJECT (self), gsecret_item_delete), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result),
	                                           error))
		return FALSE;

	return TRUE;
}

gboolean
gsecret_item_delete_sync (GSecretItem *self, GCancellable *cancellable,
                          GError **error)
{
	const gchar *object_path;
	gchar *collection_path;
	GVariant *ret;

	g_return_val_if_fail (GSECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	object_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (self));
	collection_path = _gsecret_util_parent_path (object_path);

	ret = g_dbus_connection_call_sync (g_dbus_proxy_get_connection (G_DBUS_PROXY (self)),
	                                   g_dbus_proxy_get_name (G_DBUS_PROXY (self)),
	                                   collection_path, GSECRET_COLLECTION_INTERFACE,
	                                   "Delete", NULL, NULL,
	                                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                                   cancellable, error);

	g_free (collection_path);

	if (ret != NULL) {
		g_variant_unref (ret);
		return TRUE;
	}

	return FALSE;
}

static void
on_item_get_secret_ready (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretItem *self = GSECRET_ITEM (g_async_result_get_source_object (user_data));
	GError *error = NULL;
	GSecretValue *value;
	GVariant *ret;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error == NULL) {
		value = _gsecret_service_decode_secret (self->pv->service, ret);
		if (value == NULL) {
			g_set_error (&error, GSECRET_ERROR, GSECRET_ERROR_PROTOCOL,
			             _("Received invalid secret from the secret storage"));
		}
		g_object_unref (ret);
	}

	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	else
		g_simple_async_result_set_op_res_gpointer (res, value,
		                                           gsecret_value_unref);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_service_ensure_session (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretItem *self = GSECRET_ITEM (g_async_result_get_source_object (user_data));
	GError *error = NULL;
	const gchar *session_path;

	session_path = gsecret_service_ensure_session_finish (self->pv->service,
	                                                      result, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else {
		g_assert (session_path != NULL && session_path[0] != '\0');
		g_dbus_proxy_call (G_DBUS_PROXY (self), "GetSecret",
		                   g_variant_new ("o", session_path),
		                   G_DBUS_CALL_FLAGS_NONE, -1,
		                   _gsecret_async_result_get_cancellable (res),
		                   on_item_get_secret_ready, g_object_ref (res));
	}

	g_object_unref (res);
}

void
gsecret_item_get_secret (GSecretItem *self, GCancellable *cancellable,
                         GAsyncReadyCallback callback, gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (GSECRET_IS_ITEM (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback,
	                                 user_data, gsecret_item_get_secret);

	gsecret_service_ensure_session (self->pv->service, cancellable,
	                                on_service_ensure_session,
	                                g_object_ref (res));

	g_object_unref (res);
}

GSecretValue*
gsecret_item_get_secret_finish (GSecretItem *self, GAsyncResult *result,
                                GError **error)
{
	GSimpleAsyncResult *res;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_item_get_secret), NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	return gsecret_value_ref (g_simple_async_result_get_op_res_gpointer (res));
}

GSecretValue*
gsecret_item_get_secret_sync (GSecretItem *self,
                              GCancellable *cancellable,
                              GError **error)
{
	const gchar *session_path;
	GSecretValue *value;
	GVariant *ret;

	session_path = gsecret_service_ensure_session_sync (self->pv->service,
	                                                    cancellable, error);
	if (session_path != NULL)
		return NULL;

	g_assert (session_path != NULL && session_path[0] != '\0');
	ret = g_dbus_proxy_call_sync (G_DBUS_PROXY (self), "GetSecret",
	                              g_variant_new ("o", session_path),
	                              G_DBUS_CALL_FLAGS_NONE, -1,
	                              cancellable, error);

	if (ret != NULL) {
		value = _gsecret_service_decode_secret (self->pv->service, ret);
		if (value == NULL) {
			g_set_error (error, GSECRET_ERROR, GSECRET_ERROR_PROTOCOL,
			             _("Received invalid secret from the secret storage"));
		}
	}

	g_object_unref (ret);
	return value;
}

#ifdef UNIMPLEMENTED

GHashTable*         gsecret_item_get_attributes             (GSecretItem *self);

void                gsecret_item_set_attributes             (GSecretItem *self,
                                                             GHashTable *attributes,
                                                             GCancellable *cancellable,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

gboolean            gsecret_item_set_attributes_finish      (GSecretItem *self,
                                                             GAsyncResult *result,
                                                             GError **error);

void                gsecret_item_set_attributes_sync        (GSecretItem *self,
                                                             GHashTable *attributes,
                                                             GCancellable *cancellable,
                                                             GError **error);

const gchar*        gsecret_item_get_label                  (GSecretItem *self);

void                gsecret_item_set_label                  (GSecretItem *self,
                                                             const gchar *label,
                                                             GCancellable *cancellable,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

gboolean            gsecret_item_set_label_finish           (GSecretItem *self,
                                                             GAsyncResult *result,
                                                             GError **error);

void                gsecret_item_set_label_sync             (GSecretItem *self,
                                                             const gchar *label,
                                                             GCancellable *cancellable,
                                                             GError **error);

gboolean            gsecret_item_get_locked                 (GSecretItem *self);

guint64             gsecret_item_get_created                (GSecretItem *self);

guint64             gsecret_item_get_modified               (GSecretItem *self);

#endif /* UNIMPLEMENTED */
