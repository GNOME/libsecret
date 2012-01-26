/* GSecret - GLib wrapper for Secret Service
 *
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

#include "gsecret-dbus-generated.h"
#include "gsecret-item.h"
#include "gsecret-private.h"
#include "gsecret-service.h"
#include "gsecret-types.h"
#include "gsecret-value.h"

#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_SERVICE,
	PROP_ATTRIBUTES,
	PROP_LABEL,
	PROP_LOCKED,
	PROP_CREATED,
	PROP_MODIFIED
};

/* Thread safe: no changes between construct and finalize */
typedef struct _GSecretItemPrivate {
	GSecretService *service;
	GCancellable *cancellable;
} GSecretItemPrivate;

static GInitableIface *gsecret_item_initable_parent_iface = NULL;

static GAsyncInitableIface *gsecret_item_async_initable_parent_iface = NULL;

static void   gsecret_item_initable_iface         (GInitableIface *iface);

static void   gsecret_item_async_initable_iface   (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GSecretItem, gsecret_item, G_TYPE_DBUS_PROXY,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, gsecret_item_initable_iface);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, gsecret_item_async_initable_iface);
);

static void
gsecret_item_init (GSecretItem *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GSECRET_TYPE_ITEM, GSecretItemPrivate);
	self->pv->cancellable = g_cancellable_new ();
}

static void
on_set_attributes (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSecretItem *self = GSECRET_ITEM (user_data);
	GError *error = NULL;

	gsecret_item_set_attributes_finish (self, result, &error);
	if (error != NULL) {
		g_warning ("couldn't set GSecretItem Attributes: %s", error->message);
		g_error_free (error);
	}

	g_object_unref (self);
}

static void
on_set_label (GObject *source,
              GAsyncResult *result,
              gpointer user_data)
{
	GSecretItem *self = GSECRET_ITEM (user_data);
	GError *error = NULL;

	gsecret_item_set_label_finish (self, result, &error);
	if (error != NULL) {
		g_warning ("couldn't set GSecretItem Label: %s", error->message);
		g_error_free (error);
	}

	g_object_unref (self);
}

static void
gsecret_item_set_property (GObject *obj,
                           guint prop_id,
                           const GValue *value,
                           GParamSpec *pspec)
{
	GSecretItem *self = GSECRET_ITEM (obj);

	switch (prop_id) {
	case PROP_SERVICE:
		g_return_if_fail (self->pv->service == NULL);
		self->pv->service = g_value_get_object (value);
		if (self->pv->service)
			g_object_add_weak_pointer (G_OBJECT (self->pv->service),
			                           (gpointer *)&self->pv->service);
		break;
	case PROP_ATTRIBUTES:
		gsecret_item_set_attributes (self, g_value_get_boxed (value),
		                             self->pv->cancellable, on_set_attributes,
		                             g_object_ref (self));
		break;
	case PROP_LABEL:
		gsecret_item_set_label (self, g_value_get_string (value),
		                        self->pv->cancellable, on_set_label,
		                        g_object_ref (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gsecret_item_get_property (GObject *obj,
                           guint prop_id,
                           GValue *value,
                           GParamSpec *pspec)
{
	GSecretItem *self = GSECRET_ITEM (obj);

	switch (prop_id) {
	case PROP_SERVICE:
		g_value_set_object (value, self->pv->service);
		break;
	case PROP_ATTRIBUTES:
		g_value_take_boxed (value, gsecret_item_get_attributes (self));
		break;
	case PROP_LABEL:
		g_value_take_string (value, gsecret_item_get_label (self));
		break;
	case PROP_LOCKED:
		g_value_set_boolean (value, gsecret_item_get_locked (self));
		break;
	case PROP_CREATED:
		g_value_set_uint64 (value, gsecret_item_get_created (self));
		break;
	case PROP_MODIFIED:
		g_value_set_uint64 (value, gsecret_item_get_modified (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gsecret_item_dispose (GObject *obj)
{
	GSecretItem *self = GSECRET_ITEM (obj);

	g_cancellable_cancel (self->pv->cancellable);

	G_OBJECT_CLASS (gsecret_item_parent_class)->dispose (obj);
}

static void
gsecret_item_finalize (GObject *obj)
{
	GSecretItem *self = GSECRET_ITEM (obj);

	if (self->pv->service)
		g_object_remove_weak_pointer (G_OBJECT (self->pv->service),
		                              (gpointer *)&self->pv->service);

	g_object_unref (self->pv->cancellable);

	G_OBJECT_CLASS (gsecret_item_parent_class)->finalize (obj);
}

static void
handle_property_changed (GObject *object,
                         const gchar *property_name)
{
	if (g_str_equal (property_name, "Attributes"))
		g_object_notify (object, "attributes");

	else if (g_str_equal (property_name, "Label"))
		g_object_notify (object, "label");

	else if (g_str_equal (property_name, "Locked"))
		g_object_notify (object, "locked");

	else if (g_str_equal (property_name, "Created"))
		g_object_notify (object, "created");

	else if (g_str_equal (property_name, "Modified"))
		g_object_notify (object, "modified");
}

static void
gsecret_item_properties_changed (GDBusProxy *proxy,
                                 GVariant *changed_properties,
                                 const gchar* const *invalidated_properties)
{
	GObject *obj = G_OBJECT (proxy);
	gchar *property_name;
	GVariantIter iter;
	GVariant *value;

	g_object_freeze_notify (obj);

	g_variant_iter_init (&iter, changed_properties);
	while (g_variant_iter_loop (&iter, "{sv}", &property_name, &value))
		handle_property_changed (obj, property_name);

	g_object_thaw_notify (obj);
}

static void
gsecret_item_class_init (GSecretItemClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GDBusProxyClass *proxy_class = G_DBUS_PROXY_CLASS (klass);

	gobject_class->get_property = gsecret_item_get_property;
	gobject_class->set_property = gsecret_item_set_property;
	gobject_class->dispose = gsecret_item_dispose;
	gobject_class->finalize = gsecret_item_finalize;

	proxy_class->g_properties_changed = gsecret_item_properties_changed;

	g_object_class_install_property (gobject_class, PROP_SERVICE,
	            g_param_spec_object ("service", "Service", "Secret Service",
	                                 GSECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_ATTRIBUTES,
	             g_param_spec_boxed ("attributes", "Attributes", "Item attributes",
	                                 G_TYPE_HASH_TABLE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_LABEL,
	            g_param_spec_string ("label", "Label", "Item label",
	                                 NULL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_LOCKED,
	           g_param_spec_boolean ("locked", "Locked", "Item locked",
	                                 TRUE, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_CREATED,
	            g_param_spec_uint64 ("created", "Created", "Item creation date",
	                                 0UL, G_MAXUINT64, 0UL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_MODIFIED,
	            g_param_spec_uint64 ("modified", "Modified", "Item modified date",
	                                 0UL, G_MAXUINT64, 0UL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	g_type_class_add_private (gobject_class, sizeof (GSecretItemPrivate));
}

static gboolean
gsecret_item_initable_init (GInitable *initable,
                            GCancellable *cancellable,
                            GError **error)
{
	GDBusProxy *proxy;

	if (!gsecret_item_initable_parent_iface->init (initable, cancellable, error))
		return FALSE;

	proxy = G_DBUS_PROXY (initable);

	if (!_gsecret_util_have_cached_properties (proxy)) {
		g_set_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD,
		             "No such secret item at path: %s",
		             g_dbus_proxy_get_object_path (proxy));
		return FALSE;
	}

	return TRUE;
}

static void
gsecret_item_initable_iface (GInitableIface *iface)
{
	gsecret_item_initable_parent_iface = g_type_interface_peek_parent (iface);

	iface->init = gsecret_item_initable_init;
}

static void
on_init_base (GObject *source,
              GAsyncResult *result,
              gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretItem *self = GSECRET_ITEM (source);
	GDBusProxy *proxy = G_DBUS_PROXY (self);
	GError *error = NULL;

	if (!gsecret_item_async_initable_parent_iface->init_finish (G_ASYNC_INITABLE (self),
	                                                            result, &error)) {
		g_simple_async_result_take_error (res, error);

	} else if (!_gsecret_util_have_cached_properties (proxy)) {
		g_simple_async_result_set_error (res, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD,
		                                 "No such secret item at path: %s",
		                                 g_dbus_proxy_get_object_path (proxy));
	}

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
gsecret_item_async_initable_init_async (GAsyncInitable *initable,
                                        int io_priority,
                                        GCancellable *cancellable,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
	GSimpleAsyncResult *res;

	res = g_simple_async_result_new (G_OBJECT (initable), callback, user_data,
	                                 gsecret_item_async_initable_init_async);

	gsecret_item_async_initable_parent_iface->init_async (initable, io_priority,
	                                                      cancellable,
	                                                      on_init_base,
	                                                      g_object_ref (res));

	g_object_unref (res);
}

static gboolean
gsecret_item_async_initable_init_finish (GAsyncInitable *initable,
                                         GAsyncResult *result,
                                         GError **error)
{
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (initable),
	                      gsecret_item_async_initable_init_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	return TRUE;
}

static void
gsecret_item_async_initable_iface (GAsyncInitableIface *iface)
{
	gsecret_item_async_initable_parent_iface = g_type_interface_peek_parent (iface);

	iface->init_async = gsecret_item_async_initable_init_async;
	iface->init_finish = gsecret_item_async_initable_init_finish;
}

void
gsecret_item_new (GSecretService *service,
                  const gchar *item_path,
                  GCancellable *cancellable,
                  GAsyncReadyCallback callback,
                  gpointer user_data)
{
	GDBusProxy *proxy;

	g_return_if_fail (GSECRET_IS_SERVICE (service));
	g_return_if_fail (item_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	proxy = G_DBUS_PROXY (service);

	g_async_initable_new_async (GSECRET_SERVICE_GET_CLASS (service)->item_gtype,
	                            G_PRIORITY_DEFAULT, cancellable, callback, user_data,
	                            "g-flags", G_DBUS_CALL_FLAGS_NONE,
	                            "g-interface-info", _gsecret_gen_item_interface_info (),
	                            "g-name", g_dbus_proxy_get_name (proxy),
	                            "g-connection", g_dbus_proxy_get_connection (proxy),
	                            "g-object-path", item_path,
	                            "g-interface-name", GSECRET_ITEM_INTERFACE,
	                            "service", service,
	                            NULL);
}

GSecretItem *
gsecret_item_new_finish (GAsyncResult *result,
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

	return GSECRET_ITEM (object);
}

GSecretItem *
gsecret_item_new_sync (GSecretService *service,
                       const gchar *item_path,
                       GCancellable *cancellable,
                       GError **error)
{
	GDBusProxy *proxy;

	g_return_val_if_fail (GSECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (item_path != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	proxy = G_DBUS_PROXY (service);

	return g_initable_new (GSECRET_SERVICE_GET_CLASS (service)->item_gtype,
	                       cancellable, error,
	                       "g-flags", G_DBUS_CALL_FLAGS_NONE,
	                       "g-interface-info", _gsecret_gen_item_interface_info (),
	                       "g-name", g_dbus_proxy_get_name (proxy),
	                       "g-connection", g_dbus_proxy_get_connection (proxy),
	                       "g-object-path", item_path,
	                       "g-interface-name", GSECRET_ITEM_INTERFACE,
	                       "service", service,
	                       NULL);
}

void
gsecret_item_refresh (GSecretItem *self)
{
	g_return_if_fail (GSECRET_IS_ITEM (self));

	_gsecret_util_get_properties (G_DBUS_PROXY (self),
	                              gsecret_item_refresh,
	                              NULL, NULL, NULL);
}

static void
on_item_deleted (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretItem *self = GSECRET_ITEM (g_async_result_get_source_object (user_data));
	GError *error = NULL;

	if (gsecret_service_delete_path_finish (GSECRET_SERVICE (source), result, &error)) {
		g_simple_async_result_set_op_res_gboolean (res, TRUE);
		g_object_run_dispose (G_OBJECT (self));
	}

	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (self);
	g_object_unref (res);
}

void
gsecret_item_delete (GSecretItem *self,
                     GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	GSimpleAsyncResult *res;
	const gchar *object_path;

	g_return_if_fail (GSECRET_IS_ITEM (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	object_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (self));
	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_item_delete);

	_gsecret_service_delete_path (self->pv->service, object_path, TRUE,
	                              cancellable, on_item_deleted, g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_item_delete_finish (GSecretItem *self,
                            GAsyncResult *result,
                            GError **error)
{
	GSimpleAsyncResult *res;

	g_return_val_if_fail (GSECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_item_delete), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	return g_simple_async_result_get_op_res_gboolean (res);
}

gboolean
gsecret_item_delete_sync (GSecretItem *self,
                          GCancellable *cancellable,
                          GError **error)
{
	GSecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (GSECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_item_delete (self, cancellable, _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = gsecret_item_delete_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return ret;
}

typedef struct {
	GCancellable *cancellable;
	GSecretValue *value;
} GetClosure;

static void
get_closure_free (gpointer data)
{
	GetClosure *closure = data;
	g_clear_object (&closure->cancellable);
	gsecret_value_unref (closure->value);
	g_slice_free (GetClosure, closure);
}

static void
on_item_get_secret_ready (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretItem *self = GSECRET_ITEM (g_async_result_get_source_object (user_data));
	GetClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretSession *session;
	GError *error = NULL;
	GVariant *retval;
	GVariant *child;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error == NULL) {
		child = g_variant_get_child_value (retval, 0);
		g_variant_unref (retval);

		session = _gsecret_service_get_session (self->pv->service);
		closure->value = _gsecret_session_decode_secret (session, child);
		g_variant_unref (child);

		if (closure->value == NULL)
			g_set_error (&error, GSECRET_ERROR, GSECRET_ERROR_PROTOCOL,
			             _("Received invalid secret from the secret storage"));
	}

	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_service_ensure_session (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretItem *self = GSECRET_ITEM (g_async_result_get_source_object (user_data));
	GetClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	const gchar *session_path;
	GError *error = NULL;

	session_path = gsecret_service_ensure_session_finish (self->pv->service, result, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else {
		g_assert (session_path != NULL && session_path[0] != '\0');
		g_dbus_proxy_call (G_DBUS_PROXY (self), "GetSecret",
		                   g_variant_new ("(o)", session_path),
		                   G_DBUS_CALL_FLAGS_NONE, -1, closure->cancellable,
		                   on_item_get_secret_ready, g_object_ref (res));
	}

	g_object_unref (res);
}

void
gsecret_item_get_secret (GSecretItem *self,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_if_fail (GSECRET_IS_ITEM (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback,
	                                 user_data, gsecret_item_get_secret);
	closure = g_slice_new0 (GetClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, get_closure_free);

	gsecret_service_ensure_session (self->pv->service, cancellable,
	                                on_service_ensure_session,
	                                g_object_ref (res));

	g_object_unref (res);
}

GSecretValue*
gsecret_item_get_secret_finish (GSecretItem *self,
                                GAsyncResult *result,
                                GError **error)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_item_get_secret), NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->value ? gsecret_value_ref (closure->value) : NULL;
}

GSecretValue*
gsecret_item_get_secret_sync (GSecretItem *self,
                              GCancellable *cancellable,
                              GError **error)
{
	GSecretSync *sync;
	GSecretValue *value;

	g_return_val_if_fail (GSECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_item_get_secret (self, cancellable, _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	value = gsecret_item_get_secret_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return value;
}

GHashTable *
gsecret_item_get_attributes (GSecretItem *self)
{
	GHashTable *attributes;
	GVariant *variant;

	g_return_val_if_fail (GSECRET_IS_ITEM (self), NULL);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Attributes");
	g_return_val_if_fail (variant != NULL, NULL);

	attributes = _gsecret_util_attributes_for_variant (variant);
	g_variant_unref (variant);

	return attributes;
}

void
gsecret_item_set_attributes (GSecretItem *self,
                             GHashTable *attributes,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	g_return_if_fail (GSECRET_IS_ITEM (self));
	g_return_if_fail (attributes != NULL);

	_gsecret_util_set_property (G_DBUS_PROXY (self), "Attributes",
	                            _gsecret_util_variant_for_attributes (attributes),
	                            gsecret_item_set_attributes, cancellable,
	                            callback, user_data);
}

gboolean
gsecret_item_set_attributes_finish (GSecretItem *self,
                                    GAsyncResult *result,
                                    GError **error)
{
	g_return_val_if_fail (GSECRET_IS_ITEM (self), FALSE);

	return _gsecret_util_set_property_finish (G_DBUS_PROXY (self),
	                                          gsecret_item_set_attributes,
	                                          result, error);
}

gboolean
gsecret_item_set_attributes_sync (GSecretItem *self,
                                  GHashTable *attributes,
                                  GCancellable *cancellable,
                                  GError **error)
{
	g_return_val_if_fail (GSECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);

	return _gsecret_util_set_property_sync (G_DBUS_PROXY (self), "Attributes",
	                                        _gsecret_util_variant_for_attributes (attributes),
	                                        cancellable, error);
}

gchar *
gsecret_item_get_label (GSecretItem *self)
{
	GVariant *variant;
	gchar *label;

	g_return_val_if_fail (GSECRET_IS_ITEM (self), NULL);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Label");
	g_return_val_if_fail (variant != NULL, NULL);

	label = g_variant_dup_string (variant, NULL);
	g_variant_unref (variant);

	return label;
}

void
gsecret_item_set_label (GSecretItem *self,
                        const gchar *label,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	g_return_if_fail (GSECRET_IS_ITEM (self));
	g_return_if_fail (label != NULL);

	_gsecret_util_set_property (G_DBUS_PROXY (self), "Label",
	                            g_variant_new_string (label),
	                            gsecret_item_set_label,
	                            cancellable, callback, user_data);
}

gboolean
gsecret_item_set_label_finish (GSecretItem *self,
                               GAsyncResult *result,
                               GError **error)
{
	g_return_val_if_fail (GSECRET_IS_ITEM (self), FALSE);

	return _gsecret_util_set_property_finish (G_DBUS_PROXY (self),
	                                          gsecret_item_set_label,
	                                          result, error);
}

gboolean
gsecret_item_set_label_sync (GSecretItem *self,
                             const gchar *label,
                             GCancellable *cancellable,
                             GError **error)
{
	g_return_val_if_fail (GSECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (label != NULL, FALSE);

	return _gsecret_util_set_property_sync (G_DBUS_PROXY (self), "Label",
	                                       g_variant_new_string (label),
	                                       cancellable, error);
}

gboolean
gsecret_item_get_locked (GSecretItem *self)
{
	GVariant *variant;
	gboolean locked;

	g_return_val_if_fail (GSECRET_IS_ITEM (self), TRUE);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Locked");
	g_return_val_if_fail (variant != NULL, TRUE);

	locked = g_variant_get_boolean (variant);
	g_variant_unref (variant);

	return locked;
}

guint64
gsecret_item_get_created (GSecretItem *self)
{
	GVariant *variant;
	guint64 created;

	g_return_val_if_fail (GSECRET_IS_ITEM (self), TRUE);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Created");
	g_return_val_if_fail (variant != NULL, 0);

	created = g_variant_get_uint64 (variant);
	g_variant_unref (variant);

	return created;
}

guint64
gsecret_item_get_modified (GSecretItem *self)
{
	GVariant *variant;
	guint64 modified;

	g_return_val_if_fail (GSECRET_IS_ITEM (self), TRUE);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Modified");
	g_return_val_if_fail (variant != NULL, 0);

	modified = g_variant_get_uint64 (variant);
	g_variant_unref (variant);

	return modified;
}
