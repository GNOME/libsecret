/* GSecret - GLib wrapper for Secret Service
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

#include "gsecret-collection.h"
#include "gsecret-dbus-generated.h"
#include "gsecret-enum-types.h"
#include "gsecret-item.h"
#include "gsecret-private.h"
#include "gsecret-service.h"
#include "gsecret-types.h"
#include "gsecret-value.h"

#include "egg/egg-secure-memory.h"

#include <glib.h>
#include <glib/gi18n-lib.h>

#include <gcrypt.h>

EGG_SECURE_GLIB_DEFINITIONS ();

EGG_SECURE_DECLARE (secret_service);

static const gchar *default_bus_name = GSECRET_SERVICE_BUS_NAME;

enum {
	PROP_0,
	PROP_FLAGS,
	PROP_COLLECTIONS
};

typedef struct _GSecretServicePrivate {
	/* No change between construct and finalize */
	GCancellable *cancellable;
	GSecretServiceFlags init_flags;

	/* Locked by mutex */
	GMutex mutex;
	gpointer session;
	GHashTable *collections;
} GSecretServicePrivate;

G_LOCK_DEFINE (service_instance);
static gpointer service_instance = NULL;

static GInitableIface *gsecret_service_initable_parent_iface = NULL;

static GAsyncInitableIface *gsecret_service_async_initable_parent_iface = NULL;

static void   gsecret_service_initable_iface         (GInitableIface *iface);

static void   gsecret_service_async_initable_iface   (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (GSecretService, gsecret_service, G_TYPE_DBUS_PROXY,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, gsecret_service_initable_iface);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, gsecret_service_async_initable_iface);
);

static void
gsecret_service_init (GSecretService *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GSECRET_TYPE_SERVICE,
	                                        GSecretServicePrivate);

	g_mutex_init (&self->pv->mutex);
	self->pv->cancellable = g_cancellable_new ();
}

static void
gsecret_service_get_property (GObject *obj,
                              guint prop_id,
                              GValue *value,
                              GParamSpec *pspec)
{
	GSecretService *self = GSECRET_SERVICE (obj);

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_flags (value, gsecret_service_get_flags (self));
		break;
	case PROP_COLLECTIONS:
		g_value_take_boxed (value, gsecret_service_get_collections (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gsecret_service_set_property (GObject *obj,
                              guint prop_id,
                              const GValue *value,
                              GParamSpec *pspec)
{
	GSecretService *self = GSECRET_SERVICE (obj);

	switch (prop_id) {
	case PROP_FLAGS:
		self->pv->init_flags = g_value_get_flags (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gsecret_service_dispose (GObject *obj)
{
	GSecretService *self = GSECRET_SERVICE (obj);

	g_cancellable_cancel (self->pv->cancellable);

	G_OBJECT_CLASS (gsecret_service_parent_class)->dispose (obj);
}

static void
gsecret_service_finalize (GObject *obj)
{
	GSecretService *self = GSECRET_SERVICE (obj);

	_gsecret_session_free (self->pv->session);
	if (self->pv->collections)
		g_hash_table_destroy (self->pv->collections);
	g_clear_object (&self->pv->cancellable);

	G_OBJECT_CLASS (gsecret_service_parent_class)->finalize (obj);
}

static gboolean
gsecret_service_real_prompt_sync (GSecretService *self,
                                  GSecretPrompt *prompt,
                                  GCancellable *cancellable,
                                  GError **error)
{
	return gsecret_prompt_perform_sync (prompt, 0, cancellable, error);
}

static void
on_real_prompt_completed (GObject *source,
                          GAsyncResult *result,
                          gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;
	gboolean ret;

	ret = gsecret_prompt_perform_finish (GSECRET_PROMPT (source), result, &error);
	g_simple_async_result_set_op_res_gboolean (res, ret);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);
	g_simple_async_result_complete (res);

	g_object_unref (res);
}

static void
gsecret_service_real_prompt_async (GSecretService *self,
                                   GSecretPrompt *prompt,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
	GSimpleAsyncResult *res;

	res =  g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                  gsecret_service_real_prompt_async);

	gsecret_prompt_perform (prompt, 0, cancellable,
	                        on_real_prompt_completed,
	                        g_object_ref (res));

	g_object_unref (res);
}

static gboolean
gsecret_service_real_prompt_finish (GSecretService *self,
                                    GAsyncResult *result,
                                    GError **error)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	return g_simple_async_result_get_op_res_gboolean (res);
}

static void
handle_property_changed (GSecretService *self,
                         const gchar *property_name,
                         GVariant *value)
{
	gboolean perform;

	if (g_str_equal (property_name, "Collections")) {

		g_mutex_lock (&self->pv->mutex);
		perform = self->pv->collections != NULL;
		g_mutex_unlock (&self->pv->mutex);

		if (perform)
			gsecret_service_ensure_collections (self, self->pv->cancellable, NULL, NULL);
	}
}

static void
gsecret_service_properties_changed (GDBusProxy *proxy,
                                    GVariant *changed_properties,
                                    const gchar* const *invalidated_properties)
{
	GSecretService *self = GSECRET_SERVICE (proxy);
	gchar *property_name;
	GVariantIter iter;
	GVariant *value;

	g_object_freeze_notify (G_OBJECT (self));

	g_variant_iter_init (&iter, changed_properties);
	while (g_variant_iter_loop (&iter, "{sv}", &property_name, &value))
		handle_property_changed (self, property_name, value);

	g_object_thaw_notify (G_OBJECT (self));
}

static void
gsecret_service_class_init (GSecretServiceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GDBusProxyClass *proxy_class = G_DBUS_PROXY_CLASS (klass);

	object_class->get_property = gsecret_service_get_property;
	object_class->set_property = gsecret_service_set_property;
	object_class->dispose = gsecret_service_dispose;
	object_class->finalize = gsecret_service_finalize;

	proxy_class->g_properties_changed = gsecret_service_properties_changed;

	klass->prompt_sync = gsecret_service_real_prompt_sync;
	klass->prompt_async = gsecret_service_real_prompt_async;
	klass->prompt_finish = gsecret_service_real_prompt_finish;

	klass->item_gtype = GSECRET_TYPE_ITEM;
	klass->collection_gtype = GSECRET_TYPE_COLLECTION;

	g_object_class_install_property (object_class, PROP_FLAGS,
	             g_param_spec_flags ("flags", "Flags", "Service flags",
	                                 g_secret_service_flags_get_type (), GSECRET_SERVICE_NONE,
	                                 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (object_class, PROP_COLLECTIONS,
	             g_param_spec_boxed ("collections", "Collections", "Secret Service Collections",
	                                 _gsecret_list_get_type (), G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_type_class_add_private (klass, sizeof (GSecretServicePrivate));
}

typedef struct {
	GCancellable *cancellable;
	GSecretServiceFlags flags;
} InitClosure;

static void
init_closure_free (gpointer data)
{
	InitClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_slice_free (InitClosure, closure);
}

static gboolean
service_ensure_for_flags_sync (GSecretService *self,
                               GSecretServiceFlags flags,
                               GCancellable *cancellable,
                               GError **error)
{
	if (flags & GSECRET_SERVICE_OPEN_SESSION)
		if (!gsecret_service_ensure_session_sync (self, cancellable, error))
			return FALSE;

	if (flags & GSECRET_SERVICE_LOAD_COLLECTIONS)
		if (!gsecret_service_ensure_collections_sync (self, cancellable, error))
			return FALSE;

	return TRUE;
}

static void
on_ensure_collections (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;

	if (!gsecret_service_ensure_collections_finish (self, result, &error))
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_ensure_session (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	InitClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;

	if (!gsecret_service_ensure_session_finish (self, result, &error)) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else if (closure->flags & GSECRET_SERVICE_LOAD_COLLECTIONS) {
		gsecret_service_ensure_collections (self, closure->cancellable,
		                                    on_ensure_collections, g_object_ref (res));

	} else {
		g_simple_async_result_complete_in_idle (res);
	}

	g_object_unref (res);
}

static void
service_ensure_for_flags_async (GSecretService *self,
                                GSecretServiceFlags flags,
                                GSimpleAsyncResult *res)
{
	InitClosure *closure = g_simple_async_result_get_op_res_gpointer (res);

	closure->flags = flags;

	if (closure->flags & GSECRET_SERVICE_OPEN_SESSION)
		gsecret_service_ensure_session (self, closure->cancellable,
		                                on_ensure_session, g_object_ref (res));

	else if (closure->flags & GSECRET_SERVICE_LOAD_COLLECTIONS)
		gsecret_service_ensure_collections (self, closure->cancellable,
		                                    on_ensure_collections, g_object_ref (res));

	else
		g_simple_async_result_complete_in_idle (res);
}

static gboolean
gsecret_service_initable_init (GInitable *initable,
                               GCancellable *cancellable,
                               GError **error)
{
	GSecretService *self;

	if (!gsecret_service_initable_parent_iface->init (initable, cancellable, error))
		return FALSE;

	self = GSECRET_SERVICE (initable);
	return service_ensure_for_flags_sync (self, self->pv->init_flags, cancellable, error);
}

static void
gsecret_service_initable_iface (GInitableIface *iface)
{
	gsecret_service_initable_parent_iface = g_type_interface_peek_parent (iface);

	iface->init = gsecret_service_initable_init;
}

static void
on_init_base (GObject *source,
              GAsyncResult *result,
              gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;

	if (!gsecret_service_async_initable_parent_iface->init_finish (G_ASYNC_INITABLE (self),
	                                                               result, &error)) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	service_ensure_for_flags_async (self, self->pv->init_flags, res);
	g_object_unref (res);
}

static void
gsecret_service_async_initable_init_async (GAsyncInitable *initable,
                                           int io_priority,
                                           GCancellable *cancellable,
                                           GAsyncReadyCallback callback,
                                           gpointer user_data)
{
	GSimpleAsyncResult *res;
	InitClosure *closure;

	res = g_simple_async_result_new (G_OBJECT (initable), callback, user_data,
	                               gsecret_service_async_initable_init_async);
	closure = g_slice_new0 (InitClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, init_closure_free);

	gsecret_service_async_initable_parent_iface->init_async (initable, io_priority,
	                                                         cancellable,
	                                                         on_init_base,
	                                                         g_object_ref (res));

	g_object_unref (res);
}

static gboolean
gsecret_service_async_initable_init_finish (GAsyncInitable *initable,
                                            GAsyncResult *result,
                                            GError **error)
{
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (initable),
	                      gsecret_service_async_initable_init_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	return TRUE;
}

static void
gsecret_service_async_initable_iface (GAsyncInitableIface *iface)
{
	gsecret_service_async_initable_parent_iface = g_type_interface_peek_parent (iface);

	iface->init_async = gsecret_service_async_initable_init_async;
	iface->init_finish = gsecret_service_async_initable_init_finish;
}

void
_gsecret_service_set_default_bus_name (const gchar *bus_name)
{
	g_return_if_fail (bus_name != NULL);
	default_bus_name = bus_name;
}

static void
on_service_instance_gone (gpointer user_data,
                          GObject *where_the_object_was)
{
	G_LOCK (service_instance);

		g_assert (service_instance == where_the_object_was);
		service_instance = NULL;

	G_UNLOCK (service_instance);
}

void
gsecret_service_get (GSecretServiceFlags flags,
                     GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	GSecretService *service = NULL;
	GSimpleAsyncResult *res;
	InitClosure *closure;

	G_LOCK (service_instance);
	if (service_instance != NULL)
		service = g_object_ref (service_instance);
	G_UNLOCK (service_instance);

	/* Create a whole new service */
	if (service == NULL) {
		g_async_initable_new_async (GSECRET_TYPE_SERVICE, G_PRIORITY_DEFAULT,
		                            cancellable, callback, user_data,
		                            "g-flags", G_DBUS_PROXY_FLAGS_NONE,
		                            "g-interface-info", _gsecret_gen_service_interface_info (),
		                            "g-name", default_bus_name,
		                            "g-bus-type", G_BUS_TYPE_SESSION,
		                            "g-object-path", GSECRET_SERVICE_PATH,
		                            "g-interface-name", GSECRET_SERVICE_INTERFACE,
		                            "flags", flags,
		                            NULL);

	/* Just have to ensure that the service matches flags */
	} else {
		res = g_simple_async_result_new (G_OBJECT (service), callback,
		                                 user_data, gsecret_service_get);
		closure = g_slice_new0 (InitClosure);
		closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
		closure->flags = flags;
		g_simple_async_result_set_op_res_gpointer (res, closure, init_closure_free);

		service_ensure_for_flags_async (service, flags, res);

		g_object_unref (res);
	}
}

GSecretService *
gsecret_service_get_finish (GAsyncResult *result,
                            GError **error)
{
	GObject *service = NULL;
	GObject *source_object;

	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	source_object = g_async_result_get_source_object (result);

	/* Just ensuring that the service matches flags */
	if (g_simple_async_result_is_valid (result, source_object, gsecret_service_get)) {
		if (!g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
			service = g_object_ref (source_object);

	/* Creating a whole new service */
	} else {
		service = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object), result, error);
	}

	if (source_object)
		g_object_unref (source_object);

	if (service == NULL)
		return NULL;

	return GSECRET_SERVICE (service);
}

GSecretService *
gsecret_service_get_sync (GSecretServiceFlags flags,
                          GCancellable *cancellable,
                          GError **error)
{
	GSecretService *service = NULL;

	G_LOCK (service_instance);
	if (service_instance != NULL)
		service = g_object_ref (service_instance);
	G_UNLOCK (service_instance);

	if (service == NULL) {
		service = g_initable_new (GSECRET_TYPE_SERVICE, cancellable, error,
		                          "g-flags", G_DBUS_PROXY_FLAGS_NONE,
		                          "g-interface-info", _gsecret_gen_service_interface_info (),
		                          "g-name", default_bus_name,
		                          "g-bus-type", G_BUS_TYPE_SESSION,
		                          "g-object-path", GSECRET_SERVICE_PATH,
		                          "g-interface-name", GSECRET_SERVICE_INTERFACE,
		                          "flags", flags,
		                          NULL);
		if (service == NULL)
			return NULL;

		G_LOCK (service_instance);
		if (service_instance == NULL) {
			service_instance = service;
			g_object_weak_ref (G_OBJECT (service), on_service_instance_gone, NULL);
		}
		G_UNLOCK (service_instance);

	} else {
		if (!service_ensure_for_flags_sync (service, flags, cancellable, error)) {
			g_object_unref (service);
			return NULL;
		}
	}

	return service;
}

void
gsecret_service_new (const gchar *service_bus_name,
                     GSecretServiceFlags flags,
                     GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	if (service_bus_name == NULL)
		service_bus_name = default_bus_name;

	g_async_initable_new_async (GSECRET_TYPE_SERVICE, G_PRIORITY_DEFAULT,
	                            cancellable, callback, user_data,
	                            "g-flags", G_DBUS_PROXY_FLAGS_NONE,
	                            "g-interface-info", _gsecret_gen_service_interface_info (),
	                            "g-name", service_bus_name,
	                            "g-bus-type", G_BUS_TYPE_SESSION,
	                            "g-object-path", GSECRET_SERVICE_PATH,
	                            "g-interface-name", GSECRET_SERVICE_INTERFACE,
	                            "flags", flags,
	                            NULL);
}

GSecretService *
gsecret_service_new_finish (GAsyncResult *result,
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

	return GSECRET_SERVICE (object);
}

GSecretService *
gsecret_service_new_sync (const gchar *service_bus_name,
                          GSecretServiceFlags flags,
                          GCancellable *cancellable,
                          GError **error)
{
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);

	if (service_bus_name == NULL)
		service_bus_name = default_bus_name;

	return g_initable_new (GSECRET_TYPE_SERVICE, cancellable, error,
	                       "g-flags", G_DBUS_PROXY_FLAGS_NONE,
	                       "g-interface-info", _gsecret_gen_service_interface_info (),
	                       "g-name", service_bus_name,
	                       "g-bus-type", G_BUS_TYPE_SESSION,
	                       "g-object-path", GSECRET_SERVICE_PATH,
	                       "g-interface-name", GSECRET_SERVICE_INTERFACE,
	                       "flags", flags,
	                       NULL);
}

GSecretServiceFlags
gsecret_service_get_flags (GSecretService *self)
{
	GSecretServiceFlags flags = 0;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), GSECRET_SERVICE_NONE);

	g_mutex_lock (&self->pv->mutex);

	if (self->pv->session)
		flags |= GSECRET_SERVICE_OPEN_SESSION;
	if (self->pv->collections)
		flags |= GSECRET_SERVICE_LOAD_COLLECTIONS;

	g_mutex_unlock (&self->pv->mutex);

	return flags;
}

GList *
gsecret_service_get_collections (GSecretService *self)
{
	GList *l, *collections;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);

	g_mutex_lock (&self->pv->mutex);

	if (self->pv->collections == NULL) {
		collections = NULL;

	} else {
		collections = g_hash_table_get_values (self->pv->collections);
		for (l = collections; l != NULL; l = g_list_next (l))
			g_object_ref (l->data);
	}

	g_mutex_unlock (&self->pv->mutex);

	return collections;
}

GSecretItem *
_gsecret_service_find_item_instance (GSecretService *self,
                                     const gchar *item_path)
{
	GSecretCollection *collection;
	gchar *collection_path;
	GSecretItem *item;

	collection_path = _gsecret_util_parent_path (item_path);

	g_mutex_lock (&self->pv->mutex);
	collection = g_hash_table_lookup (self->pv->collections, collection_path);
	if (collection != NULL)
		g_object_ref (collection);
	g_mutex_unlock (&self->pv->mutex);

	g_free (collection_path);

	if (collection == NULL)
		return NULL;

	item = _gsecret_collection_find_item_instance (collection, item_path);
	g_object_unref (collection);

	return item;
}

GSecretSession *
_gsecret_service_get_session (GSecretService *self)
{
	GSecretSession *session;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);

	g_mutex_lock (&self->pv->mutex);
	session = self->pv->session;
	g_mutex_unlock (&self->pv->mutex);

	return session;
}

void
_gsecret_service_take_session (GSecretService *self,
                               GSecretSession *session)
{
	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (session != NULL);

	g_mutex_lock (&self->pv->mutex);
	if (self->pv->session == NULL)
		self->pv->session = session;
	else
		_gsecret_session_free (session);
	g_mutex_unlock (&self->pv->mutex);
}

const gchar *
gsecret_service_get_session_algorithms (GSecretService *self)
{
	GSecretSession *session;
	const gchar *algorithms;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);

	g_mutex_lock (&self->pv->mutex);
	session = self->pv->session;
	algorithms = session ? _gsecret_session_get_algorithms (session) : NULL;
	g_mutex_unlock (&self->pv->mutex);

	/* Session never changes once established, so can return const */
	return algorithms;
}

const gchar *
gsecret_service_get_session_path (GSecretService *self)
{
	GSecretSession *session;
	const gchar *path;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);

	g_mutex_lock (&self->pv->mutex);
	session = self->pv->session;
	path = session ? _gsecret_session_get_path (session) : NULL;
	g_mutex_unlock (&self->pv->mutex);

	/* Session never changes once established, so can return const */
	return path;
}

void
gsecret_service_ensure_session (GSecretService *self,
                                GCancellable *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
	GSimpleAsyncResult *res;
	GSecretSession *session;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	g_mutex_lock (&self->pv->mutex);
	session = self->pv->session;
	g_mutex_unlock (&self->pv->mutex);

	if (session == NULL) {
		_gsecret_session_open (self, cancellable, callback, user_data);

	} else {
		res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
		                                 gsecret_service_ensure_session);
		g_simple_async_result_complete_in_idle (res);
		g_object_unref (res);
	}
}

const gchar *
gsecret_service_ensure_session_finish (GSecretService *self,
                                       GAsyncResult *result,
                                       GError **error)
{
	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	if (!g_simple_async_result_is_valid (result, G_OBJECT (self),
	                                     gsecret_service_ensure_session)) {
		if (!_gsecret_session_open_finish (result, error))
			return NULL;
	}

	g_return_val_if_fail (self->pv->session != NULL, NULL);
	return gsecret_service_get_session_path (self);
}

const gchar *
gsecret_service_ensure_session_sync (GSecretService *self,
                                     GCancellable *cancellable,
                                     GError **error)
{
	GSecretSync *sync;
	const gchar *path;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_ensure_session (self, cancellable,
	                                _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	path = gsecret_service_ensure_session_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return path;
}

static GSecretCollection *
service_lookup_collection (GSecretService *self,
                           const gchar *path)
{
	GSecretCollection *collection = NULL;

	g_mutex_lock (&self->pv->mutex);

	if (self->pv->collections) {
		collection = g_hash_table_lookup (self->pv->collections, path);
		if (collection != NULL)
			g_object_ref (collection);
	}

	g_mutex_unlock (&self->pv->mutex);

	return collection;
}

static void
service_update_collections (GSecretService *self,
                            GHashTable *collections)
{
	GHashTable *previous;

	g_hash_table_ref (collections);

	g_mutex_lock (&self->pv->mutex);

	previous = self->pv->collections;
	self->pv->collections = collections;

	g_mutex_unlock (&self->pv->mutex);

	if (previous != NULL)
		g_hash_table_unref (previous);
}

typedef struct {
	GCancellable *cancellable;
	GHashTable *collections;
	gint collections_loading;
} EnsureClosure;

static GHashTable *
collections_table_new (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal,
	                              g_free, g_object_unref);
}

static void
ensure_closure_free (gpointer data)
{
	EnsureClosure *closure = data;
	g_clear_object (&closure->cancellable);
	g_hash_table_unref (closure->collections);
	g_slice_free (EnsureClosure, closure);
}

static void
on_ensure_collection (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretService *self = GSECRET_SERVICE (g_async_result_get_source_object (user_data));
	EnsureClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretCollection *collection;
	const gchar *path;
	GError *error = NULL;

	closure->collections_loading--;

	collection = gsecret_collection_new_finish (result, &error);

	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	if (collection != NULL) {
		path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (self));
		g_hash_table_insert (closure->collections, g_strdup (path), collection);
	}

	if (closure->collections_loading == 0) {
		service_update_collections (self, closure->collections);
		g_simple_async_result_complete (res);
	}

	g_object_unref (self);
	g_object_unref (res);
}

void
gsecret_service_ensure_collections (GSecretService *self,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
	EnsureClosure *closure;
	GSecretCollection *collection;
	GSimpleAsyncResult *res;
	const gchar *path;
	GVariant *paths;
	GVariantIter iter;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	paths = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Collections");
	g_return_if_fail (paths == NULL);

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_ensure_collections);
	closure = g_slice_new0 (EnsureClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->collections = collections_table_new ();
	g_simple_async_result_set_op_res_gpointer (res, closure, ensure_closure_free);

	g_variant_iter_init (&iter, paths);
	while (g_variant_iter_loop (&iter, "&o", &path)) {
		collection = service_lookup_collection (self, path);

		/* No such collection yet create a new one */
		if (collection == NULL) {
			gsecret_collection_new (self, path, cancellable,
			                        on_ensure_collection, g_object_ref (res));
			closure->collections_loading++;
		} else {
			g_hash_table_insert (closure->collections, g_strdup (path), collection);
		}
	}

	if (closure->collections_loading == 0) {
		service_update_collections (self, closure->collections);
		g_simple_async_result_complete_in_idle (res);
	}

	g_variant_unref (paths);
	g_object_unref (res);
}

gboolean
gsecret_service_ensure_collections_finish (GSecretService *self,
                                           GAsyncResult *result,
                                           GError **error)
{
	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_ensure_collections), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	return TRUE;
}

gboolean
gsecret_service_ensure_collections_sync (GSecretService *self,
                                         GCancellable *cancellable,
                                         GError **error)
{
	GSecretCollection *collection;
	GHashTable *collections;
	GVariant *paths;
	GVariantIter iter;
	const gchar *path;
	gboolean ret = TRUE;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	paths = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Collections");
	g_return_val_if_fail (paths == NULL, FALSE);

	collections = collections_table_new ();

	g_variant_iter_init (&iter, paths);
	while (g_variant_iter_next (&iter, "&o", &path)) {
		collection = service_lookup_collection (self, path);

		/* No such collection yet create a new one */
		if (collection == NULL) {
			collection = gsecret_collection_new_sync (self, path, cancellable, error);
			if (collection == NULL) {
				ret = FALSE;
				break;
			}
		}

		g_hash_table_insert (collections, g_strdup (path), collection);
	}

	if (ret)
		service_update_collections (self, collections);

	g_hash_table_unref (collections);
	g_variant_unref (paths);
	return ret;
}

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

void
gsecret_service_search_for_paths (GSecretService *self,
                                  GHashTable *attributes,
                                  GCancellable *cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_search_for_paths);

	g_dbus_proxy_call (G_DBUS_PROXY (self), "SearchItems",
	                   g_variant_new ("(@a{ss})",
	                                  _gsecret_util_variant_for_attributes (attributes)),
	                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable,
	                   on_search_items_complete, g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_service_search_for_paths_finish (GSecretService *self,
                                         GAsyncResult *result,
                                         gchar ***unlocked,
                                         gchar ***locked,
                                         GError **error)
{
	GVariant *response;
	GSimpleAsyncResult *res;
	gchar **dummy = NULL;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_search_for_paths), FALSE);
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

gboolean
gsecret_service_search_for_paths_sync (GSecretService *self,
                                       GHashTable *attributes,
                                       GCancellable *cancellable,
                                       gchar ***unlocked,
                                       gchar ***locked,
                                       GError **error)
{
	gchar **dummy = NULL;
	GVariant *response;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	response = g_dbus_proxy_call_sync (G_DBUS_PROXY (self), "SearchItems",
	                                   g_variant_new ("(@a{ss})",
	                                                  _gsecret_util_variant_for_attributes (attributes)),
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
search_closure_add_item (SearchClosure *closure,
                         GSecretItem *item)
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
	GSecretItem *item;

	closure->loading--;

	item = gsecret_item_new_finish (result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	if (item != NULL)
		search_closure_add_item (closure, item);
	if (closure->loading == 0)
		g_simple_async_result_complete (res);

	g_object_unref (res);
}

static void
search_load_item (GSecretService *self,
                  GSimpleAsyncResult *res,
                  SearchClosure *closure,
                  const gchar *path)
{
	GSecretItem *item;

	item = _gsecret_service_find_item_instance (self, path);
	if (item == NULL) {
		// TODO: xxxxxxxxxx;
		gsecret_item_new (self, path, closure->cancellable,
		                  on_search_loaded, g_object_ref (res));
		closure->loading++;
	} else {
		search_closure_add_item (closure, item);
	}
}

static void
on_search_paths (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	SearchClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;
	guint i;

	if (!gsecret_service_search_for_paths_finish (self, result, &closure->unlocked,
	                                              &closure->locked, &error)) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	for (i = 0; closure->unlocked[i] != NULL; i++)
		search_load_item (self, res, closure, closure->unlocked[i]);
	for (i = 0; closure->locked[i] != NULL; i++)
		search_load_item (self, res, closure, closure->locked[i]);

	if (closure->loading == 0)
		g_simple_async_result_complete (res);

	g_object_unref (res);
}

void
gsecret_service_search (GSecretService *self,
                        GHashTable *attributes,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GSimpleAsyncResult *res;
	SearchClosure *closure;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_search);
	closure = g_slice_new0 (SearchClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->items = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
	g_simple_async_result_set_op_res_gpointer (res, closure, search_closure_free);

	gsecret_service_search_for_paths (self, attributes, cancellable,
	                                  on_search_paths, g_object_ref (res));

	g_object_unref (res);
}

static GList *
search_finish_build (gchar **paths,
                     SearchClosure *closure)
{
	GList *results = NULL;
	GSecretItem *item;
	guint i;

	for (i = 0; paths[i]; i++) {
		item = g_hash_table_lookup (closure->items, paths[i]);
		if (item != NULL)
			results = g_list_prepend (results, g_object_ref (item));
	}

	return g_list_reverse (results);
}

gboolean
gsecret_service_search_finish (GSecretService *self,
                               GAsyncResult *result,
                               GList **unlocked,
                               GList **locked,
                               GError **error)
{
	GSimpleAsyncResult *res;
	SearchClosure *closure;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_search), FALSE);

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

gboolean
gsecret_service_search_sync (GSecretService *self,
                             GHashTable *attributes,
                             GCancellable *cancellable,
                             GList **unlocked,
                             GList **locked,
                             GError **error)
{
	GSecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_search (self, attributes, cancellable,
	                        _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = gsecret_service_search_finish (self, sync->result, unlocked, locked, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

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

	session = gsecret_service_ensure_session_finish (GSECRET_SERVICE (source),
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

void
gsecret_service_get_secret_for_path (GSecretService *self,
                                     const gchar *object_path,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (object_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_get_secret_for_path);

	closure = g_slice_new (GetClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->in = g_variant_ref_sink (g_variant_new_objv (&object_path, 1));
	g_simple_async_result_set_op_res_gpointer (res, closure, get_closure_free);

	gsecret_service_ensure_session (self, cancellable,
	                                on_get_secrets_session,
	                                g_object_ref (res));

	g_object_unref (res);
}

static GSecretValue *
service_decode_get_secrets_first (GSecretService *self,
                                  GVariant *out)
{
	GSecretSession *session;
	GSecretValue *value;
	GVariantIter *iter;
	GVariant *variant;
	const gchar *path;

	g_variant_get (out, "(a{o(oayays)})", &iter);
	while (g_variant_iter_next (iter, "{&o@(oayays)}", &path, &variant)) {
		session = _gsecret_service_get_session (self);
		value = _gsecret_session_decode_secret (session, variant);
		g_variant_unref (variant);
		break;
	}
	g_variant_iter_free (iter);
	return value;
}

static GHashTable *
service_decode_get_secrets_all (GSecretService *self,
                                GVariant *out)
{
	GSecretSession *session;
	GVariantIter *iter;
	GVariant *variant;
	GHashTable *values;
	GSecretValue *value;
	gchar *path;

	session = _gsecret_service_get_session (self);
	values = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                g_free, gsecret_value_unref);
	g_variant_get (out, "(a{o(oayays)})", &iter);
	while (g_variant_iter_loop (iter, "{o@(oayays)}", &path, &variant)) {
		value = _gsecret_session_decode_secret (session, variant);
		if (value && path)
			g_hash_table_insert (values, g_strdup (path), value);
	}
	g_variant_iter_free (iter);
	return values;
}

GSecretValue *
gsecret_service_get_secret_for_path_finish (GSecretService *self,
                                            GAsyncResult *result,
                                            GError **error)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_get_secret_for_path), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return service_decode_get_secrets_first (self, closure->out);
}

GSecretValue *
gsecret_service_get_secret_for_path_sync (GSecretService *self,
                                          const gchar *object_path,
                                          GCancellable *cancellable,
                                          GError **error)
{
	GSecretSync *sync;
	GSecretValue *value;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_get_secret_for_path (self, object_path, cancellable,
	                                     _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	value = gsecret_service_get_secret_for_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return value;

}

void
gsecret_service_get_secrets_for_paths (GSecretService *self,
                                       const gchar **object_paths,
                                       GCancellable *cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (object_paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_get_secret_for_path);

	closure = g_slice_new (GetClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->in = g_variant_ref_sink (g_variant_new_objv (object_paths, -1));
	g_simple_async_result_set_op_res_gpointer (res, closure, get_closure_free);

	gsecret_service_ensure_session (self, cancellable,
	                                on_get_secrets_session,
	                                g_object_ref (res));

	g_object_unref (res);
}

GHashTable *
gsecret_service_get_secrets_for_paths_finish (GSecretService *self,
                                              GAsyncResult *result,
                                              GError **error)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_get_secret_for_path), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return service_decode_get_secrets_all (self, closure->out);
}

GHashTable *
gsecret_service_get_secrets_for_paths_sync (GSecretService *self,
                                            const gchar **object_paths,
                                            GCancellable *cancellable,
                                            GError **error)
{
	GSecretSync *sync;
	GHashTable *secrets;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_get_secrets_for_paths (self, object_paths, cancellable,
	                                       _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	secrets = gsecret_service_get_secrets_for_paths_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return secrets;
}

void
gsecret_service_get_secrets (GSecretService *self,
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

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_get_secrets);
	closure = g_slice_new (GetClosure);
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

	gsecret_service_ensure_session (self, cancellable,
	                                on_get_secrets_session,
	                                g_object_ref (res));

	g_object_unref (res);
}

GHashTable *
gsecret_service_get_secrets_finish (GSecretService *self,
                                    GAsyncResult *result,
                                    GError **error)
{
	GSimpleAsyncResult *res;
	GetClosure *closure;
	GHashTable *with_paths;
	GHashTable *with_items;
	GHashTableIter iter;
	const gchar *path;
	GSecretValue *value;
	GSecretItem *item;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_get_secret_for_path), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	with_paths = service_decode_get_secrets_all (self, closure->out);
	g_return_val_if_fail (with_paths != NULL, NULL);

	with_items = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                    g_object_unref, gsecret_value_unref);

	g_hash_table_iter_init (&iter, with_paths);
	while (g_hash_table_iter_next (&iter, (gpointer *)&path, (gpointer *)&value)) {
		item = g_hash_table_lookup (closure->items, path);
		if (item != NULL)
			g_hash_table_insert (with_items, g_object_ref (item),
			                     gsecret_value_ref (value));
	}

	g_hash_table_unref (with_paths);
	return with_items;
}

GHashTable *
gsecret_service_get_secrets_sync (GSecretService *self,
                                  GList *items,
                                  GCancellable *cancellable,
                                  GError **error)
{
	GSecretSync *sync;
	GHashTable *secrets;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_get_secrets (self, items, cancellable,
	                             _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	secrets = gsecret_service_get_secrets_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return secrets;
}

typedef struct {
	GCancellable *cancellable;
	GSecretPrompt *prompt;
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
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;
	GVariantIter iter;
	GVariant *retval;
	gchar *path;
	gboolean ret;

	ret = gsecret_service_prompt_finish (self, result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	if (ret) {
		retval = gsecret_prompt_get_result_value (closure->prompt, G_VARIANT_TYPE ("ao"));
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
	GSecretService *self = GSECRET_SERVICE (g_async_result_get_source_object (user_data));
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

		if (_gsecret_util_empty_path (prompt)) {
			for (i = 0; xlocked[i]; i++)
				g_ptr_array_add (closure->xlocked, g_strdup (xlocked[i]));
			g_simple_async_result_complete (res);

		} else {
			closure->prompt = gsecret_prompt_instance (self, prompt);
			gsecret_service_prompt (self, closure->prompt, closure->cancellable,
			                        on_xlock_prompted, g_object_ref (res));
		}

		g_strfreev (xlocked);
		g_variant_unref (retval);
	}

	g_object_unref (self);
	g_object_unref (res);
}

static GSimpleAsyncResult *
service_xlock_paths_async (GSecretService *self,
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
	closure = g_slice_new (XlockClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : cancellable;
	g_simple_async_result_set_op_res_gpointer (res, closure, xlock_closure_free);

	g_dbus_proxy_call (G_DBUS_PROXY (self), method,
	                   g_variant_new ("(@ao)", g_variant_new_objv (paths, -1)),
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                   cancellable, on_xlock_called, g_object_ref (res));

	return res;
}

static gint
service_xlock_paths_finish (GSecretService *self,
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
service_xlock_async (GSecretService *self,
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
service_xlock_finish (GSecretService *self,
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

void
gsecret_service_lock (GSecretService *self,
                      GList *objects,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	service_xlock_async (self, "Lock", objects, cancellable, callback, user_data);
}

gint
gsecret_service_lock_finish (GSecretService *self,
                             GAsyncResult *result,
                             GList **locked,
                             GError **error)
{
	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	return service_xlock_finish (self, result, locked, error);
}

gint
gsecret_service_lock_sync (GSecretService *self,
                           GList *objects,
                           GCancellable *cancellable,
                           GList **locked,
                           GError **error)
{
	GSecretSync *sync;
	gint count;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_lock (self, objects, cancellable,
	                      _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = gsecret_service_lock_finish (self, sync->result, locked, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return count;
}

gint
gsecret_service_lock_paths_sync (GSecretService *self,
                                 const gchar **paths,
                                 GCancellable *cancellable,
                                 gchar ***locked,
                                 GError **error)
{
	GSecretSync *sync;
	gint count;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (paths != NULL, -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_lock_paths (self, paths, cancellable,
	                            _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = gsecret_service_lock_paths_finish (self, sync->result,
	                                           locked, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return count;
}

void
gsecret_service_lock_paths (GSecretService *self,
                            const gchar **paths,
                            GCancellable *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = service_xlock_paths_async (self, "Lock", paths, cancellable,
	                                 callback, user_data);

	g_object_unref (res);
}

gint
gsecret_service_lock_paths_finish (GSecretService *self,
                                   GAsyncResult *result,
                                   gchar ***unlocked,
                                   GError **error)
{
	g_return_val_if_fail (GSECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (unlocked != NULL, -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	return service_xlock_paths_finish (self, result, unlocked, error);
}

gint
gsecret_service_unlock_paths_sync (GSecretService *self,
                                   const gchar **paths,
                                   GCancellable *cancellable,
                                   gchar ***unlocked,
                                   GError **error)
{
	GSecretSync *sync;
	gint count;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (paths != NULL, -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (unlocked != NULL, -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_unlock_paths (self, paths, cancellable,
	                              _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = gsecret_service_unlock_paths_finish (self, sync->result,
	                                             unlocked, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return count;
}

void
gsecret_service_unlock_paths (GSecretService *self,
                              const gchar **paths,
                              GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	GSimpleAsyncResult *res;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (paths != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = service_xlock_paths_async (self, "Unlock",
	                                 paths, cancellable,
	                                 callback, user_data);

	g_object_unref (res);
}

gint
gsecret_service_unlock_paths_finish (GSecretService *self,
                                     GAsyncResult *result,
                                     gchar ***unlocked,
                                     GError **error)
{
	g_return_val_if_fail (GSECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	return service_xlock_paths_finish (self, result,
	                                   unlocked, error);
}

void
gsecret_service_unlock (GSecretService *self,
                        GList *objects,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	service_xlock_async (self, "Unlock", objects, cancellable, callback, user_data);
}

gint
gsecret_service_unlock_finish (GSecretService *self,
                               GAsyncResult *result,
                               GList **unlocked,
                               GError **error)
{
	g_return_val_if_fail (GSECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_unlock_paths), -1);

	return service_xlock_finish (self, result, unlocked, error);
}

gint
gsecret_service_unlock_sync (GSecretService *self,
                             GList *objects,
                             GCancellable *cancellable,
                             GList **unlocked,
                             GError **error)
{
	GSecretSync *sync;
	gint count;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), -1);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), -1);
	g_return_val_if_fail (error == NULL || *error == NULL, -1);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_unlock (self, objects, cancellable,
	                        _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	count = gsecret_service_unlock_finish (self, sync->result,
	                                       unlocked, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return count;
}

gboolean
gsecret_service_prompt_sync (GSecretService *self,
                             GSecretPrompt *prompt,
                             GCancellable *cancellable,
                             GError **error)
{
	GSecretServiceClass *klass;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (GSECRET_IS_PROMPT (prompt), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	klass = GSECRET_SERVICE_GET_CLASS (self);
	g_return_val_if_fail (klass->prompt_sync != NULL, FALSE);

	return (klass->prompt_sync) (self, prompt, cancellable, error);
}

void
gsecret_service_prompt (GSecretService *self,
                        GSecretPrompt *prompt,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GSecretServiceClass *klass;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (GSECRET_IS_PROMPT (prompt));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	klass = GSECRET_SERVICE_GET_CLASS (self);
	g_return_if_fail (klass->prompt_async != NULL);

	(klass->prompt_async) (self, prompt, cancellable, callback, user_data);
}

gboolean
gsecret_service_prompt_finish (GSecretService *self,
                               GAsyncResult *result,
                               GError **error)
{
	GSecretServiceClass *klass;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	klass = GSECRET_SERVICE_GET_CLASS (self);
	g_return_val_if_fail (klass->prompt_finish != NULL, FALSE);

	return (klass->prompt_finish) (self, result, error);
}

typedef struct {
	gchar *collection_path;
	GSecretValue *value;
	GCancellable *cancellable;
	GSecretPrompt *prompt;
	gboolean created;
} StoreClosure;

static void
store_closure_free (gpointer data)
{
	StoreClosure *closure = data;
	g_free (closure->collection_path);
	gsecret_value_unref (closure->value);
	g_clear_object (&closure->cancellable);
	g_clear_object (&closure->prompt);
	g_free (closure);
}

void
gsecret_service_store (GSecretService *self,
                       const GSecretSchema *schema,
                       const gchar *collection_path,
                       const gchar *label,
                       GSecretValue *value,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data,
                       ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (collection_path != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (value != NULL);

	va_start (va, user_data);
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	gsecret_service_storev (self, schema, attributes, collection_path,
	                        label, value, cancellable, callback, user_data);

	g_hash_table_unref (attributes);
}

static void
on_store_prompt (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	StoreClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	closure->created = gsecret_service_prompt_finish (GSECRET_SERVICE (source), result, &error);
	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
on_store_create (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	StoreClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretService *self = GSECRET_SERVICE (g_async_result_get_source_object (result));
	const gchar *prompt_path = NULL;
	const gchar *item_path = NULL;
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o&o)", &item_path, &prompt_path);
		if (!_gsecret_util_empty_path (prompt_path)) {
			closure->prompt = gsecret_prompt_instance (self, prompt_path);
			gsecret_service_prompt (self, closure->prompt, closure->cancellable,
			                        on_store_prompt, g_object_ref (res));

		} else {
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

void
gsecret_service_storev (GSecretService *self,
                        const GSecretSchema *schema,
                        GHashTable *attributes,
                        const gchar *collection_path,
                        const gchar *label,
                        GSecretValue *value,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GSimpleAsyncResult *res;
	GSecretSession *session;
	GVariant *attrs;
	StoreClosure *closure;
	GVariantBuilder builder;
	GVariant *params;
	GDBusProxy *proxy;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (collection_path != NULL);
	g_return_if_fail (label != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Build up the attributes */
	attrs = _gsecret_util_variant_for_attributes (attributes);

	/* Build up the various properties */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&builder, "{sv}", GSECRET_SERVICE_INTERFACE "Attributes", attrs);
	g_variant_builder_add (&builder, "{sv}", GSECRET_SERVICE_INTERFACE "Label", g_variant_new_string (label));
	g_variant_builder_add (&builder, "{sv}", GSECRET_SERVICE_INTERFACE "Schema", g_variant_new_string (schema->schema_name));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_storev);
	closure = g_new0 (StoreClosure, 1);
	closure->collection_path = g_strdup (collection_path);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, store_closure_free);

	session = _gsecret_service_get_session (self);
	params = g_variant_new ("(&a{sv}&(oayays)b)",
	                        g_variant_builder_end (&builder),
	                        _gsecret_session_encode_secret (session, value),
	                        TRUE);

	proxy = G_DBUS_PROXY (self);
	g_dbus_connection_call (g_dbus_proxy_get_connection (proxy),
	                        g_dbus_proxy_get_name (proxy),
	                        closure->collection_path,
	                        GSECRET_COLLECTION_INTERFACE,
	                        "CreateItem", params, G_VARIANT_TYPE ("(oo)"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                        closure->cancellable, on_store_create,
	                        g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_service_store_finish (GSecretService *self,
                              GAsyncResult *result,
                              GError **error)
{
	GSimpleAsyncResult *res;
	StoreClosure *closure;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_storev), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (!g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->created;
}

gboolean
gsecret_service_store_sync (GSecretService *self,
                            const GSecretSchema *schema,
                            const gchar *collection_path,
                            const gchar *label,
                            GSecretValue *value,
                            GCancellable *cancellable,
                            GError **error,
                            ...)
{
	GHashTable *attributes;
	gboolean ret;
	va_list va;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (collection_path != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	va_start (va, error);
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	ret = gsecret_service_storev_sync (self, schema, attributes, collection_path,
	                                   label, value, cancellable, error);

	g_hash_table_unref (attributes);

	return ret;
}

gboolean
gsecret_service_storev_sync (GSecretService *self,
                             const GSecretSchema *schema,
                             GHashTable *attributes,
                             const gchar *collection_path,
                             const gchar *label,
                             GSecretValue *value,
                             GCancellable *cancellable,
                             GError **error)
{
	GSecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (schema != NULL, FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);
	g_return_val_if_fail (collection_path != NULL, FALSE);
	g_return_val_if_fail (label != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_storev (self, schema, attributes, collection_path,
	                        label, value, cancellable, _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = gsecret_service_store_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return ret;
}

typedef struct {
	GSecretValue *value;
	GCancellable *cancellable;
} LookupClosure;

static void
lookup_closure_free (gpointer data)
{
	LookupClosure *closure = data;
	gsecret_value_unref (closure->value);
	g_clear_object (&closure->cancellable);
	g_slice_free (LookupClosure, closure);
}

void
gsecret_service_lookup (GSecretService *self,
                        const GSecretSchema *schema,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data,
                        ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	gsecret_service_lookupv (self, attributes, cancellable, callback, user_data);

	g_hash_table_unref (attributes);
}

static void
on_lookup_get_secret (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	LookupClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;

	closure->value = gsecret_service_get_secret_for_path_finish (self, result, &error);
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
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;
	gchar **unlocked = NULL;

	gsecret_service_unlock_paths_finish (GSECRET_SERVICE (source),
	                                     result, &unlocked, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else if (unlocked && unlocked[0]) {
		gsecret_service_get_secret_for_path (self, unlocked[0],
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
	GSecretService *self = GSECRET_SERVICE (source);
	GError *error = NULL;
	gchar **unlocked = NULL;
	gchar **locked = NULL;

	gsecret_service_search_for_paths_finish (self, result, &unlocked, &locked, &error);
	if (error != NULL) {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);

	} else if (unlocked && unlocked[0]) {
		gsecret_service_get_secret_for_path (self, unlocked[0],
		                                     closure->cancellable,
		                                     on_lookup_get_secret,
		                                     g_object_ref (res));

	} else if (locked && locked[0]) {
		const gchar *paths[] = { locked[0], NULL };
		gsecret_service_unlock_paths (self, paths,
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

void
gsecret_service_lookupv (GSecretService *self,
                         GHashTable *attributes,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	GSimpleAsyncResult *res;
	LookupClosure *closure;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_lookupv);
	closure = g_slice_new0 (LookupClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, lookup_closure_free);

	gsecret_service_search_for_paths (self, attributes, cancellable,
	                                  on_lookup_searched, g_object_ref (res));

	g_object_unref (res);
}

GSecretValue *
gsecret_service_lookup_finish (GSecretService *self,
                               GAsyncResult *result,
                               GError **error)
{
	GSimpleAsyncResult *res;
	LookupClosure *closure;
	GSecretValue *value;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_lookupv), NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	value = closure->value;
	closure->value = NULL;
	return value;
}

GSecretValue *
gsecret_service_lookup_sync (GSecretService *self,
                             const GSecretSchema *schema,
                             GCancellable *cancellable,
                             GError **error,
                             ...)
{
	GHashTable *attributes;
	GSecretValue *value;
	va_list va;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (schema != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);

	va_start (va, error);
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	value = gsecret_service_lookupv_sync (self, attributes, cancellable, error);

	g_hash_table_unref (attributes);

	return value;
}

GSecretValue *
gsecret_service_lookupv_sync (GSecretService *self,
                              GHashTable *attributes,
                              GCancellable *cancellable,
                              GError **error)
{
	GSecretSync *sync;
	GSecretValue *value;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (attributes != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_lookupv (self, attributes, cancellable,
	                         _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	value = gsecret_service_lookup_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return value;
}

typedef struct {
	GCancellable *cancellable;
	GSecretPrompt *prompt;
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

	gsecret_service_prompt_finish (GSECRET_SERVICE (source), result, &error);

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
	GSecretService *self = GSECRET_SERVICE (g_async_result_get_source_object (user_data));
	const gchar *prompt_path;
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (error == NULL) {
		g_variant_get (retval, "(&o)", &prompt_path);

		if (_gsecret_util_empty_path (prompt_path)) {
			closure->deleted = TRUE;
			g_simple_async_result_complete (res);

		} else {
			closure->prompt = gsecret_prompt_instance (self, prompt_path);

			gsecret_service_prompt (self, closure->prompt,
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
gsecret_service_delete_path (GSecretService *self,
                             const gchar *item_path,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_if_fail (GSECRET_IS_SERVICE (self));
	g_return_if_fail (item_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_delete_path);
	closure = g_slice_new0 (DeleteClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, delete_closure_free);

	g_dbus_connection_call (g_dbus_proxy_get_connection (G_DBUS_PROXY (self)),
	                        g_dbus_proxy_get_name (G_DBUS_PROXY (self)),
	                        item_path, GSECRET_ITEM_INTERFACE,
	                        "Delete", g_variant_new ("()"), G_VARIANT_TYPE ("(o)"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                        cancellable, on_delete_complete, g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_service_delete_path_finish (GSecretService *self,
                                    GAsyncResult *result,
                                    GError **error)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_delete_path), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->deleted;
}

gboolean
gsecret_service_delete_path_sync (GSecretService *self,
                                  const gchar *item_path,
                                  GCancellable *cancellable,
                                  GError **error)
{
	GSecretSync *sync;
	gboolean result;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (item_path != NULL, FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_delete_path (self, item_path, cancellable, _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = gsecret_service_delete_path_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return result;
}

static void
on_delete_password_complete (GObject *source,
                             GAsyncResult *result,
                             gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretService *self = GSECRET_SERVICE (g_async_result_get_source_object (user_data));
	DeleteClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GError *error = NULL;

	closure->deleted = gsecret_service_delete_path_finish (self, result, &error);
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
	GSecretService *self = GSECRET_SERVICE (g_async_result_get_source_object (user_data));
	const gchar *path = NULL;
	GError *error = NULL;
	gchar **locked;
	gchar **unlocked;

	gsecret_service_search_for_paths_finish (self, result, &unlocked, &locked, &error);
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
			gsecret_service_delete_path (self, path,
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

void
gsecret_service_remove (GSecretService *self,
                        const GSecretSchema *schema,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data,
                        ...)
{
	GHashTable *attributes;
	va_list va;

	g_return_if_fail (GSECRET_SERVICE (self));
	g_return_if_fail (schema != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	va_start (va, user_data);
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	gsecret_service_removev (self, attributes, cancellable,
	                         callback, user_data);

	g_hash_table_unref (attributes);
}

void
gsecret_service_removev (GSecretService *self,
                         GHashTable *attributes,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_if_fail (GSECRET_SERVICE (self));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                 gsecret_service_remove);
	closure = g_slice_new0 (DeleteClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	g_simple_async_result_set_op_res_gpointer (res, closure, delete_closure_free);

	gsecret_service_search_for_paths (self, attributes, cancellable,
	                                  on_search_delete_password, g_object_ref (res));

	g_object_unref (res);
}

gboolean
gsecret_service_remove_finish (GSecretService *self,
                               GAsyncResult *result,
                               GError **error)
{
	GSimpleAsyncResult *res;
	DeleteClosure *closure;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self),
	                      gsecret_service_remove), FALSE);

	res = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (res, error))
		return FALSE;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return closure->deleted;
}

gboolean
gsecret_service_remove_sync (GSecretService *self,
                             const GSecretSchema* schema,
                             GCancellable *cancellable,
                             GError **error,
                             ...)
{
	GHashTable *attributes;
	gboolean result;
	va_list va;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	va_start (va, error);
	attributes = _gsecret_util_attributes_for_varargs (schema, va);
	va_end (va);

	result = gsecret_service_removev_sync (self, attributes, cancellable, error);

	g_hash_table_unref (attributes);

	return result;
}

gboolean
gsecret_service_removev_sync (GSecretService *self,
                              GHashTable *attributes,
                              GCancellable *cancellable,
                              GError **error)
{
	GSecretSync *sync;
	gboolean result;

	g_return_val_if_fail (GSECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_service_removev (self, attributes, cancellable,
	                         _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = gsecret_service_remove_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return result;
}
