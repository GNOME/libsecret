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

EGG_SECURE_GLIB_DEFINITIONS ();

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
	} else {

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

		g_object_unref (service);
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

		if (service) {
			G_LOCK (service_instance);
			if (service_instance == NULL) {
				service_instance = service;
				g_object_weak_ref (G_OBJECT (service), on_service_instance_gone, NULL);
			}
			G_UNLOCK (service_instance);
		}
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

		if (service != NULL) {
			G_LOCK (service_instance);
			if (service_instance == NULL) {
				service_instance = service;
				g_object_weak_ref (G_OBJECT (service), on_service_instance_gone, NULL);
			}
			G_UNLOCK (service_instance);
		}

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
	GSecretCollection *collection = NULL;
	gchar *collection_path;
	GSecretItem *item;

	collection_path = _gsecret_util_parent_path (item_path);

	g_mutex_lock (&self->pv->mutex);
	if (self->pv->collections) {
		collection = g_hash_table_lookup (self->pv->collections, collection_path);
		if (collection != NULL)
			g_object_ref (collection);
	}
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
	g_return_if_fail (paths != NULL);

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
	g_return_val_if_fail (paths != NULL, FALSE);

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
