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

#include "secret-backend.h"
#include "secret-collection.h"
#include "secret-dbus-generated.h"
#include "secret-item.h"
#include "secret-paths.h"
#include "secret-private.h"
#include "secret-service.h"
#include "secret-types.h"
#include "secret-value.h"

#include "libsecret/secret-enum-types.h"

#include "egg/egg-secure-memory.h"

/**
 * SecretService:
 *
 * A proxy object representing the Secret Service.
 *
 * A #SecretService object either represents an implementation of the
 * [`org.freedesktop.Secret`](https://specifications.freedesktop.org/secret-service/latest/)
 * D-Bus service or a file that is encrypted using a master secret that was
 * provided by the
 * [secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Secret.html).
 *
 * Normally a single #SecretService object can be shared between multiple
 * callers. The [func@Service.get] method is used to access this #SecretService
 * object. If a new independent #SecretService object is required, use
 * [func@Service.open].
 *
 * In order to securely transfer secrets to the Sercret Service, a session
 * is established. This session can be established while initializing a
 * #SecretService object by passing the %SECRET_SERVICE_OPEN_SESSION flag
 * to the [func@Service.get] or [func@Service.open] functions. In order to
 * establish a session on an already existing #SecretService, use the
 * [method@Service.ensure_session] function.
 *
 * To search for items, use the [method@Service.search] method.
 *
 * Multiple collections can exist in the Secret Service, each of which contains
 * secret items. In order to instantiate [class@Collection] objects which
 * represent those collections while initializing a #SecretService then pass
 * the %SECRET_SERVICE_LOAD_COLLECTIONS flag to the [func@Service.get] or
 * [func@Service.open] functions. In order to establish a session on an already
 * existing #SecretService, use the [method@Service.load_collections] function.
 * To access the list of collections use [method@Service.get_collections].
 *
 * Certain actions on the Secret Service require user prompting to complete,
 * such as creating a collection, or unlocking a collection. When such a prompt
 * is necessary, then a [class@Prompt] object is created by this library, and
 * passed to the [method@Service.prompt] method. In this way it is handled
 * automatically.
 *
 * In order to customize prompt handling, override the
 * [vfunc@Service.prompt_async] and [vfunc@Service.prompt_finish] virtual
 * methods of the #SecretService class.
 *
 * Stability: Stable
 */

/**
 * SecretServiceClass:
 * @parent_class: the parent class
 * @collection_gtype: the [alias@GObject.Type] of the [class@Collection] objects
 *   instantiated by the #SecretService proxy
 * @item_gtype: the [alias@GObject.Type] of the [class@Item] objects
 *   instantiated by the #SecretService proxy
 * @prompt_async: called to perform asynchronous prompting when necessary
 * @prompt_finish: called to complete an asynchronous prompt operation
 * @prompt_sync: called to perform synchronous prompting when necessary
 * @get_collection_gtype: called to get the GObject type for collections
 *   instantiated by the #SecretService proxy
 * @get_item_gtype: called to get the GObject type for collections
 *   instantiated by the #SecretService proxy
 *
 * The class for #SecretService.
 */

/**
 * SecretServiceFlags:
 * @SECRET_SERVICE_NONE: no flags for initializing the #SecretService
 * @SECRET_SERVICE_OPEN_SESSION: establish a session for transfer of secrets
 *   while initializing the #SecretService
 * @SECRET_SERVICE_LOAD_COLLECTIONS: load collections while initializing the
 *   #SecretService
 *
 * Flags which determine which parts of the #SecretService proxy are initialized
 * during a [func@Service.get] or [func@Service.open] operation.
 */

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

GQuark _secret_error_quark = 0;

enum {
	PROP_0,
	PROP_FLAGS,
	PROP_COLLECTIONS
};

struct _SecretServicePrivate {
	/* No change between construct and finalize */
	GCancellable *cancellable;
	SecretServiceFlags init_flags;

	/* Locked by mutex */
	GMutex mutex;
	gpointer session;
	GHashTable *collections;
};

G_LOCK_DEFINE (service_instance);
static gpointer service_instance = NULL;
static guint service_watch = 0;

static GInitableIface *secret_service_initable_parent_iface = NULL;

static GAsyncInitableIface *secret_service_async_initable_parent_iface = NULL;

static SecretBackendInterface *secret_service_backend_parent_iface = NULL;

static void   secret_service_initable_iface         (GInitableIface *iface);

static void   secret_service_async_initable_iface   (GAsyncInitableIface *iface);

static void   secret_service_backend_iface          (SecretBackendInterface *iface);

G_DEFINE_TYPE_WITH_CODE (SecretService, secret_service, G_TYPE_DBUS_PROXY,
                         G_ADD_PRIVATE (SecretService)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, secret_service_initable_iface);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, secret_service_async_initable_iface);
			 G_IMPLEMENT_INTERFACE (SECRET_TYPE_BACKEND, secret_service_backend_iface);
			 _secret_backend_ensure_extension_point ();
			 g_io_extension_point_implement (SECRET_BACKEND_EXTENSION_POINT_NAME,
                                                         g_define_type_id,
                                                         "service",
                                                         0)
);

static SecretService *
service_get_instance (void)
{
	SecretService *instance = NULL;

	G_LOCK (service_instance);
	if (service_instance != NULL)
		instance = g_object_ref (service_instance);
	G_UNLOCK (service_instance);

	return instance;
}

static gboolean
service_uncache_instance (SecretService *which)
{
	SecretService *instance = NULL;
	guint watch = 0;
	gboolean matched = FALSE;

	G_LOCK (service_instance);
	if (which == NULL || service_instance == which) {
		instance = service_instance;
		service_instance = NULL;
		watch = service_watch;
		service_watch = 0;
		matched = TRUE;
	}
	G_UNLOCK (service_instance);

	if (instance != NULL)
		g_object_unref (instance);
	if (watch != 0)
		g_bus_unwatch_name (watch);

	_secret_backend_uncache_instance ();

	return matched;
}

static void
on_service_instance_vanished (GDBusConnection *connection,
                              const gchar *name,
                              gpointer user_data)
{
	if (!service_uncache_instance (user_data)) {
		g_warning ("Global default SecretService instance out of sync "
		           "with the watch for its DBus name");
	}
}

static void
service_cache_instance (SecretService *instance)
{
	GDBusProxy *proxy;
	guint watch;

	g_object_ref (instance);
	proxy = G_DBUS_PROXY (instance);
	watch = g_bus_watch_name_on_connection (g_dbus_proxy_get_connection (proxy),
	                                        g_dbus_proxy_get_name (proxy),
	                                        G_BUS_NAME_WATCHER_FLAGS_NONE,
	                                        NULL, on_service_instance_vanished,
	                                        instance, NULL);

	G_LOCK (service_instance);
	if (service_instance == NULL) {
		service_instance = instance;
		instance = NULL;
		service_watch = watch;
		watch = 0;
	}
	G_UNLOCK (service_instance);

	if (instance != NULL)
		g_object_unref (instance);
	if (watch != 0)
		g_bus_unwatch_name (watch);
}

static void
secret_service_init (SecretService *self)
{
	self->pv = secret_service_get_instance_private (self);

	g_mutex_init (&self->pv->mutex);
	self->pv->cancellable = g_cancellable_new ();
}

static void
secret_service_get_property (GObject *obj,
                             guint prop_id,
                             GValue *value,
                             GParamSpec *pspec)
{
	SecretService *self = SECRET_SERVICE (obj);

	switch (prop_id) {
	case PROP_FLAGS:
		g_value_set_flags (value, secret_service_get_flags (self));
		break;
	case PROP_COLLECTIONS:
		g_value_take_boxed (value, secret_service_get_collections (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
secret_service_set_property (GObject *obj,
                             guint prop_id,
                             const GValue *value,
                             GParamSpec *pspec)
{
	SecretService *self = SECRET_SERVICE (obj);

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
secret_service_dispose (GObject *obj)
{
	SecretService *self = SECRET_SERVICE (obj);

	g_cancellable_cancel (self->pv->cancellable);

	G_OBJECT_CLASS (secret_service_parent_class)->dispose (obj);
}

static void
secret_service_finalize (GObject *obj)
{
	SecretService *self = SECRET_SERVICE (obj);

	_secret_session_free (self->pv->session);
	if (self->pv->collections)
		g_hash_table_destroy (self->pv->collections);
	g_clear_object (&self->pv->cancellable);
	g_mutex_clear (&self->pv->mutex);

	G_OBJECT_CLASS (secret_service_parent_class)->finalize (obj);
}

static GVariant *
secret_service_real_prompt_sync (SecretService *self,
                                 SecretPrompt *prompt,
                                 GCancellable *cancellable,
                                 const GVariantType *return_type,
                                 GError **error)
{
	return secret_prompt_perform_sync (prompt, NULL, cancellable, return_type, error);
}

static void
on_real_prompt_completed (GObject *source,
                          GAsyncResult *result,
                          gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GError *error = NULL;
	GVariant *retval;

	retval = secret_prompt_perform_finish (SECRET_PROMPT (source),
	                                       result,
	                                       &error);
	if (retval != NULL)
		g_task_return_pointer (task,
		                       g_steal_pointer (&retval),
		                       (GDestroyNotify) g_variant_unref);
	else
		g_task_return_error (task, g_steal_pointer (&error));

	g_object_unref (task);
}

static void
secret_service_real_prompt_async (SecretService *self,
                                  SecretPrompt *prompt,
                                  const GVariantType *return_type,
                                  GCancellable *cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
	GTask *task;

	task =  g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_real_prompt_async);

	secret_prompt_perform (prompt, 0, return_type, cancellable,
	                       on_real_prompt_completed,
	                       g_object_ref (task));

	g_object_unref (task);
}

static GVariant *
secret_service_real_prompt_finish (SecretService *self,
                                   GAsyncResult *result,
                                   GError **error)
{
	GVariant *retval;

	g_return_val_if_fail (g_task_is_valid (result, self), NULL);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                      secret_service_real_prompt_async, NULL);

	retval = g_task_propagate_pointer (G_TASK (result), error);
	if (!retval) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	return retval;
}

static void
handle_property_changed (SecretService *self,
                         const gchar *property_name,
                         GVariant *value)
{
	gboolean perform;

	g_variant_ref_sink (value);

	if (g_str_equal (property_name, "Collections")) {

		g_mutex_lock (&self->pv->mutex);
		perform = self->pv->collections != NULL;
		g_mutex_unlock (&self->pv->mutex);

		if (perform)
			secret_service_load_collections (self, self->pv->cancellable, NULL, NULL);
	}

	g_variant_unref (value);
}

static void
secret_service_properties_changed (GDBusProxy *proxy,
                                   GVariant *changed_properties,
                                   const gchar* const *invalidated_properties)
{
	SecretService *self = SECRET_SERVICE (proxy);
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
secret_service_signal (GDBusProxy *proxy,
                       const gchar *sender_name,
                       const gchar *signal_name,
                       GVariant *parameters)
{
	SecretService *self = SECRET_SERVICE (proxy);
	SecretCollection *collection;
	const gchar *collection_path;
	GVariantBuilder builder;
	gboolean found = FALSE;
	GVariantIter iter;
	GVariant *value;
	GVariant *paths;
	GVariant *path;

	/*
	 * Remember that these signals come from a time before PropertiesChanged.
	 * We support them because they're in the spec, and ksecretservice uses them.
	 */

	paths = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Collections");
	g_return_if_fail (paths != NULL);

	/* A new collection was added, add it to the Collections property */
	if (g_str_equal (signal_name, SECRET_SIGNAL_COLLECTION_CREATED)) {
		g_variant_get (parameters, "(@o)", &value);
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ao"));
		g_variant_iter_init (&iter, paths);
		while ((path = g_variant_iter_next_value (&iter)) != NULL) {
			if (g_variant_equal (path, value)) {
				found = TRUE;
				break;
			}
			g_variant_builder_add_value (&builder, path);
			g_variant_unref (path);
		}
		if (!found) {
			g_variant_builder_add_value (&builder, value);
			handle_property_changed (self, "Collections", g_variant_builder_end (&builder));
		}
		g_variant_builder_clear (&builder);
		g_variant_unref (value);

	/* A collection was deleted, remove it from the Collections property */
	} else if (g_str_equal (signal_name, SECRET_SIGNAL_COLLECTION_DELETED)) {
		g_variant_get (parameters, "(@o)", &value);
		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ao"));
		g_variant_iter_init (&iter, paths);
		while ((path = g_variant_iter_next_value (&iter)) != NULL) {
			if (g_variant_equal (path, value))
				found = TRUE;
			else
				g_variant_builder_add_value (&builder, path);
			g_variant_unref (path);
		}
		if (found)
			handle_property_changed (self, "Collections", g_variant_builder_end (&builder));
		g_variant_unref (value);

	/* The collection changed, update it */
	} else if (g_str_equal (signal_name, SECRET_SIGNAL_COLLECTION_CHANGED)) {
		g_variant_get (parameters, "(&o)", &collection_path);

		g_mutex_lock (&self->pv->mutex);

		if (self->pv->collections)
			collection = g_hash_table_lookup (self->pv->collections, collection_path);
		else
			collection = NULL;
		if (collection)
			g_object_ref (collection);

		g_mutex_unlock (&self->pv->mutex);

		if (collection) {
			secret_collection_refresh (collection);
			g_object_unref (collection);
		}
	}

	g_variant_unref (paths);
}

static GType
secret_service_real_get_collection_gtype (SecretService *self)
{
	SecretServiceClass *klass;

	klass = SECRET_SERVICE_GET_CLASS (self);
	return klass->collection_gtype;
}

static GType
secret_service_real_get_item_gtype (SecretService *self)
{
	SecretServiceClass *klass;

	klass = SECRET_SERVICE_GET_CLASS (self);
	return klass->item_gtype;
}

static const gchar *
get_default_bus_name (void)
{
	const gchar *bus_name;

	bus_name = g_getenv ("SECRET_SERVICE_BUS_NAME");
	if (bus_name == NULL)
		bus_name = SECRET_SERVICE_BUS_NAME;

	return bus_name;
}

static GObject *
secret_service_constructor (GType type,
                            guint n_construct_properties,
                            GObjectConstructParam *construct_properties)
{
	GObject *object;

	object = G_OBJECT_CLASS (secret_service_parent_class)->
		constructor (type, n_construct_properties, construct_properties);
	g_object_set (object,
		      "g-flags", G_DBUS_PROXY_FLAGS_NONE,
		      "g-interface-info", _secret_gen_service_interface_info (),
		      "g-name", get_default_bus_name (),
		      "g-bus-type", G_BUS_TYPE_SESSION,
		      "g-object-path", SECRET_SERVICE_PATH,
		      "g-interface-name", SECRET_SERVICE_INTERFACE,
		      NULL);
	return object;
}

static void
secret_service_class_init (SecretServiceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GDBusProxyClass *proxy_class = G_DBUS_PROXY_CLASS (klass);

	object_class->get_property = secret_service_get_property;
	object_class->set_property = secret_service_set_property;
	object_class->dispose = secret_service_dispose;
	object_class->finalize = secret_service_finalize;
	object_class->constructor = secret_service_constructor;

	proxy_class->g_properties_changed = secret_service_properties_changed;
	proxy_class->g_signal = secret_service_signal;

	klass->prompt_sync = secret_service_real_prompt_sync;
	klass->prompt_async = secret_service_real_prompt_async;
	klass->prompt_finish = secret_service_real_prompt_finish;

	klass->item_gtype = SECRET_TYPE_ITEM;
	klass->collection_gtype = SECRET_TYPE_COLLECTION;
	klass->get_item_gtype = secret_service_real_get_item_gtype;
	klass->get_collection_gtype = secret_service_real_get_collection_gtype;

	/**
	 * SecretService:flags:
	 *
	 * A set of flags describing which parts of the secret service have
	 * been initialized.
	 */
	g_object_class_override_property (object_class, PROP_FLAGS, "flags");

	/**
	 * SecretService:collections: (attributes org.gtk.Property.get=secret_service_get_collections)
	 *
	 * A list of [class@Collection] objects representing the collections in
	 * the Secret Service.
	 *
	 * This list may be %NULL if the collections have not been loaded.
	 *
	 * To load the collections, specify the %SECRET_SERVICE_LOAD_COLLECTIONS
	 * initialization flag when calling the [func@Service.get] or
	 * [func@Service.open] functions. Or call the [method@Service.load_collections]
	 * method.
	 */
	g_object_class_install_property (object_class, PROP_COLLECTIONS,
	             g_param_spec_boxed ("collections", "Collections", "Secret Service Collections",
	                                 _secret_list_get_type (), G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	/* Initialize this error domain, registers dbus errors */
	_secret_error_quark = secret_error_get_quark ();
}

typedef struct {
	SecretServiceFlags flags;
} InitClosure;

static void
init_closure_free (gpointer data)
{
	InitClosure *closure = data;
	g_free (closure);
}

static gboolean
service_ensure_for_flags_sync (SecretService *self,
                               SecretServiceFlags flags,
                               GCancellable *cancellable,
                               GError **error)
{
	if (flags & SECRET_SERVICE_OPEN_SESSION)
		if (!secret_service_ensure_session_sync (self, cancellable, error))
			return FALSE;

	if (flags & SECRET_SERVICE_LOAD_COLLECTIONS)
		if (!secret_service_load_collections_sync (self, cancellable, error))
			return FALSE;

	return TRUE;
}

static void
on_load_collections (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretService *self = SECRET_SERVICE (source);
	GError *error = NULL;

	if (!secret_service_load_collections_finish (self, result, &error))
		g_task_return_error (task, g_steal_pointer (&error));
	else
		g_task_return_boolean (task, TRUE);

	g_object_unref (task);
}

static void
on_ensure_session (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	InitClosure *closure = g_task_get_task_data (task);
	SecretService *self = SECRET_SERVICE (source);
	GError *error = NULL;

	if (!secret_service_ensure_session_finish (self, result, &error)) {
		g_task_return_error (task, g_steal_pointer (&error));

	} else if (closure->flags & SECRET_SERVICE_LOAD_COLLECTIONS) {
		secret_service_load_collections (self, g_task_get_cancellable (task),
		                                 on_load_collections,
		                                 g_object_ref (task));

	} else {
		g_task_return_boolean (task, TRUE);
	}

	g_object_unref (task);
}

static void
service_ensure_for_flags_async (SecretService *self,
                                SecretServiceFlags flags,
                                GTask *task)
{
	InitClosure *closure = g_task_get_task_data (task);

	closure->flags = flags;

	if (closure->flags & SECRET_SERVICE_OPEN_SESSION)
		secret_service_ensure_session (self, g_task_get_cancellable (task),
		                               on_ensure_session,
		                               g_object_ref (task));

	else if (closure->flags & SECRET_SERVICE_LOAD_COLLECTIONS)
		secret_service_load_collections (self, g_task_get_cancellable (task),
		                                 on_load_collections,
		                                 g_object_ref (task));

	else
		g_task_return_boolean (task, TRUE);
}

static gboolean
secret_service_initable_init (GInitable *initable,
                              GCancellable *cancellable,
                              GError **error)
{
	SecretService *self;

	if (!secret_service_initable_parent_iface->init (initable, cancellable, error))
		return FALSE;

	self = SECRET_SERVICE (initable);
	return service_ensure_for_flags_sync (self, self->pv->init_flags, cancellable, error);
}

static void
secret_service_initable_iface (GInitableIface *iface)
{
	secret_service_initable_parent_iface = g_type_interface_peek_parent (iface);

	iface->init = secret_service_initable_init;
}

static void
secret_service_async_initable_init_async (GAsyncInitable *initable,
                                          int io_priority,
                                          GCancellable *cancellable,
                                          GAsyncReadyCallback callback,
                                          gpointer user_data);

typedef struct {
	GAsyncReadyCallback callback;
	gpointer user_data;
} InitBaseClosure;

static void
on_init_base (GObject *source,
              GAsyncResult *result,
              gpointer user_data)
{
	GTask *base_task = G_TASK (user_data);
	InitBaseClosure *base = g_task_get_task_data (base_task);
	GCancellable *cancellable = g_task_get_cancellable (base_task);
	GTask *task;
	InitClosure *init;
	SecretService *self = SECRET_SERVICE (source);
	GError *error = NULL;

	task = g_task_new (source, cancellable, base->callback, base->user_data);
	g_task_set_source_tag (task, secret_service_async_initable_init_async);
	init = g_new0 (InitClosure, 1);
	g_task_set_task_data (task, init, init_closure_free);

	g_clear_object (&base_task);

	if (!secret_service_async_initable_parent_iface->init_finish (G_ASYNC_INITABLE (self),
	                                                              result, &error)) {
		g_task_return_error (task, g_steal_pointer (&error));
	} else {
		service_ensure_for_flags_async (self, self->pv->init_flags, task);
	}

	g_object_unref (task);
}

static void
secret_service_async_initable_init_async (GAsyncInitable *initable,
                                          int io_priority,
                                          GCancellable *cancellable,
                                          GAsyncReadyCallback callback,
                                          gpointer user_data)
{
	GTask *task;
	InitBaseClosure *base;

	task = g_task_new (initable, cancellable, NULL, NULL);
	g_task_set_source_tag (task, secret_service_async_initable_init_async);
	base = g_new0 (InitBaseClosure, 1);
	base->callback = callback;
	base->user_data = user_data;
	g_task_set_task_data (task, base, g_free);

	secret_service_async_initable_parent_iface->init_async (initable,
	                                                        io_priority,
	                                                        cancellable,
	                                                        on_init_base,
	                                                        g_object_ref (task));

	g_object_unref (task);
}

static gboolean
secret_service_async_initable_init_finish (GAsyncInitable *initable,
                                           GAsyncResult *result,
                                           GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, initable), FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

static void
secret_service_async_initable_iface (GAsyncInitableIface *iface)
{
	secret_service_async_initable_parent_iface = g_type_interface_peek_parent (iface);

	iface->init_async = secret_service_async_initable_init_async;
	iface->init_finish = secret_service_async_initable_init_finish;
}

static void
secret_service_real_ensure_for_flags (SecretBackend *self,
				      SecretBackendFlags flags,
				      GCancellable *cancellable,
				      GAsyncReadyCallback callback,
				      gpointer user_data)
{
	GTask *task;
	InitClosure *closure;

	g_return_if_fail (SECRET_IS_SERVICE (self));

	task = g_task_new (self, cancellable, callback, user_data);
	closure = g_new0 (InitClosure, 1);
	g_task_set_task_data (task, closure, init_closure_free);
	service_ensure_for_flags_async (SECRET_SERVICE (self), flags, task);
	g_object_unref (task);
}

static gboolean
secret_service_real_ensure_for_flags_finish (SecretBackend *self,
					     GAsyncResult *result,
					     GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

static void
secret_service_real_store (SecretBackend *self,
			   const SecretSchema *schema,
			   GHashTable *attributes,
			   const gchar *collection,
			   const gchar *label,
			   SecretValue *value,
			   GCancellable *cancellable,
			   GAsyncReadyCallback callback,
			   gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));

	secret_service_store (SECRET_SERVICE (self), schema, attributes,
			      collection, label, value,
			      cancellable, callback, user_data);
}

static gboolean
secret_service_real_store_finish (SecretBackend *self,
				  GAsyncResult *result,
				  GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);

	return secret_service_store_finish (SECRET_SERVICE (self),
					    result, error);
}

static void
secret_service_real_lookup (SecretBackend *self,
			    const SecretSchema *schema,
			    GHashTable *attributes,
			    GCancellable *cancellable,
			    GAsyncReadyCallback callback,
			    gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));

	secret_service_lookup (SECRET_SERVICE (self), schema, attributes,
			       cancellable, callback, user_data);
}

static SecretValue *
secret_service_real_lookup_finish (SecretBackend *self,
				   GAsyncResult *result,
				   GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);

	return secret_service_lookup_finish (SECRET_SERVICE (self),
					     result, error);
}

static void
secret_service_real_clear (SecretBackend *self,
			   const SecretSchema *schema,
			   GHashTable *attributes,
			   GCancellable *cancellable,
			   GAsyncReadyCallback callback,
			   gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));

	secret_service_clear (SECRET_SERVICE (self), schema, attributes,
			      cancellable, callback, user_data);
}

static gboolean
secret_service_real_clear_finish (SecretBackend *self,
				  GAsyncResult *result,
				  GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);

	return secret_service_clear_finish (SECRET_SERVICE (self),
					    result, error);
}

static void
secret_service_real_search (SecretBackend *self,
			    const SecretSchema *schema,
			    GHashTable *attributes,
			    SecretSearchFlags flags,
			    GCancellable *cancellable,
			    GAsyncReadyCallback callback,
			    gpointer user_data)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));

	secret_service_search (SECRET_SERVICE (self), schema, attributes, flags,
			       cancellable, callback, user_data);
}

static GList *
secret_service_real_search_finish (SecretBackend *self,
				   GAsyncResult *result,
				   GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);

	return secret_service_search_finish (SECRET_SERVICE (self),
					     result, error);
}

static void
secret_service_backend_iface (SecretBackendInterface *iface)
{
	secret_service_backend_parent_iface = g_type_interface_peek_parent (iface);

	iface->ensure_for_flags = secret_service_real_ensure_for_flags;
	iface->ensure_for_flags_finish = secret_service_real_ensure_for_flags_finish;
	iface->store = secret_service_real_store;
	iface->store_finish = secret_service_real_store_finish;
	iface->lookup = secret_service_real_lookup;
	iface->lookup_finish = secret_service_real_lookup_finish;
	iface->clear = secret_service_real_clear;
	iface->clear_finish = secret_service_real_clear_finish;
	iface->search = secret_service_real_search;
	iface->search_finish = secret_service_real_search_finish;
}

/**
 * secret_service_get:
 * @flags: flags for which service functionality to ensure is initialized
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Get a #SecretService proxy for the Secret Service.
 *
 * If such a proxy object already exists, then the same proxy is returned.
 *
 * If @flags contains any flags of which parts of the secret service to
 * ensure are initialized, then those will be initialized before completing.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_get (SecretServiceFlags flags,
                    GCancellable *cancellable,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
	SecretService *service = NULL;
	GTask *task;
	InitClosure *closure;

	service = service_get_instance ();

	/* Create a whole new service */
	if (service == NULL) {
		g_async_initable_new_async (SECRET_TYPE_SERVICE, G_PRIORITY_DEFAULT,
		                            cancellable, callback, user_data,
					    "flags", flags,
		                            NULL);

	/* Just have to ensure that the service matches flags */
	} else {
		task = g_task_new (service, cancellable, callback, user_data);
		g_task_set_source_tag (task, secret_service_get);
		closure = g_new0 (InitClosure, 1);
		closure->flags = flags;
		g_task_set_task_data (task, closure, init_closure_free);

		service_ensure_for_flags_async (service, flags, task);

		g_object_unref (service);
		g_object_unref (task);
	}
}

/**
 * secret_service_get_finish:
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Complete an asynchronous operation to get a #SecretService proxy for the
 * Secret Service.
 *
 * Returns: (transfer full): a new reference to a #SecretService proxy, which
 *   should be released with [method@GObject.Object.unref].
 */
SecretService *
secret_service_get_finish (GAsyncResult *result,
                           GError **error)
{
	GTask *task;
	GObject *service = NULL;
	GObject *source_object;

	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	task = G_TASK (result);
	source_object = g_task_get_source_object (task);

	g_return_val_if_fail (g_task_is_valid (result, source_object), NULL);

	/* Just ensuring that the service matches flags */
	if (g_task_get_source_tag (task) == secret_service_get) {
		if (g_task_had_error (task)) {
			g_task_propagate_pointer (task, error);
			_secret_util_strip_remote_error (error);
		} else {
			service = g_object_ref (source_object);
		}

	/* Creating a whole new service */
	} else {
		service = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object), result, error);
		if (service)
			service_cache_instance (SECRET_SERVICE (service));
	}

	if (service == NULL)
		return NULL;

	return SECRET_SERVICE (service);
}

/**
 * secret_service_get_sync:
 * @flags: flags for which service functionality to ensure is initialized
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Get a #SecretService proxy for the Secret Service.
 *
 * If such a proxy object already exists, then the same proxy is returned.
 *
 * If @flags contains any flags of which parts of the secret service to
 * ensure are initialized, then those will be initialized before returning.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a new reference to a #SecretService proxy, which
 *   should be released with [method@GObject.Object.unref].
 */
SecretService *
secret_service_get_sync (SecretServiceFlags flags,
                         GCancellable *cancellable,
                         GError **error)
{
	SecretService *service = NULL;

	service = service_get_instance ();

	if (service == NULL) {
		service = g_initable_new (SECRET_TYPE_SERVICE, cancellable, error,
		                          "flags", flags,
		                          NULL);

		if (service != NULL)
			service_cache_instance (service);

	} else {
		if (!service_ensure_for_flags_sync (service, flags, cancellable, error)) {
			g_object_unref (service);
			return NULL;
		}
	}

	return service;
}

/**
 * secret_service_disconnect:
 *
 * Disconnect the default #SecretService proxy returned by [func@Service.get]
 * and [func@Service.get_sync].
 *
 * It is not necessary to call this function, but you may choose to do so at
 * program exit. It is useful for testing that memory is not leaked.
 *
 * This function is safe to call at any time. But if other objects in this
 * library are still referenced, then this will not result in all memory
 * being freed.
 */
void
secret_service_disconnect (void)
{
	service_uncache_instance (NULL);
}

/**
 * secret_service_open:
 * @service_gtype: the GType of the new secret service
 * @service_bus_name: (nullable): the D-Bus service name of the secret service
 * @flags: flags for which service functionality to ensure is initialized
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Create a new #SecretService proxy for the Secret Service.
 *
 * This function is rarely used, see [func@Service.get] instead.
 *
 * The @service_gtype argument should be set to %SECRET_TYPE_SERVICE or a the type
 * of a derived class.
 *
 * If @flags contains any flags of which parts of the secret service to
 * ensure are initialized, then those will be initialized before returning.
 *
 * If @service_bus_name is %NULL then the default is used.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_open (GType service_gtype,
                     const gchar *service_bus_name,
                     SecretServiceFlags flags,
                     GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));
	g_return_if_fail (g_type_is_a (service_gtype, SECRET_TYPE_SERVICE));

	g_async_initable_new_async (service_gtype, G_PRIORITY_DEFAULT,
	                            cancellable, callback, user_data,
	                            "flags", flags,
	                            NULL);
}

/**
 * secret_service_open_finish:
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Complete an asynchronous operation to create a new #SecretService proxy for
 * the Secret Service.
 *
 * Returns: (transfer full): a new reference to a #SecretService proxy, which
 *   should be released with [method@GObject.Object.unref].
 */
SecretService *
secret_service_open_finish (GAsyncResult *result,
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

	return SECRET_SERVICE (object);
}

/**
 * secret_service_open_sync:
 * @service_gtype: the GType of the new secret service
 * @service_bus_name: (nullable): the D-Bus service name of the secret service
 * @flags: flags for which service functionality to ensure is initialized
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Create a new #SecretService proxy for the Secret Service.
 *
 * This function is rarely used, see [func@Service.get_sync] instead.
 *
 * The @service_gtype argument should be set to %SECRET_TYPE_SERVICE or a the
 * type of a derived class.
 *
 * If @flags contains any flags of which parts of the secret service to
 * ensure are initialized, then those will be initialized before returning.
 *
 * If @service_bus_name is %NULL then the default is used.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full): a new reference to a #SecretService proxy, which
 *   should be released with [method@GObject.Object.unref].
 */
SecretService *
secret_service_open_sync (GType service_gtype,
                          const gchar *service_bus_name,
                          SecretServiceFlags flags,
                          GCancellable *cancellable,
                          GError **error)
{
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (g_type_is_a (service_gtype, SECRET_TYPE_SERVICE), NULL);

	return g_initable_new (service_gtype, cancellable, error,
	                       "flags", flags,
	                       NULL);
}

/**
 * secret_service_get_flags:
 * @self: the secret service proxy
 *
 * Get the flags representing what features of the #SecretService proxy
 * have been initialized.
 *
 * Use [method@Service.ensure_session] or [method@Service.load_collections]
 * to initialize further features and change the flags.
 *
 * Returns: the flags for features initialized
 */
SecretServiceFlags
secret_service_get_flags (SecretService *self)
{
	SecretServiceFlags flags = 0;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), SECRET_SERVICE_NONE);

	g_mutex_lock (&self->pv->mutex);

	if (self->pv->session)
		flags |= SECRET_SERVICE_OPEN_SESSION;
	if (self->pv->collections)
		flags |= SECRET_SERVICE_LOAD_COLLECTIONS;

	g_mutex_unlock (&self->pv->mutex);

	return flags;
}

/**
 * secret_service_get_collections: (attributes org.gtk.Method.get_property=collections)
 * @self: the secret service proxy
 *
 * Get a list of [class@Collection] objects representing all the collections
 * in the secret service.
 *
 * If the %SECRET_SERVICE_LOAD_COLLECTIONS flag was not specified when
 * initializing #SecretService proxy object, then this method will return
 * %NULL. Use [method@Service.load_collections] to load the collections.
 *
 * Returns: (transfer full) (element-type Secret.Collection) (nullable): a
 *   list of the collections in the secret service
 */
GList *
secret_service_get_collections (SecretService *self)
{
	GList *l, *collections;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);

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

SecretItem *
_secret_service_find_item_instance (SecretService *self,
                                    const gchar *item_path)
{
	SecretCollection *collection = NULL;
	gchar *collection_path;
	SecretItem *item;

	collection_path = _secret_util_parent_path (item_path);

	collection = _secret_service_find_collection_instance (self, collection_path);

	g_free (collection_path);

	if (collection == NULL)
		return NULL;

	item = _secret_collection_find_item_instance (collection, item_path);
	g_object_unref (collection);

	return item;
}

SecretCollection *
_secret_service_find_collection_instance (SecretService *self,
                                          const gchar *collection_path)
{
	SecretCollection *collection = NULL;

	g_mutex_lock (&self->pv->mutex);
	if (self->pv->collections) {
		collection = g_hash_table_lookup (self->pv->collections, collection_path);
		if (collection != NULL)
			g_object_ref (collection);
	}
	g_mutex_unlock (&self->pv->mutex);

	return collection;
}

SecretSession *
_secret_service_get_session (SecretService *self)
{
	SecretSession *session;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);

	g_mutex_lock (&self->pv->mutex);
	session = self->pv->session;
	g_mutex_unlock (&self->pv->mutex);

	return session;
}

void
_secret_service_take_session (SecretService *self,
                              SecretSession *session)
{
	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (session != NULL);

	g_mutex_lock (&self->pv->mutex);
	if (self->pv->session == NULL)
		self->pv->session = session;
	else
		_secret_session_free (session);
	g_mutex_unlock (&self->pv->mutex);
}

/**
 * secret_service_get_session_algorithms:
 * @self: the secret service proxy
 *
 * Get the set of algorithms being used to transfer secrets between this
 * secret service proxy and the Secret Service itself.
 *
 * This will be %NULL if no session has been established. Use
 * [method@Service.ensure_session] to establish a session.
 *
 * Returns: (nullable): a string representing the algorithms for transferring
 *   secrets
 */
const gchar *
secret_service_get_session_algorithms (SecretService *self)
{
	SecretSession *session;
	const gchar *algorithms;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);

	g_mutex_lock (&self->pv->mutex);
	session = self->pv->session;
	algorithms = session ? _secret_session_get_algorithms (session) : NULL;
	g_mutex_unlock (&self->pv->mutex);

	/* Session never changes once established, so can return const */
	return algorithms;
}

/**
 * secret_service_get_session_dbus_path:
 * @self: the secret service proxy
 *
 * Get the D-Bus object path of the session object being used to transfer
 * secrets between this secret service proxy and the Secret Service itself.
 *
 * This will be %NULL if no session has been established. Use
 * [method@Service.ensure_session] to establish a session.
 *
 * Returns: (nullable): a string representing the D-Bus object path of the
 *   session
 */
const gchar *
secret_service_get_session_dbus_path (SecretService *self)
{
	SecretSession *session;
	const gchar *path;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);

	g_mutex_lock (&self->pv->mutex);
	session = self->pv->session;
	path = session ? _secret_session_get_path (session) : NULL;
	g_mutex_unlock (&self->pv->mutex);

	/* Session never changes once established, so can return const */
	return path;
}

/**
 * secret_service_ensure_session:
 * @self: the secret service
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Ensure that the #SecretService proxy has established a session with the
 * Secret Service.
 *
 * This session is used to transfer secrets.
 *
 * It is not normally necessary to call this method, as the session is
 * established as necessary. You can also pass the %SECRET_SERVICE_OPEN_SESSION
 * to [func@Service.get] in order to ensure that a session has been established
 * by the time you get the #SecretService proxy.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_ensure_session (SecretService *self,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GTask *task;
	SecretSession *session;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	g_mutex_lock (&self->pv->mutex);
	session = self->pv->session;
	g_mutex_unlock (&self->pv->mutex);

	if (session == NULL) {
		_secret_session_open (self, cancellable, callback, user_data);

	} else {
		task = g_task_new (self, cancellable, callback, user_data);
		g_task_set_source_tag (task, secret_service_ensure_session);
		g_task_return_boolean (task, TRUE);
		g_object_unref (task);
	}
}

/**
 * secret_service_ensure_session_finish:
 * @self: the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish an asynchronous operation to ensure that the #SecretService proxy
 * has established a session with the Secret Service.
 *
 * Returns: whether a session is established or not
 */
gboolean
secret_service_ensure_session_finish (SecretService *self,
                                      GAsyncResult *result,
                                      GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	g_return_val_if_fail (self->pv->session != NULL, FALSE);
	return TRUE;
}

/**
 * secret_service_ensure_session_sync:
 * @self: the secret service
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Ensure that the #SecretService proxy has established a session with the
 * Secret Service.
 *
 * This session is used to transfer secrets.
 *
 * It is not normally necessary to call this method, as the session is
 * established as necessary. You can also pass the %SECRET_SERVICE_OPEN_SESSION
 * to [func@Service.get_sync] in order to ensure that a session has been
 * established by the time you get the #SecretService proxy.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether a session is established or not
 */
gboolean
secret_service_ensure_session_sync (SecretService *self,
                                    GCancellable *cancellable,
                                    GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_service_ensure_session (self, cancellable,
	                               _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_service_ensure_session_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

static SecretCollection *
service_lookup_collection (SecretService *self,
                           const gchar *path)
{
	SecretCollection *collection = NULL;

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
service_update_collections (SecretService *self,
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

	g_object_notify (G_OBJECT (self), "collections");
}

typedef struct {
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
	g_hash_table_unref (closure->collections);
	g_free (closure);
}

static void
on_ensure_collection (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretService *self = SECRET_SERVICE (g_async_result_get_source_object (user_data));
	EnsureClosure *closure = g_task_get_task_data (task);
	SecretCollection *collection;
	const gchar *path;
	GError *error = NULL;

	closure->collections_loading--;

	collection = secret_collection_new_for_dbus_path_finish (result, &error);

	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));

	} else if (collection != NULL) {
		path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (collection));
		g_hash_table_insert (closure->collections, g_strdup (path), collection);

		if (closure->collections_loading == 0) {
			service_update_collections (self, closure->collections);
			g_task_return_boolean (task, TRUE);
		}
	}

	g_object_unref (self);
	g_object_unref (task);
}

/**
 * secret_service_load_collections:
 * @self: the secret service
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Ensure that the #SecretService proxy has loaded all the collections present
 * in the Secret Service.
 *
 * This affects the result of [method@Service.get_collections].
 *
 * You can also pass the %SECRET_SERVICE_LOAD_COLLECTIONS to
 * [func@Service.get_sync] in order to ensure that the collections have been
 * loaded by the time you get the #SecretService proxy.
 *
 * This method will return immediately and complete asynchronously.
 */
void
secret_service_load_collections (SecretService *self,
                                 GCancellable *cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
	EnsureClosure *closure;
	SecretCollection *collection;
	GTask *task;
	const gchar *path;
	GVariant *paths;
	GVariantIter iter;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	paths = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Collections");
	g_return_if_fail (paths != NULL);

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_service_load_collections);
	closure = g_new0 (EnsureClosure, 1);
	closure->collections = collections_table_new ();
	g_task_set_task_data (task, closure, ensure_closure_free);

	g_variant_iter_init (&iter, paths);
	while (g_variant_iter_loop (&iter, "&o", &path)) {
		collection = service_lookup_collection (self, path);

		/* No such collection yet create a new one */
		if (collection == NULL) {
			secret_collection_new_for_dbus_path (self, path,
			                                     SECRET_COLLECTION_LOAD_ITEMS,
			                                     cancellable,
			                                     on_ensure_collection,
			                                     g_object_ref (task));
			closure->collections_loading++;
		} else {
			g_hash_table_insert (closure->collections, g_strdup (path), collection);
		}
	}

	if (closure->collections_loading == 0) {
		service_update_collections (self, closure->collections);
		g_task_return_boolean (task, TRUE);
	}

	g_variant_unref (paths);
	g_object_unref (task);
}

/**
 * secret_service_load_collections_finish:
 * @self: the secret service
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Complete an asynchronous operation to ensure that the #SecretService proxy
 * has loaded all the collections present in the Secret Service.
 *
 * Returns: whether the load was successful or not
 */
gboolean
secret_service_load_collections_finish (SecretService *self,
                                        GAsyncResult *result,
                                        GError **error)
{
	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);
	g_return_val_if_fail (g_task_get_source_tag (G_TASK (result)) ==
	                      secret_service_load_collections, FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

/**
 * secret_service_load_collections_sync:
 * @self: the secret service
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Ensure that the #SecretService proxy has loaded all the collections present
 * in the Secret Service.
 *
 * This affects the result of [method@Service.get_collections].
 *
 * You can also pass the %SECRET_SERVICE_LOAD_COLLECTIONS to
 * [func@Service.get_sync] in order to ensure that the collections have been
 * loaded by the time you get the #SecretService proxy.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: whether the load was successful or not
 */
gboolean
secret_service_load_collections_sync (SecretService *self,
                                      GCancellable *cancellable,
                                      GError **error)
{
	SecretCollection *collection;
	GHashTable *collections;
	GVariant *paths;
	GVariantIter iter;
	const gchar *path;
	gboolean ret = TRUE;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), FALSE);
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
			collection = secret_collection_new_for_dbus_path_sync (self, path,
			                                                       SECRET_COLLECTION_LOAD_ITEMS,
			                                                       cancellable, error);
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

/**
 * secret_service_prompt_sync:
 * @self: the secret service
 * @prompt: the prompt
 * @cancellable: (nullable): optional cancellation object
 * @return_type: the variant type of the prompt result
 * @error: location to place an error on failure
 *
 * Perform prompting for a [class@Prompt].
 *
 * Runs a prompt and performs the prompting. Returns a variant result if the
 * prompt was completed and not dismissed. The type of result depends on the
 * action the prompt is completing, and is defined in the Secret Service DBus
 * API specification.
 *
 * This function is called by other parts of this library to handle prompts
 * for the various actions that can require prompting.
 *
 * Override the #SecretServiceClass [vfunc@Service.prompt_sync] virtual method
 * to change the behavior of the prompting. The default behavior is to simply
 * run [method@Prompt.perform_sync] on the prompt with a %NULL `window_id`.
 *
 * Returns: (transfer full): %NULL if the prompt was dismissed or an error occurred,
 *   a variant result if the prompt was successful
 */
GVariant *
secret_service_prompt_sync (SecretService *self,
                            SecretPrompt *prompt,
                            GCancellable *cancellable,
                            const GVariantType *return_type,
                            GError **error)
{
	SecretServiceClass *klass;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (SECRET_IS_PROMPT (prompt), NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	klass = SECRET_SERVICE_GET_CLASS (self);
	g_return_val_if_fail (klass->prompt_sync != NULL, NULL);

	return (klass->prompt_sync) (self, prompt, cancellable, return_type, error);
}

/**
 * secret_service_prompt:
 * @self: the secret service
 * @prompt: the prompt
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
 * to change the behavior of the prompting. The default behavior is to simply
 * run [method@Prompt.perform] on the prompt.
 */
void
secret_service_prompt (SecretService *self,
                       SecretPrompt *prompt,
                       const GVariantType *return_type,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	SecretServiceClass *klass;

	g_return_if_fail (SECRET_IS_SERVICE (self));
	g_return_if_fail (SECRET_IS_PROMPT (prompt));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	klass = SECRET_SERVICE_GET_CLASS (self);
	g_return_if_fail (klass->prompt_async != NULL);

	(klass->prompt_async) (self, prompt, return_type, cancellable, callback, user_data);
}

/**
 * secret_service_prompt_finish:
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
 * Returns: (transfer full): %NULL if the prompt was dismissed or an error occurred,
 *   a variant result if the prompt was successful
 */
GVariant *
secret_service_prompt_finish (SecretService *self,
                              GAsyncResult *result,
                              GError **error)
{
	SecretServiceClass *klass;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), NULL);
	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	klass = SECRET_SERVICE_GET_CLASS (self);
	g_return_val_if_fail (klass->prompt_finish != NULL, NULL);

	return (klass->prompt_finish) (self, result, error);
}

/**
 * secret_service_get_collection_gtype:
 * @self: the secret service
 *
 * Get the GObject type for collections instantiated by this service.
 *
 * This will always be either [class@Collection] or derived from it.
 *
 * Returns: the gobject type for collections
 */
GType
secret_service_get_collection_gtype (SecretService *self)
{
	SecretServiceClass *klass;
	GType type;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), 0);

	klass = SECRET_SERVICE_GET_CLASS (self);
	g_return_val_if_fail (klass->get_collection_gtype != NULL,
	                      SECRET_TYPE_COLLECTION);

	type = (klass->get_collection_gtype) (self);
	g_return_val_if_fail (g_type_is_a (type, SECRET_TYPE_COLLECTION),
	                      SECRET_TYPE_COLLECTION);

	return type;
}

/**
 * secret_service_get_item_gtype:
 * @self: the service
 *
 * Get the GObject type for items instantiated by this service.
 *
 * This will always be either [class@Item] or derived from it.
 *
 * Returns: the gobject type for items
 */
GType
secret_service_get_item_gtype (SecretService *self)
{
	SecretServiceClass *klass;
	GType type;

	g_return_val_if_fail (SECRET_IS_SERVICE (self), 0);

	klass = SECRET_SERVICE_GET_CLASS (self);
	g_return_val_if_fail (klass->get_item_gtype != NULL,
	                      SECRET_TYPE_ITEM);

	type = (klass->get_item_gtype) (self);
	g_return_val_if_fail (g_type_is_a (type, SECRET_TYPE_ITEM),
	                      SECRET_TYPE_ITEM);

	return type;
}
