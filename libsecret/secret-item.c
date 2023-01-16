/* libsecret - GLib wrapper for Secret Service
 *
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
#include "secret-retrievable.h"
#include "secret-service.h"
#include "secret-types.h"
#include "secret-value.h"

#include "libsecret/secret-enum-types.h"

#include <glib/gi18n-lib.h>

/**
 * SecretItem:
 *
 * A secret item
 *
 * #SecretItem represents a secret item stored in the Secret Service.
 *
 * Each item has a value, represented by a [struct@Value], which can be
 * retrieved by [method@Item.get_secret] or set by [method@Item.set_secret].
 * The item is only available when the item is not locked.
 *
 * Items can be locked or unlocked using the [method@Service.lock] or
 * [method@Service.unlock] functions. The Secret Service may not be able to
 * unlock individual items, and may unlock an entire collection when a single
 * item is unlocked.
 *
 * Each item has a set of attributes, which are used to locate the item later.
 * These are not stored or transferred in a secure manner. Each attribute has
 * a string name and a string value. Use [method@Service.search] to search for
 * items based on their attributes, and [method@Item.set_attributes] to change
 * the attributes associated with an item.
 *
 * Items can be created with [func@Item.create] or [method@Service.store].
 *
 * Stability: Stable
 */

/**
 * SecretItemClass:
 * @parent_class: the parent class
 *
 * The class for #SecretItem.
 */

/**
 * SecretItemFlags:
 * @SECRET_ITEM_NONE: no flags
 * @SECRET_ITEM_LOAD_SECRET: a secret has been (or should be) loaded for #SecretItem
 *
 * Flags which determine which parts of the #SecretItem proxy are initialized.
 */

/**
 * SecretItemCreateFlags:
 * @SECRET_ITEM_CREATE_NONE: no flags
 * @SECRET_ITEM_CREATE_REPLACE: replace an item with the same attributes.
 *
 * Flags for [func@Item.create].
 */

enum {
	PROP_0,
	PROP_SERVICE,
	PROP_FLAGS,
	PROP_ATTRIBUTES,
	PROP_LABEL,
	PROP_LOCKED,
	PROP_CREATED,
	PROP_MODIFIED
};

struct _SecretItemPrivate {
	/* No changes between construct and finalize */
	SecretService *service;
	SecretItemFlags init_flags;

	/* Locked by mutex */
	GMutex mutex;
	SecretValue *value;
	gint disposed;
};

static SecretRetrievableInterface *secret_item_retrievable_parent_iface = NULL;

static GInitableIface *secret_item_initable_parent_iface = NULL;

static GAsyncInitableIface *secret_item_async_initable_parent_iface = NULL;

static void   secret_item_retrievable_iface      (SecretRetrievableInterface *iface);

static void   secret_item_initable_iface         (GInitableIface *iface);

static void   secret_item_async_initable_iface   (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (SecretItem, secret_item, G_TYPE_DBUS_PROXY,
                         G_ADD_PRIVATE (SecretItem)
			 G_IMPLEMENT_INTERFACE (SECRET_TYPE_RETRIEVABLE, secret_item_retrievable_iface);
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, secret_item_initable_iface);
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, secret_item_async_initable_iface);
);

static void
secret_item_init (SecretItem *self)
{
	self->pv = secret_item_get_instance_private (self);
	g_mutex_init (&self->pv->mutex);
}

static void
on_set_attributes (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	SecretItem *self = SECRET_ITEM (user_data);
	GError *error = NULL;

	if (!g_atomic_int_get (&self->pv->disposed)) {
		secret_item_set_attributes_finish (self, result, &error);
		if (error != NULL) {
			g_warning ("couldn't set SecretItem Attributes: %s", error->message);
			g_error_free (error);
		}
	}

	g_object_unref (self);
}

static void
on_set_label (GObject *source,
              GAsyncResult *result,
              gpointer user_data)
{
	SecretItem *self = SECRET_ITEM (user_data);
	GError *error = NULL;

	if (!g_atomic_int_get (&self->pv->disposed)) {
		secret_item_set_label_finish (self, result, &error);
		if (error != NULL) {
			g_warning ("couldn't set SecretItem Label: %s", error->message);
			g_error_free (error);
		}
	}

	g_object_unref (self);
}


static void
item_take_service (SecretItem *self,
                   SecretService *service)
{
	if (service == NULL)
		return;

	g_return_if_fail (self->pv->service == NULL);

	self->pv->service = service;
	g_object_add_weak_pointer (G_OBJECT (self->pv->service),
	                           (gpointer *)&self->pv->service);

	/* Yes, we expect that the service will stay around */
	g_object_unref (service);
}

static void
secret_item_set_property (GObject *obj,
                          guint prop_id,
                          const GValue *value,
                          GParamSpec *pspec)
{
	SecretItem *self = SECRET_ITEM (obj);

	switch (prop_id) {
	case PROP_SERVICE:
		item_take_service (self, g_value_dup_object (value));
		break;
	case PROP_FLAGS:
		self->pv->init_flags = g_value_get_flags (value);
		break;
	case PROP_ATTRIBUTES:
		secret_item_set_attributes (self, NULL, g_value_get_boxed (value),
		                            NULL, on_set_attributes,
		                            g_object_ref (self));
		break;
	case PROP_LABEL:
		secret_item_set_label (self, g_value_get_string (value),
		                       NULL, on_set_label,
		                       g_object_ref (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
secret_item_get_property (GObject *obj,
                          guint prop_id,
                          GValue *value,
                          GParamSpec *pspec)
{
	SecretItem *self = SECRET_ITEM (obj);

	switch (prop_id) {
	case PROP_SERVICE:
		g_value_set_object (value, self->pv->service);
		break;
	case PROP_FLAGS:
		g_value_set_flags (value, secret_item_get_flags (self));
		break;
	case PROP_ATTRIBUTES:
		g_value_take_boxed (value, secret_item_get_attributes (self));
		break;
	case PROP_LABEL:
		g_value_take_string (value, secret_item_get_label (self));
		break;
	case PROP_LOCKED:
		g_value_set_boolean (value, secret_item_get_locked (self));
		break;
	case PROP_CREATED:
		g_value_set_uint64 (value, secret_item_get_created (self));
		break;
	case PROP_MODIFIED:
		g_value_set_uint64 (value, secret_item_get_modified (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
secret_item_dispose (GObject *obj)
{
	SecretItem *self = SECRET_ITEM (obj);

	g_atomic_int_inc (&self->pv->disposed);

	G_OBJECT_CLASS (secret_item_parent_class)->dispose (obj);
}

static void
secret_item_finalize (GObject *obj)
{
	SecretItem *self = SECRET_ITEM (obj);

	if (self->pv->service)
		g_object_remove_weak_pointer (G_OBJECT (self->pv->service),
		                              (gpointer *)&self->pv->service);

	if (self->pv->value != NULL)
		secret_value_unref (self->pv->value);

	g_mutex_clear (&self->pv->mutex);

	G_OBJECT_CLASS (secret_item_parent_class)->finalize (obj);
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
secret_item_properties_changed (GDBusProxy *proxy,
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
secret_item_class_init (SecretItemClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GDBusProxyClass *proxy_class = G_DBUS_PROXY_CLASS (klass);

	gobject_class->get_property = secret_item_get_property;
	gobject_class->set_property = secret_item_set_property;
	gobject_class->dispose = secret_item_dispose;
	gobject_class->finalize = secret_item_finalize;

	proxy_class->g_properties_changed = secret_item_properties_changed;

	/**
	 * SecretItem:service: (attributes org.gtk.Property.get=secret_item_get_service)
	 *
	 * The [class@Service] object that this item is associated with and
	 * uses to interact with the actual D-Bus Secret Service.
	 */
	g_object_class_install_property (gobject_class, PROP_SERVICE,
	            g_param_spec_object ("service", "Service", "Secret Service",
	                                 SECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

	/**
	 * SecretItem:flags: (attributes org.gtk.Property.get=secret_item_get_flags)
	 *
	 * A set of flags describing which parts of the secret item have
	 * been initialized.
	 */
	g_object_class_install_property (gobject_class, PROP_FLAGS,
	             g_param_spec_flags ("flags", "Flags", "Item flags",
	                                 secret_item_flags_get_type (), SECRET_ITEM_NONE,
	                                 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

	/**
	 * SecretItem:attributes: (type GLib.HashTable(utf8,utf8)) (transfer full)
	 *
	 * The attributes set on this item. Attributes are used to locate an
	 * item.
	 *
	 * They are not guaranteed to be stored or transferred securely.
	 */
	g_object_class_override_property (gobject_class, PROP_ATTRIBUTES, "attributes");

	/**
	 * SecretItem:label:
	 *
	 * The human readable label for the item.
	 *
	 * Setting this property will result in the label of the item being
	 * set asynchronously. To properly track the changing of the label use the
	 * [method@Item.set_label] function.
	 */
	g_object_class_override_property (gobject_class, PROP_LABEL, "label");

	/**
	 * SecretItem:locked: (attributes org.gtk.Property.get=secret_item_get_locked)
	 *
	 * Whether the item is locked or not.
	 *
	 * An item may not be independently lockable separate from other items in
	 * its collection.
	 *
	 * To lock or unlock a item use the [method@Service.lock] or
	 * [method@Service.unlock] functions.
	 */
	g_object_class_install_property (gobject_class, PROP_LOCKED,
	           g_param_spec_boolean ("locked", "Locked", "Item locked",
	                                 TRUE, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	/**
	 * SecretItem:created:
	 *
	 * The date and time (in seconds since the UNIX epoch) that this
	 * item was created.
	 */
	g_object_class_override_property (gobject_class, PROP_CREATED, "created");

	/**
	 * SecretItem:modified:
	 *
	 * The date and time (in seconds since the UNIX epoch) that this
	 * item was last modified.
	 */
	g_object_class_override_property (gobject_class, PROP_MODIFIED, "modified");
}

static gboolean
item_ensure_for_flags_sync (SecretItem *self,
                            SecretItemFlags flags,
                            GCancellable *cancellable,
                            GError **error)
{
	if (flags & SECRET_ITEM_LOAD_SECRET && !secret_item_get_locked (self)) {
		if (!secret_item_load_secret_sync (self, cancellable, error))
			return FALSE;
	}

	return TRUE;
}


static void
on_init_load_secret (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretItem *self = SECRET_ITEM (source);
	GError *error = NULL;

	if (!secret_item_load_secret_finish (self, result, &error))
		g_task_return_error (task, g_steal_pointer (&error));
	else
		g_task_return_boolean (task, TRUE);

	g_clear_object (&task);
}

static void
item_ensure_for_flags_async (SecretItem *self,
                             SecretItemFlags flags,
                             GTask *task)
{
	GCancellable *cancellable = g_task_get_cancellable (task);

	if (flags & SECRET_ITEM_LOAD_SECRET && !secret_item_get_locked (self))
		secret_item_load_secret (self, cancellable, on_init_load_secret,
		                         g_object_ref (task));

	else
		g_task_return_boolean (task, TRUE);
}

static gboolean
secret_item_initable_init (GInitable *initable,
                           GCancellable *cancellable,
                           GError **error)
{
	SecretItem *self;
	SecretService *service;
	GDBusProxy *proxy;

	if (!secret_item_initable_parent_iface->init (initable, cancellable, error))
		return FALSE;

	proxy = G_DBUS_PROXY (initable);

	if (!_secret_util_have_cached_properties (proxy)) {
		g_set_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD,
		             "No such secret item at path: %s",
		             g_dbus_proxy_get_object_path (proxy));
		return FALSE;
	}

	self = SECRET_ITEM (initable);
	if (!self->pv->service) {
		service = secret_service_get_sync (SECRET_SERVICE_NONE, cancellable, error);
		if (service == NULL)
			return FALSE;
		else
			item_take_service (self, service);
	}

	return item_ensure_for_flags_sync (self, self->pv->init_flags, cancellable, error);
}

static void
secret_item_initable_iface (GInitableIface *iface)
{
	secret_item_initable_parent_iface = g_type_interface_peek_parent (iface);

	iface->init = secret_item_initable_init;
}

static void
on_init_service (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretItem *self = SECRET_ITEM (g_task_get_source_object (task));
	SecretService *service;
	GError *error = NULL;

	service = secret_service_get_finish (result, &error);
	if (error == NULL) {
		item_take_service (self, g_steal_pointer (&service));
		item_ensure_for_flags_async (self, self->pv->init_flags, task);

	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

typedef struct {
	GAsyncReadyCallback callback;
	gpointer user_data;
} InitBaseClosure;

static void
secret_item_async_initable_init_async (GAsyncInitable *initable,
                                       int io_priority,
                                       GCancellable *cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data);

static void
on_init_base (GObject *source,
              GAsyncResult *result,
              gpointer user_data)
{
	GTask *base_task = G_TASK (user_data);
	InitBaseClosure *base = g_task_get_task_data (base_task);
	GCancellable *cancellable = g_task_get_cancellable (base_task);
	GTask *task;
	SecretItem *self = SECRET_ITEM (source);
	GDBusProxy *proxy = G_DBUS_PROXY (self);
	GError *error = NULL;

	task = g_task_new (source, cancellable, base->callback, base->user_data);
	g_task_set_source_tag (task, secret_item_async_initable_init_async);
	g_clear_object (&base_task);

	if (!secret_item_async_initable_parent_iface->init_finish (G_ASYNC_INITABLE (self),
	                                                           result, &error)) {
		g_task_return_error (task, g_steal_pointer (&error));

	} else if (!_secret_util_have_cached_properties (proxy)) {
		g_task_return_new_error (task, G_DBUS_ERROR,
		                         G_DBUS_ERROR_UNKNOWN_METHOD,
		                         "No such secret item at path: %s",
		                         g_dbus_proxy_get_object_path (proxy));

	} else if (self->pv->service == NULL) {
		secret_service_get (SECRET_SERVICE_NONE, cancellable,
		                    on_init_service, g_steal_pointer (&task));

	} else {
		item_ensure_for_flags_async (self, self->pv->init_flags, task);
	}

	g_clear_object (&task);
}

static void
secret_item_async_initable_init_async (GAsyncInitable *initable,
                                       int io_priority,
                                       GCancellable *cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
	GTask *task;
	InitBaseClosure *base;

	task = g_task_new (initable, cancellable, NULL, NULL);
	g_task_set_source_tag (task, secret_item_async_initable_init_async);

	base = g_new0 (InitBaseClosure, 1);
	base->callback = callback;
	base->user_data = user_data;
	g_task_set_task_data (task, base, g_free);

	secret_item_async_initable_parent_iface->init_async (initable, io_priority,
	                                                     cancellable,
	                                                     on_init_base,
	                                                     g_steal_pointer (&task));

	g_clear_object (&task);
}

static gboolean
secret_item_async_initable_init_finish (GAsyncInitable *initable,
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
secret_item_async_initable_iface (GAsyncInitableIface *iface)
{
	secret_item_async_initable_parent_iface = g_type_interface_peek_parent (iface);

	iface->init_async = secret_item_async_initable_init_async;
	iface->init_finish = secret_item_async_initable_init_finish;
}

/**
 * secret_item_refresh:
 * @self: the collection
 *
 * Refresh the properties on this item.
 *
 * This fires off a request to refresh, and the properties will be updated
 * later.
 *
 * Calling this method is not normally necessary, as the secret service
 * will notify the client when properties change.
 */
void
secret_item_refresh (SecretItem *self)
{
	g_return_if_fail (SECRET_IS_ITEM (self));

	_secret_util_get_properties (G_DBUS_PROXY (self),
	                             secret_item_refresh,
	                             NULL, NULL, NULL);
}

void
_secret_item_set_cached_secret (SecretItem *self,
                                SecretValue *value)
{
	SecretValue *other = NULL;
	gboolean updated = FALSE;

	g_return_if_fail (SECRET_IS_ITEM (self));

	if (value != NULL)
		secret_value_ref (value);

	g_mutex_lock (&self->pv->mutex);

	if (value != self->pv->value) {
		other = self->pv->value;
		self->pv->value = value;
		updated = TRUE;
	} else {
		other = value;
	}

	g_mutex_unlock (&self->pv->mutex);

	if (other != NULL)
		secret_value_unref (other);

	if (updated)
		g_object_notify (G_OBJECT (self), "flags");
}

static void
on_create_item (GObject *source,
                GAsyncResult *result,
                gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretValue *value = g_task_get_task_data (task);
	SecretItem *item;
	GError *error = NULL;

	item = secret_item_new_for_dbus_path_finish (result, &error);
	if (item) {
		/* As a convenience mark down the SecretValue on the item */
		_secret_item_set_cached_secret (item, value);
		g_task_return_pointer (task, item, g_object_unref);
	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}

	g_clear_object (&task);
}

static void
on_create_path (GObject *source,
                GAsyncResult *result,
                gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	GCancellable *cancellable = g_task_get_cancellable (task);
	SecretService *service = SECRET_SERVICE (source);
	GError *error = NULL;
	gchar *path;

	path = secret_service_create_item_dbus_path_finish (service, result, &error);
	if (error == NULL) {
		secret_item_new_for_dbus_path (service, path, SECRET_ITEM_NONE,
		                               cancellable, on_create_item,
		                               g_steal_pointer (&task));
	} else {
		g_task_return_error (task, g_steal_pointer (&error));
	}
	g_free (path);

	g_clear_object (&task);
}

static GHashTable *
item_properties_new (const gchar *label,
                     const SecretSchema *schema,
                     GHashTable *attributes)
{
	const gchar *schema_name = NULL;
	GHashTable *properties;
	GVariant *value;

	if (schema != NULL)
		schema_name = schema->name;

	properties = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
	                                    (GDestroyNotify)g_variant_unref);

	value = g_variant_new_string (label);
	g_hash_table_insert (properties,
	                     SECRET_ITEM_INTERFACE ".Label",
	                     g_variant_ref_sink (value));

	value = _secret_attributes_to_variant (attributes, schema_name);
	g_hash_table_insert (properties,
	                     SECRET_ITEM_INTERFACE ".Attributes",
	                     g_variant_ref_sink (value));

	return properties;
}

/**
 * secret_item_create:
 * @collection: a secret collection to create this item in
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): attributes for the new item
 * @label: label for the new item
 * @value: secret value for the new item
 * @flags: flags for the creation of the new item
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Create a new item in the secret service.
 *
 * If the @flags contains %SECRET_ITEM_CREATE_REPLACE, then the secret
 * service will search for an item matching the @attributes, and update that item
 * instead of creating a new one.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads. The secret service may prompt the user. [method@Service.prompt]
 * will be used to handle any prompts that are required.
 */
void
secret_item_create (SecretCollection *collection,
                    const SecretSchema *schema,
                    GHashTable *attributes,
                    const gchar *label,
                    SecretValue *value,
                    SecretItemCreateFlags flags,
                    GCancellable *cancellable,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
	SecretService *service = NULL;
	const gchar *collection_path;
	GTask *task;
	GHashTable *properties;

	g_return_if_fail (SECRET_IS_COLLECTION (collection));
	g_return_if_fail (label != NULL);
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return;

	task = g_task_new (NULL, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_item_create);
	g_task_set_task_data (task, secret_value_ref (value), secret_value_unref);

	properties = item_properties_new (label, schema, attributes);
	g_object_get (collection, "service", &service, NULL);

	collection_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (collection));

	secret_service_create_item_dbus_path (service, collection_path, properties,
	                                      value, flags, cancellable,
	                                      on_create_path,
	                                      g_steal_pointer (&task));

	g_hash_table_unref (properties);
	g_object_unref (service);
	g_clear_object (&task);
}

/**
 * secret_item_create_finish:
 * @result: the asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Finish operation to create a new item in the secret service.
 *
 * Returns: (transfer full): the new item, which should be unreferenced
 *   with [method@GObject.Object.unref]
 */
SecretItem *
secret_item_create_finish (GAsyncResult *result,
                           GError **error)
{
	SecretItem *retval;

	g_return_val_if_fail (g_task_is_valid (result, NULL), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	retval = g_task_propagate_pointer (G_TASK (result), error);
	if (!retval) {
		_secret_util_strip_remote_error (error);
		return NULL;
	}

	return g_steal_pointer (&retval);
}

/**
 * secret_item_create_sync:
 * @collection: a secret collection to create this item in
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): attributes for the new item
 * @label: label for the new item
 * @value: secret value for the new item
 * @flags: flags for the creation of the new item
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Create a new item in the secret service.
 *
 * If the @flags contains %SECRET_ITEM_CREATE_REPLACE, then the secret
 * service will search for an item matching the @attributes, and update that item
 * instead of creating a new one.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads. The secret service may prompt the user. [method@Service.prompt]
 * will be used to handle any prompts that are required.
 *
 * Returns: (transfer full): the new item, which should be unreferenced
 *   with [method@GObject.Object.unref]
 */
SecretItem *
secret_item_create_sync (SecretCollection *collection,
                         const SecretSchema *schema,
                         GHashTable *attributes,
                         const gchar *label,
                         SecretValue *value,
                         SecretItemCreateFlags flags,
                         GCancellable *cancellable,
                         GError **error)
{
	SecretService *service = NULL;
	const gchar *collection_path;
	SecretItem *item = NULL;
	GHashTable *properties;
	gchar *path;

	g_return_val_if_fail (SECRET_IS_COLLECTION (collection), NULL);
	g_return_val_if_fail (label != NULL, NULL);
	g_return_val_if_fail (attributes != NULL, NULL);
	g_return_val_if_fail (value != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* Warnings raised already */
	if (schema != NULL && !_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
		return NULL;

	properties = item_properties_new (label, schema, attributes);
	g_object_get (collection, "service", &service, NULL);

	collection_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (collection));

	path = secret_service_create_item_dbus_path_sync (service, collection_path, properties,
	                                                  value, flags, cancellable, error);

	if (path != NULL) {
		item = secret_item_new_for_dbus_path_sync (service, path, SECRET_ITEM_NONE,
		                                           cancellable, error);
		g_free (path);
	}

	g_hash_table_unref (properties);
	g_object_unref (service);

	return item;
}

static void
on_item_deleted (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretService *service = SECRET_SERVICE (source);
	GError *error = NULL;

	if (!_secret_service_delete_path_finish (service, result, &error))
		g_task_return_error (task, g_steal_pointer (&error));
	else
		g_task_return_boolean (task, TRUE);

	g_clear_object (&task);
}

/**
 * secret_item_delete:
 * @self: an item
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Delete this item.
 *
 * This method returns immediately and completes asynchronously. The secret
 * service may prompt the user. [method@Service.prompt] will be used to handle
 * any prompts that show up.
 */
void
secret_item_delete (SecretItem *self,
                    GCancellable *cancellable,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
	GTask *task;
	const gchar *object_path;

	g_return_if_fail (SECRET_IS_ITEM (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	object_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (self));
	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_item_delete);

	_secret_service_delete_path (self->pv->service, object_path, TRUE,
	                             cancellable, on_item_deleted,
	                             g_steal_pointer (&task));

	g_clear_object (&task);
}

/**
 * secret_item_delete_finish:
 * @self: an item
 * @result: asynchronous result passed to the callback
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to delete the secret item.
 *
 * Returns: whether the item was successfully deleted or not
 */
gboolean
secret_item_delete_finish (SecretItem *self,
                           GAsyncResult *result,
                           GError **error)
{
	g_return_val_if_fail (SECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

/**
 * secret_item_delete_sync:
 * @self: an item
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Delete this secret item.
 *
 * This method may block indefinitely and should not be used in user
 * interface threads. The secret service may prompt the user.
 * [method@Service.prompt] will be used to handle any prompts that show up.
 *
 * Returns: whether the item was successfully deleted or not
 */
gboolean
secret_item_delete_sync (SecretItem *self,
                         GCancellable *cancellable,
                         GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (SECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_item_delete (self, cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_item_delete_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

/**
 * secret_item_get_flags:  (attributes org.gtk.Method.get_property=flags)
 * @self: the secret item proxy
 *
 * Get the flags representing what features of the #SecretItem proxy
 * have been initialized.
 *
 * Use [method@Item.load_secret] to initialize further features
 * and change the flags.
 *
 * Returns: the flags for features initialized
 */
SecretItemFlags
secret_item_get_flags (SecretItem *self)
{
	SecretServiceFlags flags = 0;

	g_return_val_if_fail (SECRET_IS_ITEM (self), SECRET_ITEM_NONE);

	g_mutex_lock (&self->pv->mutex);

	if (self->pv->value)
		flags |= SECRET_ITEM_LOAD_SECRET;

	g_mutex_unlock (&self->pv->mutex);

	return flags;

}

/**
 * secret_item_get_service: (attributes org.gtk.Method.get_property=service)
 * @self: an item
 *
 * Get the Secret Service object that this item was created with.
 *
 * Returns: (transfer none): the Secret Service object
 */
SecretService *
secret_item_get_service (SecretItem *self)
{
	g_return_val_if_fail (SECRET_IS_ITEM (self), NULL);
	return self->pv->service;
}


/**
 * secret_item_get_secret:
 * @self: an item
 *
 * Get the secret value of this item.
 *
 * If this item is locked or the secret has not yet been loaded then this will
 * return %NULL.
 *
 * To load the secret call the [method@Item.load_secret] method.
 *
 * Returns: (transfer full) (nullable): the secret value which should be
 *   released with [method@Value.unref], or %NULL
 */
SecretValue *
secret_item_get_secret (SecretItem *self)
{
	SecretValue *value = NULL;

	g_return_val_if_fail (SECRET_IS_ITEM (self), NULL);

	g_mutex_lock (&self->pv->mutex);

	if (self->pv->value)
		value = secret_value_ref (self->pv->value);

	g_mutex_unlock (&self->pv->mutex);

	return value;
}

static void
on_item_load_secret (GObject *source,
                     GAsyncResult *result,
                     gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretItem *self = SECRET_ITEM (g_task_get_source_object (task));
	SecretSession *session;
	GError *error = NULL;
	SecretValue *value;
	GVariant *retval;
	GVariant *child;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (error == NULL) {
		child = g_variant_get_child_value (retval, 0);
		g_variant_unref (retval);

		session = _secret_service_get_session (self->pv->service);
		value = _secret_session_decode_secret (session, child);
		g_variant_unref (child);

		if (value == NULL) {
			g_set_error (&error, SECRET_ERROR, SECRET_ERROR_PROTOCOL,
			             _("Received invalid secret from the secret storage"));
		} else {
			_secret_item_set_cached_secret (self, value);
			secret_value_unref (value);
		}
	}

	if (error == NULL)
		g_task_return_boolean (task, TRUE);
	else
		g_task_return_error (task, g_steal_pointer (&error));

	g_clear_object (&task);
}

static void
on_load_ensure_session (GObject *source,
                        GAsyncResult *result,
                        gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretItem *self = SECRET_ITEM (g_task_get_source_object (task));
	GCancellable *cancellable = g_task_get_cancellable (task);
	const gchar *session_path;
	GError *error = NULL;

	secret_service_ensure_session_finish (self->pv->service, result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));

	} else {
		session_path = secret_service_get_session_dbus_path (self->pv->service);
		g_assert (session_path != NULL && session_path[0] != '\0');
		g_dbus_proxy_call (G_DBUS_PROXY (self), "GetSecret",
		                   g_variant_new ("(o)", session_path),
		                   G_DBUS_CALL_FLAGS_NONE, -1, cancellable,
		                   on_item_load_secret, g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

/**
 * secret_item_load_secret:
 * @self: an item proxy
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Load the secret value of this item.
 *
 * Each item has a single secret which might be a password or some
 * other secret binary value.
 *
 * This function will fail if the secret item is locked.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_item_load_secret (SecretItem *self,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	GTask *task;

	g_return_if_fail (SECRET_IS_ITEM (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_item_load_secret);

	secret_service_ensure_session (self->pv->service, cancellable,
	                               on_load_ensure_session,
	                               g_steal_pointer (&task));

	g_clear_object (&task);
}

/**
 * secret_item_load_secret_finish:
 * @self: an item proxy
 * @result: asynchronous result passed to callback
 * @error: location to place error on failure
 *
 * Complete asynchronous operation to load the secret value of this item.
 *
 * The newly loaded secret value can be accessed by calling
 * [method@Item.get_secret].
 *
 * Returns: whether the secret item successfully loaded or not
 */
gboolean
secret_item_load_secret_finish (SecretItem *self,
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

/**
 * secret_item_load_secret_sync:
 * @self: an item
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place error on failure
 *
 * Load the secret value of this item.
 *
 * Each item has a single secret which might be a password or some
 * other secret binary value.
 *
 * This function may block indefinitely. Use the asynchronous version
 * in user interface threads.
 *
 * Returns: whether the secret item successfully loaded or not
 */
gboolean
secret_item_load_secret_sync (SecretItem *self,
                              GCancellable *cancellable,
                              GError **error)
{
	SecretSync *sync;
	gboolean result;

	g_return_val_if_fail (SECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_item_load_secret (self, cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	result = secret_item_load_secret_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return result;
}

static void
on_retrieve_load (GObject *source_object,
		  GAsyncResult *res,
		  gpointer user_data)
{
	SecretItem *self = SECRET_ITEM (source_object);
	GTask *task = G_TASK (user_data);
	GError *error = NULL;

	if (secret_item_load_secret_finish (self, res, &error)) {
		g_task_return_pointer (task,
				       secret_item_get_secret (self),
				       secret_value_unref);
		g_object_unref (task);
	} else {
		g_task_return_error (task, error);
		g_object_unref (task);
	}
}

static void
secret_item_retrieve_secret (SecretRetrievable *self,
			     GCancellable *cancellable,
			     GAsyncReadyCallback callback,
			     gpointer user_data)
{
	GTask *task = g_task_new (self, cancellable, callback, user_data);

	secret_item_load_secret (SECRET_ITEM (self), cancellable, on_retrieve_load, task);
}

static SecretValue *
secret_item_retrieve_secret_finish (SecretRetrievable *self,
				    GAsyncResult *result,
				    GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, self), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
secret_item_retrievable_iface (SecretRetrievableInterface *iface)
{
	secret_item_retrievable_parent_iface = g_type_interface_peek_parent (iface);
	iface->retrieve_secret = secret_item_retrieve_secret;
	iface->retrieve_secret_finish = secret_item_retrieve_secret_finish;
}

typedef struct {
	SecretService *service;
	GVariant *in;
	GHashTable *items;
} LoadsClosure;

static void
loads_closure_free (gpointer data)
{
	LoadsClosure *loads = data;
	if (loads->in)
		g_variant_unref (loads->in);
	if (loads->service)
		g_object_unref (loads->service);
	g_hash_table_destroy (loads->items);
	g_free (loads);
}

static void
on_get_secrets_complete (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	LoadsClosure *loads = g_task_get_task_data (task);
	GHashTable *with_paths;
	GError *error = NULL;
	GHashTableIter iter;
	const gchar *path;
	SecretValue *value;
	SecretItem *item;
	GVariant *retval;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (retval != NULL) {
		with_paths = _secret_service_decode_get_secrets_all (loads->service, retval);
		g_return_if_fail (with_paths != NULL);

		g_hash_table_iter_init (&iter, with_paths);
		while (g_hash_table_iter_next (&iter, (gpointer *)&path, (gpointer *)&value)) {
			item = g_hash_table_lookup (loads->items, path);
			if (item != NULL)
				_secret_item_set_cached_secret (item, value);
		}

		g_hash_table_unref (with_paths);
		g_variant_unref (retval);
	}

	if (error != NULL)
		g_task_return_error (task, g_steal_pointer (&error));
	else
		g_task_return_boolean (task, TRUE);

	g_clear_object (&task);
}

static void
on_loads_secrets_session (GObject *source,
                          GAsyncResult *result,
                          gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	LoadsClosure *loads = g_task_get_task_data (task);
	GError *error = NULL;
	const gchar *session;

	secret_service_ensure_session_finish (SECRET_SERVICE (source), result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
		g_clear_object (&task);
		return;
	}

	session = secret_service_get_session_dbus_path (SECRET_SERVICE (source));
	g_dbus_proxy_call (G_DBUS_PROXY (source), "GetSecrets",
	                   g_variant_new ("(@aoo)", loads->in, session),
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
	                   g_task_get_cancellable (task),
	                   on_get_secrets_complete,
	                   g_object_ref (task));

	g_clear_object (&task);
}

/**
 * secret_item_load_secrets:
 * @items: (element-type Secret.Item): the items to retrieve secrets for
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Load the secret values for a secret item stored in the service.
 *
 * The @items must all have the same [property@Item:service] property.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_item_load_secrets (GList *items,
                          GCancellable *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
	GTask *task;
	LoadsClosure *loads;
	GPtrArray *paths;
	const gchar *path;
	GList *l;

	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	for (l = items; l != NULL; l = g_list_next (l))
		g_return_if_fail (SECRET_IS_ITEM (l->data));

	task = g_task_new (NULL, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_item_load_secrets);
	loads = g_new0 (LoadsClosure, 1);
	loads->items = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                      g_free, g_object_unref);

	paths = g_ptr_array_new ();
	for (l = items; l != NULL; l = g_list_next (l)) {
		if (secret_item_get_locked (l->data))
			continue;

		if (loads->service == NULL) {
			loads->service = secret_item_get_service (l->data);
			if (loads->service)
				g_object_ref (loads->service);
		}

		path = g_dbus_proxy_get_object_path (l->data);
		g_hash_table_insert (loads->items, g_strdup (path), g_object_ref (l->data));
		g_ptr_array_add (paths, (gpointer)path);
	}

	loads->in = g_variant_new_objv ((const gchar * const *)paths->pdata, paths->len);
	g_variant_ref_sink (loads->in);

	g_ptr_array_free (paths, TRUE);
	g_task_set_task_data (task, loads, loads_closure_free);

	if (loads->service) {
		secret_service_ensure_session (loads->service, cancellable,
		                               on_loads_secrets_session,
		                               g_object_ref (task));
	} else {
		g_task_return_boolean (task, TRUE);
	}

	g_clear_object (&task);
}

/**
 * secret_item_load_secrets_finish:
 * @result: asynchronous result passed to callback
 * @error: location to place an error on failure
 *
 * Complete asynchronous operation to load the secret values for
 * secret items stored in the service.
 *
 * Items that are locked will not have their secrets loaded.
 *
 * Returns: whether the operation succeeded or not
 */
gboolean
secret_item_load_secrets_finish (GAsyncResult *result,
                                 GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, NULL), FALSE);

	if (!g_task_propagate_boolean (G_TASK (result), error)) {
		_secret_util_strip_remote_error (error);
		return FALSE;
	}

	return TRUE;
}

/**
 * secret_item_load_secrets_sync:
 * @items: (element-type Secret.Item): the items to retrieve secrets for
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place an error on failure
 *
 * Load the secret values for a secret item stored in the service.
 *
 * The @items must all have the same [property@Item:service] property.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Items that are locked will not have their secrets loaded.
 *
 * Returns: whether the operation succeeded or not
 */
gboolean
secret_item_load_secrets_sync (GList *items,
                               GCancellable *cancellable,
                               GError **error)
{
	SecretSync *sync;
	gboolean ret;
	GList *l;

	for (l = items; l != NULL; l = g_list_next (l))
		g_return_val_if_fail (SECRET_IS_ITEM (l->data), FALSE);

	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_item_load_secrets (items, cancellable,
	                          _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_item_load_secrets_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

static void
on_item_set_secret (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretItem *self = SECRET_ITEM (g_task_get_source_object (task));
	SecretValue *value = g_task_get_task_data (task);
	GError *error = NULL;
	GVariant *retval;

	retval = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);

	if (error) {
		g_task_return_error (task, g_steal_pointer (&error));
		g_clear_object (&task);
		return;
	}

	_secret_item_set_cached_secret (self, value);
	g_clear_pointer (&retval, g_variant_unref);

	g_task_return_boolean (task, TRUE);
	g_clear_object (&task);
}

static void
on_set_ensure_session (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GTask *task = G_TASK (user_data);
	SecretItem *self = SECRET_ITEM (g_task_get_source_object (task));
	SecretValue *value = g_task_get_task_data (task);
	SecretSession *session;
	GVariant *encoded;
	GError *error = NULL;

	secret_service_ensure_session_finish (self->pv->service, result, &error);
	if (error != NULL) {
		g_task_return_error (task, g_steal_pointer (&error));
		g_clear_object (&task);
		return;
	}

	session = _secret_service_get_session (self->pv->service);
	encoded = _secret_session_encode_secret (session, value);
	g_dbus_proxy_call (G_DBUS_PROXY (self), "SetSecret",
	                   g_variant_new ("(@(oayays))", encoded),
	                   G_DBUS_CALL_FLAGS_NO_AUTO_START, -1,
					   g_task_get_cancellable (task),
	                   on_item_set_secret, g_object_ref (task));

	g_clear_object (&task);
}

/**
 * secret_item_set_secret:
 * @self: an item
 * @value: a new secret value
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Set the secret value of this item.
 *
 * Each item has a single secret which might be a password or some
 * other secret binary value.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_item_set_secret (SecretItem *self,
                        SecretValue *value,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GTask *task = NULL;

	g_return_if_fail (SECRET_IS_ITEM (self));
	g_return_if_fail (value != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	task = g_task_new (self, cancellable, callback, user_data);
	g_task_set_source_tag (task, secret_item_set_secret);
	g_task_set_task_data (task, secret_value_ref (value), secret_value_unref);

	secret_service_ensure_session (self->pv->service, cancellable,
	                               on_set_ensure_session,
	                               g_steal_pointer (&task));

	g_clear_object (&task);
}

/**
 * secret_item_set_secret_finish:
 * @self: an item
 * @result: asynchronous result passed to callback
 * @error: location to place error on failure
 *
 * Complete asynchronous operation to set the secret value of this item.
 *
 * Returns: whether the change was successful or not
 */
gboolean
secret_item_set_secret_finish (SecretItem *self,
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

/**
 * secret_item_set_secret_sync:
 * @self: an item
 * @value: a new secret value
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place error on failure
 *
 * Set the secret value of this item.
 *
 * Each item has a single secret which might be a password or some
 * other secret binary value.
 *
 * This function may block indefinitely. Use the asynchronous version
 * in user interface threads.
 *
 * Returns: whether the change was successful or not
 */
gboolean
secret_item_set_secret_sync (SecretItem *self,
                             SecretValue *value,
                             GCancellable *cancellable,
                             GError **error)
{
	SecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (SECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_item_set_secret (self, value, cancellable, _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = secret_item_set_secret_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return ret;
}

/**
 * secret_item_get_schema_name:
 * @self: an item
 *
 * Gets the name of the schema that this item was stored with. This is also
 * available at the `xdg:schema` attribute.
 *
 * Returns: (nullable) (transfer full): the schema name
 */
gchar *
secret_item_get_schema_name (SecretItem *self)
{
	gchar *schema_name = NULL;
	GVariant *variant;

	g_return_val_if_fail (SECRET_IS_ITEM (self), NULL);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Attributes");
	g_return_val_if_fail (variant != NULL, NULL);

	g_variant_lookup (variant, "xdg:schema", "s", &schema_name);
	g_variant_unref (variant);

	return schema_name;
}

/**
 * secret_item_get_attributes:
 * @self: an item
 *
 * Set the attributes of this item.
 *
 * The @attributes are a mapping of string keys to string values.
 * Attributes are used to search for items. Attributes are not stored
 * or transferred securely by the secret service.
 *
 * Do not modify the attributes returned by this method. Use
 * [method@Item.set_attributes] instead.
 *
 * Returns: (transfer full) (element-type utf8 utf8): a new reference
 *   to the attributes, which should not be modified, and
 *   released with [func@GLib.HashTable.unref]
 */
GHashTable *
secret_item_get_attributes (SecretItem *self)
{
	GHashTable *attributes;
	GVariant *variant;

	g_return_val_if_fail (SECRET_IS_ITEM (self), NULL);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Attributes");
	g_return_val_if_fail (variant != NULL, NULL);

	attributes = _secret_attributes_for_variant (variant);
	g_variant_unref (variant);

	return attributes;
}

/**
 * secret_item_set_attributes:
 * @self: an item
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): a new set of attributes
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the asynchronous operation completes
 * @user_data: data to pass to the callback
 *
 * Set the attributes of this item.
 *
 * The @attributes are a mapping of string keys to string values.
 * Attributes are used to search for items. Attributes are not stored
 * or transferred securely by the secret service.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_item_set_attributes (SecretItem *self,
                            const SecretSchema *schema,
                            GHashTable *attributes,
                            GCancellable *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
	const gchar *schema_name = NULL;

	g_return_if_fail (SECRET_IS_ITEM (self));
	g_return_if_fail (attributes != NULL);

	if (schema != NULL) {
		if (!_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
			return; /* Warnings raised already */
		schema_name = schema->name;
	}

	_secret_util_set_property (G_DBUS_PROXY (self), "Attributes",
	                           _secret_attributes_to_variant (attributes, schema_name),
	                           secret_item_set_attributes, cancellable,
	                           callback, user_data);
}

/**
 * secret_item_set_attributes_finish:
 * @self: an item
 * @result: asynchronous result passed to the callback
 * @error: location to place error on failure
 *
 * Complete operation to set the attributes of this item.
 *
 * Returns: whether the change was successful or not
 */
gboolean
secret_item_set_attributes_finish (SecretItem *self,
                                   GAsyncResult *result,
                                   GError **error)
{
	g_return_val_if_fail (SECRET_IS_ITEM (self), FALSE);

	return _secret_util_set_property_finish (G_DBUS_PROXY (self),
	                                         secret_item_set_attributes,
	                                         result, error);
}

/**
 * secret_item_set_attributes_sync:
 * @self: an item
 * @schema: (nullable): the schema for the attributes
 * @attributes: (element-type utf8 utf8): a new set of attributes
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place error on failure
 *
 * Set the attributes of this item.
 *
 * The @attributes are a mapping of string keys to string values.
 * Attributes are used to search for items. Attributes are not stored
 * or transferred securely by the secret service.
 *
 * This function may block indefinitely. Use the asynchronous version
 * in user interface threads.
 *
 * Returns: whether the change was successful or not
 */
gboolean
secret_item_set_attributes_sync (SecretItem *self,
                                 const SecretSchema *schema,
                                 GHashTable *attributes,
                                 GCancellable *cancellable,
                                 GError **error)
{
	const gchar *schema_name = NULL;

	g_return_val_if_fail (SECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (attributes != NULL, FALSE);

	if (schema != NULL) {
		if (!_secret_attributes_validate (schema, attributes, G_STRFUNC, FALSE))
			return FALSE; /* Warnings raised already */
		schema_name = schema->name;
	}

	return _secret_util_set_property_sync (G_DBUS_PROXY (self), "Attributes",
	                                       _secret_attributes_to_variant (attributes, schema_name),
	                                       cancellable, error);
}

/**
 * secret_item_get_label:
 * @self: an item
 *
 * Get the label of this item.
 *
 * Returns: (transfer full): the label, which should be freed with [func@GLib.free]
 */
gchar *
secret_item_get_label (SecretItem *self)
{
	GVariant *variant;
	gchar *label;

	g_return_val_if_fail (SECRET_IS_ITEM (self), NULL);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Label");
	g_return_val_if_fail (variant != NULL, NULL);

	label = g_variant_dup_string (variant, NULL);
	g_variant_unref (variant);

	return label;
}

/**
 * secret_item_set_label:
 * @self: an item
 * @label: a new label
 * @cancellable: (nullable): optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Set the label of this item.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_item_set_label (SecretItem *self,
                       const gchar *label,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	g_return_if_fail (SECRET_IS_ITEM (self));
	g_return_if_fail (label != NULL);

	_secret_util_set_property (G_DBUS_PROXY (self), "Label",
	                           g_variant_new_string (label),
	                           secret_item_set_label,
	                           cancellable, callback, user_data);
}

/**
 * secret_item_set_label_finish:
 * @self: an item
 * @result: asynchronous result passed to callback
 * @error: location to place error on failure
 *
 * Complete asynchronous operation to set the label of this collection.
 *
 * Returns: whether the change was successful or not
 */
gboolean
secret_item_set_label_finish (SecretItem *self,
                              GAsyncResult *result,
                              GError **error)
{
	g_return_val_if_fail (SECRET_IS_ITEM (self), FALSE);

	return _secret_util_set_property_finish (G_DBUS_PROXY (self),
	                                         secret_item_set_label,
	                                         result, error);
}

/**
 * secret_item_set_label_sync:
 * @self: an item
 * @label: a new label
 * @cancellable: (nullable): optional cancellation object
 * @error: location to place error on failure
 *
 * Set the label of this item.
 *
 * This function may block indefinitely. Use the asynchronous version
 * in user interface threads.
 *
 * Returns: whether the change was successful or not
 */
gboolean
secret_item_set_label_sync (SecretItem *self,
                            const gchar *label,
                            GCancellable *cancellable,
                            GError **error)
{
	g_return_val_if_fail (SECRET_IS_ITEM (self), FALSE);
	g_return_val_if_fail (label != NULL, FALSE);

	return _secret_util_set_property_sync (G_DBUS_PROXY (self), "Label",
	                                       g_variant_new_string (label),
	                                       cancellable, error);
}

/**
 * secret_item_get_locked:
 * @self: an item
 *
 * Get whether the item is locked or not.
 *
 * Depending on the secret service an item may not be able to be locked
 * independently from the collection that it is in.
 *
 * Returns: whether the item is locked or not
 */
gboolean
secret_item_get_locked (SecretItem *self)
{
	GVariant *variant;
	gboolean locked;

	g_return_val_if_fail (SECRET_IS_ITEM (self), TRUE);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Locked");
	g_return_val_if_fail (variant != NULL, TRUE);

	locked = g_variant_get_boolean (variant);
	g_variant_unref (variant);

	return locked;
}

/**
 * secret_item_get_created:
 * @self: an item
 *
 * Get the created date and time of the item.
 *
 * The return value is the number of seconds since the unix epoch, January 1st
 * 1970.
 *
 * Returns: the created date and time
 */
guint64
secret_item_get_created (SecretItem *self)
{
	GVariant *variant;
	guint64 created;

	g_return_val_if_fail (SECRET_IS_ITEM (self), TRUE);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Created");
	g_return_val_if_fail (variant != NULL, 0);

	created = g_variant_get_uint64 (variant);
	g_variant_unref (variant);

	return created;
}

/**
 * secret_item_get_modified:
 * @self: an item
 *
 * Get the modified date and time of the item.
 *
 * The return value is the number of seconds since the unix epoch, January 1st
 * 1970.
 *
 * Returns: the modified date and time
 */
guint64
secret_item_get_modified (SecretItem *self)
{
	GVariant *variant;
	guint64 modified;

	g_return_val_if_fail (SECRET_IS_ITEM (self), TRUE);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Modified");
	g_return_val_if_fail (variant != NULL, 0);

	modified = g_variant_get_uint64 (variant);
	g_variant_unref (variant);

	return modified;
}
