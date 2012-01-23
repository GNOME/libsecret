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

#include "gsecret-collection.h"
#include "gsecret-dbus-generated.h"
#include "gsecret-item.h"
#include "gsecret-private.h"
#include "gsecret-service.h"
#include "gsecret-types.h"

#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_SERVICE,
	PROP_ITEMS,
	PROP_LABEL,
	PROP_LOCKED,
	PROP_CREATED,
	PROP_MODIFIED
};

struct _GSecretCollectionPrivate {
	/* Doesn't change between construct and finalize */
	GSecretService *service;
	GCancellable *cancellable;
	gboolean constructing;

	/* Protected by mutex */
	GMutex mutex;
	GHashTable *items;
};

G_DEFINE_TYPE (GSecretCollection, gsecret_collection, G_TYPE_DBUS_PROXY);

static GHashTable *
items_table_new (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal,
	                              g_free, g_object_unref);
}

static void
gsecret_collection_init (GSecretCollection *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GSECRET_TYPE_COLLECTION,
	                                        GSecretCollectionPrivate);

	g_mutex_init (&self->pv->mutex);
	self->pv->cancellable = g_cancellable_new ();
	self->pv->items = items_table_new ();
	self->pv->constructing = TRUE;
}

static void
on_set_label (GObject *source,
              GAsyncResult *result,
              gpointer user_data)
{
	GSecretCollection *self = GSECRET_COLLECTION (user_data);
	GError *error = NULL;

	gsecret_collection_set_label_finish (self, result, &error);
	if (error != NULL) {
		g_warning ("couldn't set GSecretCollection Label: %s", error->message);
		g_error_free (error);
	}

	g_object_unref (self);
}

static void
gsecret_collection_set_property (GObject *obj,
                                 guint prop_id,
                                 const GValue *value,
                                 GParamSpec *pspec)
{
	GSecretCollection *self = GSECRET_COLLECTION (obj);

	switch (prop_id) {
	case PROP_SERVICE:
		g_return_if_fail (self->pv->service == NULL);
		self->pv->service = g_value_get_object (value);
		if (self->pv->service)
			g_object_add_weak_pointer (G_OBJECT (self->pv->service),
			                           (gpointer *)&self->pv->service);
		break;
	case PROP_LABEL:
		gsecret_collection_set_label (self, g_value_get_string (value),
		                              self->pv->cancellable, on_set_label,
		                              g_object_ref (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gsecret_collection_get_property (GObject *obj,
                                 guint prop_id,
                                 GValue *value,
                                 GParamSpec *pspec)
{
	GSecretCollection *self = GSECRET_COLLECTION (obj);

	switch (prop_id) {
	case PROP_SERVICE:
		g_value_set_object (value, self->pv->service);
		break;
	case PROP_ITEMS:
		g_value_take_boxed (value, gsecret_collection_get_items (self));
		break;
	case PROP_LABEL:
		g_value_take_string (value, gsecret_collection_get_label (self));
		break;
	case PROP_LOCKED:
		g_value_set_boolean (value, gsecret_collection_get_locked (self));
		break;
	case PROP_CREATED:
		g_value_set_uint64 (value, gsecret_collection_get_created (self));
		break;
	case PROP_MODIFIED:
		g_value_set_uint64 (value, gsecret_collection_get_modified (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gsecret_collection_dispose (GObject *obj)
{
	GSecretCollection *self = GSECRET_COLLECTION (obj);

	g_cancellable_cancel (self->pv->cancellable);

	G_OBJECT_CLASS (gsecret_collection_parent_class)->dispose (obj);
}

static void
gsecret_collection_finalize (GObject *obj)
{
	GSecretCollection *self = GSECRET_COLLECTION (obj);

	if (self->pv->service)
		g_object_remove_weak_pointer (G_OBJECT (self->pv->service),
		                              (gpointer *)&self->pv->service);

	g_mutex_clear (&self->pv->mutex);
	g_hash_table_destroy (self->pv->items);
	g_object_unref (self->pv->cancellable);

	G_OBJECT_CLASS (gsecret_collection_parent_class)->finalize (obj);
}

typedef struct {
	GSecretCollection *collection;
	GCancellable *cancellable;
	GHashTable *items;
	gint items_loading;
} LoadClosure;

static void
load_closure_free (gpointer data)
{
	LoadClosure *closure = data;
	g_object_unref (closure->collection);
	g_clear_object (&closure->cancellable);
	g_hash_table_unref (closure->items);
	g_slice_free (LoadClosure, closure);
}

static GSimpleAsyncResult *
load_result_new (GCancellable *cancellable,
                 GAsyncReadyCallback callback,
                 gpointer user_data)
{
	GSimpleAsyncResult *res;
	LoadClosure *closure;

	res = g_simple_async_result_new (NULL, callback, user_data, load_result_new);
	closure = g_slice_new0 (LoadClosure);
	closure->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	closure->items = items_table_new ();
	g_simple_async_result_set_op_res_gpointer (res, closure, load_closure_free);

	return res;
}

static void
load_items_complete (GSimpleAsyncResult *res)
{
	LoadClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretCollection *self = closure->collection;
	GHashTable *items;

	g_assert (closure->items_loading == 0);

	g_hash_table_ref (closure->items);

	g_mutex_lock (&self->pv->mutex);
	items = self->pv->items;
	self->pv->items = closure->items;
	g_mutex_unlock (&self->pv->mutex);

	g_hash_table_unref (items);

	g_simple_async_result_complete (res);
}

static void
on_item_loading (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	LoadClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	const gchar *item_path;
	GError *error = NULL;
	GSecretItem *item;

	closure->items_loading--;

	item = gsecret_item_new_finish (result, &error);

	if (error != NULL)
		g_simple_async_result_take_error (res, error);

	if (item != NULL) {
		item_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (item));
		g_hash_table_insert (closure->items, g_strdup (item_path), item);
	}

	if (closure->items_loading == 0)
		load_items_complete (res);

	g_object_unref (res);
}

static void
load_items_perform (GSecretCollection *self,
                    GSimpleAsyncResult *res,
                    GVariant *item_paths)
{
	LoadClosure *closure = g_simple_async_result_get_op_res_gpointer (res);
	GSecretItem *item;
	GVariantIter iter;
	gchar *item_path;

	g_assert (GSECRET_IS_COLLECTION (self));
	g_assert (item_paths != NULL);
	g_assert (closure->collection == NULL);

	closure->collection = g_object_ref (self);

	g_variant_iter_init (&iter, item_paths);
	while (g_variant_iter_loop (&iter, "o", &item_path)) {

		g_mutex_lock (&self->pv->mutex);
		item = g_hash_table_lookup (self->pv->items, item_path);
		if (item != NULL)
			g_object_ref (item);
		g_mutex_unlock (&self->pv->mutex);

		if (item == NULL) {
			// TODO: xxxxxxxxxxxx;
			gsecret_item_new (self->pv->service, item_path,
			                  closure->cancellable, on_item_loading,
			                  g_object_ref (res));
			closure->items_loading++;

		} else {
			g_hash_table_insert (closure->items,
			                     g_strdup (item_path), item);
		}

	}

	if (closure->items_loading == 0)
		load_items_complete (res);
}

static void
handle_property_changed (GSecretCollection *self,
                         const gchar *property_name,
                         GVariant *value)
{
	GSimpleAsyncResult *res;

	if (g_str_equal (property_name, "Label"))
		g_object_notify (G_OBJECT (self), "label");

	else if (g_str_equal (property_name, "Locked"))
		g_object_notify (G_OBJECT (self), "locked");

	else if (g_str_equal (property_name, "Created"))
		g_object_notify (G_OBJECT (self), "created");

	else if (g_str_equal (property_name, "Modified"))
		g_object_notify (G_OBJECT (self), "modified");

	else if (g_str_equal (property_name, "Items") && !self->pv->constructing) {
		res = load_result_new (self->pv->cancellable, NULL, NULL);

		if (value == NULL)
			value = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Items");
		else
			g_variant_ref (value);
		if (value == NULL) {
			g_warning ("couldn't retrieve Collection Items property");
			g_simple_async_result_complete (res);
		} else {
			// TODO: yyyy;
			load_items_perform (self, res, value);
			g_variant_unref (value);
		}

		g_object_unref (res);
	}
}

static void
gsecret_collection_properties_changed (GDBusProxy *proxy,
                                       GVariant *changed_properties,
                                       const gchar* const *invalidated_properties)
{
	GSecretCollection *self = GSECRET_COLLECTION (proxy);
	gchar *property_name;
	GVariantIter iter;
	GVariant *value;

	g_object_freeze_notify (G_OBJECT (self));

	g_variant_iter_init (&iter, changed_properties);
	while (g_variant_iter_loop (&iter, "{sv}", &property_name, &value))
		// TODO: zzzz;
		handle_property_changed (self, property_name, value);

	g_object_thaw_notify (G_OBJECT (self));
}

static void
gsecret_collection_class_init (GSecretCollectionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GDBusProxyClass *proxy_class = G_DBUS_PROXY_CLASS (klass);

	gobject_class->get_property = gsecret_collection_get_property;
	gobject_class->set_property = gsecret_collection_set_property;
	gobject_class->dispose = gsecret_collection_dispose;
	gobject_class->finalize = gsecret_collection_finalize;

	proxy_class->g_properties_changed = gsecret_collection_properties_changed;

	g_object_class_install_property (gobject_class, PROP_SERVICE,
	            g_param_spec_object ("service", "Service", "Secret Service",
	                                 GSECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_ITEMS,
	             g_param_spec_boxed ("items", "Items", "Items in collection",
	                                 _gsecret_list_get_type (), G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

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

	g_type_class_add_private (gobject_class, sizeof (GSecretCollectionPrivate));
}

static void
on_collection_new (GObject *source,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GSecretCollection *self;
	GObject *source_object;
	GError *error = NULL;
	GVariant *item_paths;
	GObject *object;
	GDBusProxy *proxy;

	source_object = g_async_result_get_source_object (result);
	object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
	                                      result, &error);
	g_object_unref (source_object);

	proxy = G_DBUS_PROXY (object);
	if (error == NULL && !_gsecret_util_have_cached_properties (proxy)) {
		g_set_error (&error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD,
		             "No such secret collection at path: %s", g_dbus_proxy_get_object_path (proxy));
	}

	if (error == NULL) {
		self = GSECRET_COLLECTION (object);
		self->pv->constructing = FALSE;

		item_paths = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (object), "Items");
		g_return_if_fail (item_paths != NULL);
		// TODO: yyyy;
		load_items_perform (self, res, item_paths);
		g_variant_unref (item_paths);

	} else {
		g_simple_async_result_take_error (res, error);
		g_simple_async_result_complete (res);
	}

	g_clear_object (&object);
	g_object_unref (res);
}

void
gsecret_collection_new (GSecretService *service,
                        const gchar *collection_path,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	GSimpleAsyncResult *res;
	GDBusProxy *proxy;

	g_return_if_fail (GSECRET_IS_SERVICE (service));
	g_return_if_fail (collection_path != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	res = load_result_new (cancellable, callback, user_data);
	proxy = G_DBUS_PROXY (service);

	g_async_initable_new_async (GSECRET_SERVICE_GET_CLASS (service)->collection_gtype,
	                            G_PRIORITY_DEFAULT,
	                            cancellable,
	                            // TODO: zzzz;
	                            on_collection_new,
	                            g_object_ref (res),
	                            "g-flags", G_DBUS_CALL_FLAGS_NONE,
	                            "g-interface-info", _gsecret_gen_collection_interface_info (),
	                            "g-name", g_dbus_proxy_get_name (proxy),
	                            "g-connection", g_dbus_proxy_get_connection (proxy),
	                            "g-object-path", collection_path,
	                            "g-interface-name", GSECRET_COLLECTION_INTERFACE,
	                            "service", service,
	                            NULL);

	g_object_unref (res);
}

GSecretCollection *
gsecret_collection_new_finish (GAsyncResult *result,
                               GError **error)
{
	GSimpleAsyncResult *res;
	LoadClosure *closure;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, NULL, load_result_new), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	res = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (res, error))
		return NULL;

	closure = g_simple_async_result_get_op_res_gpointer (res);
	return g_object_ref (closure->collection);
}

GSecretCollection *
gsecret_collection_new_sync (GSecretService *service,
                             const gchar *collection_path,
                             GCancellable *cancellable,
                             GError **error)
{
	GSecretSync *sync;
	GSecretCollection *collection;

	g_return_val_if_fail (GSECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (collection_path != NULL, NULL);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	// TODO: xxxxx;
	gsecret_collection_new (service, collection_path, cancellable,
	                        _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	collection = gsecret_collection_new_finish (sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return collection;
}

void
gsecret_collection_refresh (GSecretCollection *self)
{
	g_return_if_fail (GSECRET_IS_COLLECTION (self));

	_gsecret_util_get_properties (G_DBUS_PROXY (self),
	                              gsecret_collection_refresh,
	                              self->pv->cancellable, NULL, NULL);
}

void
gsecret_collection_delete (GSecretCollection *self,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	const gchar *object_path;

	g_return_if_fail (GSECRET_IS_COLLECTION (self));
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	object_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (self));
	gsecret_service_delete_path (self->pv->service, object_path, cancellable,
	                             callback, user_data);
}

gboolean
gsecret_collection_delete_finish (GSecretCollection *self,
                                  GAsyncResult *result,
                                  GError **error)
{
	g_return_val_if_fail (GSECRET_IS_COLLECTION (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	return gsecret_service_delete_path_finish (self->pv->service, result, error);
}

gboolean
gsecret_collection_delete_sync (GSecretCollection *self,
                                GCancellable *cancellable,
                                GError **error)
{
	GSecretSync *sync;
	gboolean ret;

	g_return_val_if_fail (GSECRET_IS_COLLECTION (self), FALSE);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _gsecret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	gsecret_collection_delete (self, cancellable, _gsecret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	ret = gsecret_collection_delete_finish (self, sync->result, error);

	g_main_context_pop_thread_default (sync->context);
	_gsecret_sync_free (sync);

	return ret;
}

GList *
gsecret_collection_get_items (GSecretCollection *self)
{
	GList *l, *items;

	g_return_val_if_fail (GSECRET_IS_COLLECTION (self), NULL);

	g_mutex_lock (&self->pv->mutex);
	items = g_hash_table_get_values (self->pv->items);
	for (l = items; l != NULL; l = g_list_next (l))
		g_object_ref (l->data);
	g_mutex_unlock (&self->pv->mutex);

	return items;
}

GSecretItem *
_gsecret_collection_find_item_instance (GSecretCollection *self,
                                        const gchar *item_path)
{
	GSecretItem *item;

	g_mutex_lock (&self->pv->mutex);
	item = g_hash_table_lookup (self->pv->items, item_path);
	if (item != NULL)
		g_object_ref (item);
	g_mutex_unlock (&self->pv->mutex);

	return item;
}

gchar *
gsecret_collection_get_label (GSecretCollection *self)
{
	GVariant *variant;
	gchar *label;

	g_return_val_if_fail (GSECRET_IS_COLLECTION (self), NULL);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Label");
	g_return_val_if_fail (variant != NULL, NULL);

	label = g_variant_dup_string (variant, NULL);
	g_variant_unref (variant);

	return label;
}

void
gsecret_collection_set_label (GSecretCollection *self,
                              const gchar *label,
                              GCancellable *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
	g_return_if_fail (GSECRET_IS_COLLECTION (self));
	g_return_if_fail (label != NULL);

	_gsecret_util_set_property (G_DBUS_PROXY (self), "Label",
	                            g_variant_new_string (label),
	                            gsecret_collection_set_label,
	                            cancellable, callback, user_data);
}

gboolean
gsecret_collection_set_label_finish (GSecretCollection *self,
                                     GAsyncResult *result,
                                     GError **error)
{
	g_return_val_if_fail (GSECRET_IS_COLLECTION (self), FALSE);

	return _gsecret_util_set_property_finish (G_DBUS_PROXY (self),
	                                          gsecret_collection_set_label,
	                                          result, error);
}

gboolean
gsecret_collection_set_label_sync (GSecretCollection *self,
                                   const gchar *label,
                                   GCancellable *cancellable,
                                   GError **error)
{
	g_return_val_if_fail (GSECRET_IS_COLLECTION (self), FALSE);
	g_return_val_if_fail (label != NULL, FALSE);

	return _gsecret_util_set_property_sync (G_DBUS_PROXY (self), "Label",
	                                        g_variant_new_string (label),
	                                        cancellable, error);
}

gboolean
gsecret_collection_get_locked (GSecretCollection *self)
{
	GVariant *variant;
	gboolean locked;

	g_return_val_if_fail (GSECRET_IS_COLLECTION (self), TRUE);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Locked");
	g_return_val_if_fail (variant != NULL, TRUE);

	locked = g_variant_get_boolean (variant);
	g_variant_unref (variant);

	return locked;
}

guint64
gsecret_collection_get_created (GSecretCollection *self)
{
	GVariant *variant;
	guint64 created;

	g_return_val_if_fail (GSECRET_IS_COLLECTION (self), TRUE);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Created");
	g_return_val_if_fail (variant != NULL, 0);

	created = g_variant_get_uint64 (variant);
	g_variant_unref (variant);

	return created;
}

guint64
gsecret_collection_get_modified (GSecretCollection *self)
{
	GVariant *variant;
	guint64 modified;

	g_return_val_if_fail (GSECRET_IS_COLLECTION (self), TRUE);

	variant = g_dbus_proxy_get_cached_property (G_DBUS_PROXY (self), "Modified");
	g_return_val_if_fail (variant != NULL, 0);

	modified = g_variant_get_uint64 (variant);
	g_variant_unref (variant);

	return modified;
}
