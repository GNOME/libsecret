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
#ifndef __GSECRET_PRIVATE_H__
#define __GSECRET_PRIVATE_H__

#include <gio/gio.h>

#include "gsecret-service.h"
#include "gsecret-value.h"

G_BEGIN_DECLS

typedef struct {
	GAsyncResult *result;
	GMainContext *context;
	GMainLoop *loop;
} GSecretSync;

typedef struct _GSecretSession GSecretSession;

#define             GSECRET_SERVICE_PATH              "/org/freedesktop/secrets"

#define             GSECRET_SERVICE_BUS_NAME          "org.freedesktop.Secret.Service"

#define             GSECRET_ITEM_INTERFACE            "org.freedesktop.Secret.Item"
#define             GSECRET_COLLECTION_INTERFACE      "org.freedesktop.Secret.Collection"
#define             GSECRET_PROMPT_INTERFACE          "org.freedesktop.Secret.Prompt"
#define             GSECRET_SERVICE_INTERFACE         "org.freedesktop.Secret.Service"

#define             GSECRET_PROMPT_SIGNAL_COMPLETED   "Completed"

#define             GSECRET_PROPERTIES_INTERFACE      "org.freedesktop.DBus.Properties"

GSecretSync *       _gsecret_sync_new                          (void);

void                _gsecret_sync_free                         (gpointer data);

void                _gsecret_sync_on_result                    (GObject *source,
                                                                GAsyncResult *result,
                                                                gpointer user_data);

GSecretPrompt *     _gsecret_prompt_instance                   (GDBusConnection *connection,
                                                                const gchar *object_path);

gchar *             _gsecret_util_parent_path         (const gchar *path);

gboolean            _gsecret_util_empty_path                   (const gchar *path);

GType               _gsecret_list_get_type                     (void) G_GNUC_CONST;

GVariant *          _gsecret_util_variant_for_attributes       (GHashTable *attributes);

GHashTable *        _gsecret_util_attributes_for_variant       (GVariant *variant);

GHashTable *        _gsecret_util_attributes_for_varargs       (const GSecretSchema *schema,
                                                                va_list va);

void                _gsecret_util_get_properties               (GDBusProxy *proxy,
                                                                gpointer result_tag,
                                                                GCancellable *cancellable,
                                                                GAsyncReadyCallback callback,
                                                                gpointer user_data);

gboolean            _gsecret_util_get_properties_finish        (GDBusProxy *proxy,
                                                                gpointer result_tag,
                                                                GAsyncResult *result,
                                                                GError **error);

void                _gsecret_util_set_property                 (GDBusProxy *proxy,
                                                                const gchar *property,
                                                                GVariant *value,
                                                                gpointer result_tag,
                                                                GCancellable *cancellable,
                                                                GAsyncReadyCallback callback,
                                                                gpointer user_data);

gboolean            _gsecret_util_set_property_finish          (GDBusProxy *proxy,
                                                                gpointer result_tag,
                                                                GAsyncResult *result,
                                                                GError **error);

gboolean            _gsecret_util_set_property_sync            (GDBusProxy *proxy,
                                                                const gchar *property,
                                                                GVariant *value,
                                                                GCancellable *cancellable,
                                                                GError **error);

gboolean            _gsecret_util_have_cached_properties       (GDBusProxy *proxy);

void                _gsecret_service_set_default_bus_name      (const gchar *bus_name);

GSecretSession *    _gsecret_service_get_session               (GSecretService *self);

void                _gsecret_service_take_session              (GSecretService *self,
                                                                GSecretSession *session);

void                _gsecret_service_delete_path               (GSecretService *self,
                                                                const gchar *object_path,
                                                                gboolean is_an_item,
                                                                GCancellable *cancellable,
                                                                GAsyncReadyCallback callback,
                                                                gpointer user_data);

GSecretItem *       _gsecret_service_find_item_instance        (GSecretService *self,
                                                                const gchar *item_path);

GSecretItem *       _gsecret_collection_find_item_instance     (GSecretCollection *self,
                                                                const gchar *item_path);

gchar *             _gsecret_value_unref_to_password           (GSecretValue *value);

void                _gsecret_session_free                      (gpointer data);

const gchar *       _gsecret_session_get_algorithms            (GSecretSession *session);

const gchar *       _gsecret_session_get_path                  (GSecretSession *session);

void                _gsecret_session_open                      (GSecretService *service,
                                                                GCancellable *cancellable,
                                                                GAsyncReadyCallback callback,
                                                                gpointer user_data);

gboolean            _gsecret_session_open_finish               (GAsyncResult *result,
                                                                GError **error);

GVariant *          _gsecret_session_encode_secret             (GSecretSession *session,
                                                                GSecretValue *value);

GSecretValue *      _gsecret_session_decode_secret             (GSecretSession *session,
                                                                GVariant *encoded);

G_END_DECLS

#endif /* __G_SERVICE_H___ */
