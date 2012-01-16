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
	GVariant *in;
	GVariant *out;
	GCancellable *cancellable;
} GSecretParams;

#define             GSECRET_SERVICE_PATH              "/org/freedesktop/secrets"

#define             GSECRET_SERVICE_BUS_NAME          "org.freedesktop.Secret.Service"

#define             GSECRET_ITEM_INTERFACE            "org.freedesktop.Secret.Item"
#define             GSECRET_COLLECTION_INTERFACE      "org.freedesktop.Secret.Collection"
#define             GSECRET_PROMPT_INTERFACE          "org.freedesktop.Secret.Prompt"
#define             GSECRET_SERVICE_INTERFACE         "org.freedesktop.Secret.Service"

#define             GSECRET_PROMPT_SIGNAL_COMPLETED   "Completed"

#define             GSECRET_PROPERTIES_INTERFACE      "org.freedesktop.DBus.Properties"

GSecretParams *     _gsecret_params_new                        (GCancellable *cancellable,
                                                                GVariant *in);

void                _gsecret_params_free                       (gpointer data);

GSecretPrompt *     _gsecret_prompt_instance                   (GDBusConnection *connection,
                                                                const gchar *object_path);

gchar *             _gsecret_util_parent_path         (const gchar *path);

gboolean            _gsecret_util_empty_path                   (const gchar *path);

GVariant *          _gsecret_util_variant_for_attributes       (GHashTable *attributes);

GHashTable *        _gsecret_util_attributes_for_variant       (GVariant *variant);

GHashTable *        _gsecret_util_attributes_for_varargs       (const GSecretSchema *schema,
                                                                va_list va);

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

void                _gsecret_service_set_default_bus_name      (const gchar *bus_name);

GSecretService *    _gsecret_service_bare_instance    (GDBusConnection *connection,
                                                       const gchar *bus_name);

void                _gsecret_service_bare_connect              (const gchar *bus_name,
                                                                gboolean ensure_session,
                                                                GCancellable *cancellable,
                                                                GAsyncReadyCallback callback,
                                                                gpointer user_data);

GSecretService *    _gsecret_service_bare_connect_finish       (GAsyncResult *result,
                                                                GError **error);

GVariant *          _gsecret_service_encode_secret    (GSecretService *self,
                                                       GSecretValue *value);

GSecretValue *      _gsecret_service_decode_secret    (GSecretService *service,
                                                       GVariant *encoded);

const gchar *       _gsecret_service_ensure_session_finish     (GSecretService *self,
                                                                GAsyncResult *result,
                                                                GCancellable **cancellable,
                                                                GError **error);

gchar *             _gsecret_value_unref_to_password           (GSecretValue *value);

G_END_DECLS

#endif /* __G_SERVICE_H___ */
