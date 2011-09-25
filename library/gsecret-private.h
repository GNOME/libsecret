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

#define             GSECRET_SERVICE_PATH              "/org/freedesktop/secrets"

#define             GSECRET_SERVICE_BUS_NAME          "org.freedesktop.Secret.Service"

#define             GSECRET_SERVICE_INTERFACE         "org.freedesktop.Secret.Service"

#define             GSECRET_COLLECTION_INTERFACE      "org.freedesktop.Secret.Collection"

gchar *             _gsecret_util_parent_path         (const gchar *path);

GSecretService *    _gsecret_service_bare_instance    (GDBusConnection *connection,
                                                       const gchar *bus_name);

GVariant *          _gsecret_service_encode_secret    (GSecretService *self,
                                                       GSecretValue *value);

GSecretValue *      _gsecret_service_decode_secret    (GSecretService *service,
                                                       GVariant *encoded);

const gchar *       _gsecret_service_ensure_session_finish     (GSecretService *self,
                                                                GAsyncResult *result,
                                                                GCancellable **cancellable,
                                                                GError **error);

G_END_DECLS

#endif /* __G_SERVICE_H___ */
