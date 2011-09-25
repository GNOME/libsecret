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

#define             GSECRET_COLLECTION_INTERFACE      "org.freedesktop.Secret.Collection"

gchar *             _gsecret_util_parent_path         (const gchar *path);

GVariant *          _gsecret_service_encode_secret    (GSecretService *self,
                                                       GSecretValue *value);

GSecretValue *      _gsecret_service_decode_secret    (GSecretService *service,
                                                       GVariant *encoded);

GCancellable *      _gsecret_async_result_get_cancellable     (GSimpleAsyncResult *result);

void                _gsecret_async_result_set_cancellable     (GSimpleAsyncResult *result,
                                                               GCancellable *cancellable);

gboolean            _gsecret_async_result_propagate_cancelled (GSimpleAsyncResult *result);

G_END_DECLS

#endif /* __G_SERVICE_H___ */
