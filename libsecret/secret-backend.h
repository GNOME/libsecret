/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2019 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Daiki Ueno
 */

#if !defined (__SECRET_INSIDE_HEADER__) && !defined (SECRET_COMPILATION)
#error "Only <libsecret/secret.h> can be included directly."
#endif

#ifndef __SECRET_BACKEND_H__
#define __SECRET_BACKEND_H__

#include <glib-object.h>
#include "secret-schema.h"
#include "secret-service.h"
#include "secret-value.h"

G_BEGIN_DECLS

typedef enum {
        SECRET_BACKEND_NONE = SECRET_SERVICE_NONE,
        SECRET_BACKEND_OPEN_SESSION = SECRET_SERVICE_OPEN_SESSION,
        SECRET_BACKEND_LOAD_COLLECTIONS = SECRET_SERVICE_LOAD_COLLECTIONS,
} SecretBackendFlags;

#define SECRET_TYPE_BACKEND secret_backend_get_type ()
G_DECLARE_INTERFACE (SecretBackend, secret_backend, SECRET, BACKEND, GObject)

struct _SecretBackendInterface
{
        GTypeInterface parent_iface;

        void         (*ensure_for_flags)        (SecretBackend *self,
                                                 SecretBackendFlags flags,
						 GCancellable *cancellable,
						 GAsyncReadyCallback callback,
                                                 gpointer user_data);
        gboolean     (*ensure_for_flags_finish) (SecretBackend *self,
                                                 GAsyncResult *result,
                                                 GError **error);

        void         (*store)                   (SecretBackend *self,
                                                 const SecretSchema *schema,
                                                 GHashTable *attributes,
                                                 const gchar *collection,
                                                 const gchar *label,
                                                 SecretValue *value,
                                                 GCancellable *cancellable,
                                                 GAsyncReadyCallback callback,
                                                 gpointer user_data);
        gboolean     (*store_finish)            (SecretBackend *self,
                                                 GAsyncResult *result,
                                                 GError **error);

        void         (*lookup)                  (SecretBackend *self,
                                                 const SecretSchema *schema,
                                                 GHashTable *attributes,
                                                 GCancellable *cancellable,
                                                 GAsyncReadyCallback callback,
                                                 gpointer user_data);
        SecretValue *(*lookup_finish)           (SecretBackend *self,
                                                 GAsyncResult *result,
                                                 GError **error);

        void         (*clear)                   (SecretBackend *self,
                                                 const SecretSchema *schema,
                                                 GHashTable *attributes,
                                                 GCancellable *cancellable,
                                                 GAsyncReadyCallback callback,
                                                 gpointer user_data);
        gboolean     (*clear_finish)            (SecretBackend *self,
                                                 GAsyncResult *result,
                                                 GError **error);

        void         (*search)                  (SecretBackend *self,
                                                 const SecretSchema *schema,
                                                 GHashTable *attributes,
                                                 SecretSearchFlags flags,
                                                 GCancellable *cancellable,
                                                 GAsyncReadyCallback callback,
                                                 gpointer user_data);
        GList *      (*search_finish)           (SecretBackend *self,
                                                 GAsyncResult *result,
                                                 GError **error);
};

#define SECRET_BACKEND_EXTENSION_POINT_NAME "secret-backend"

void           _secret_backend_ensure_extension_point
                                         (void);
void           _secret_backend_uncache_instance
                                         (void);

void           secret_backend_get        (SecretBackendFlags flags,
                                          GCancellable *cancellable,
                                          GAsyncReadyCallback callback,
                                          gpointer user_data);

SecretBackend *secret_backend_get_finish (GAsyncResult *result,
                                          GError **error);

G_END_DECLS

#endif /* __SECRET_BACKEND_H__ */
