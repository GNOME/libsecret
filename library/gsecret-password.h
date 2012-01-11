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

#ifndef __GSECRET_PASSWORD_H__
#define __GSECRET_PASSWORD_H__

#include <gio/gio.h>

G_BEGIN_DECLS

#include "gsecret-types.h"

#if 0

void        gsecret_password_store                      (const GSecretSchema *schema,
                                                         const gchar *collection_path,
                                                         const gchar *label,
                                                         const gchar *password,
                                                         GCancellable *cancellable,
                                                         GAsyncReadyCallback callback,
                                                         gpointer user_data,
                                                         ...) G_GNUC_NULL_TERMINATED;

gboolean    gsecret_password_store_finish               (GAsyncResult *result,
                                                         GError **error);

void        gsecret_password_store_sync                 (const GSecretSchema *schema,
                                                         const gchar *collection,
                                                         const gchar *display_name,
                                                         const gchar *password,
                                                         GCancellable *cancellable,
                                                         GError **error,
                                                         ...) G_GNUC_NULL_TERMINATED;

void        gsecret_password_lookup                     (const GSecretSchema *schema,
                                                         GCancellable *cancellable,
                                                         GAsyncReadyCallback callback,
                                                         gpointer user_data,
                                                         ...) G_GNUC_NULL_TERMINATED;

gchar *     gsecret_password_lookup_finish              (GAsyncResult *result,
                                                         GError **error);

gchar *     gsecret_password_lookup_sync                (const GSecretSchema *schema,
                                                         GCancellable *cancellable,
                                                         GError **error,
                                                         ...) G_GNUC_NULL_TERMINATED;

#endif

void        gsecret_password_delete                     (const GSecretSchema *schema,
                                                         GCancellable *cancellable,
                                                         GAsyncReadyCallback callback,
                                                         gpointer user_data,
                                                         ...) G_GNUC_NULL_TERMINATED;

void        gsecret_password_deletev                    (GHashTable *attributes,
                                                         GCancellable *cancellable,
                                                         GAsyncReadyCallback callback,
                                                         gpointer user_data);

gboolean    gsecret_password_delete_finish              (GAsyncResult *result,
                                                         GError **error);

gboolean    gsecret_password_delete_sync                (const GSecretSchema* schema,
                                                         GCancellable *cancellable,
                                                         GError **error,
                                                         ...) G_GNUC_NULL_TERMINATED;

gboolean    gsecret_password_deletev_sync               (GHashTable *attributes,
                                                         GCancellable *cancellable,
                                                         GError **error);

void        gsecret_password_free                       (gpointer password);

G_END_DECLS

#endif /* __G_SERVICE_H___ */
