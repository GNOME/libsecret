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

#ifndef __SECRET_FILE_COLLECTION_H__
#define __SECRET_FILE_COLLECTION_H__

#include "secret-file-item.h"
#include "secret-value.h"

G_BEGIN_DECLS

#define SECRET_TYPE_FILE_COLLECTION (secret_file_collection_get_type ())
G_DECLARE_FINAL_TYPE (SecretFileCollection, secret_file_collection, SECRET, FILE_COLLECTION, GObject)

gboolean        secret_file_collection_replace (SecretFileCollection  *self,
                                                GHashTable            *attributes,
                                                const gchar           *label,
                                                SecretValue           *value,
                                                GError               **error);
GList          *secret_file_collection_search (SecretFileCollection  *self,
                                                GHashTable            *attributes);
gboolean        secret_file_collection_clear   (SecretFileCollection  *self,
                                                GHashTable            *attributes,
                                                GError               **error);
void            secret_file_collection_write   (SecretFileCollection  *self,
                                                GCancellable          *cancellable,
                                                GAsyncReadyCallback    callback,
                                                gpointer               user_data);
gboolean        secret_file_collection_write_finish
                                               (SecretFileCollection  *self,
                                                GAsyncResult          *result,
                                                GError               **error);

SecretFileItem *_secret_file_item_decrypt
                                               (GVariant              *encrypted,
                                                SecretFileCollection  *collection,
                                                GError               **error);

G_END_DECLS

#endif /* __SECRET_FILE_COLLECTION_H__ */
