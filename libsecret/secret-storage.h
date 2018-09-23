/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 * Copyright 2018 Red Hat Inc.
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


#ifndef SECRET_STORAGE_H_
#define SECRET_STORAGE_H_

#include <glib-object.h>

#include "secret-schema.h"
#include "secret-value.h"

G_BEGIN_DECLS

#define SECRET_TYPE_STORAGE            (secret_storage_get_type ())
#define SECRET_STORAGE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), SECRET_TYPE_STORAGE, SecretStorage))
#define SECRET_STORAGE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), SECRET_TYPE_STORAGE, SecretStorageClass))
#define SECRET_IS_STORAGE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), SECRET_TYPE_STORAGE))
#define SECRET_IS_STORAGE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), SECRET_TYPE_STORAGE))
#define SECRET_STORAGE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), SECRET_TYPE_STORAGE, SecretStorageClass))

typedef struct _SecretStorage        SecretStorage;
typedef struct _SecretStorageClass   SecretStorageClass;

GType        secret_storage_get_type      (void) G_GNUC_CONST;

void         secret_storage_get_default   (int                  io_priority,
                                           GCancellable        *cancellable,
                                           GAsyncReadyCallback  callback,
                                           gpointer             user_data);

SecretStorage *secret_storage_get_default_finish
                                          (GAsyncResult        *result,
                                           GError             **error);

void         secret_storage_store         (SecretStorage       *self,
                                           const SecretSchema  *schema,
                                           GHashTable          *attributes,
                                           const gchar         *collection,
                                           const gchar         *label,
                                           SecretValue         *value,
                                           GCancellable        *cancellable,
                                           GAsyncReadyCallback  callback,
                                           gpointer             user_data);

gboolean     secret_storage_store_finish  (SecretStorage       *self,
                                           GAsyncResult        *result,
                                           GError             **error);

void         secret_storage_lookup        (SecretStorage       *self,
                                           const SecretSchema  *schema,
                                           GHashTable          *attributes,
                                           GCancellable        *cancellable,
                                           GAsyncReadyCallback  callback,
                                           gpointer             user_data);

SecretValue *secret_storage_lookup_finish (SecretStorage       *self,
                                           GAsyncResult        *result,
                                           GError             **error);

void         secret_storage_clear         (SecretStorage       *self,
                                           const SecretSchema  *schema,
                                           GHashTable          *attributes,
                                           GCancellable        *cancellable,
                                           GAsyncReadyCallback  callback,
                                           gpointer             user_data);

gboolean     secret_storage_clear_finish  (SecretStorage       *self,
                                           GAsyncResult        *result,
                                           GError             **error);

G_END_DECLS

#endif /* SECRET_STORAGE_H_ */
