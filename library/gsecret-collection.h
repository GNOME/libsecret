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

#ifndef __GSECRET_COLLECTION_H__
#define __GSECRET_COLLECTION_H__

#include <gio/gio.h>

#include "gsecret-types.h"

G_BEGIN_DECLS

#define GSECRET_TYPE_COLLECTION            (gsecret_collection_get_type ())
#define GSECRET_COLLECTION(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), GSECRET_TYPE_COLLECTION, GSecretCollection))
#define GSECRET_COLLECTION_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), GSECRET_TYPE_COLLECTION, GSecretCollectionClass))
#define GSECRET_IS_COLLECTION(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), GSECRET_TYPE_COLLECTION))
#define GSECRET_IS_COLLECTION_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), GSECRET_TYPE_COLLECTION))
#define GSECRET_COLLECTION_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), GSECRET_TYPE_COLLECTION, GSecretCollectionClass))

typedef struct _GSecretCollectionClass   GSecretCollectionClass;
typedef struct _GSecretCollectionPrivate GSecretCollectionPrivate;

struct _GSecretCollection {
	GDBusProxy parent;
	GSecretCollectionPrivate *pv;
};

struct _GSecretCollectionClass {
	GDBusProxyClass parent_class;
	gpointer padding[8];
};

GType               gsecret_collection_get_type                 (void) G_GNUC_CONST;

void                gsecret_collection_new                      (GSecretService *service,
                                                                 const gchar *collection_path,
                                                                 GCancellable *cancellable,
                                                                 GAsyncReadyCallback callback,
                                                                 gpointer user_data);

GSecretCollection * gsecret_collection_new_finish               (GAsyncResult *result,
                                                                 GError **error);

GSecretCollection * gsecret_collection_new_sync                 (GSecretService *service,
                                                                 const gchar *collection_path,
                                                                 GCancellable *cancellable,
                                                                 GError **error);

void                gsecret_collection_refresh                  (GSecretCollection *self);

void                gsecret_collection_delete                   (GSecretCollection *self,
                                                                 GCancellable *cancellable,
                                                                 GAsyncReadyCallback callback,
                                                                 gpointer user_data);

gboolean            gsecret_collection_delete_finish            (GSecretCollection *self,
                                                                 GAsyncResult *result,
                                                                 GError **error);

gboolean            gsecret_collection_delete_sync              (GSecretCollection *self,
                                                                 GCancellable *cancellable,
                                                                 GError **error);

GList *             gsecret_collection_get_items                (GSecretCollection *self);

gchar *             gsecret_collection_get_label                (GSecretCollection *self);

void                gsecret_collection_set_label                (GSecretCollection *self,
                                                                 const gchar *label,
                                                                 GCancellable *cancellable,
                                                                 GAsyncReadyCallback callback,
                                                                 gpointer user_data);

gboolean            gsecret_collection_set_label_finish         (GSecretCollection *self,
                                                                 GAsyncResult *result,
                                                                 GError **error);

gboolean            gsecret_collection_set_label_sync           (GSecretCollection *self,
                                                                 const gchar *label,
                                                                 GCancellable *cancellable,
                                                                 GError **error);

gboolean            gsecret_collection_get_locked               (GSecretCollection *self);

guint64             gsecret_collection_get_created              (GSecretCollection *self);

guint64             gsecret_collection_get_modified             (GSecretCollection *self);

G_END_DECLS

#endif /* __GSECRET_COLLECTION_H___ */
