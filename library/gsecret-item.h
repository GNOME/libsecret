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

#ifndef __GSECRET_ITEM_H__
#define __GSECRET_ITEM_H__

#include <gio/gio.h>

#include "gsecret-item.h"
#include "gsecret-service.h"
#include "gsecret-value.h"

G_BEGIN_DECLS

#define GSECRET_TYPE_ITEM            (gsecret_item_get_type ())
#define GSECRET_ITEM(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), GSECRET_TYPE_ITEM, GSecretItem))
#define GSECRET_ITEM_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), GSECRET_TYPE_ITEM, GSecretItemClass))
#define GSECRET_IS_ITEM(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), GSECRET_TYPE_ITEM))
#define GSECRET_IS_ITEM_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), GSECRET_TYPE_ITEM))
#define GSECRET_ITEM_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), GSECRET_TYPE_ITEM, GSecretItemClass))

typedef struct _GSecretItemClass   GSecretItemClass;
typedef struct _GSecretItemPrivate   GSecretItemPrivate;

struct _GSecretItem {
	GDBusProxy parent_instance;
	GSecretItemPrivate *pv;;
};

struct _GSecretItemClass {
	GDBusProxyClass parent_class;
	gpointer padding[4];
};

GType               gsecret_item_get_type                   (void) G_GNUC_CONST;

void                gsecret_item_new                        (GSecretService *service,
                                                             const gchar *item_path,
                                                             GCancellable *cancellable,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

GSecretItem *       gsecret_item_new_finish                 (GAsyncResult *result,
                                                             GError **error);

GSecretItem *       gsecret_item_new_sync                   (GSecretService *service,
                                                             const gchar *item_path,
                                                             GCancellable *cancellable,
                                                             GError **error);

void                gsecret_item_refresh                    (GSecretItem *self);

void                gsecret_item_delete                     (GSecretItem *self,
                                                             GCancellable *cancellable,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

gboolean            gsecret_item_delete_finish              (GSecretItem *self,
                                                             GAsyncResult *result,
                                                             GError **error);

gboolean            gsecret_item_delete_sync                (GSecretItem *self,
                                                             GCancellable *cancellable,
                                                             GError **error);

void                gsecret_item_get_secret                 (GSecretItem *self,
                                                             GCancellable *cancellable,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

GSecretValue *      gsecret_item_get_secret_finish          (GSecretItem *self,
                                                             GAsyncResult *result,
                                                             GError **error);

GSecretValue *      gsecret_item_get_secret_sync            (GSecretItem *self,
                                                             GCancellable *cancellable,
                                                             GError **error);

GHashTable*         gsecret_item_get_attributes             (GSecretItem *self);

void                gsecret_item_set_attributes             (GSecretItem *self,
                                                             GHashTable *attributes,
                                                             GCancellable *cancellable,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

gboolean            gsecret_item_set_attributes_finish      (GSecretItem *self,
                                                             GAsyncResult *result,
                                                             GError **error);

gboolean            gsecret_item_set_attributes_sync        (GSecretItem *self,
                                                             GHashTable *attributes,
                                                             GCancellable *cancellable,
                                                             GError **error);

gchar *             gsecret_item_get_label                  (GSecretItem *self);

void                gsecret_item_set_label                  (GSecretItem *self,
                                                             const gchar *label,
                                                             GCancellable *cancellable,
                                                             GAsyncReadyCallback callback,
                                                             gpointer user_data);

gboolean            gsecret_item_set_label_finish           (GSecretItem *self,
                                                             GAsyncResult *result,
                                                             GError **error);

gboolean            gsecret_item_set_label_sync             (GSecretItem *self,
                                                             const gchar *label,
                                                             GCancellable *cancellable,
                                                             GError **error);

gboolean            gsecret_item_get_locked                 (GSecretItem *self);

guint64             gsecret_item_get_created                (GSecretItem *self);

guint64             gsecret_item_get_modified               (GSecretItem *self);

G_END_DECLS

#endif /* __G_ITEM_H___ */
