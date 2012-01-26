/* GSecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 * Copyright 2012 Red Hat Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */

#ifndef __GSECRET_SERVICE_H__
#define __GSECRET_SERVICE_H__

#include <gio/gio.h>

#include "gsecret-prompt.h"
#include "gsecret-types.h"
#include "gsecret-value.h"

G_BEGIN_DECLS

typedef enum {
	GSECRET_SERVICE_NONE,
	GSECRET_SERVICE_OPEN_SESSION = 1 << 1,
	GSECRET_SERVICE_LOAD_COLLECTIONS = 1 << 2,
} GSecretServiceFlags;

#define GSECRET_TYPE_SERVICE            (gsecret_service_get_type ())
#define GSECRET_SERVICE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), GSECRET_TYPE_SERVICE, GSecretService))
#define GSECRET_SERVICE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), GSECRET_TYPE_SERVICE, GSecretServiceClass))
#define GSECRET_IS_SERVICE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), GSECRET_TYPE_SERVICE))
#define GSECRET_IS_SERVICE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), GSECRET_TYPE_SERVICE))
#define GSECRET_SERVICE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), GSECRET_TYPE_SERVICE, GSecretServiceClass))

typedef struct _GSecretServiceClass   GSecretServiceClass;
typedef struct _GSecretServicePrivate GSecretServicePrivate;

struct _GSecretService {
	GDBusProxy parent;
	GSecretServicePrivate *pv;
};

struct _GSecretServiceClass {
	GDBusProxyClass parent_class;

	GType collection_gtype;
	GType item_gtype;

	gboolean (*prompt_sync)          (GSecretService *self,
	                                  GSecretPrompt *prompt,
	                                  GCancellable *cancellable,
	                                  GError **error);

	void     (*prompt_async)         (GSecretService *self,
	                                  GSecretPrompt *prompt,
	                                  GCancellable *cancellable,
	                                  GAsyncReadyCallback callback,
	                                  gpointer user_data);

	gboolean (*prompt_finish)        (GSecretService *self,
	                                  GAsyncResult *result,
	                                  GError **error);

	gpointer padding[16];
};

GType                gsecret_service_get_type                      (void) G_GNUC_CONST;

void                 gsecret_service_get                           (GSecretServiceFlags flags,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

GSecretService *     gsecret_service_get_finish                    (GAsyncResult *result,
                                                                    GError **error);

GSecretService *     gsecret_service_get_sync                      (GSecretServiceFlags flags,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_new                           (const gchar *service_bus_name,
                                                                    GSecretServiceFlags flags,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

GSecretService *     gsecret_service_new_finish                    (GAsyncResult *result,
                                                                    GError **error);

GSecretService *     gsecret_service_new_sync                      (const gchar *service_bus_name,
                                                                    GSecretServiceFlags flags,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

GSecretServiceFlags  gsecret_service_get_flags                     (GSecretService *self);

const gchar *        gsecret_service_get_session_algorithms        (GSecretService *self);

const gchar *        gsecret_service_get_session_path              (GSecretService *self);

GList *              gsecret_service_get_collections               (GSecretService *self);

void                 gsecret_service_ensure_session                (GSecretService *self,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

const gchar *        gsecret_service_ensure_session_finish         (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

const gchar *        gsecret_service_ensure_session_sync           (GSecretService *self,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_ensure_collections            (GSecretService *self,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gboolean             gsecret_service_ensure_collections_finish     (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

gboolean             gsecret_service_ensure_collections_sync       (GSecretService *self,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_search                        (GSecretService *self,
                                                                    GHashTable *attributes,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gboolean             gsecret_service_search_finish                 (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GList **unlocked,
                                                                    GList **locked,
                                                                    GError **error);

gboolean             gsecret_service_search_sync                   (GSecretService *self,
                                                                    GHashTable *attributes,
                                                                    GCancellable *cancellable,
                                                                    GList **unlocked,
                                                                    GList **locked,
                                                                    GError **error);

void                 gsecret_service_search_for_paths              (GSecretService *self,
                                                                    GHashTable *attributes,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gboolean             gsecret_service_search_for_paths_finish       (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    gchar ***unlocked,
                                                                    gchar ***locked,
                                                                    GError **error);

gboolean             gsecret_service_search_for_paths_sync         (GSecretService *self,
                                                                    GHashTable *attributes,
                                                                    GCancellable *cancellable,
                                                                    gchar ***unlocked,
                                                                    gchar ***locked,
                                                                    GError **error);

void                 gsecret_service_get_secret_for_path           (GSecretService *self,
                                                                    const gchar *object_path,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

GSecretValue *       gsecret_service_get_secret_for_path_finish    (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

GSecretValue *       gsecret_service_get_secret_for_path_sync      (GSecretService *self,
                                                                    const gchar *object_path,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_get_secrets_for_paths         (GSecretService *self,
                                                                    const gchar **object_paths,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

GHashTable *         gsecret_service_get_secrets_for_paths_finish  (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

GHashTable *         gsecret_service_get_secrets_for_paths_sync    (GSecretService *self,
                                                                    const gchar **object_paths,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_get_secrets                   (GSecretService *self,
                                                                    GList *items,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

GHashTable *         gsecret_service_get_secrets_finish            (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

GHashTable *         gsecret_service_get_secrets_sync              (GSecretService *self,
                                                                    GList *items,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_lock                          (GSecretService *self,
                                                                    GList *objects,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gint                 gsecret_service_lock_finish                   (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GList **locked,
                                                                    GError **error);

gint                 gsecret_service_lock_sync                     (GSecretService *self,
                                                                    GList *objects,
                                                                    GCancellable *cancellable,
                                                                    GList **locked,
                                                                    GError **error);

gint                 gsecret_service_lock_paths_sync               (GSecretService *self,
                                                                    const gchar **paths,
                                                                    GCancellable *cancellable,
                                                                    gchar ***locked,
                                                                    GError **error);

void                 gsecret_service_lock_paths                    (GSecretService *self,
                                                                    const gchar **paths,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gint                 gsecret_service_lock_paths_finish             (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    gchar ***locked,
                                                                    GError **error);

void                 gsecret_service_unlock                        (GSecretService *self,
                                                                    GList *objects,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gint                 gsecret_service_unlock_finish                 (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GList **unlocked,
                                                                    GError **error);

gint                 gsecret_service_unlock_sync                   (GSecretService *self,
                                                                    GList *objects,
                                                                    GCancellable *cancellable,
                                                                    GList **unlocked,
                                                                    GError **error);

gint                 gsecret_service_unlock_paths_sync             (GSecretService *self,
                                                                    const gchar **paths,
                                                                    GCancellable *cancellable,
                                                                    gchar ***unlocked,
                                                                    GError **error);

void                 gsecret_service_unlock_paths                  (GSecretService *self,
                                                                    const gchar **paths,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gint                 gsecret_service_unlock_paths_finish           (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    gchar ***unlocked,
                                                                    GError **error);

gboolean             gsecret_service_prompt_sync                   (GSecretService *self,
                                                                    GSecretPrompt *prompt,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_prompt                        (GSecretService *self,
                                                                    GSecretPrompt *prompt,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gboolean             gsecret_service_prompt_finish                 (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

void                 gsecret_service_store                         (GSecretService *self,
                                                                    const GSecretSchema *schema,
                                                                    const gchar *collection_path,
                                                                    const gchar *label,
                                                                    GSecretValue *value,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data,
                                                                    ...) G_GNUC_NULL_TERMINATED;

void                 gsecret_service_storev                        (GSecretService *self,
                                                                    const GSecretSchema *schema,
                                                                    GHashTable *attributes,
                                                                    const gchar *collection_path,
                                                                    const gchar *label,
                                                                    GSecretValue *value,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gboolean             gsecret_service_store_finish                  (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

gboolean             gsecret_service_store_sync                    (GSecretService *self,
                                                                    const GSecretSchema *schema,
                                                                    const gchar *collection_path,
                                                                    const gchar *label,
                                                                    GSecretValue *value,
                                                                    GCancellable *cancellable,
                                                                    GError **error,
                                                                    ...) G_GNUC_NULL_TERMINATED;

gboolean             gsecret_service_storev_sync                   (GSecretService *self,
                                                                    const GSecretSchema *schema,
                                                                    GHashTable *attributes,
                                                                    const gchar *collection_path,
                                                                    const gchar *label,
                                                                    GSecretValue *value,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_lookup                        (GSecretService *self,
                                                                    const GSecretSchema *schema,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data,
                                                                    ...) G_GNUC_NULL_TERMINATED;

void                 gsecret_service_lookupv                       (GSecretService *self,
                                                                    GHashTable *attributes,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

GSecretValue *       gsecret_service_lookup_finish                 (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

GSecretValue *       gsecret_service_lookup_sync                   (GSecretService *self,
                                                                    const GSecretSchema *schema,
                                                                    GCancellable *cancellable,
                                                                    GError **error,
                                                                    ...) G_GNUC_NULL_TERMINATED;

GSecretValue *       gsecret_service_lookupv_sync                  (GSecretService *self,
                                                                    GHashTable *attributes,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_delete_path                   (GSecretService *self,
                                                                    const gchar *object_path,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gboolean             gsecret_service_delete_path_finish            (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

gboolean             gsecret_service_delete_path_sync              (GSecretService *self,
                                                                    const gchar *object_path,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

void                 gsecret_service_remove                        (GSecretService *self,
                                                                    const GSecretSchema *schema,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data,
                                                                    ...) G_GNUC_NULL_TERMINATED;

void                 gsecret_service_removev                       (GSecretService *self,
                                                                    GHashTable *attributes,
                                                                    GCancellable *cancellable,
                                                                    GAsyncReadyCallback callback,
                                                                    gpointer user_data);

gboolean             gsecret_service_remove_finish                 (GSecretService *self,
                                                                    GAsyncResult *result,
                                                                    GError **error);

gboolean             gsecret_service_remove_sync                   (GSecretService *self,
                                                                    const GSecretSchema* schema,
                                                                    GCancellable *cancellable,
                                                                    GError **error,
                                                                    ...) G_GNUC_NULL_TERMINATED;

gboolean             gsecret_service_removev_sync                  (GSecretService *self,
                                                                    GHashTable *attributes,
                                                                    GCancellable *cancellable,
                                                                    GError **error);

G_END_DECLS

#endif /* __GSECRET_SERVICE_H___ */
