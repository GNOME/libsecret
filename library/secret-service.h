/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 * Copyright 2012 Red Hat Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#if !defined (__SECRET_INSIDE_HEADER__) && !defined (SECRET_COMPILATION)
#error "Only <secret/secret.h> or <secret/secret-unstable.h> can be included directly."
#endif

#ifndef __SECRET_SERVICE_H__
#define __SECRET_SERVICE_H__

#include <gio/gio.h>

#include "secret-prompt.h"
#include "secret-schema.h"
#include "secret-types.h"
#include "secret-value.h"

G_BEGIN_DECLS

typedef enum {
	SECRET_SERVICE_NONE,
	SECRET_SERVICE_OPEN_SESSION = 1 << 1,
	SECRET_SERVICE_LOAD_COLLECTIONS = 1 << 2,
} SecretServiceFlags;

#define SECRET_TYPE_SERVICE            (secret_service_get_type ())
#define SECRET_SERVICE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), SECRET_TYPE_SERVICE, SecretService))
#define SECRET_SERVICE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), SECRET_TYPE_SERVICE, SecretServiceClass))
#define SECRET_IS_SERVICE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), SECRET_TYPE_SERVICE))
#define SECRET_IS_SERVICE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), SECRET_TYPE_SERVICE))
#define SECRET_SERVICE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), SECRET_TYPE_SERVICE, SecretServiceClass))

typedef struct _SecretServiceClass   SecretServiceClass;
typedef struct _SecretServicePrivate SecretServicePrivate;

struct _SecretService {
	GDBusProxy parent;

	/*< private >*/
	SecretServicePrivate *pv;
};

struct _SecretServiceClass {
	GDBusProxyClass parent_class;

	GType collection_gtype;
	GType item_gtype;

	gboolean (*prompt_sync)          (SecretService *self,
	                                  SecretPrompt *prompt,
	                                  GCancellable *cancellable,
	                                  GError **error);

	void     (*prompt_async)         (SecretService *self,
	                                  SecretPrompt *prompt,
	                                  GCancellable *cancellable,
	                                  GAsyncReadyCallback callback,
	                                  gpointer user_data);

	gboolean (*prompt_finish)        (SecretService *self,
	                                  GAsyncResult *result,
	                                  GError **error);

	/*< private >*/
	gpointer padding[16];
};

GType                secret_service_get_type                      (void) G_GNUC_CONST;

void                 secret_service_get                           (SecretServiceFlags flags,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

SecretService *      secret_service_get_finish                    (GAsyncResult *result,
                                                                   GError **error);

SecretService *      secret_service_get_sync                      (SecretServiceFlags flags,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_new                           (const gchar *service_bus_name,
                                                                   SecretServiceFlags flags,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

SecretService *      secret_service_new_finish                    (GAsyncResult *result,
                                                                   GError **error);

SecretService *      secret_service_new_sync                      (const gchar *service_bus_name,
                                                                   SecretServiceFlags flags,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

SecretServiceFlags   secret_service_get_flags                     (SecretService *self);

const gchar *        secret_service_get_session_algorithms        (SecretService *self);

const gchar *        secret_service_get_session_path              (SecretService *self);

GList *              secret_service_get_collections               (SecretService *self);

void                 secret_service_ensure_session                (SecretService *self,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

const gchar *        secret_service_ensure_session_finish         (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

const gchar *        secret_service_ensure_session_sync           (SecretService *self,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_ensure_collections            (SecretService *self,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gboolean             secret_service_ensure_collections_finish     (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

gboolean             secret_service_ensure_collections_sync       (SecretService *self,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_search                        (SecretService *self,
                                                                   GHashTable *attributes,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gboolean             secret_service_search_finish                 (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GList **unlocked,
                                                                   GList **locked,
                                                                   GError **error);

gboolean             secret_service_search_sync                   (SecretService *self,
                                                                   GHashTable *attributes,
                                                                   GCancellable *cancellable,
                                                                   GList **unlocked,
                                                                   GList **locked,
                                                                   GError **error);

void                 secret_service_search_for_paths              (SecretService *self,
                                                                   GHashTable *attributes,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gboolean             secret_service_search_for_paths_finish       (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   gchar ***unlocked,
                                                                   gchar ***locked,
                                                                   GError **error);

gboolean             secret_service_search_for_paths_sync         (SecretService *self,
                                                                   GHashTable *attributes,
                                                                   GCancellable *cancellable,
                                                                   gchar ***unlocked,
                                                                   gchar ***locked,
                                                                   GError **error);

void                 secret_service_get_secret_for_path           (SecretService *self,
                                                                   const gchar *item_path,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

SecretValue *        secret_service_get_secret_for_path_finish    (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

SecretValue *        secret_service_get_secret_for_path_sync      (SecretService *self,
                                                                   const gchar *item_path,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_get_secrets_for_paths         (SecretService *self,
                                                                   const gchar **item_paths,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

GHashTable *         secret_service_get_secrets_for_paths_finish  (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

GHashTable *         secret_service_get_secrets_for_paths_sync    (SecretService *self,
                                                                   const gchar **item_paths,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_get_secrets                   (SecretService *self,
                                                                   GList *items,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

GHashTable *         secret_service_get_secrets_finish            (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

GHashTable *         secret_service_get_secrets_sync              (SecretService *self,
                                                                   GList *items,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_lock                          (SecretService *self,
                                                                   GList *objects,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gint                 secret_service_lock_finish                   (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GList **locked,
                                                                   GError **error);

gint                 secret_service_lock_sync                     (SecretService *self,
                                                                   GList *objects,
                                                                   GCancellable *cancellable,
                                                                   GList **locked,
                                                                   GError **error);

gint                 secret_service_lock_paths_sync               (SecretService *self,
                                                                   const gchar **paths,
                                                                   GCancellable *cancellable,
                                                                   gchar ***locked,
                                                                   GError **error);

void                 secret_service_lock_paths                    (SecretService *self,
                                                                   const gchar **paths,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gint                 secret_service_lock_paths_finish             (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   gchar ***locked,
                                                                   GError **error);

void                 secret_service_unlock                        (SecretService *self,
                                                                   GList *objects,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gint                 secret_service_unlock_finish                 (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GList **unlocked,
                                                                   GError **error);

gint                 secret_service_unlock_sync                   (SecretService *self,
                                                                   GList *objects,
                                                                   GCancellable *cancellable,
                                                                   GList **unlocked,
                                                                   GError **error);

gint                 secret_service_unlock_paths_sync             (SecretService *self,
                                                                   const gchar **paths,
                                                                   GCancellable *cancellable,
                                                                   gchar ***unlocked,
                                                                   GError **error);

void                 secret_service_unlock_paths                  (SecretService *self,
                                                                   const gchar **paths,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gint                 secret_service_unlock_paths_finish           (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   gchar ***unlocked,
                                                                   GError **error);

gboolean             secret_service_prompt_sync                   (SecretService *self,
                                                                   SecretPrompt *prompt,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_prompt                        (SecretService *self,
                                                                   SecretPrompt *prompt,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gboolean             secret_service_prompt_finish                 (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

void                 secret_service_store                         (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   const gchar *collection_path,
                                                                   const gchar *label,
                                                                   SecretValue *value,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data,
                                                                   ...) G_GNUC_NULL_TERMINATED;

void                 secret_service_storev                        (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   GHashTable *attributes,
                                                                   const gchar *collection_path,
                                                                   const gchar *label,
                                                                   SecretValue *value,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gboolean             secret_service_store_finish                  (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

gboolean             secret_service_store_sync                    (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   const gchar *collection_path,
                                                                   const gchar *label,
                                                                   SecretValue *value,
                                                                   GCancellable *cancellable,
                                                                   GError **error,
                                                                   ...) G_GNUC_NULL_TERMINATED;

gboolean             secret_service_storev_sync                   (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   GHashTable *attributes,
                                                                   const gchar *collection_path,
                                                                   const gchar *label,
                                                                   SecretValue *value,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_lookup                        (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data,
                                                                   ...) G_GNUC_NULL_TERMINATED;

void                 secret_service_lookupv                       (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   GHashTable *attributes,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

SecretValue *        secret_service_lookup_finish                 (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

SecretValue *        secret_service_lookup_sync                   (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   GCancellable *cancellable,
                                                                   GError **error,
                                                                   ...) G_GNUC_NULL_TERMINATED;

SecretValue *        secret_service_lookupv_sync                  (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   GHashTable *attributes,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_delete_path                   (SecretService *self,
                                                                   const gchar *item_path,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gboolean             secret_service_delete_path_finish            (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

gboolean             secret_service_delete_path_sync              (SecretService *self,
                                                                   const gchar *item_path,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_remove                        (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data,
                                                                   ...) G_GNUC_NULL_TERMINATED;

void                 secret_service_removev                       (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   GHashTable *attributes,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gboolean             secret_service_remove_finish                 (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

gboolean             secret_service_remove_sync                   (SecretService *self,
                                                                   const SecretSchema* schema,
                                                                   GCancellable *cancellable,
                                                                   GError **error,
                                                                   ...) G_GNUC_NULL_TERMINATED;

gboolean             secret_service_removev_sync                  (SecretService *self,
                                                                   const SecretSchema *schema,
                                                                   GHashTable *attributes,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_create_collection_path        (SecretService *self,
                                                                   GHashTable *properties,
                                                                   const gchar *alias,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gchar *              secret_service_create_collection_path_finish (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

gchar *              secret_service_create_collection_path_sync   (SecretService *self,
                                                                   GHashTable *properties,
                                                                   const gchar *alias,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

void                 secret_service_create_item_path              (SecretService *self,
                                                                   const gchar *collection_path,
                                                                   GHashTable *properties,
                                                                   SecretValue *value,
                                                                   gboolean replace,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);

gchar *              secret_service_create_item_path_finish       (SecretService *self,
                                                                   GAsyncResult *result,
                                                                   GError **error);

gchar *              secret_service_create_item_path_sync         (SecretService *self,
                                                                   const gchar *collection_path,
                                                                   GHashTable *properties,
                                                                   SecretValue *value,
                                                                   gboolean replace,
                                                                   GCancellable *cancellable,
                                                                   GError **error);

G_END_DECLS

#endif /* __SECRET_SERVICE_H___ */
