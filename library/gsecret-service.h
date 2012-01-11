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

#ifndef __GSECRET_SERVICE_H__
#define __GSECRET_SERVICE_H__

#include <gio/gio.h>

#include "gsecret-prompt.h"
#include "gsecret-types.h"
#include "gsecret-value.h"

G_BEGIN_DECLS

#define GSECRET_TYPE_SERVICE            (gsecret_service_get_type ())
#define GSECRET_SERVICE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), GSECRET_TYPE_SERVICE, GSecretService))
#define GSECRET_SERVICE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), GSECRET_TYPE_SERVICE, GSecretServiceClass))
#define GSECRET_IS_SERVICE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), GSECRET_TYPE_SERVICE))
#define GSECRET_IS_SERVICE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), GSECRET_TYPE_SERVICE))
#define GSECRET_SERVICE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), GSECRET_TYPE_SERVICE, GSecretServiceClass))

typedef struct _GSecretServiceClass   GSecretServiceClass;
typedef struct _GSecretServicePrivate GSecretServicePrivate;

struct _GSecretServiceClass {
	GDBusProxyClass parent_class;

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
};

struct _GSecretService {
	GDBusProxy parent_instance;
	GSecretServicePrivate *pv;
};

GType               gsecret_service_get_type                 (void) G_GNUC_CONST;

#if 0
void                gsecret_service_get                      (GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

GSecretService*     gsecret_service_get_finish               (GAsyncResult *result,
                                                              GError **error);

GSecretService*     gsecret_service_get_sync                 (GAsyncResult *result,
                                                              GError **error);

void                gsecret_service_instance                 (GDBusConnection *connection,
                                                              const gchar *object_path,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

GSecretService *    gsecret_service_instance_finish          (GAsyncResult *result,
                                                              GError **error);

GSecretService *    gsecret_service_instance_sync            (GDBusConnection *connection,
                                                              const gchar *object_path,
                                                              GCancellable *cancellable,
                                                              GError **error);
#endif

const gchar *       gsecret_service_get_session_algorithms   (GSecretService *self);

const gchar *       gsecret_service_get_session_path         (GSecretService *self);

void                gsecret_service_ensure_session           (GSecretService *self,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

const gchar *       gsecret_service_ensure_session_finish    (GSecretService *self,
                                                              GAsyncResult *result,
                                                              GError **error);

const gchar *       gsecret_service_ensure_session_sync      (GSecretService *self,
                                                              GCancellable *cancellable,
                                                              GError **error);

#if 0
void                gsecret_service_search                   (GSecretService *self,
                                                              GHashTable *attributes,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

gboolean            gsecret_service_search_finish            (GSecretService *self,
                                                              GAsyncResult *result,
                                                              GList **unlocked,
                                                              GList **locked,
                                                              GError **error);

gboolean            gsecret_service_search_sync              (GSecretService *self,
                                                              GHashTable *attributes,
                                                              GCancellable *cancellable,
                                                              GList **unlocked,
                                                              GList **locked,
                                                              GError **error);
#endif

void              gsecret_service_search_for_paths                  (GSecretService *self,
                                                                     GHashTable *attributes,
                                                                     GCancellable *cancellable,
                                                                     GAsyncReadyCallback callback,
                                                                     gpointer user_data);

gboolean          gsecret_service_search_for_paths_finish           (GSecretService *self,
                                                                     GAsyncResult *result,
                                                                     gchar ***unlocked,
                                                                     gchar ***locked,
                                                                     GError **error);

gboolean          gsecret_service_search_for_paths_sync             (GSecretService *self,
                                                                     GHashTable *attributes,
                                                                     GCancellable *cancellable,
                                                                     gchar ***unlocked,
                                                                     gchar ***locked,
                                                                     GError **error);

void              gsecret_service_get_secret_for_path               (GSecretService *self,
                                                                     const gchar *object_path,
                                                                     GCancellable *cancellable,
                                                                     GAsyncReadyCallback callback,
                                                                     gpointer user_data);

GSecretValue *    gsecret_service_get_secret_for_path_finish        (GSecretService *self,
                                                                     GAsyncResult *result,
                                                                     GError **error);

GSecretValue *    gsecret_service_get_secret_for_path_sync          (GSecretService *self,
                                                                     const gchar *object_path,
                                                                     GCancellable *cancellable,
                                                                     GError **error);

void              gsecret_service_get_secrets_for_paths             (GSecretService *self,
                                                                     const gchar **object_paths,
                                                                     GCancellable *cancellable,
                                                                     GAsyncReadyCallback callback,
                                                                     gpointer user_data);

GHashTable *      gsecret_service_get_secrets_for_paths_finish      (GSecretService *self,
                                                                     GAsyncResult *result,
                                                                     GError **error);

GHashTable *      gsecret_service_get_secrets_for_paths_sync        (GSecretService *self,
                                                                     const gchar **object_paths,
                                                                     GCancellable *cancellable,
                                                                     GError **error);

#if 0
void                gsecret_service_lock                     (GSecretService *self,
                                                              GList *objects,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

gboolean            gsecret_service_lock_finish              (GSecretService *self,
                                                              GAsyncResult *result,
                                                              GList **locked,
                                                              GSecretPrompt *prompt,
                                                              GError **error);

void                gsecret_service_lock_sync                (GSecretService *self,
                                                              GList *objects,
                                                              GCancellable *cancellable,
                                                              GList **locked,
                                                              GSecretPrompt *prompt,
                                                              GError **error);

void                gsecret_service_unlock                   (GSecretService *self,
                                                              GList *objects,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);
#endif

gint                gsecret_service_unlock_paths_sync        (GSecretService *self,
                                                              const gchar **paths,
                                                              GCancellable *cancellable,
                                                              gchar ***unlocked,
                                                              GError **error);

void                gsecret_service_unlock_paths             (GSecretService *self,
                                                              const gchar **paths,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

gint                gsecret_service_unlock_paths_finish      (GSecretService *self,
                                                              GAsyncResult *result,
                                                              gchar ***unlocked,
                                                              GError **error);

gboolean            gsecret_service_prompt_sync              (GSecretService *self,
                                                              GSecretPrompt *prompt,
                                                              GCancellable *cancellable,
                                                              GError **error);

void                gsecret_service_prompt                   (GSecretService *self,
                                                              GSecretPrompt *prompt,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

void                gsecret_service_prompt_path              (GSecretService *self,
                                                              const gchar *prompt_path,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

gboolean            gsecret_service_prompt_finish            (GSecretService *self,
                                                              GAsyncResult *result,
                                                              GError **error);

#if 0
void                gsecret_service_store_password           (GSecretService *self,
                                                              const GSecretSchema *schema,
                                                              const gchar *collection_path,
                                                              const gchar *label,
                                                              const gchar *password,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data,
                                                              ...) G_GNUC_NULL_TERMINATED;

gboolean            gsecret_service_store_password_finish    (GSecretService *self,
                                                              GAsyncResult *result,
                                                              GError **error);

void                gsecret_service_store_password_sync      (GSecretService *self,
                                                              const GSecretSchema *schema,
                                                              const gchar *collection,
                                                              const gchar *display_name,
                                                              const gchar *password,
                                                              GCancellable *cancellable,
                                                              GError **error,
                                                              ...) G_GNUC_NULL_TERMINATED;

void                gsecret_service_lookup_password          (GSecretService *self,
                                                              const GSecretSchema *schema,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data,
                                                              ...) G_GNUC_NULL_TERMINATED;

gchar *             gsecret_service_lookup_password_finish   (GSecretService *self,
                                                              GAsyncResult *result,
                                                              GError **error);

gchar *             gsecret_service_lookup_password_sync     (GSecretService *self,
                                                              const GSecretSchema *schema,
                                                              GCancellable *cancellable,
                                                              GError **error,
                                                              ...) G_GNUC_NULL_TERMINATED;
#endif

void                gsecret_service_delete_path              (GSecretService *self,
                                                              const gchar *item_path,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

gboolean            gsecret_service_delete_path_finish       (GSecretService *self,
                                                              GAsyncResult *result,
                                                              GError **error);

gboolean            gsecret_service_delete_path_sync         (GSecretService *self,
                                                              const gchar *item_path,
                                                              GCancellable *cancellable,
                                                              GError **error);

void                gsecret_service_delete_password          (GSecretService *self,
                                                              const GSecretSchema *schema,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data,
                                                              ...) G_GNUC_NULL_TERMINATED;

void                gsecret_service_delete_passwordv         (GSecretService *self,
                                                              GHashTable *attributes,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

gboolean            gsecret_service_delete_password_finish   (GSecretService *self,
                                                              GAsyncResult *result,
                                                              GError **error);

gboolean            gsecret_service_delete_password_sync     (GSecretService *self,
                                                              const GSecretSchema* schema,
                                                              GCancellable *cancellable,
                                                              GError **error,
                                                              ...) G_GNUC_NULL_TERMINATED;

gboolean            gsecret_service_delete_passwordv_sync    (GSecretService *self,
                                                              GHashTable *attributes,
                                                              GCancellable *cancellable,
                                                              GError **error);

#if 0
GSecretCollection*  gsecret_service_read_alias               (GSecretService *self,
                                                              const gchar *alias,
                                                              GError **error);

GSecretCollection*  gsecret_service_set_alias                (GSecretService *self,
                                                              const gchar *alias,
                                                              GSecretCollection *collection,
                                                              GError **error);

#endif

G_END_DECLS

#endif /* __G_SERVICE_H___ */
