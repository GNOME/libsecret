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

G_BEGIN_DECLS

#define GSECRET_TYPE_SERVICE            (gsecret_service_get_type ())
#define GSECRET_SERVICE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), GSECRET_TYPE_SERVICE, GSecretService))
#define GSECRET_SERVICE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), GSECRET_TYPE_SERVICE, GSecretServiceClass))
#define GSECRET_IS_SERVICE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), GSECRET_TYPE_SERVICE))
#define GSECRET_IS_SERVICE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), GSECRET_TYPE_SERVICE))
#define GSECRET_SERVICE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), GSECRET_TYPE_SERVICE, GSecretServiceClass))

typedef struct _GSecretService        GSecretService;
typedef struct _GSecretServiceClass   GSecretServiceClass;
typedef struct _GSecretServicePrivate GSecretServicePrivate;

struct _GSecretServiceClass {
	GDBusProxyClass parent_class;

	GType collection_type;
	GType item_type;

#if 0
	padding;
#endif
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

void                gsecret_service_search_paths             (GSecretService *self,
                                                              GHashTable *attributes,
                                                              GCancellable *cancellable,
                                                              GAsyncReadyCallback callback,
                                                              gpointer user_data);

gboolean            gsecret_service_search_paths_finish      (GSecretService *self,
                                                              GAsyncResult *result,
                                                              gchar ***unlocked,
                                                              gchar ***locked,
                                                              GError **error);

gboolean            gsecret_service_search_paths_sync        (GSecretService *self,
                                                              GHashTable *attributes,
                                                              GCancellable *cancellable,
                                                              gchar ***unlocked,
                                                              gchar ***locked,
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

gboolean            gsecret_service_
                                                              GList **unlocked,
                                                              GSecretPrompt *prompt,
                                                              GError **error);

gboolean            gsecret_service_unlock                   (GSecretService *self,
                                                              GList *objects,
                                                              GList **unlocked,
                                                              GSecretPrompt *prompt,
                                                              GError **error);

gboolean            gsecret_service_unlock_for_paths             (GSecretService *self,
                                                              GList *objects,
                                                              GList **unlocked,
                                                              GSecretPrompt *prompt,
                                                              GError **error);

GHashTable*         gsecret_service_get_secrets              (GList *items,
                                                              GError **error);

GHashTable*         gsecret_service_get_secrets_for_paths    (GList *items,
                                                              GError **error);

gsecret_collection_create_collection

GList*              gsecret_service_get_collections

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
