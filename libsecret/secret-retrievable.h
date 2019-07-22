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

#ifndef __SECRET_RETRIEVABLE_H__
#define __SECRET_RETRIEVABLE_H__

#include <glib-object.h>
#include "secret-value.h"

G_BEGIN_DECLS

#define SECRET_TYPE_RETRIEVABLE secret_retrievable_get_type ()
G_DECLARE_INTERFACE (SecretRetrievable, secret_retrievable, SECRET, RETRIEVABLE, GObject)

struct _SecretRetrievableInterface
{
	GTypeInterface parent_iface;

	void         (*retrieve_secret)        (SecretRetrievable *self,
						GCancellable *cancellable,
						GAsyncReadyCallback callback,
						gpointer user_data);
	SecretValue *(*retrieve_secret_finish) (SecretRetrievable *self,
						GAsyncResult *result,
						GError **error);
};

void         secret_retrievable_retrieve_secret        (SecretRetrievable *self,
							GCancellable *cancellable,
							GAsyncReadyCallback callback,
							gpointer user_data);

SecretValue *secret_retrievable_retrieve_secret_finish (SecretRetrievable *self,
							GAsyncResult *result,
							GError **error);

SecretValue *secret_retrievable_retrieve_secret_sync   (SecretRetrievable *self,
							GCancellable *cancellable,
							GError **error);

GHashTable  *secret_retrievable_get_attributes         (SecretRetrievable *self);
gchar       *secret_retrievable_get_label              (SecretRetrievable *self);
guint64      secret_retrievable_get_created            (SecretRetrievable *self);
guint64      secret_retrievable_get_modified           (SecretRetrievable *self);


G_END_DECLS

#endif /* __SECRET_RETRIEVABLE_H__ */
