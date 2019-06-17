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

#ifndef __SECRET_READABLE_ITEM_H__
#define __SECRET_READABLE_ITEM_H__

#include <glib-object.h>
#include "secret-value.h"

G_BEGIN_DECLS

#define SECRET_TYPE_READABLE_ITEM secret_readable_item_get_type ()
G_DECLARE_INTERFACE (SecretReadableItem, secret_readable_item, SECRET, READABLE_ITEM, GObject)

struct _SecretReadableItemInterface
{
	GTypeInterface parent_iface;

	void        *(*retrieve_secret)        (SecretReadableItem *self,
						GCancellable *cancellable,
						GAsyncReadyCallback callback,
						gpointer user_data);
	SecretValue *(*retrieve_secret_finish) (SecretReadableItem *self,
						GAsyncResult *result,
						GError **error);
};

void         secret_readable_item_retrieve_secret        (SecretReadableItem *self,
							  GCancellable *cancellable,
							  GAsyncReadyCallback callback,
							  gpointer user_data);

SecretValue *secret_readable_item_retrieve_secret_finish (SecretReadableItem *self,
							  GAsyncResult *result,
							  GError **error);

GHashTable  *secret_readable_item_get_attributes         (SecretReadableItem *self);
guint64      secret_readable_item_get_created            (SecretReadableItem *self);
guint64      secret_readable_item_get_modified           (SecretReadableItem *self);


G_END_DECLS

#endif /* __SECRET_READABLE_ITEM_H__ */
