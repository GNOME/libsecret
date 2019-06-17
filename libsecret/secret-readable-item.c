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

#include "config.h"

#include "secret-readable-item.h"

/**
 * SECTION:secret-readable-item
 * @title: SecretReadableItem
 * @short_description: A read-only secret item
 *
 * #SecretReadableItem provides a read-only view of a secret item
 * stored in the Secret Service.
 *
 * Each item has a value, represented by a #SecretValue, which can be
 * retrieved by secret_readable_item_retrieve() and
 * secret_readable_item_retrieve_finish().
 *
 * Stability: Stable
 */

/**
 * SecretReadableItem:
 *
 * An object providing a read-only view of a secret item in the Secret Service.
 */

/**
 * SecretReadableItemInterface:
 * @parent_iface: the parent interface
 *
 * The interface for #SecretReadableItem.
 */

G_DEFINE_INTERFACE (SecretReadableItem, secret_readable_item, G_TYPE_OBJECT);

static void
secret_readable_item_default_init (SecretReadableItemInterface *iface)
{
	/**
	 * SecretReadableItem:attributes: (type GLib.HashTable(utf8,utf8)) (transfer full)
	 *
	 * The attributes set on this item. Attributes are used to locate an
	 * item. They are not guaranteed to be stored or transferred securely.
	 */
	g_object_interface_install_property (iface,
	             g_param_spec_boxed ("attributes", "Attributes", "Item attributes",
	                                 G_TYPE_HASH_TABLE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	/**
	 * SecretReadableItem:created:
	 *
	 * The date and time (in seconds since the UNIX epoch) that this
	 * item was created.
	 */
	g_object_interface_install_property (iface,
	            g_param_spec_uint64 ("created", "Created", "Item creation date",
	                                 0UL, G_MAXUINT64, 0UL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	/**
	 * SecretReadableItem:modified:
	 *
	 * The date and time (in seconds since the UNIX epoch) that this
	 * item was last modified.
	 */
	g_object_interface_install_property (iface,
	            g_param_spec_uint64 ("modified", "Modified", "Item modified date",
	                                 0UL, G_MAXUINT64, 0UL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

void
secret_readable_item_retrieve_secret (SecretReadableItem *self,
				      GCancellable *cancellable,
				      GAsyncReadyCallback callback,
				      gpointer user_data)
{
	SecretReadableItemInterface *iface;

	g_return_if_fail (SECRET_IS_READABLE_ITEM (self));
	iface = SECRET_READABLE_ITEM_GET_IFACE (self);
	g_return_if_fail (iface->retrieve_secret != NULL);
	iface->retrieve_secret (self, cancellable, callback, user_data);
}

SecretValue *
secret_readable_item_retrieve_secret_finish (SecretReadableItem *self,
					     GAsyncResult *result,
					     GError **error)
{
	SecretReadableItemInterface *iface;

	g_return_if_fail (SECRET_IS_READABLE_ITEM (self));
	iface = SECRET_READABLE_ITEM_GET_IFACE (self);
	g_return_if_fail (iface->retrieve_secret_finish != NULL);
	return iface->retrieve_secret_finish (self, result, error);
}

GHashTable *
secret_readable_item_get_attributes (SecretReadableItem *self)
{
	GValue value;

	g_return_val_if_fail (SECRET_IS_READABLE_ITEM (self), NULL);

	g_object_get_property (self, "attributes", &value);
	return g_value_get_boxed (&value);
}

guint64
secret_readable_item_get_created (SecretReadableItem *self)
{
	GValue value;

	g_return_val_if_fail (SECRET_IS_READABLE_ITEM (self), NULL);

	g_object_get_property (self, "created", &value);
	return g_value_get_uint64 (&value);
}

guint64
secret_readable_item_get_modified (SecretReadableItem *self)
{
	GValue value;

	g_return_val_if_fail (SECRET_IS_READABLE_ITEM (self), NULL);

	g_object_get_property (self, "modified", &value);
	return g_value_get_uint64 (&value);
}
