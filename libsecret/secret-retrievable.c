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

#include "secret-retrievable.h"
#include "secret-private.h"

/**
 * SECTION:secret-retrievable
 * @title: SecretRetrievable
 * @short_description: A read-only secret item
 *
 * #SecretRetrievable provides a read-only view of a secret item
 * stored in the Secret Service.
 *
 * Each item has a value, represented by a #SecretValue, which can be
 * retrieved by secret_retrievable_retrieve_secret() and
 * secret_retrievable_retrieve_secret_finish().
 *
 * Stability: Stable
 */

/**
 * SecretRetrievable:
 *
 * An object representing a read-only view of a secret item in the Secret Service.
 */

/**
 * SecretRetrievableInterface:
 * @parent_iface: the parent interface
 * @retrieve_secret: implementation of secret_retrievable_retrieve_secret(), required
 * @retrieve_secret_finish: implementation of secret_retrievable_retrieve_secret_finish(), required
 *
 * The interface for #SecretRetrievable.
 */

G_DEFINE_INTERFACE (SecretRetrievable, secret_retrievable, G_TYPE_OBJECT);

static void
secret_retrievable_default_init (SecretRetrievableInterface *iface)
{
	/**
	 * SecretRetrievable:attributes: (type GLib.HashTable(utf8,utf8)) (transfer full)
	 *
	 * The attributes set on this item. Attributes are used to locate an
	 * item. They are not guaranteed to be stored or transferred securely.
	 */
	g_object_interface_install_property (iface,
	             g_param_spec_boxed ("attributes", "Attributes", "Item attributes",
	                                 G_TYPE_HASH_TABLE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	/**
	 * SecretRetrievable:label:
	 *
	 * The human readable label for the item.
	 */
	g_object_interface_install_property (iface,
	            g_param_spec_string ("label", "Label", "Item label",
	                                 NULL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	/**
	 * SecretRetrievable:created:
	 *
	 * The date and time (in seconds since the UNIX epoch) that this
	 * item was created.
	 */
	g_object_interface_install_property (iface,
	            g_param_spec_uint64 ("created", "Created", "Item creation date",
	                                 0UL, G_MAXUINT64, 0UL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	/**
	 * SecretRetrievable:modified:
	 *
	 * The date and time (in seconds since the UNIX epoch) that this
	 * item was last modified.
	 */
	g_object_interface_install_property (iface,
	            g_param_spec_uint64 ("modified", "Modified", "Item modified date",
	                                 0UL, G_MAXUINT64, 0UL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

/**
 * secret_retrievable_retrieve_secret:
 * @self: a retrievable object
 * @cancellable: optional cancellation object
 * @callback: called when the operation completes
 * @user_data: data to pass to the callback
 *
 * Retrieve the secret value of this object.
 *
 * Each retrievable object has a single secret which might be a
 * password or some other secret binary value.
 *
 * This function returns immediately and completes asynchronously.
 */
void
secret_retrievable_retrieve_secret (SecretRetrievable *self,
				    GCancellable *cancellable,
				    GAsyncReadyCallback callback,
				    gpointer user_data)
{
	SecretRetrievableInterface *iface;

	g_return_if_fail (SECRET_IS_RETRIEVABLE (self));
	iface = SECRET_RETRIEVABLE_GET_IFACE (self);
	g_return_if_fail (iface->retrieve_secret != NULL);
	iface->retrieve_secret (self, cancellable, callback, user_data);
}

/**
 * secret_retrievable_retrieve_secret_finish:
 * @self: a retrievable object
 * @result: asynchronous result passed to callback
 * @error: location to place error on failure
 *
 * Complete asynchronous operation to retrieve the secret value of this object.
 *
 * Returns: (transfer full) (nullable): the secret value which should be
 *          released with secret_value_unref(), or %NULL
 */
SecretValue *
secret_retrievable_retrieve_secret_finish (SecretRetrievable *self,
					   GAsyncResult *result,
					   GError **error)
{
	SecretRetrievableInterface *iface;

	g_return_val_if_fail (SECRET_IS_RETRIEVABLE (self), NULL);
	iface = SECRET_RETRIEVABLE_GET_IFACE (self);
	g_return_val_if_fail (iface->retrieve_secret_finish != NULL, NULL);
	return iface->retrieve_secret_finish (self, result, error);
}

/**
 * secret_retrievable_retrieve_secret_sync:
 * @self: a retrievable object
 * @cancellable: optional cancellation object
 * @error: location to place error on failure
 *
 * Retrieve the secret value of this object synchronously.
 *
 * Each retrievable object has a single secret which might be a
 * password or some other secret binary value.
 *
 * This method may block indefinitely and should not be used in user interface
 * threads.
 *
 * Returns: (transfer full) (nullable): the secret value which should be
 *          released with secret_value_unref(), or %NULL
 */
SecretValue *
secret_retrievable_retrieve_secret_sync (SecretRetrievable *self,
					 GCancellable *cancellable,
					 GError **error)
{
	SecretSync *sync;
	SecretValue *value;

	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	sync = _secret_sync_new ();
	g_main_context_push_thread_default (sync->context);

	secret_retrievable_retrieve_secret (self,
					    cancellable,
					    _secret_sync_on_result, sync);

	g_main_loop_run (sync->loop);

	value = secret_retrievable_retrieve_secret_finish (self,
							   sync->result,
							   error);

	g_main_context_pop_thread_default (sync->context);
	_secret_sync_free (sync);

	return value;
}

/**
 * secret_retrievable_get_attributes:
 * @self: a retrievable object
 *
 * Get the attributes of this object.
 *
 * The attributes are a mapping of string keys to string values.
 * Attributes are used to search for items. Attributes are not stored
 * or transferred securely by the secret service.
 *
 * Do not modify the attribute returned by this method.
 *
 * Returns: (transfer full) (element-type utf8 utf8): a new reference
 *          to the attributes, which should not be modified, and
 *          released with g_hash_table_unref()
 */
GHashTable *
secret_retrievable_get_attributes (SecretRetrievable *self)
{
	GValue value;

	g_return_val_if_fail (SECRET_IS_RETRIEVABLE (self), NULL);

	g_object_get_property (G_OBJECT (self), "attributes", &value);
	return g_value_dup_boxed (&value);
}

/**
 * secret_retrievable_get_label:
 * @self: a retrievable object
 *
 * Get the label of this item.
 *
 * Returns: the label
 */
const gchar *
secret_retrievable_get_label (SecretRetrievable *self)
{
	GValue value;

	g_return_val_if_fail (SECRET_IS_RETRIEVABLE (self), NULL);

	g_object_get_property (G_OBJECT (self), "label", &value);
	return g_value_get_string (&value);
}

/**
 * secret_retrievable_get_created:
 * @self: a retrievable object
 *
 * Get the created date and time of the object. The return value is
 * the number of seconds since the unix epoch, January 1st 1970.
 *
 * Returns: the created date and time
 */
guint64
secret_retrievable_get_created (SecretRetrievable *self)
{
	GValue value;

	g_return_val_if_fail (SECRET_IS_RETRIEVABLE (self), 0);

	g_object_get_property (G_OBJECT (self), "created", &value);
	return g_value_get_uint64 (&value);
}

/**
 * secret_retrievable_get_modified:
 * @self: a retrievable object
 *
 * Get the modified date and time of the object. The return value is
 * the number of seconds since the unix epoch, January 1st 1970.
 *
 * Returns: the modified date and time
 */
guint64
secret_retrievable_get_modified (SecretRetrievable *self)
{
	GValue value;

	g_return_val_if_fail (SECRET_IS_RETRIEVABLE (self), 0);

	g_object_get_property (G_OBJECT (self), "modified", &value);
	return g_value_get_uint64 (&value);
}
