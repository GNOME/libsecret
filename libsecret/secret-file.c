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

#include "secret-file.h"

static GAsyncInitableIface *secret_file_async_initable_parent_iface = NULL;

static SecretBackendInterface *secret_file_backend_parent_iface = NULL;

static void secret_file_async_initable_iface (GAsyncInitableIface *iface);

static void secret_file_backend_iface (SecretBackendInterface *iface);

struct _SecretFile {
	GObject parent;
	GBytes *master_secret;
	GVariant *items;
};

G_DEFINE_TYPE_WITH_CODE (SecretFile, secret_file, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, secret_file_async_initable_iface);
			 G_IMPLEMENT_INTERFACE (SECRET_TYPE_BACKEND, secret_file_backend_iface);
			 _secret_backend_ensure_extension_point ();
			 g_io_extension_point_implement (SECRET_BACKEND_EXTENSION_POINT_NAME,
							 g_define_type_id,
							 "service",
							 0)
);

#define MAC_ALGO GCRY_MAC_HMAC_SHA256
#define MAC_SIZE 32

enum {
	PROP_0,
	PROP_PATH,
	PROP_MASTER_SECRET
};

static void
secret_file_init (SecretFile *self)
{
}

static void
secret_file_finalize (GObject *object)
{
	SecretFile *self = SECRET_FILE (object);

	g_bytes_unref (self->master_secret);
	g_clear_pointer (&self->items, g_variant_unref)

	G_OBJECT_CLASS (secret_file_parent_class)->finalize (object);
}

static void
secret_file_class_init (SecretFileClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = secret_file_finalize;

	/**
	 * SecretFile:flags:
	 *
	 * A set of flags describing which parts of the secret file have
	 * been initialized.
	 */
	g_object_class_override_property (object_class, PROP_FLAGS, "flags");
}

static void
secret_file_real_ensure_for_flags (SecretBackend *self,
				   SecretBackendFlags flags,
				   GCancellable *cancellable,
				   GAsyncReadyCallback callback,
				   gpointer user_data)
{
	SecretFile *file = SECRET_FILE (self);
}

static gboolean
secret_file_real_ensure_for_flags_finish) (SecretBackend *self,
					   GAsyncResult *result,
					   GError **error)
{
}

static void
secret_file_real_store (SecretBackend *self,
			const SecretSchema *schema,
			GHashTable *attributes,
			const gchar *collection,
			const gchar *label,
			SecretValue *value,
			GCancellable *cancellable,
			GAsyncReadyCallback callback,
			gpointer user_data)
{
}

static gboolean
secret_file_real_store_finish (SecretBackend *self,
			       GAsyncResult *result,
			       GError **error)
{
}

static gboolean
calculate_mac (SecretFile *self,
	       const guint8 *value, gsize n_value,
	       guint8 *buffer)
{
	gcry_mac_hd_t hd;
	gcry_error_t gcry;
	gboolean ret = TRUE;

	gcry = gcry_mac_open (&hd, MAC_ALGO, 0, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	gcry = gcry_mac_setkey (hd,
				g_bytes_get_data (self->master_secret),
				g_bytes_get_size (self->master_secret));
	if (gcry != 0) {
		ret = FALSE;
		goto out;
	}
	gcry = gcry_mac_write (hd, value, strlen ((char *)value));
	if (gcry != 0) {
		ret = FALSE;
		goto out;
	}
	gcry = gcry_mac_read (hd, buffer, sizeof(buffer));
	if (gcry != 0) {
		ret = FALSE;
		goto out;
	}

 out:
	gcry_mac_close (hd);
	return ret;
}

static gboolean
item_matches_attributes (SecretFile *self,
			 GVariant *item,
			 GHashTable *attributes)
{
	GHashTableIter iter;
	GVariant *hashed_attributes = NULL;
	GVariant *hashed_attribute = NULL;
	gpointer key;
	gpointer value;
	guint8 buffer[32];
	gboolean ret = TRUE;

	g_variant_get (item, "@a{say}*", &hashed_attributes, NULL);

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		const guint8 *data;
		gsize n_data;

		if (!g_variant_lookup (hashed_attributes, key,
				       "@ay", &hashed_attribute)) {
			ret = FALSE;
			goto out;
		}

		data = g_variant_get_fixed_array (hashed_attribute,
						  &n_data, sizeof(guint8));
		if (n_data != MAC_SIZE) {
			ret = FALSE;
			goto out;
		}

		calculate_mac (self, value, strlen ((char *)value), buffer);
		if (memcmp (data, buffer, MAC_SIZE) != 0) {
			ret = FALSE;
			goto out;
		}
	}
 out:
	g_clear_pointer (&hashed_attributes, g_variant_unref);
	g_clear_pointer (&hashed_attribute, g_variant_unref);
	return ret;
}

static void
secret_file_real_lookup (SecretBackend *self,
			 const SecretSchema *schema,
			 GHashTable *attributes,
			 GCancellable *cancellable,
			 GAsyncReadyCallback callback,
			 gpointer user_data)
{
	SecretFile *file = SECRET_FILE (self);
	GTask *task = g_task_new (file, cancellable, callback, user_data);
	GVariantIter iter;
	GVariant *item = NULL;
	SecretRetrievable *retrievable;
	SecretValue *value;
	GError *error = NULL;

	g_variant_iter_init (&iter, self->items);
	while ((item = g_variant_iter_next_value (&iter)) != NULL) {
		if (item_matches_attributes (item, attributes))
			break;
		g_variant_unref (item);
	}

	if (item == NULL) {
		g_task_return_pointer (task, NULL, NULL);
		g_object_unref (task);
		return;
	}

	retrievable = decrypt_item (self, item, &error);
	if (retrievable == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	secret_retrievable_retrieve_secret (retrievable,
					    cancellable,
					    on_retrieve_secret,
					    task);
}

static SecretValue *
secret_file_real_lookup_finish (SecretBackend *self,
				GAsyncResult *result,
				GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, self), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
secret_file_real_clear (SecretBackend *self,
			const SecretSchema *schema,
			GHashTable *attributes,
			GCancellable *cancellable,
			GAsyncReadyCallback callback,
			gpointer user_data)
{
}

static gboolean
secret_file_real_clear_finish (SecretBackend *self,
			       GAsyncResult *result,
			       GError **error)
{
}

static void
secret_file_real_search (SecretBackend *self,
			 const SecretSchema *schema,
			 GHashTable *attributes,
			 SecretSearchFlags flags,
			 GCancellable *cancellable,
			 GAsyncReadyCallback callback,
			 gpointer user_data)
{
}

static GList *
secret_file_real_search_finish (SecretBackend *self,
				GAsyncResult *result,
				GError **error)
{
}

