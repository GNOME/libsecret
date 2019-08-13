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
#include "secret-file-item.h"

static void secret_file_async_initable_iface (GAsyncInitableIface *iface);
static void secret_file_backend_iface (SecretBackendInterface *iface);

struct _SecretFile {
	GObject parent;
	gchar *path;
	gchar *etag;
	GBytes *key;
	GBytes *iv;
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

#define CIPHER_ALGO GCRY_CIPHER_AES128
#define IV_SIZE 16

#define KEYRING_FILE_HEADER "GnomeKeyring\n\r\0\n"
#define KEYRING_FILE_HEADER_LEN 16

enum {
	PROP_0,
	PROP_PATH,
	PROP_KEY
};

static void
secret_file_init (SecretFile *self)
{
}

static void
secret_file_finalize (GObject *object)
{
	SecretFile *self = SECRET_FILE (object);

	g_bytes_unref (self->key);
	g_bytes_unref (self->iv);
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

	/**
	 * SecretFile:path:
	 *
	 * The path from which keyrings are read.
	 */
	g_object_class_install_property (object_class, PROP_PATH,
		   g_param_spec_string ("path", "Path", "Path",
					NULL, G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
}

static void
on_load_contents (GObject *source_object,
		  GAsyncResult *result,
		  gpointer user_data)
{
	GFile *file = G_FILE (source_object);
	GTask *task = G_TASK (user_data);
	SecretFile *self = g_task_get_task_data (task);
	gchar *contents;
	gchar *p;
	gsize length;
	GError *error = NULL;

	if (!g_file_load_contents_finish (file, result,
					  &contents, &length,
					  &self->etag,
					  &error)) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND)) {
			GVariantBuilder builder;
			guint8 iv[IV_SIZE];

			g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(a{say}ay)"));
			gcry_create_nonce (iv, sizeof(iv));
			self->iv = g_bytes_new (iv, sizeof(iv));
			self->items = g_variant_builder_end (&builder);
			g_task_return_boolean (task, TRUE);
			g_object_unref (task);
		}

		g_object_unref (file);
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_object_unref (file);

	p = contents;
	if (length < KEYRING_FILE_HEADER_LEN ||
	    memcmp (p, KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN) != 0) {
		g_task_return_new_error (task,
					 SECRET_ERROR,
					 SECRET_ERROR_PROTOCOL,
					 "file header mismatch");
		g_object_unref (task);
		return;
	}
	p += KEYRING_FILE_HEADER_LEN;
	length -= KEYRING_FILE_HEADER_LEN;

	if (length < 2 || *p != 1 || *(p + 1) != 0) {
		g_task_return_new_error (task,
					 SECRET_ERROR,
					 SECRET_ERROR_PROTOCOL,
					 "version mismatch");
		g_object_unref (task);
		return;
	}
	p += 2;
	length += 2;

	if (length < IV_SIZE) {
		g_task_return_new_error (task,
					 SECRET_ERROR,
					 SECRET_ERROR_PROTOCOL,
					 "invalid iv");
		g_object_unref (task);
		return;
	}
	self->iv = g_bytes_new (p, IV_SIZE);
	p += IV_SIZE;
	length += IV_SIZE;

	self->items = g_variant_new_from_data (G_VARIANT_TYPE ("a{say}ay"),
					       p,
					       length,
					       TRUE,
					       g_free,
					       contents);
	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static void
secret_file_real_init_async (GAsyncInitable *initable,
			     int io_priority,
			     GCancellable *cancellable,
			     GAsyncReadyCallback callback,
			     gpointer user_data)
{
	SecretFile *self = SECRET_FILE (initable);
	GTask *task;
	GFile *file;

	task = g_task_new (initable, cancellable, callback, user_data);

	file = g_file_new_for_path (self->path);
	g_file_load_contents_async (file,
				    cancellable,
				    on_load_contents,
				    task);
}

static gboolean
secret_file_real_init_async_finish (GAsyncInitable *initable,
				    GAsyncResult *result,
				    GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, initable), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
secret_file_async_initable_iface (GAsyncInitableIface *iface)
{
}

static gboolean
calculate_mac (SecretFile *self,
	       const guint8 *value, gsize n_value,
	       guint8 *buffer)
{
	gcry_mac_hd_t hd;
	gcry_error_t gcry;
	gboolean ret = FALSE;

	gcry = gcry_mac_open (&hd, MAC_ALGO, 0, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	gcry = gcry_mac_setkey (hd,
				g_bytes_get_data (self->key),
				g_bytes_get_size (self->key));
	if (gcry != 0)
		goto out;

	gcry = gcry_mac_write (hd, value, strlen ((char *)value));
	if (gcry != 0)
		goto out;

	gcry = gcry_mac_read (hd, buffer, sizeof(buffer));
	if (gcry != 0)
		goto out;

	ret = TRUE;
 out:
	gcry_mac_close (hd);
	return ret;
}

static gboolean
decrypt (SecretFile *self,
	 guint8 *data,
	 gsize n_data)
{
	gcry_cipher_hd_t hd;
	gcry_error_t gcry;
	gboolean ret = FALSE;

	gcry = gcry_cipher_open (&hd,
				 GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC,
				 0);
	if (gcry != 0)
		goto out;

	gcry = gcry_cipher_setkey (hd,
				   g_bytes_get_data (self->key),
				   g_bytes_get_size (self->key));
	if (gcry != 0)
		goto out;

	gcry = gcry_cipher_setiv (hd,
				  g_bytes_get_data (self->iv),
				  g_bytes_get_size (self->iv));
	if (gcry != 0)
		goto out;

	gcry = gcry_cipher_decrypt (hd, data, n_data, NULL, 0);
	if (gcry != 0)
		goto out;

	ret = TRUE;
 out:
	(void) gcry_cipher_final (hd);
	return ret;
}

static void
secret_file_real_store (SecretBackend *backend,
			const SecretSchema *schema,
			GHashTable *attributes,
			const gchar *collection,
			const gchar *label,
			SecretValue *value,
			GCancellable *cancellable,
			GAsyncReadyCallback callback,
			gpointer user_data)
{
	SecretFile *self = SECRET_FILE (backend);
	GTask *task;
	GVariantBuilder builder;
	GVariant *hashed_attributes;
	GVariantIter items;
	GVariant *child;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	guint8 buffer[MAC_SIZE];
	SecretFileItem *item;

	task = g_task_new (self, cancellable, callback, user_data);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{say}"));
	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		if (!calculate_mac (self, value, strlen ((char *)value), buffer)) {
			g_task_return_new_error (task,
						 SECRET_ERROR,
						 SECRET_ERROR_PROTOCOL,
						 "couldn't calculate mac");
			g_object_unref (task);
			return;
		}
		g_variant_builder_add (&builder, "{say}", key, buffer);
	}
	hashed_attributes = g_variant_builder_end (&builder);

	/* Filter out the existing item */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{say}ay"));
	g_variant_iter_init (&items, self->items);
	while ((child = g_variant_iter_next_value (&items)) != NULL) {
		if (!item_matches_attributes (child, attributes))
			g_variant_builder_add_value (&builder, child);
		else
			g_variant_unref (child);
	}
	g_variant_unref (self->items);
	self->items = g_variant_builder_end (&builder);
}

static gboolean
secret_file_real_store_finish (SecretBackend *backend,
			       GAsyncResult *result,
			       GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), NULL);

	return g_task_propagate_boolean (G_TASK (result), error);
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
	guint8 buffer[MAC_SIZE];
	gboolean ret = TRUE;

	g_variant_get (item, "@a{say}ay", &hashed_attributes, NULL);

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
on_retrieve_secret (GObject *source_object,
		    GAsyncResult *result,
		    gpointer user_data)
{
	SecretRetrievable *retrievable = SECRET_RETRIEVABLE (source_object);
	GTask *task = G_TASK (user_data);
	SecretValue *value;
	GError *error;

	value = secret_retrievable_retrieve_secret_finish (retrievable,
							   result,
							   &error);
	if (value == NULL) {
		g_task_return_error (task, error);
		g_object_unref (task);
	}
	g_task_return_pointer (task, value, secret_value_unref);
	g_object_unref (task);
}

static void
secret_file_real_lookup (SecretBackend *backend,
			 const SecretSchema *schema,
			 GHashTable *attributes,
			 GCancellable *cancellable,
			 GAsyncReadyCallback callback,
			 gpointer user_data)
{
	SecretFile *self = SECRET_FILE (backend);
	GTask *task = g_task_new (self, cancellable, callback, user_data);
	GVariantIter iter;
	GVariant *child;
	SecretFileItem *item;
	const guint8 *data;
	gsize n_data;
	GVariant *blob;
	guint8 *buffer;

	g_variant_iter_init (&iter, self->items);
	while ((child = g_variant_iter_next_value (&iter)) != NULL) {
		if (item_matches_attributes (child, attributes))
			break;
		g_variant_unref (child);
	}

	if (child == NULL) {
		g_task_return_pointer (task, NULL, NULL);
		g_object_unref (task);
		return;
	}

	g_variant_get (child, "a{say}@ay", NULL, &blob);
	data = g_variant_get_fixed_array (blob, &n_data, sizeof(guint8));
	buffer = egg_secure_alloc (n_data);
	memcpy (buffer, data, n_data);
	g_variant_unref (blob);
	g_variant_unref (child);

	if (!decrypt (self, buffer, n_data)) {
		egg_secure_free (buffer);
		g_task_return_new_error (task,
					 SECRET_ERROR,
					 SECRET_ERROR_PROTOCOL,
					 "couldn't decrypt item");
		g_object_unref (task);
		return;
	}

	item = secret_file_item_deserialize (buffer, n_data);
	egg_secure_free (buffer);

	secret_retrievable_retrieve_secret (SECRET_RETRIEVABLE (item),
					    cancellable,
					    on_retrieve_secret,
					    task);
}

static SecretValue *
secret_file_real_lookup_finish (SecretBackend *backend,
				GAsyncResult *result,
				GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
secret_file_real_clear (SecretBackend *backend,
			const SecretSchema *schema,
			GHashTable *attributes,
			GCancellable *cancellable,
			GAsyncReadyCallback callback,
			gpointer user_data)
{
}

static gboolean
secret_file_real_clear_finish (SecretBackend *backend,
			       GAsyncResult *result,
			       GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), NULL);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
secret_file_real_search (SecretBackend *backend,
			 const SecretSchema *schema,
			 GHashTable *attributes,
			 SecretSearchFlags flags,
			 GCancellable *cancellable,
			 GAsyncReadyCallback callback,
			 gpointer user_data)
{
}

static GList *
secret_file_real_search_finish (SecretBackend *backend,
				GAsyncResult *result,
				GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, backend), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
secret_file_backend_iface (SecretBackendInterface *iface)
{
	iface->store = secret_file_real_store;
	iface->store_finish = secret_file_real_store_finish;
}
