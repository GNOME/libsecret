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

#include "secret-file-collection.h"

#include "egg/egg-secure-memory.h"

EGG_SECURE_DECLARE (secret_file_collection);

#ifdef WITH_GCRYPT
#include <gcrypt.h>
#endif

#define MAC_ALGO GCRY_MAC_HMAC_SHA256
#define MAC_SIZE 32

#define CIPHER_ALGO GCRY_CIPHER_AES128
#define CIPHER_BLOCK_SIZE 16
#define IV_SIZE CIPHER_BLOCK_SIZE

#define KEYRING_FILE_HEADER "GnomeKeyring\n\r\0\n"
#define KEYRING_FILE_HEADER_LEN 16

#define MAJOR_VERSION 1
#define MINOR_VERSION 0

struct _SecretFileCollection
{
	GObject parent;
	GFile *file;
	gchar *etag;
	SecretValue *key;
	GBytes *iv;
	GVariant *items;
};

static void secret_file_collection_async_initable_iface (GAsyncInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (SecretFileCollection, secret_file_collection, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, secret_file_collection_async_initable_iface);
);

enum {
	PROP_0,
	PROP_FILE,
	PROP_KEY
};

static gboolean
calculate_mac (SecretFileCollection *self,
	       const guint8 *value, gsize n_value,
	       guint8 *buffer)
{
	gcry_mac_hd_t hd;
	gcry_error_t gcry;
	gconstpointer secret;
	gsize n_secret;
	gboolean ret = FALSE;

	gcry = gcry_mac_open (&hd, MAC_ALGO, 0, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	secret = secret_value_get (self->key, &n_secret);
	gcry = gcry_mac_setkey (hd, secret, n_secret);
	if (gcry != 0)
		goto out;

	gcry = gcry_mac_write (hd, value, n_value);
	if (gcry != 0)
		goto out;

	n_value = MAC_SIZE;
	gcry = gcry_mac_read (hd, buffer, &n_value);
	if (gcry != 0)
		goto out;

	if (n_value != MAC_SIZE)
		goto out;

	ret = TRUE;
 out:
	gcry_mac_close (hd);
	return ret;
}

static gboolean
decrypt (SecretFileCollection *self,
	 guint8 *data,
	 gsize n_data)
{
	gcry_cipher_hd_t hd;
	gcry_error_t gcry;
	gconstpointer secret;
	gsize n_secret;
	gconstpointer iv;
	gsize n_iv;
	gboolean ret = FALSE;

	gcry = gcry_cipher_open (&hd, CIPHER_ALGO, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry != 0)
		goto out;

	secret = secret_value_get (self->key, &n_secret);
	gcry = gcry_cipher_setkey (hd, secret, n_secret);
	if (gcry != 0)
		goto out;

	iv = g_bytes_get_data (self->iv, &n_iv);
	gcry = gcry_cipher_setiv (hd, iv, n_iv);
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

static gboolean
encrypt (SecretFileCollection *self,
	 guint8 *data,
	 gsize n_data)
{
	gcry_cipher_hd_t hd;
	gcry_error_t gcry;
	gconstpointer secret;
	gsize n_secret;
	gconstpointer iv;
	gsize n_iv;
	gboolean ret = FALSE;

	gcry = gcry_cipher_open (&hd, CIPHER_ALGO, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry != 0)
		goto out;

	secret = secret_value_get (self->key, &n_secret);
	gcry = gcry_cipher_setkey (hd, secret, n_secret);
	if (gcry != 0)
		goto out;

	iv = g_bytes_get_data (self->iv, &n_iv);
	gcry = gcry_cipher_setiv (hd, iv, n_iv);
	if (gcry != 0)
		goto out;

	gcry = gcry_cipher_encrypt (hd, data, n_data, NULL, 0);
	if (gcry != 0)
		goto out;

	ret = TRUE;
 out:
	(void) gcry_cipher_final (hd);
	return ret;
}

static void
secret_file_collection_init (SecretFileCollection *self)
{
}

static void
secret_file_collection_set_property (GObject      *object,
                                     guint         prop_id,
                                     const GValue *value,
                                     GParamSpec   *pspec)
{
	SecretFileCollection *self = SECRET_FILE_COLLECTION (object);

	switch (prop_id) {
	case PROP_FILE:
		self->file = g_value_dup_object (value);
		break;
	case PROP_KEY:
		self->key = g_value_dup_boxed (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
secret_file_collection_get_property (GObject    *object,
                                     guint       prop_id,
                                     GValue     *value,
                                     GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
secret_file_collection_finalize (GObject *object)
{
	SecretFileCollection *self = SECRET_FILE_COLLECTION (object);

	g_object_unref (self->file);
	g_free (self->etag);

	secret_value_unref (self->key);
	g_clear_pointer (&self->iv, g_bytes_unref);

	G_OBJECT_CLASS (secret_file_collection_parent_class)->finalize (object);
}

static void
secret_file_collection_class_init (SecretFileCollectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	object_class->set_property = secret_file_collection_set_property;
	object_class->get_property = secret_file_collection_get_property;
	object_class->finalize = secret_file_collection_finalize;

	g_object_class_install_property (object_class, PROP_FILE,
		   g_param_spec_object ("file", "File", "File",
					G_TYPE_FILE, G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (object_class, PROP_KEY,
		   g_param_spec_boxed ("key", "key", "Key",
				       SECRET_TYPE_VALUE,
				       G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
}

static void
on_load_contents (GObject *source_object,
		  GAsyncResult *result,
		  gpointer user_data)
{
	GFile *file = G_FILE (source_object);
	GTask *task = G_TASK (user_data);
	SecretFileCollection *self = g_task_get_source_object (task);
	gchar *contents;
	gchar *p;
	gsize length;
	GError *error = NULL;
	gboolean ret;

	ret = g_file_load_contents_finish (file, result,
					   &contents, &length,
					   &self->etag,
					   &error);

	if (!ret) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND)) {
			GVariantBuilder builder;
			guint8 iv[IV_SIZE];

			g_variant_builder_init (&builder,
						G_VARIANT_TYPE ("a(a{say}ay)"));
			gcry_create_nonce (iv, sizeof(iv));
			self->iv = g_bytes_new (iv, sizeof(iv));
			self->items = g_variant_builder_end (&builder);
			g_task_return_boolean (task, TRUE);
			g_object_unref (task);
			return;
		}

		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

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

	if (length < 2 || *p != MAJOR_VERSION || *(p + 1) != MINOR_VERSION) {
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
secret_file_collection_real_init_async (GAsyncInitable *initable,
					int io_priority,
					GCancellable *cancellable,
					GAsyncReadyCallback callback,
					gpointer user_data)
{
	SecretFileCollection *self = SECRET_FILE_COLLECTION (initable);
	GTask *task;

	task = g_task_new (initable, cancellable, callback, user_data);

	g_file_load_contents_async (self->file, cancellable, on_load_contents, task);
}

static gboolean
secret_file_collection_real_init_finish (GAsyncInitable *initable,
					 GAsyncResult *result,
					 GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, initable), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
secret_file_collection_async_initable_iface (GAsyncInitableIface *iface)
{
	iface->init_async = secret_file_collection_real_init_async;
	iface->init_finish = secret_file_collection_real_init_finish;
}

static GVariant *
hash_attributes (SecretFileCollection *self,
		 GHashTable *attributes)
{
	GVariantBuilder builder;
	guint8 buffer[MAC_SIZE];
	GList *keys;
	GList *l;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{say}"));

	keys = g_hash_table_get_keys (attributes);
	keys = g_list_sort (keys, (GCompareFunc) g_strcmp0);

	for (l = keys; l; l = g_list_next (l)) {
		const gchar *value;
		GVariant *variant;

		value = g_hash_table_lookup (attributes, l->data);
		if (!calculate_mac (self, (guint8 *)value, strlen (value), buffer)) {
			g_list_free (keys);
			return NULL;
		}

		variant = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
						     buffer,
						     MAC_SIZE,
						     sizeof(guint8));
		g_variant_builder_add (&builder, "{s@ay}", l->data, variant);
	}

	return g_variant_builder_end (&builder);
}

static gboolean
hashed_attributes_match (SecretFileCollection *self,
			 GVariant *hashed_attributes,
			 GHashTable *attributes)
{
	GHashTableIter iter;
	GVariant *hashed_attribute = NULL;
	gpointer key;
	gpointer value;
	guint8 buffer[MAC_SIZE];
	gboolean ret;

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		const guint8 *data;
		gsize n_data;

		if (!g_variant_lookup (hashed_attributes, key,
				       "@ay", &hashed_attribute))
			return FALSE;

		data = g_variant_get_fixed_array (hashed_attribute,
						  &n_data, sizeof(guint8));
		if (n_data != MAC_SIZE) {
			g_variant_unref (&hashed_attribute);
			return FALSE;
		}

		if (!calculate_mac (self, value, strlen ((char *)value), buffer)) {
			g_variant_unref (&hashed_attribute);
			return FALSE;
		}

		if (memcmp (data, buffer, MAC_SIZE) != 0) {
			g_variant_unref (&hashed_attribute);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
secret_file_collection_replace (SecretFileCollection *self,
				GHashTable *attributes,
				const gchar *label,
				SecretValue *value,
				GError **error)
{
	GVariantBuilder builder;
	GVariant *hashed_attributes;
	GVariantIter iter;
	GVariant *child;
	SecretFileItem *item;
	GVariant *serialized_item;
	guint8 *data = NULL;
	gsize n_data;
	gsize n_padded;
	GVariant *variant;

	hashed_attributes = hash_attributes (self, attributes);
	if (!hashed_attributes) {
		g_set_error (error,
			     SECRET_ERROR,
			     SECRET_ERROR_PROTOCOL,
			     "couldn't calculate mac");
		return FALSE;
	}

	/* Filter out the existing item */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(a{say}ay)"));
	g_variant_iter_init (&iter, self->items);
	while ((child = g_variant_iter_next_value (&iter)) != NULL) {
		GVariant *_hashed_attributes;
		g_variant_get (child, "(@a{say}ay)", &_hashed_attributes, NULL);
		if (!g_variant_equal (hashed_attributes, _hashed_attributes))
			g_variant_builder_add_value (&builder, child);
		else
			g_variant_unref (child);
		g_variant_unref (_hashed_attributes);
	}

	/* Create a new item and append it */
	item = g_object_new (SECRET_TYPE_FILE_ITEM,
			     "attributes", attributes,
			     "label", label,
			     "value", value,
			     "created", 0,
			     "modified", 0,
			     NULL);
	serialized_item = secret_file_item_serialize (item);
	g_object_unref (item);

	/* Encrypt the item with PKCS #7 padding */
	n_data = g_variant_get_size (serialized_item);
	n_padded = ((n_data + CIPHER_BLOCK_SIZE) / CIPHER_BLOCK_SIZE) *
		CIPHER_BLOCK_SIZE;
	data = egg_secure_alloc (n_padded);
	g_variant_store (serialized_item, data);
	g_variant_unref (serialized_item);
	memset (data + n_data, n_padded - n_data, n_padded - n_data);
	if (!encrypt (self, data, n_padded)) {
		egg_secure_free (data);
		g_set_error (error,
			     SECRET_ERROR,
			     SECRET_ERROR_PROTOCOL,
			     "couldn't encrypt item");
		return FALSE;
	}

	variant = g_variant_new_from_data (G_VARIANT_TYPE ("ay"),
					   data,
					   n_padded,
					   TRUE,
					   egg_secure_free,
					   data);
	variant = g_variant_new ("(@a{say}@ay)", hashed_attributes, variant);
	g_variant_builder_add_value (&builder, variant);

	g_variant_unref (self->items);
	self->items = g_variant_builder_end (&builder);

	return TRUE;
}

GList *
secret_file_collection_search (SecretFileCollection *self,
			       GHashTable *attributes)
{
	GVariantIter iter;
	GVariant *child;
	GList *result = NULL;

	g_variant_iter_init (&iter, self->items);
	while ((child = g_variant_iter_next_value (&iter)) != NULL) {
		GVariant *hashed_attributes;
		gboolean matched;

		g_variant_get (child, "(@a{say}ay)", &hashed_attributes, NULL);
		matched = hashed_attributes_match (self,
						   hashed_attributes,
						   attributes);
		g_variant_unref (hashed_attributes);
		if (matched)
			result = g_list_append (result, child);
		else
			g_variant_unref (child);
	}

	return result;
}

SecretFileItem *
_secret_file_item_decrypt (GVariant *encrypted,
			   SecretFileCollection *collection,
			   GError **error)
{
	GVariant *blob;
	gconstpointer padded;
	gsize n_data;
	gsize n_padded;
	guint8 *data;
	SecretFileItem *item;
	GVariant *serialized_item;

	g_variant_get (encrypted, "(a{say}@ay)", NULL, &blob);

	/* Decrypt the item */
	padded = g_variant_get_fixed_array (blob, &n_padded, sizeof(guint8));
	data = egg_secure_alloc (n_padded);
	memcpy (data, padded, n_padded);
	g_variant_unref (blob);

	if (!decrypt (collection, data, n_padded)) {
		egg_secure_free (data);
		g_set_error (error,
			     SECRET_ERROR,
			     SECRET_ERROR_PROTOCOL,
			     "couldn't decrypt item");
		return NULL;
	}

	/* Remove PKCS #7 padding */
	n_data = n_padded - data[n_padded - 1];
	serialized_item =
		g_variant_new_from_data (G_VARIANT_TYPE ("(a{ss}sttay)"),
					 data,
					 n_data,
					 TRUE,
					 egg_secure_free,
					 data);
	item = secret_file_item_deserialize (serialized_item);
	egg_secure_free (data);
	return item;
}

gboolean
secret_file_collection_clear (SecretFileCollection *self,
			      GHashTable *attributes,
			      GError **error)
{
	GVariantBuilder builder;
	GVariantIter items;
	GVariant *child;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{say}ay"));
	g_variant_iter_init (&items, self->items);
	while ((child = g_variant_iter_next_value (&items)) != NULL) {
		GVariant *hashed_attributes;
		gboolean matched;

		g_variant_get (child, "@a{say}ay", &hashed_attributes, NULL);
		matched = hashed_attributes_match (self,
						   hashed_attributes,
						   attributes);
		g_variant_unref (hashed_attributes);
		if (!matched)
			g_variant_builder_add_value (&builder, child);
		else
			g_variant_unref (child);
	}
	g_variant_unref (self->items);
	self->items = g_variant_builder_end (&builder);
	return TRUE;
}

static void
on_replace_contents (GObject *source_object,
		     GAsyncResult *result,
		     gpointer user_data)
{
	GFile *file = G_FILE (source_object);
	GTask *task = G_TASK (user_data);
	SecretFileCollection *self = g_task_get_source_object (task);
	GError *error = NULL;

	if (!g_file_replace_contents_finish (file, result, &self->etag, &error)) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return;
	}

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

void
secret_file_collection_write (SecretFileCollection *self,
			      GCancellable *cancellable,
			      GAsyncReadyCallback callback,
			      gpointer user_data)
{
	GTask *task;
	guint8 *contents;
	gsize n_contents;
	guint8 *p;
	gconstpointer iv;
	gsize n_iv;

	n_contents = KEYRING_FILE_HEADER_LEN + 2 + IV_SIZE +
		g_variant_get_size (self->items);
	contents = g_new (guint8, n_contents);

	p = contents;
	memcpy (p, KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN);
	p += KEYRING_FILE_HEADER_LEN;

	*p++ = MAJOR_VERSION;
	*p++ = MINOR_VERSION;

	iv = g_bytes_get_data (self->iv, &n_iv);
	memcpy (p, iv, n_iv);
	p += n_iv;

	g_variant_store (self->items, p);

	task = g_task_new (self, cancellable, callback, user_data);
	g_file_replace_contents_async (self->file,
				       (gchar *) contents,
				       n_contents,
				       self->etag,
				       TRUE,
				       G_FILE_CREATE_PRIVATE |
				       G_FILE_CREATE_REPLACE_DESTINATION,
				       cancellable,
				       on_replace_contents,
				       task);
}

gboolean
secret_file_collection_write_finish (SecretFileCollection *self,
				     GAsyncResult *result,
				     GError **error)
{
	g_return_val_if_fail (g_task_is_valid (result, self), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}
