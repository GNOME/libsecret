/* GSecret - GLib wrapper for Secret Service
 *
 * Copyright 2012 Red Hat Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */


#include "config.h"

#include "gsecret-collection.h"
#include "gsecret-item.h"
#include "gsecret-service.h"
#include "gsecret-private.h"

#include "mock-service.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>
#include <stdlib.h>

typedef struct {
	GSecretService *service;
} Test;

static void
setup (Test *test,
       gconstpointer data)
{
	GError *error = NULL;
	const gchar *mock_script = data;

	mock_service_start (mock_script, &error);
	g_assert_no_error (error);

	test->service = gsecret_service_get_sync (GSECRET_SERVICE_NONE, NULL, &error);
	g_assert_no_error (error);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	g_object_unref (test->service);
	egg_assert_not_object (test->service);

	mock_service_stop ();
}

static void
on_async_result (GObject *source,
                 GAsyncResult *result,
                 gpointer user_data)
{
	GAsyncResult **ret = user_data;
	g_assert (ret != NULL);
	g_assert (*ret == NULL);
	*ret = g_object_ref (result);
	egg_test_wait_stop ();
}

static void
on_notify_stop (GObject *obj,
                GParamSpec *spec,
                gpointer user_data)
{
	guint *sigs = user_data;
	g_assert (sigs != NULL);
	g_assert (*sigs > 0);
	if (--(*sigs) == 0)
		egg_test_wait_stop ();
}

static void
test_new_sync (Test *test,
               gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GError *error = NULL;
	GSecretItem *item;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	g_assert_cmpstr (g_dbus_proxy_get_object_path (G_DBUS_PROXY (item)), ==, item_path);

	g_object_unref (item);
}

static void
test_new_sync_noexist (Test *test,
                       gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/0000";
	GError *error = NULL;
	GSecretItem *item;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD);
	g_assert (item == NULL);
}

static void
test_new_async (Test *test,
                gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GAsyncResult *result = NULL;
	GError *error = NULL;
	GSecretItem *item;

	gsecret_item_new (test->service, item_path, NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	item = gsecret_item_new_finish (result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	g_assert_cmpstr (g_dbus_proxy_get_object_path (G_DBUS_PROXY (item)), ==, item_path);

	g_object_unref (item);
}

static void
test_new_async_noexist (Test *test,
                        gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/0000";
	GAsyncResult *result = NULL;
	GError *error = NULL;
	GSecretItem *item;

	gsecret_item_new (test->service, item_path, NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	item = gsecret_item_new_finish (result, &error);
	g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD);
	g_assert (item == NULL);
	g_object_unref (result);
}

static void
test_create_sync (Test *test,
                  gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GSecretCollection *collection;
	GError *error = NULL;
	GSecretItem *item;
	GHashTable *attributes;
	GSecretValue *value;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "even", "true");
	g_hash_table_insert (attributes, "string", "ten");
	g_hash_table_insert (attributes, "number", "10");

	value = gsecret_value_new ("Hoohah", -1, "text/plain");

	item = gsecret_item_create_sync (collection, "org.mock.Schema", "Tunnel",
	                                 attributes, value, FALSE, NULL, &error);
	g_assert_no_error (error);

	g_hash_table_unref (attributes);
	g_object_unref (collection);
	gsecret_value_unref (value);

	g_assert (g_str_has_prefix (g_dbus_proxy_get_object_path (G_DBUS_PROXY (item)), collection_path));
	g_assert_cmpstr (gsecret_item_get_label (item), ==, "Tunnel");
	g_assert (gsecret_item_get_locked (item) == FALSE);
	g_assert_cmpstr (gsecret_item_get_schema (item), ==, "org.freedesktop.Secret.Generic");

	g_object_unref (item);
	egg_assert_not_object (item);
}

static void
test_create_async (Test *test,
                   gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GSecretCollection *collection;
	GAsyncResult *result = NULL;
	GError *error = NULL;
	GSecretItem *item;
	GHashTable *attributes;
	GSecretValue *value;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "even", "true");
	g_hash_table_insert (attributes, "string", "ten");
	g_hash_table_insert (attributes, "number", "10");

	value = gsecret_value_new ("Hoohah", -1, "text/plain");

	gsecret_item_create (collection, "org.mock.Schema", "Tunnel",
	                     attributes, value, FALSE, NULL, on_async_result, &result);
	g_assert_no_error (error);

	g_hash_table_unref (attributes);
	g_object_unref (collection);
	gsecret_value_unref (value);

	egg_test_wait ();

	item = gsecret_item_create_finish (result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	g_assert (g_str_has_prefix (g_dbus_proxy_get_object_path (G_DBUS_PROXY (item)), collection_path));
	g_assert_cmpstr (gsecret_item_get_label (item), ==, "Tunnel");
	g_assert (gsecret_item_get_locked (item) == FALSE);
	g_assert_cmpstr (gsecret_item_get_schema (item), ==, "org.freedesktop.Secret.Generic");

	g_object_unref (item);
	egg_assert_not_object (item);
}

static void
test_properties (Test *test,
                 gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GError *error = NULL;
	GHashTable *attributes;
	GSecretService *service;
	GSecretItem *item;
	guint64 created;
	guint64 modified;
	gboolean locked;
	gchar *schema;
	gchar *label;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	g_assert (gsecret_item_get_locked (item) == FALSE);
	g_assert_cmpuint (gsecret_item_get_created (item), <=, time (NULL));
	g_assert_cmpuint (gsecret_item_get_modified (item), <=, time (NULL));

	schema = gsecret_item_get_schema (item);
	g_assert_cmpstr (schema, ==, "org.mock.type.Store");
	g_free (schema);

	label = gsecret_item_get_label (item);
	g_assert_cmpstr (label, ==, "Item One");
	g_free (label);

	attributes = gsecret_item_get_attributes (item);
	g_assert_cmpstr (g_hash_table_lookup (attributes, "string"), ==, "one");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "number"), ==, "1");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "even"), ==, "false");
	g_assert_cmpuint (g_hash_table_size (attributes), ==, 3);
	g_hash_table_unref (attributes);

	g_object_get (item,
	              "locked", &locked,
	              "created", &created,
	              "modified", &modified,
	              "label", &label,
	              "schema", &schema,
	              "attributes", &attributes,
	              "service", &service,
	              NULL);

	g_assert (locked == FALSE);
	g_assert_cmpuint (created, <=, time (NULL));
	g_assert_cmpuint (modified, <=, time (NULL));

	g_assert_cmpstr (label, ==, "Item One");
	g_free (label);

	g_assert_cmpstr (schema, ==, "org.mock.type.Store");
	g_free (schema);

	g_assert_cmpstr (g_hash_table_lookup (attributes, "string"), ==, "one");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "number"), ==, "1");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "even"), ==, "false");
	g_assert_cmpuint (g_hash_table_size (attributes), ==, 3);
	g_hash_table_unref (attributes);

	g_assert (service == test->service);
	g_object_unref (service);

	g_object_unref (item);
}

static void
test_set_label_sync (Test *test,
                     gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GError *error = NULL;
	GSecretItem *item;
	gboolean ret;
	gchar *label;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	label = gsecret_item_get_label (item);
	g_assert_cmpstr (label, ==, "Item One");
	g_free (label);

	ret = gsecret_item_set_label_sync (item, "Another label", NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	label = gsecret_item_get_label (item);
	g_assert_cmpstr (label, ==, "Another label");
	g_free (label);

	g_object_unref (item);
}

static void
test_set_label_async (Test *test,
                      gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GAsyncResult *result = NULL;
	GError *error = NULL;
	GSecretItem *item;
	gboolean ret;
	gchar *label;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	label = gsecret_item_get_label (item);
	g_assert_cmpstr (label, ==, "Item One");
	g_free (label);

	gsecret_item_set_label (item, "Another label", NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	ret = gsecret_item_set_label_finish (item, result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_object_unref (result);

	label = gsecret_item_get_label (item);
	g_assert_cmpstr (label, ==, "Another label");
	g_free (label);

	g_object_unref (item);
}

static void
test_set_label_prop (Test *test,
                     gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GError *error = NULL;
	GSecretItem *item;
	guint sigs = 2;
	gchar *label;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	label = gsecret_item_get_label (item);
	g_assert_cmpstr (label, ==, "Item One");
	g_free (label);

	g_signal_connect (item, "notify::label", G_CALLBACK (on_notify_stop), &sigs);
	g_object_set (item, "label", "Blah blah", NULL);

	/* Wait for the property to actually 'take' */
	egg_test_wait ();

	label = gsecret_item_get_label (item);
	g_assert_cmpstr (label, ==, "Blah blah");
	g_free (label);

	g_object_unref (item);
}

static void
test_set_attributes_sync (Test *test,
                           gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GError *error = NULL;
	GSecretItem *item;
	gboolean ret;
	GHashTable *attributes;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	attributes = gsecret_item_get_attributes (item);
	g_assert_cmpstr (g_hash_table_lookup (attributes, "string"), ==, "one");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "number"), ==, "1");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "even"), ==, "false");
	g_assert_cmpuint (g_hash_table_size (attributes), ==, 3);
	g_hash_table_unref (attributes);

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "string", "five");
	g_hash_table_insert (attributes, "number", "5");
	ret = gsecret_item_set_attributes_sync (item, attributes, NULL, &error);
	g_hash_table_unref (attributes);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	attributes = gsecret_item_get_attributes (item);
	g_assert_cmpstr (g_hash_table_lookup (attributes, "string"), ==, "five");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "number"), ==, "5");
	g_assert_cmpuint (g_hash_table_size (attributes), ==, 2);
	g_hash_table_unref (attributes);

	g_object_unref (item);
}

static void
test_set_attributes_async (Test *test,
                           gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GHashTable *attributes;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GSecretItem *item;
	gboolean ret;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	attributes = gsecret_item_get_attributes (item);
	g_assert_cmpstr (g_hash_table_lookup (attributes, "string"), ==, "one");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "number"), ==, "1");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "even"), ==, "false");
	g_assert_cmpuint (g_hash_table_size (attributes), ==, 3);
	g_hash_table_unref (attributes);

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "string", "five");
	g_hash_table_insert (attributes, "number", "5");
	gsecret_item_set_attributes (item, attributes, NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	ret = gsecret_item_set_attributes_finish (item, result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_object_unref (result);

	attributes = gsecret_item_get_attributes (item);
	g_assert_cmpstr (g_hash_table_lookup (attributes, "string"), ==, "five");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "number"), ==, "5");
	g_assert_cmpuint (g_hash_table_size (attributes), ==, 2);
	g_hash_table_unref (attributes);

	g_object_unref (item);
}

static void
test_set_attributes_prop (Test *test,
                          gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GError *error = NULL;
	GSecretItem *item;
	GHashTable *attributes;
	guint sigs = 2;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	attributes = gsecret_item_get_attributes (item);
	g_assert_cmpstr (g_hash_table_lookup (attributes, "string"), ==, "one");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "number"), ==, "1");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "even"), ==, "false");
	g_assert_cmpuint (g_hash_table_size (attributes), ==, 3);
	g_hash_table_unref (attributes);

	g_signal_connect (item, "notify::attributes", G_CALLBACK (on_notify_stop), &sigs);

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "string", "five");
	g_hash_table_insert (attributes, "number", "5");
	g_object_set (item, "attributes", attributes, NULL);
	g_hash_table_unref (attributes);

	/* Wait for the property to actually 'take' */
	egg_test_wait ();

	attributes = gsecret_item_get_attributes (item);
	g_assert_cmpstr (g_hash_table_lookup (attributes, "string"), ==, "five");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "number"), ==, "5");
	g_assert_cmpuint (g_hash_table_size (attributes), ==, 2);
	g_hash_table_unref (attributes);

	g_object_unref (item);
}

static void
test_get_secret_sync (Test *test,
                      gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GError *error = NULL;
	GSecretItem *item;
	GSecretValue *value;
	gconstpointer data;
	gsize length;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	value = gsecret_item_get_secret_sync (item, NULL, &error);
	g_assert_no_error (error);
	g_assert (value != NULL);

	data = gsecret_value_get (value, &length);
	egg_assert_cmpmem (data, length, ==, "111", 3);

	gsecret_value_unref (value);

	g_object_unref (item);
}

static void
test_get_secret_async (Test *test,
                       gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GAsyncResult *result = NULL;
	GError *error = NULL;
	GSecretItem *item;
	GSecretValue *value;
	gconstpointer data;
	gsize length;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	gsecret_item_get_secret (item, NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	value = gsecret_item_get_secret_finish (item, result, &error);
	g_assert_no_error (error);
	g_assert (value != NULL);
	g_object_unref (result);

	data = gsecret_value_get (value, &length);
	egg_assert_cmpmem (data, length, ==, "111", 3);

	gsecret_value_unref (value);

	g_object_unref (item);
}

static void
test_set_secret_sync (Test *test,
                      gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GError *error = NULL;
	GSecretItem *item;
	gconstpointer data;
	GSecretValue *value;
	gsize length;
	gboolean ret;

	value = gsecret_value_new ("Sinking", -1, "strange/content-type");

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	ret = gsecret_item_set_secret_sync (item, value, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	gsecret_value_unref (value);

	value = gsecret_item_get_secret_sync (item, NULL, &error);
	g_assert_no_error (error);
	g_assert (value != NULL);

	data = gsecret_value_get (value, &length);
	egg_assert_cmpmem (data, length, ==, "Sinking", 7);
	g_assert_cmpstr (gsecret_value_get_content_type (value), ==, "strange/content-type");

	gsecret_value_unref (value);
	g_object_unref (item);
}

static void
test_delete_sync (Test *test,
                  gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GError *error = NULL;
	GSecretItem *item;
	gboolean ret;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	ret = gsecret_item_delete_sync (item, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_object_unref (item);

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD);
	g_assert (item == NULL);
}

static void
test_delete_async (Test *test,
                   gconstpointer unused)
{
	const gchar *item_path = "/org/freedesktop/secrets/collection/english/1";
	GAsyncResult *result = NULL;
	GError *error = NULL;
	GSecretItem *item;
	gboolean ret;

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_no_error (error);

	gsecret_item_delete (item, NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	ret = gsecret_item_delete_finish (item, result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_object_unref (item);

	item = gsecret_item_new_sync (test->service, item_path, NULL, &error);
	g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD);
	g_assert (item == NULL);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-item");
	g_type_init ();

	g_test_add ("/item/new-sync", Test, "mock-service-normal.py", setup, test_new_sync, teardown);
	g_test_add ("/item/new-async", Test, "mock-service-normal.py", setup, test_new_async, teardown);
	g_test_add ("/item/new-sync-noexist", Test, "mock-service-normal.py", setup, test_new_sync_noexist, teardown);
	g_test_add ("/item/new-async-noexist", Test, "mock-service-normal.py", setup, test_new_async_noexist, teardown);
	g_test_add ("/item/create-sync", Test, "mock-service-normal.py", setup, test_create_sync, teardown);
	g_test_add ("/item/create-async", Test, "mock-service-normal.py", setup, test_create_async, teardown);
	g_test_add ("/item/properties", Test, "mock-service-normal.py", setup, test_properties, teardown);
	g_test_add ("/item/set-label-sync", Test, "mock-service-normal.py", setup, test_set_label_sync, teardown);
	g_test_add ("/item/set-label-async", Test, "mock-service-normal.py", setup, test_set_label_async, teardown);
	g_test_add ("/item/set-label-prop", Test, "mock-service-normal.py", setup, test_set_label_prop, teardown);
	g_test_add ("/item/set-attributes-sync", Test, "mock-service-normal.py", setup, test_set_attributes_sync, teardown);
	g_test_add ("/item/set-attributes-async", Test, "mock-service-normal.py", setup, test_set_attributes_async, teardown);
	g_test_add ("/item/set-attributes-prop", Test, "mock-service-normal.py", setup, test_set_attributes_prop, teardown);
	g_test_add ("/item/get-secret-sync", Test, "mock-service-normal.py", setup, test_get_secret_sync, teardown);
	g_test_add ("/item/get-secret-async", Test, "mock-service-normal.py", setup, test_get_secret_async, teardown);
	g_test_add ("/item/set-secret-sync", Test, "mock-service-normal.py", setup, test_set_secret_sync, teardown);
	g_test_add ("/item/delete-sync", Test, "mock-service-normal.py", setup, test_delete_sync, teardown);
	g_test_add ("/item/delete-async", Test, "mock-service-normal.py", setup, test_delete_async, teardown);

	return egg_tests_run_with_loop ();
}
