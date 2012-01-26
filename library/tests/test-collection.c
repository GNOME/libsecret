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
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GError *error = NULL;
	GSecretCollection *collection;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	g_assert_cmpstr (g_dbus_proxy_get_object_path (G_DBUS_PROXY (collection)), ==, collection_path);

	g_object_unref (collection);
	egg_assert_not_object (collection);
}

static void
test_new_sync_noexist (Test *test,
                       gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/nonexistant";
	GError *error = NULL;
	GSecretCollection *collection;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD);
	g_assert (collection == NULL);
}

static void
test_new_async (Test *test,
               gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GError *error = NULL;
	GSecretCollection *collection;
	GAsyncResult *result = NULL;

	gsecret_collection_new (test->service, collection_path, NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	collection = gsecret_collection_new_finish (result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	g_assert_cmpstr (g_dbus_proxy_get_object_path (G_DBUS_PROXY (collection)), ==, collection_path);

	g_object_unref (collection);
	egg_assert_not_object (collection);
}

static void
test_new_async_noexist (Test *test,
                        gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/nonexistant";
	GError *error = NULL;
	GSecretCollection *collection;
	GAsyncResult *result = NULL;

	gsecret_collection_new (test->service, collection_path, NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	collection = gsecret_collection_new_finish (result, &error);
	g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD);
	g_assert (collection == NULL);
	g_object_unref (result);
}

static void
test_properties (Test *test,
                 gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GSecretCollection *collection;
	GSecretService *service;
	GError *error = NULL;
	guint64 created;
	guint64 modified;
	gboolean locked;
	gchar *label;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	g_assert (gsecret_collection_get_locked (collection) == FALSE);
	g_assert_cmpuint (gsecret_collection_get_created (collection), <=, time (NULL));
	g_assert_cmpuint (gsecret_collection_get_modified (collection), <=, time (NULL));

	label = gsecret_collection_get_label (collection);
	g_assert_cmpstr (label, ==, "Collection One");
	g_free (label);

	g_object_get (collection,
	              "locked", &locked,
	              "created", &created,
	              "modified", &modified,
	              "label", &label,
	              "service", &service,
	              NULL);

	g_assert (locked == FALSE);
	g_assert_cmpuint (created, <=, time (NULL));
	g_assert_cmpuint (modified, <=, time (NULL));

	g_assert_cmpstr (label, ==, "Collection One");
	g_free (label);

	g_assert (service == test->service);
	g_object_unref (service);

	g_object_unref (collection);
}

static void
check_items_equal (GList *items,
                   ...)
{
	GHashTable *paths;
	gboolean have_item;
	const gchar *path;
	guint num_items;
	va_list va;
	GList *l;

	va_start (va, items);
	paths = g_hash_table_new (g_str_hash, g_str_equal);
	while ((path = va_arg (va, gchar *)) != NULL)
		g_hash_table_insert (paths, (gpointer)path, (gpointer)path);
	va_end (va);

	num_items = g_hash_table_size (paths);
	g_assert_cmpuint (num_items, ==, g_list_length (items));

	for (l = items; l != NULL; l = g_list_next (l)) {
		path = g_dbus_proxy_get_object_path (l->data);
		have_item = g_hash_table_remove (paths, path);
		g_assert (have_item);
	}

	g_hash_table_destroy (paths);
}

static void
test_items (Test *test,
            gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GSecretCollection *collection;
	GError *error = NULL;
	GList *items;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	items = gsecret_collection_get_items (collection);
	check_items_equal (items,
	                   "/org/freedesktop/secrets/collection/english/item_one",
	                   "/org/freedesktop/secrets/collection/english/item_two",
	                   "/org/freedesktop/secrets/collection/english/item_three",
	                   NULL);
	g_list_free_full (items, g_object_unref);

	g_object_get (collection, "items", &items, NULL);
	check_items_equal (items,
	                   "/org/freedesktop/secrets/collection/english/item_one",
	                   "/org/freedesktop/secrets/collection/english/item_two",
	                   "/org/freedesktop/secrets/collection/english/item_three",
	                   NULL);
	g_list_free_full (items, g_object_unref);

	g_object_unref (collection);
}

static void
test_items_empty (Test *test,
                  gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/empty";
	GSecretCollection *collection;
	GError *error = NULL;
	GList *items;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	items = gsecret_collection_get_items (collection);
	check_items_equal (items, NULL);
	g_list_free_full (items, g_object_unref);

	g_object_get (collection, "items", &items, NULL);
	check_items_equal (items, NULL);
	g_list_free_full (items, g_object_unref);

	g_object_unref (collection);
}

static void
test_items_empty_async (Test *test,
                        gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/empty";
	GSecretCollection *collection;
	GAsyncResult *result = NULL;
	GError *error = NULL;
	GList *items;

	gsecret_collection_new (test->service, collection_path, NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	collection = gsecret_collection_new_finish (result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	items = gsecret_collection_get_items (collection);
	check_items_equal (items, NULL);
	g_list_free_full (items, g_object_unref);

	g_object_get (collection, "items", &items, NULL);
	check_items_equal (items, NULL);
	g_list_free_full (items, g_object_unref);

	g_object_unref (collection);
}

static void
test_set_label_sync (Test *test,
                     gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GError *error = NULL;
	GSecretCollection *collection;
	gboolean ret;
	gchar *label;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	label = gsecret_collection_get_label (collection);
	g_assert_cmpstr (label, ==, "Collection One");
	g_free (label);

	ret = gsecret_collection_set_label_sync (collection, "Another label", NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	label = gsecret_collection_get_label (collection);
	g_assert_cmpstr (label, ==, "Another label");
	g_free (label);

	g_object_unref (collection);
}

static void
test_set_label_async (Test *test,
                      gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GAsyncResult *result = NULL;
	GError *error = NULL;
	GSecretCollection *collection;
	gboolean ret;
	gchar *label;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	label = gsecret_collection_get_label (collection);
	g_assert_cmpstr (label, ==, "Collection One");
	g_free (label);

	gsecret_collection_set_label (collection, "Another label", NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	ret = gsecret_collection_set_label_finish (collection, result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_object_unref (result);

	label = gsecret_collection_get_label (collection);
	g_assert_cmpstr (label, ==, "Another label");
	g_free (label);

	g_object_unref (collection);
}

static void
test_set_label_prop (Test *test,
                     gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GError *error = NULL;
	GSecretCollection *collection;
	guint sigs = 2;
	gchar *label;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	label = gsecret_collection_get_label (collection);
	g_assert_cmpstr (label, ==, "Collection One");
	g_free (label);

	g_signal_connect (collection, "notify::label", G_CALLBACK (on_notify_stop), &sigs);
	g_object_set (collection, "label", "Blah blah", NULL);

	/* Wait for the property to actually 'take' */
	egg_test_wait ();

	label = gsecret_collection_get_label (collection);
	g_assert_cmpstr (label, ==, "Blah blah");
	g_free (label);

	g_object_unref (collection);
}

static void
test_delete_sync (Test *test,
                  gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GSecretCollection *collection;
	GError *error = NULL;
	gboolean ret;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	ret = gsecret_collection_delete_sync (collection, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_object_unref (collection);

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD);
	g_assert (collection == NULL);
}

static void
test_delete_async (Test *test,
                   gconstpointer unused)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GSecretCollection *collection;
	GAsyncResult *result = NULL;
	GError *error = NULL;
	gboolean ret;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	gsecret_collection_delete (collection, NULL, on_async_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	ret = gsecret_collection_delete_finish (collection, result, &error);
	g_assert_no_error (error);
	g_object_unref (result);
	g_assert (ret == TRUE);

	g_object_unref (collection);

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_error (error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD);
	g_assert (collection == NULL);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-collection");
	g_type_init ();

	g_test_add ("/collection/new-sync", Test, "mock-service-normal.py", setup, test_new_sync, teardown);
	g_test_add ("/collection/new-sync-noexist", Test, "mock-service-normal.py", setup, test_new_sync_noexist, teardown);
	g_test_add ("/collection/new-async", Test, "mock-service-normal.py", setup, test_new_async, teardown);
	g_test_add ("/collection/new-async-noexist", Test, "mock-service-normal.py", setup, test_new_async_noexist, teardown);
	g_test_add ("/collection/properties", Test, "mock-service-normal.py", setup, test_properties, teardown);
	g_test_add ("/collection/items", Test, "mock-service-normal.py", setup, test_items, teardown);
	g_test_add ("/collection/items-empty", Test, "mock-service-normal.py", setup, test_items_empty, teardown);
	g_test_add ("/collection/items-empty-async", Test, "mock-service-normal.py", setup, test_items_empty_async, teardown);
	g_test_add ("/collection/set-label-sync", Test, "mock-service-normal.py", setup, test_set_label_sync, teardown);
	g_test_add ("/collection/set-label-async", Test, "mock-service-normal.py", setup, test_set_label_async, teardown);
	g_test_add ("/collection/set-label-prop", Test, "mock-service-normal.py", setup, test_set_label_prop, teardown);
	g_test_add ("/collection/delete-sync", Test, "mock-service-normal.py", setup, test_delete_sync, teardown);
	g_test_add ("/collection/delete-async", Test, "mock-service-normal.py", setup, test_delete_async, teardown);

	return egg_tests_run_with_loop ();
}
