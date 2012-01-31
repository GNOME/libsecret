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

static const GSecretSchema DELETE_SCHEMA = {
	"org.mock.schema.Delete",
	{
		{ "number", GSECRET_ATTRIBUTE_INTEGER },
		{ "string", GSECRET_ATTRIBUTE_STRING },
		{ "even", GSECRET_ATTRIBUTE_BOOLEAN },
	}
};

static const GSecretSchema STORE_SCHEMA = {
	"org.mock.type.Store",
	{
		{ "number", GSECRET_ATTRIBUTE_INTEGER },
		{ "string", GSECRET_ATTRIBUTE_STRING },
		{ "even", GSECRET_ATTRIBUTE_BOOLEAN },
	}
};

typedef struct {
	GSecretService *service;
} Test;

static void
setup_mock (Test *test,
            gconstpointer data)
{
	GError *error = NULL;
	const gchar *mock_script = data;

	mock_service_start (mock_script, &error);
	g_assert_no_error (error);
}

static void
setup (Test *test,
       gconstpointer data)
{
	GError *error = NULL;

	setup_mock (test, data);

	test->service = gsecret_service_get_sync (GSECRET_SERVICE_NONE, NULL, &error);
	g_assert_no_error (error);
}

static void
teardown_mock (Test *test,
               gconstpointer unused)
{
	mock_service_stop ();
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	egg_test_wait_idle ();

	g_object_unref (test->service);
	egg_assert_not_object (test->service);

	teardown_mock (test, unused);
}

static void
on_complete_get_result (GObject *source,
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
test_search_paths_sync (Test *test,
                        gconstpointer used)
{
	GHashTable *attributes;
	gboolean ret;
	gchar **locked;
	gchar **unlocked;
	GError *error = NULL;

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "number", "1");

	ret = gsecret_service_search_for_paths_sync (test->service, attributes, NULL,
	                                             &unlocked, &locked, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (locked);
	g_assert_cmpstr (locked[0], ==, "/org/freedesktop/secrets/collection/spanish/10");

	g_assert (unlocked);
	g_assert_cmpstr (unlocked[0], ==, "/org/freedesktop/secrets/collection/english/1");

	g_strfreev (unlocked);
	g_strfreev (locked);

	g_hash_table_unref (attributes);
}

static void
test_search_paths_async (Test *test,
                         gconstpointer used)
{
	GAsyncResult *result = NULL;
	GHashTable *attributes;
	gboolean ret;
	gchar **locked;
	gchar **unlocked;
	GError *error = NULL;

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "number", "1");

	gsecret_service_search_for_paths (test->service, attributes, NULL,
	                                  on_complete_get_result, &result);
	egg_test_wait ();

	g_assert (G_IS_ASYNC_RESULT (result));
	ret = gsecret_service_search_for_paths_finish (test->service, result,
	                                               &unlocked, &locked,
	                                               &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (locked);
	g_assert_cmpstr (locked[0], ==, "/org/freedesktop/secrets/collection/spanish/10");

	g_assert (unlocked);
	g_assert_cmpstr (unlocked[0], ==, "/org/freedesktop/secrets/collection/english/1");

	g_strfreev (unlocked);
	g_strfreev (locked);
	g_object_unref (result);

	g_hash_table_unref (attributes);
}

static void
test_search_paths_nulls (Test *test,
                         gconstpointer used)
{
	GAsyncResult *result = NULL;
	GHashTable *attributes;
	gboolean ret;
	gchar **paths;
	GError *error = NULL;

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "number", "1");

	ret = gsecret_service_search_for_paths_sync (test->service, attributes, NULL,
	                                             &paths, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_assert (paths != NULL);
	g_assert_cmpstr (paths[0], ==, "/org/freedesktop/secrets/collection/english/1");
	g_strfreev (paths);

	ret = gsecret_service_search_for_paths_sync (test->service, attributes, NULL,
	                                             NULL, &paths, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_assert (paths != NULL);
	g_assert_cmpstr (paths[0], ==, "/org/freedesktop/secrets/collection/spanish/10");
	g_strfreev (paths);

	ret = gsecret_service_search_for_paths_sync (test->service, attributes, NULL,
	                                             NULL, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	gsecret_service_search_for_paths (test->service, attributes, NULL,
	                                  on_complete_get_result, &result);
	egg_test_wait ();
	g_assert (G_IS_ASYNC_RESULT (result));
	ret = gsecret_service_search_for_paths_finish (test->service, result,
	                                               &paths, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_assert (paths != NULL);
	g_assert_cmpstr (paths[0], ==, "/org/freedesktop/secrets/collection/english/1");
	g_strfreev (paths);
	g_clear_object (&result);

	gsecret_service_search_for_paths (test->service, attributes, NULL,
	                                  on_complete_get_result, &result);
	egg_test_wait ();
	g_assert (G_IS_ASYNC_RESULT (result));
	ret = gsecret_service_search_for_paths_finish (test->service, result,
	                                               NULL, &paths, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_assert (paths != NULL);
	g_assert_cmpstr (paths[0], ==, "/org/freedesktop/secrets/collection/spanish/10");
	g_strfreev (paths);
	g_clear_object (&result);

	gsecret_service_search_for_paths (test->service, attributes, NULL,
	                                  on_complete_get_result, &result);
	egg_test_wait ();
	g_assert (G_IS_ASYNC_RESULT (result));
	ret = gsecret_service_search_for_paths_finish (test->service, result,
	                                               NULL, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_clear_object (&result);

	g_hash_table_unref (attributes);
}

static void
test_search_sync (Test *test,
                  gconstpointer used)
{
	GHashTable *attributes;
	gboolean ret;
	GList *locked;
	GList *unlocked;
	GError *error = NULL;

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "number", "1");

	ret = gsecret_service_search_sync (test->service, attributes, NULL,
	                                   &unlocked, &locked, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (locked != NULL);
	g_assert_cmpstr (g_dbus_proxy_get_object_path (locked->data), ==, "/org/freedesktop/secrets/collection/spanish/10");

	g_assert (unlocked != NULL);
	g_assert_cmpstr (g_dbus_proxy_get_object_path (unlocked->data), ==, "/org/freedesktop/secrets/collection/english/1");

	g_list_free_full (unlocked, g_object_unref);
	g_list_free_full (locked, g_object_unref);

	g_hash_table_unref (attributes);
}

static void
test_search_async (Test *test,
                   gconstpointer used)
{
	GAsyncResult *result = NULL;
	GHashTable *attributes;
	gboolean ret;
	GList *locked;
	GList *unlocked;
	GError *error = NULL;

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "number", "1");

	gsecret_service_search (test->service, attributes, NULL,
	                        on_complete_get_result, &result);
	egg_test_wait ();

	g_assert (G_IS_ASYNC_RESULT (result));
	ret = gsecret_service_search_finish (test->service, result,
	                                     &unlocked, &locked,
	                                     &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (locked != NULL);
	g_assert_cmpstr (g_dbus_proxy_get_object_path (locked->data), ==, "/org/freedesktop/secrets/collection/spanish/10");

	g_assert (unlocked != NULL);
	g_assert_cmpstr (g_dbus_proxy_get_object_path (unlocked->data), ==, "/org/freedesktop/secrets/collection/english/1");

	g_list_free_full (unlocked, g_object_unref);
	g_list_free_full (locked, g_object_unref);
	g_object_unref (result);

	g_hash_table_unref (attributes);
}

static void
test_search_nulls (Test *test,
                   gconstpointer used)
{
	GAsyncResult *result = NULL;
	GHashTable *attributes;
	gboolean ret;
	GList *items;
	GError *error = NULL;

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "number", "1");

	ret = gsecret_service_search_sync (test->service, attributes, NULL,
	                                   &items, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_assert (items != NULL);
	g_assert_cmpstr (g_dbus_proxy_get_object_path (items->data), ==, "/org/freedesktop/secrets/collection/english/1");
	g_list_free_full (items, g_object_unref);

	ret = gsecret_service_search_sync (test->service, attributes, NULL,
	                                   NULL, &items, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_assert (items != NULL);
	g_assert_cmpstr (g_dbus_proxy_get_object_path (items->data), ==, "/org/freedesktop/secrets/collection/spanish/10");
	g_list_free_full (items, g_object_unref);

	ret = gsecret_service_search_sync (test->service, attributes, NULL,
	                                   NULL, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	gsecret_service_search (test->service, attributes, NULL,
	                        on_complete_get_result, &result);
	egg_test_wait ();
	g_assert (G_IS_ASYNC_RESULT (result));
	ret = gsecret_service_search_finish (test->service, result,
	                                     &items, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_assert (items != NULL);
	g_assert_cmpstr (g_dbus_proxy_get_object_path (items->data), ==, "/org/freedesktop/secrets/collection/english/1");
	g_list_free_full (items, g_object_unref);
	g_clear_object (&result);

	gsecret_service_search (test->service, attributes, NULL,
	                        on_complete_get_result, &result);
	egg_test_wait ();
	g_assert (G_IS_ASYNC_RESULT (result));
	ret = gsecret_service_search_finish (test->service, result,
	                                     NULL, &items, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_assert (items != NULL);
	g_assert_cmpstr (g_dbus_proxy_get_object_path (items->data), ==, "/org/freedesktop/secrets/collection/spanish/10");
	g_list_free_full (items, g_object_unref);
	g_clear_object (&result);

	gsecret_service_search (test->service, attributes, NULL,
	                        on_complete_get_result, &result);
	egg_test_wait ();
	g_assert (G_IS_ASYNC_RESULT (result));
	ret = gsecret_service_search_finish (test->service, result,
	                                     NULL, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_clear_object (&result);

	g_hash_table_unref (attributes);
}

static void
test_secret_for_path_sync (Test *test,
                           gconstpointer used)
{
	GSecretValue *value;
	GError *error = NULL;
	const gchar *path;
	const gchar *password;
	gsize length;

	path = "/org/freedesktop/secrets/collection/english/1";
	value = gsecret_service_get_secret_for_path_sync (test->service, path, NULL, &error);
	g_assert_no_error (error);
	g_assert (value != NULL);

	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "111");

	password = gsecret_value_get (value, NULL);
	g_assert_cmpstr (password, ==, "111");

	gsecret_value_unref (value);
}

static void
test_secret_for_path_async (Test *test,
                            gconstpointer used)
{
	GSecretValue *value;
	GError *error = NULL;
	const gchar *path;
	const gchar *password;
	GAsyncResult *result = NULL;
	gsize length;

	path = "/org/freedesktop/secrets/collection/english/1";
	gsecret_service_get_secret_for_path (test->service, path, NULL,
	                                     on_complete_get_result, &result);
	g_assert (result == NULL);
	egg_test_wait ();

	value = gsecret_service_get_secret_for_path_finish (test->service, result, &error);
	g_assert_no_error (error);
	g_assert (value != NULL);
	g_object_unref (result);

	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "111");

	password = gsecret_value_get (value, NULL);
	g_assert_cmpstr (password, ==, "111");

	gsecret_value_unref (value);
}

static void
test_secrets_for_paths_sync (Test *test,
                             gconstpointer used)
{
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/english/1";
	const gchar *path_item_two = "/org/freedesktop/secrets/collection/english/2";
	const gchar *paths[] = {
		path_item_one,
		path_item_two,

		/* This one is locked, and not returned */
		"/org/freedesktop/secrets/collection/spanish/10",
		NULL
	};

	GSecretValue *value;
	GHashTable *values;
	GError *error = NULL;
	const gchar *password;
	gsize length;

	values = gsecret_service_get_secrets_for_paths_sync (test->service, paths, NULL, &error);
	g_assert_no_error (error);

	g_assert (values != NULL);
	g_assert_cmpuint (g_hash_table_size (values), ==, 2);

	value = g_hash_table_lookup (values, path_item_one);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "111");

	value = g_hash_table_lookup (values, path_item_two);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "222");

	g_hash_table_unref (values);
}

static void
test_secrets_for_paths_async (Test *test,
                              gconstpointer used)
{
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/english/1";
	const gchar *path_item_two = "/org/freedesktop/secrets/collection/english/2";
	const gchar *paths[] = {
		path_item_one,
		path_item_two,

		/* This one is locked, and not returned */
		"/org/freedesktop/secrets/collection/spanish/10",
		NULL
	};

	GSecretValue *value;
	GHashTable *values;
	GError *error = NULL;
	const gchar *password;
	GAsyncResult *result = NULL;
	gsize length;

	gsecret_service_get_secrets_for_paths (test->service, paths, NULL,
	                                       on_complete_get_result, &result);
	g_assert (result == NULL);
	egg_test_wait ();

	values = gsecret_service_get_secrets_for_paths_finish (test->service, result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	g_assert (values != NULL);
	g_assert_cmpuint (g_hash_table_size (values), ==, 2);

	value = g_hash_table_lookup (values, path_item_one);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "111");

	value = g_hash_table_lookup (values, path_item_two);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "222");

	g_hash_table_unref (values);
}

static void
test_secrets_sync (Test *test,
                   gconstpointer used)
{
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/english/1";
	const gchar *path_item_two = "/org/freedesktop/secrets/collection/english/2";
	const gchar *path_item_three = "/org/freedesktop/secrets/collection/spanish/10";

	GSecretValue *value;
	GHashTable *values;
	GError *error = NULL;
	const gchar *password;
	GSecretItem *item_one, *item_two, *item_three;
	GList *items = NULL;
	gsize length;

	item_one = gsecret_item_new_sync (test->service, path_item_one, NULL, &error);
	item_two = gsecret_item_new_sync (test->service, path_item_two, NULL, &error);
	item_three = gsecret_item_new_sync (test->service, path_item_three, NULL, &error);

	items = g_list_append (items, item_one);
	items = g_list_append (items, item_two);
	items = g_list_append (items, item_three);

	values = gsecret_service_get_secrets_sync (test->service, items, NULL, &error);
	g_list_free_full (items, g_object_unref);
	g_assert_no_error (error);

	g_assert (values != NULL);
	g_assert_cmpuint (g_hash_table_size (values), ==, 2);

	value = g_hash_table_lookup (values, item_one);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "111");

	value = g_hash_table_lookup (values, item_two);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "222");

	g_hash_table_unref (values);
}

static void
test_secrets_async (Test *test,
                              gconstpointer used)
{
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/english/1";
	const gchar *path_item_two = "/org/freedesktop/secrets/collection/english/2";
	const gchar *path_item_three = "/org/freedesktop/secrets/collection/spanish/10";

	GSecretValue *value;
	GHashTable *values;
	GError *error = NULL;
	const gchar *password;
	GAsyncResult *result = NULL;
	GSecretItem *item_one, *item_two, *item_three;
	GList *items = NULL;
	gsize length;

	item_one = gsecret_item_new_sync (test->service, path_item_one, NULL, &error);
	g_assert_no_error (error);

	item_two = gsecret_item_new_sync (test->service, path_item_two, NULL, &error);
	g_assert_no_error (error);

	item_three = gsecret_item_new_sync (test->service, path_item_three, NULL, &error);
	g_assert_no_error (error);


	items = g_list_append (items, item_one);
	items = g_list_append (items, item_two);
	items = g_list_append (items, item_three);

	gsecret_service_get_secrets (test->service, items, NULL,
	                             on_complete_get_result, &result);
	g_assert (result == NULL);
	g_list_free (items);

	egg_test_wait ();

	values = gsecret_service_get_secrets_finish (test->service, result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	g_assert (values != NULL);
	g_assert_cmpuint (g_hash_table_size (values), ==, 2);

	value = g_hash_table_lookup (values, item_one);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "111");

	value = g_hash_table_lookup (values, item_two);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "222");

	g_hash_table_unref (values);

	g_object_unref (item_one);
	g_object_unref (item_two);
	g_object_unref (item_three);
}

static void
test_delete_for_path_sync (Test *test,
                           gconstpointer used)

{
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/todelete/item";
	GError *error = NULL;
	gboolean ret;

	ret = gsecret_service_delete_path_sync (test->service, path_item_one, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
}

static void
test_delete_for_path_sync_prompt (Test *test,
                                  gconstpointer used)

{
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/todelete/confirm";
	GError *error = NULL;
	gboolean ret;

	ret = gsecret_service_delete_path_sync (test->service, path_item_one, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
}

static void
test_lock_paths_sync (Test *test,
                      gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/lockone";
	const gchar *paths[] = {
		collection_path,
		NULL,
	};

	GError *error = NULL;
	gchar **locked = NULL;
	gboolean ret;

	ret = gsecret_service_lock_paths_sync (test->service, paths, NULL, &locked, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (locked != NULL);
	g_assert_cmpstr (locked[0], ==, collection_path);
	g_assert (locked[1] == NULL);
	g_strfreev (locked);
}

static void
test_lock_prompt_sync (Test *test,
                       gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/lockprompt";
	const gchar *paths[] = {
		collection_path,
		NULL,
	};

	GError *error = NULL;
	gchar **locked = NULL;
	gboolean ret;

	ret = gsecret_service_lock_paths_sync (test->service, paths, NULL, &locked, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (locked != NULL);
	g_assert_cmpstr (locked[0], ==, collection_path);
	g_assert (locked[1] == NULL);
	g_strfreev (locked);
}

static void
test_lock_sync (Test *test,
                gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/lockone";
	GSecretCollection *collection;
	GError *error = NULL;
	GList *locked;
	GList *objects;
	gboolean ret;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	objects = g_list_append (NULL, collection);

	ret = gsecret_service_lock_sync (test->service, objects, NULL, &locked, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (locked != NULL);
	g_assert (locked->data == collection);
	g_assert (locked->next == NULL);
	g_list_free_full (locked, g_object_unref);

	g_list_free (objects);
	g_object_unref (collection);
}

static void
test_unlock_paths_sync (Test *test,
                        gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/lockone";
	const gchar *paths[] = {
		collection_path,
		NULL,
	};

	GError *error = NULL;
	gchar **unlocked = NULL;
	gboolean ret;

	ret = gsecret_service_unlock_paths_sync (test->service, paths, NULL, &unlocked, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (unlocked != NULL);
	g_assert_cmpstr (unlocked[0], ==, collection_path);
	g_assert (unlocked[1] == NULL);
	g_strfreev (unlocked);
}

static void
test_unlock_prompt_sync (Test *test,
                         gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/lockprompt";
	const gchar *paths[] = {
		collection_path,
		NULL,
	};

	GError *error = NULL;
	gchar **unlocked = NULL;
	gboolean ret;

	ret = gsecret_service_unlock_paths_sync (test->service, paths, NULL, &unlocked, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (unlocked != NULL);
	g_assert_cmpstr (unlocked[0], ==, collection_path);
	g_assert (unlocked[1] == NULL);
	g_strfreev (unlocked);
}

static void
test_unlock_sync (Test *test,
                  gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/lockone";
	GSecretCollection *collection;
	GError *error = NULL;
	GList *unlocked;
	GList *objects;
	gboolean ret;

	collection = gsecret_collection_new_sync (test->service, collection_path, NULL, &error);
	g_assert_no_error (error);

	objects = g_list_append (NULL, collection);

	ret = gsecret_service_unlock_sync (test->service, objects, NULL, &unlocked, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_assert (unlocked != NULL);
	g_assert (unlocked->data == collection);
	g_assert (unlocked->next == NULL);
	g_list_free_full (unlocked, g_object_unref);

	g_list_free (objects);
	g_object_unref (collection);
}

static void
test_collection_sync (Test *test,
                      gconstpointer used)
{
	GHashTable *properties;
	GError *error = NULL;
	gchar *path;

	properties = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
	                                    (GDestroyNotify)g_variant_unref);
	g_hash_table_insert (properties, GSECRET_COLLECTION_INTERFACE ".Label",
	                     g_variant_ref_sink (g_variant_new_string ("Wheeee")));

	path = gsecret_service_create_collection_path_sync (test->service, properties,
	                                                   NULL, NULL, &error);

	g_hash_table_unref (properties);

	g_assert_no_error (error);
	g_assert (path != NULL);
	g_assert (g_str_has_prefix (path, "/org/freedesktop/secrets/collection/"));

	g_free (path);
}

static void
test_collection_async (Test *test,
                       gconstpointer used)
{
	GAsyncResult *result = NULL;
	GHashTable *properties;
	GError *error = NULL;
	gchar *path;

	properties = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
	                                    (GDestroyNotify)g_variant_unref);
	g_hash_table_insert (properties, GSECRET_COLLECTION_INTERFACE ".Label",
	                     g_variant_ref_sink (g_variant_new_string ("Wheeee")));

	gsecret_service_create_collection_path (test->service, properties,
	                                        NULL, NULL, on_complete_get_result, &result);

	g_hash_table_unref (properties);
	g_assert (result == NULL);

	egg_test_wait ();

	path = gsecret_service_create_collection_path_finish (test->service, result, &error);
	g_object_unref (result);

	g_assert_no_error (error);
	g_assert (path != NULL);
	g_assert (g_str_has_prefix (path, "/org/freedesktop/secrets/collection/"));

	g_free (path);
}

static void
test_item_sync (Test *test,
                gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GHashTable *properties;
	GHashTable *attributes;
	GSecretValue *value;
	GError *error = NULL;
	gchar *path;

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "even", "true");
	g_hash_table_insert (attributes, "string", "ten");
	g_hash_table_insert (attributes, "number", "10");

	properties = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
	                                    (GDestroyNotify)g_variant_unref);
	g_hash_table_insert (properties, GSECRET_COLLECTION_INTERFACE ".Label",
	                     g_variant_ref_sink (g_variant_new_string ("Wheeee")));
	g_hash_table_insert (properties, GSECRET_COLLECTION_INTERFACE ".Attributes",
	                     g_variant_ref_sink (_gsecret_util_variant_for_attributes (attributes)));
	g_hash_table_insert (properties, GSECRET_COLLECTION_INTERFACE ".Type",
	                     g_variant_ref_sink (g_variant_new_string ("org.gnome.Test")));

	g_hash_table_unref (attributes);

	value = gsecret_value_new ("andmoreandmore", -1, "text/plain");

	path = gsecret_service_create_item_path_sync (test->service, collection_path,
	                                              properties, value, FALSE,
	                                              NULL, &error);

	gsecret_value_unref (value);
	g_hash_table_unref (properties);

	g_assert_no_error (error);
	g_assert (path != NULL);
	g_assert (g_str_has_prefix (path, collection_path));

	g_free (path);
}

static void
test_item_async (Test *test,
                       gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GHashTable *properties;
	GHashTable *attributes;
	GSecretValue *value;
	GError *error = NULL;
	GAsyncResult *result = NULL;
	gchar *path;

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "even", "true");
	g_hash_table_insert (attributes, "string", "ten");
	g_hash_table_insert (attributes, "number", "10");

	properties = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
	                                    (GDestroyNotify)g_variant_unref);
	g_hash_table_insert (properties, GSECRET_COLLECTION_INTERFACE ".Label",
	                     g_variant_ref_sink (g_variant_new_string ("Wheeee")));
	g_hash_table_insert (properties, GSECRET_COLLECTION_INTERFACE ".Attributes",
	                     g_variant_ref_sink (_gsecret_util_variant_for_attributes (attributes)));
	g_hash_table_insert (properties, GSECRET_COLLECTION_INTERFACE ".Type",
	                     g_variant_ref_sink (g_variant_new_string ("org.gnome.Test")));

	g_hash_table_unref (attributes);

	value = gsecret_value_new ("andmoreandmore", -1, "text/plain");

	gsecret_service_create_item_path (test->service, collection_path,
	                                  properties, value, FALSE,
	                                  NULL, on_complete_get_result, &result);

	g_assert (result == NULL);
	gsecret_value_unref (value);
	g_hash_table_unref (properties);

	egg_test_wait ();

	path = gsecret_service_create_item_path_finish (test->service, result, &error);
	g_object_unref (result);

	g_assert_no_error (error);
	g_assert (path != NULL);
	g_assert (g_str_has_prefix (path, collection_path));

	g_free (path);
}

static void
test_remove_sync (Test *test,
                  gconstpointer used)
{
	GError *error = NULL;
	gboolean ret;

	ret = gsecret_service_remove_sync (test->service, &DELETE_SCHEMA, NULL, &error,
	                                   "even", FALSE,
	                                   "string", "one",
	                                   "number", 1,
	                                   NULL);

	g_assert_no_error (error);
	g_assert (ret == TRUE);
}

static void
test_remove_async (Test *test,
                   gconstpointer used)
{
	GError *error = NULL;
	GAsyncResult *result = NULL;
	gboolean ret;

	gsecret_service_remove (test->service, &DELETE_SCHEMA, NULL,
	                        on_complete_get_result, &result,
	                        "even", FALSE,
	                        "string", "one",
	                        "number", 1,
	                        NULL);

	g_assert (result == NULL);

	egg_test_wait ();

	ret = gsecret_service_remove_finish (test->service, result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_object_unref (result);
}

static void
test_remove_locked (Test *test,
                    gconstpointer used)
{
	GError *error = NULL;
	gboolean ret;

	ret = gsecret_service_remove_sync (test->service, &DELETE_SCHEMA, NULL, &error,
	                                   "even", FALSE,
	                                   "string", "tres",
	                                   "number", 3,
	                                   NULL);

	g_assert_no_error (error);
	g_assert (ret == TRUE);
}

static void
test_remove_no_match (Test *test,
                      gconstpointer used)
{
	GError *error = NULL;
	gboolean ret;

	/* Won't match anything */
	ret = gsecret_service_remove_sync (test->service, &DELETE_SCHEMA, NULL, &error,
	                                   "even", TRUE,
	                                   "string", "one",
	                                   NULL);

	g_assert_no_error (error);
	g_assert (ret == FALSE);
}

static void
test_lookup_sync (Test *test,
                  gconstpointer used)
{
	GError *error = NULL;
	GSecretValue *value;
	gsize length;

	value = gsecret_service_lookup_sync (test->service, &STORE_SCHEMA, NULL, &error,
	                                     "even", FALSE,
	                                     "string", "one",
	                                     "number", 1,
	                                     NULL);

	g_assert_no_error (error);

	g_assert (value != NULL);
	g_assert_cmpstr (gsecret_value_get (value, &length), ==, "111");
	g_assert_cmpuint (length, ==, 3);

	gsecret_value_unref (value);
}

static void
test_lookup_async (Test *test,
                   gconstpointer used)
{
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GSecretValue *value;
	gsize length;

	gsecret_service_lookup (test->service, &STORE_SCHEMA, NULL,
	                        on_complete_get_result, &result,
	                        "even", FALSE,
	                        "string", "one",
	                        "number", 1,
	                        NULL);

	g_assert (result == NULL);

	egg_test_wait ();

	value = gsecret_service_lookup_finish (test->service, result, &error);
	g_assert_no_error (error);

	g_assert (value != NULL);
	g_assert_cmpstr (gsecret_value_get (value, &length), ==, "111");
	g_assert_cmpuint (length, ==, 3);

	gsecret_value_unref (value);
	g_object_unref (result);
}

static void
test_lookup_locked (Test *test,
                    gconstpointer used)
{
	GError *error = NULL;
	GSecretValue *value;
	gsize length;

	value = gsecret_service_lookup_sync (test->service, &STORE_SCHEMA, NULL, &error,
	                                     "even", FALSE,
	                                     "string", "tres",
	                                     "number", 3,
	                                     NULL);

	g_assert_no_error (error);

	g_assert (value != NULL);
	g_assert_cmpstr (gsecret_value_get (value, &length), ==, "3333");
	g_assert_cmpuint (length, ==, 4);

	gsecret_value_unref (value);
}

static void
test_lookup_no_match (Test *test,
                      gconstpointer used)
{
	GError *error = NULL;
	GSecretValue *value;

	/* Won't match anything */
	value = gsecret_service_lookup_sync (test->service, &STORE_SCHEMA, NULL, &error,
	                                     "even", TRUE,
	                                     "string", "one",
	                                     NULL);

	g_assert_no_error (error);
	g_assert (value == NULL);
}

static void
test_store_sync (Test *test,
                 gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GSecretValue *value = gsecret_value_new ("apassword", -1, "text/plain");
	GHashTable *attributes;
	GError *error = NULL;
	gchar **paths;
	gboolean ret;
	gsize length;

	ret = gsecret_service_store_sync (test->service, &STORE_SCHEMA, collection_path,
	                                  "New Item Label", value, NULL, &error,
	                                  "even", FALSE,
	                                  "string", "seventeen",
	                                  "number", 17,
	                                  NULL);
	g_assert_no_error (error);
	gsecret_value_unref (value);

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "even", "false");
	g_hash_table_insert (attributes, "string", "seventeen");
	g_hash_table_insert (attributes, "number", "17");

	ret = gsecret_service_search_for_paths_sync (test->service, attributes, NULL,
	                                             &paths, NULL, &error);
	g_hash_table_unref (attributes);
	g_assert (ret == TRUE);

	g_assert (paths != NULL);
	g_assert (paths[0] != NULL);
	g_assert (paths[1] == NULL);

	value = gsecret_service_get_secret_for_path_sync (test->service, paths[0],
	                                                  NULL, &error);
	g_assert_no_error (error);

	g_assert (value != NULL);
	g_assert_cmpstr (gsecret_value_get (value, &length), ==, "apassword");
	g_assert_cmpuint (length, ==, 9);

	gsecret_value_unref (value);
	g_strfreev (paths);
}

static void
test_store_replace (Test *test,
                    gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GSecretValue *value = gsecret_value_new ("apassword", -1, "text/plain");
	GHashTable *attributes;
	GError *error = NULL;
	gchar **paths;
	gboolean ret;

	ret = gsecret_service_store_sync (test->service, &STORE_SCHEMA, collection_path,
	                                  "New Item Label", value, NULL, &error,
	                                  "even", FALSE,
	                                  "string", "seventeen",
	                                  "number", 17,
	                                  NULL);
	g_assert_no_error (error);

	ret = gsecret_service_store_sync (test->service, &STORE_SCHEMA, collection_path,
	                                  "Another Label", value, NULL, &error,
	                                  "even", FALSE,
	                                  "string", "seventeen",
	                                  "number", 17,
	                                  NULL);
	g_assert_no_error (error);
	gsecret_value_unref (value);

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "even", "false");
	g_hash_table_insert (attributes, "string", "seventeen");
	g_hash_table_insert (attributes, "number", "17");

	ret = gsecret_service_search_for_paths_sync (test->service, attributes, NULL,
	                                             &paths, NULL, &error);
	g_hash_table_unref (attributes);
	g_assert (ret == TRUE);

	g_assert (paths != NULL);
	g_assert (paths[0] != NULL);
	g_assert (paths[1] == NULL);

	g_strfreev (paths);
}

static void
test_store_async (Test *test,
                  gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GSecretValue *value = gsecret_value_new ("apassword", -1, "text/plain");
	GAsyncResult *result = NULL;
	GHashTable *attributes;
	GError *error = NULL;
	gchar **paths;
	gboolean ret;
	gsize length;

	gsecret_service_store (test->service, &STORE_SCHEMA, collection_path,
	                       "New Item Label", value, NULL, on_complete_get_result, &result,
	                       "even", FALSE,
	                       "string", "seventeen",
	                       "number", 17,
	                       NULL);
	g_assert (result == NULL);
	gsecret_value_unref (value);

	egg_test_wait ();

	ret = gsecret_service_store_finish (test->service, result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "even", "false");
	g_hash_table_insert (attributes, "string", "seventeen");
	g_hash_table_insert (attributes, "number", "17");

	ret = gsecret_service_search_for_paths_sync (test->service, attributes, NULL,
	                                             &paths, NULL, &error);
	g_hash_table_unref (attributes);
	g_assert (ret == TRUE);

	g_assert (paths != NULL);
	g_assert (paths[0] != NULL);
	g_assert (paths[1] == NULL);

	value = gsecret_service_get_secret_for_path_sync (test->service, paths[0],
	                                                  NULL, &error);
	g_assert_no_error (error);

	g_assert (value != NULL);
	g_assert_cmpstr (gsecret_value_get (value, &length), ==, "apassword");
	g_assert_cmpuint (length, ==, 9);

	gsecret_value_unref (value);
	g_strfreev (paths);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-service");
	g_type_init ();

	g_test_add ("/service/search-for-paths", Test, "mock-service-normal.py", setup, test_search_paths_sync, teardown);
	g_test_add ("/service/search-for-paths-async", Test, "mock-service-normal.py", setup, test_search_paths_async, teardown);
	g_test_add ("/service/search-for-paths-nulls", Test, "mock-service-normal.py", setup, test_search_paths_nulls, teardown);
	g_test_add ("/service/search-sync", Test, "mock-service-normal.py", setup, test_search_sync, teardown);
	g_test_add ("/service/search-async", Test, "mock-service-normal.py", setup, test_search_async, teardown);
	g_test_add ("/service/search-nulls", Test, "mock-service-normal.py", setup, test_search_nulls, teardown);

	g_test_add ("/service/secret-for-path-sync", Test, "mock-service-normal.py", setup, test_secret_for_path_sync, teardown);
	g_test_add ("/service/secret-for-path-plain", Test, "mock-service-only-plain.py", setup, test_secret_for_path_sync, teardown);
	g_test_add ("/service/secret-for-path-async", Test, "mock-service-normal.py", setup, test_secret_for_path_async, teardown);
	g_test_add ("/service/secrets-for-paths-sync", Test, "mock-service-normal.py", setup, test_secrets_for_paths_sync, teardown);
	g_test_add ("/service/secrets-for-paths-async", Test, "mock-service-normal.py", setup, test_secrets_for_paths_async, teardown);
	g_test_add ("/service/secrets-sync", Test, "mock-service-normal.py", setup, test_secrets_sync, teardown);
	g_test_add ("/service/secrets-async", Test, "mock-service-normal.py", setup, test_secrets_async, teardown);

	g_test_add ("/service/delete-for-path", Test, "mock-service-delete.py", setup, test_delete_for_path_sync, teardown);
	g_test_add ("/service/delete-for-path-with-prompt", Test, "mock-service-delete.py", setup, test_delete_for_path_sync_prompt, teardown);

	g_test_add ("/service/lock-paths-sync", Test, "mock-service-lock.py", setup, test_lock_paths_sync, teardown);
	g_test_add ("/service/lock-prompt-sync", Test, "mock-service-lock.py", setup, test_lock_prompt_sync, teardown);
	g_test_add ("/service/lock-sync", Test, "mock-service-lock.py", setup, test_lock_sync, teardown);

	g_test_add ("/service/unlock-paths-sync", Test, "mock-service-lock.py", setup, test_unlock_paths_sync, teardown);
	g_test_add ("/service/unlock-prompt-sync", Test, "mock-service-lock.py", setup, test_unlock_prompt_sync, teardown);
	g_test_add ("/service/unlock-sync", Test, "mock-service-lock.py", setup, test_unlock_sync, teardown);

	g_test_add ("/service/create-collection-sync", Test, "mock-service-normal.py", setup, test_collection_sync, teardown);
	g_test_add ("/service/create-collection-async", Test, "mock-service-normal.py", setup, test_collection_async, teardown);

	g_test_add ("/service/create-item-sync", Test, "mock-service-normal.py", setup, test_item_sync, teardown);
	g_test_add ("/service/create-item-async", Test, "mock-service-normal.py", setup, test_item_async, teardown);

	g_test_add ("/service/lookup-sync", Test, "mock-service-normal.py", setup, test_lookup_sync, teardown);
	g_test_add ("/service/lookup-async", Test, "mock-service-normal.py", setup, test_lookup_async, teardown);
	g_test_add ("/service/lookup-locked", Test, "mock-service-normal.py", setup, test_lookup_locked, teardown);
	g_test_add ("/service/lookup-no-match", Test, "mock-service-normal.py", setup, test_lookup_no_match, teardown);

	g_test_add ("/service/remove-sync", Test, "mock-service-delete.py", setup, test_remove_sync, teardown);
	g_test_add ("/service/remove-async", Test, "mock-service-delete.py", setup, test_remove_async, teardown);
	g_test_add ("/service/remove-locked", Test, "mock-service-delete.py", setup, test_remove_locked, teardown);
	g_test_add ("/service/remove-no-match", Test, "mock-service-delete.py", setup, test_remove_no_match, teardown);

	g_test_add ("/service/store-sync", Test, "mock-service-normal.py", setup, test_store_sync, teardown);
	g_test_add ("/service/store-async", Test, "mock-service-normal.py", setup, test_store_async, teardown);
	g_test_add ("/service/store-replace", Test, "mock-service-normal.py", setup, test_store_replace, teardown);

	return egg_tests_run_with_loop ();
}
