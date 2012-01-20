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

#include "gsecret-service.h"
#include "gsecret-private.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>
#include <stdlib.h>

static gchar *MOCK_NAME = "org.mock.Service";

static const GSecretSchema DELETE_SCHEMA = {
	"org.mock.schema.Delete",
	{
		{ "number", GSECRET_ATTRIBUTE_INTEGER },
		{ "string", GSECRET_ATTRIBUTE_STRING },
		{ "even", GSECRET_ATTRIBUTE_BOOLEAN },
	}
};

typedef struct {
	GPid pid;
	GDBusConnection *connection;
	GSecretService *service;
} Test;

static void
setup_mock (Test *test,
            gconstpointer data)
{
	GError *error = NULL;
	const gchar *mock_script = data;
	gchar *argv[] = {
		"python", (gchar *)mock_script,
		"--name", MOCK_NAME,
		NULL
	};

	_gsecret_service_set_default_bus_name (MOCK_NAME);

	g_spawn_async (SRCDIR, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, &test->pid, &error);
	g_assert_no_error (error);
	g_usleep (200 * 1000);
}

static void
setup (Test *test,
       gconstpointer data)
{
	GError *error = NULL;

	setup_mock (test, data);

	test->connection = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
	g_assert_no_error (error);

	test->service = _gsecret_service_bare_instance (test->connection, NULL);
}

static void
teardown_mock (Test *test,
               gconstpointer unused)
{
	g_assert (test->pid);
	if (kill (test->pid, SIGTERM) < 0)
		g_error ("kill() failed: %s", g_strerror (errno));
	g_spawn_close_pid (test->pid);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	egg_test_wait_idle ();

	g_object_unref (test->service);
	egg_assert_not_object (test->service);

	g_clear_object (&test->connection);

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
test_instance (void)
{
	GSecretService *service1;
	GSecretService *service2;
	GSecretService *service3;
	GError *error = NULL;
	GDBusConnection *connection;

	connection = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
	g_assert_no_error (error);

	/* Both these sohuld point to the same thing */

	service1 = _gsecret_service_bare_instance (connection, MOCK_NAME);
	service2 = _gsecret_service_bare_instance (connection, MOCK_NAME);

	g_assert (GSECRET_IS_SERVICE (service1));
	g_assert (service1 == service2);

	g_object_unref (service1);
	g_assert (G_IS_OBJECT (service1));

	g_object_unref (service2);
	egg_assert_not_object (service2);

	/* Services were unreffed, so this should create a new one */
	service3 = _gsecret_service_bare_instance (connection, MOCK_NAME);
	g_assert (GSECRET_IS_SERVICE (service3));

	g_object_unref (service3);
	egg_assert_not_object (service3);

	g_object_unref (connection);
}

static void
test_connect_sync (Test *test,
                   gconstpointer used)
{
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GSecretService *service;
	const gchar *path;

	/* Passing false, not session */
	_gsecret_service_bare_connect (MOCK_NAME, FALSE, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	service = _gsecret_service_bare_connect_finish (result, &error);
	g_assert (GSECRET_IS_SERVICE (service));
	g_assert_no_error (error);
	g_object_unref (result);

	path = gsecret_service_get_session_path (service);
	g_assert (path == NULL);

	g_object_unref (service);
	egg_assert_not_object (service);
}

static void
test_connect_ensure_sync (Test *test,
                          gconstpointer used)
{
	GError *error = NULL;
	GAsyncResult *result = NULL;
	GSecretService *service;
	const gchar *path;

	/* Passing true, ensures session is established */
	_gsecret_service_bare_connect (MOCK_NAME, TRUE, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	service = _gsecret_service_bare_connect_finish (result, &error);
	g_assert_no_error (error);
	g_assert (GSECRET_IS_SERVICE (service));
	g_object_unref (result);

	path = gsecret_service_get_session_path (service);
	g_assert (path != NULL);

	g_object_unref (service);
	egg_assert_not_object (service);
}

static void
test_search_paths (Test *test,
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
	g_assert_cmpstr (locked[0], ==, "/org/freedesktop/secrets/collection/second/item_one");

	g_assert (unlocked);
	g_assert_cmpstr (unlocked[0], ==, "/org/freedesktop/secrets/collection/collection/item_one");

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
	g_assert_cmpstr (locked[0], ==, "/org/freedesktop/secrets/collection/second/item_one");

	g_assert (unlocked);
	g_assert_cmpstr (unlocked[0], ==, "/org/freedesktop/secrets/collection/collection/item_one");

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
	g_assert_cmpstr (paths[0], ==, "/org/freedesktop/secrets/collection/collection/item_one");
	g_strfreev (paths);

	ret = gsecret_service_search_for_paths_sync (test->service, attributes, NULL,
	                                             NULL, &paths, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_assert (paths != NULL);
	g_assert_cmpstr (paths[0], ==, "/org/freedesktop/secrets/collection/second/item_one");
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
	g_assert_cmpstr (paths[0], ==, "/org/freedesktop/secrets/collection/collection/item_one");
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
	g_assert_cmpstr (paths[0], ==, "/org/freedesktop/secrets/collection/second/item_one");
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
test_secret_for_path (Test *test,
                      gconstpointer used)
{
	GSecretValue *value;
	GError *error = NULL;
	const gchar *path;
	const gchar *password;
	gsize length;

	path = "/org/freedesktop/secrets/collection/collection/item_one";
	value = gsecret_service_get_secret_for_path_sync (test->service, path, NULL, &error);
	g_assert_no_error (error);
	g_assert (value != NULL);

	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "uno");

	password = gsecret_value_get (value, NULL);
	g_assert_cmpstr (password, ==, "uno");

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

	path = "/org/freedesktop/secrets/collection/collection/item_one";
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
	g_assert_cmpstr (password, ==, "uno");

	password = gsecret_value_get (value, NULL);
	g_assert_cmpstr (password, ==, "uno");

	gsecret_value_unref (value);
}

static void
test_secrets_for_paths (Test *test,
                        gconstpointer used)
{
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/collection/item_one";
	const gchar *path_item_two = "/org/freedesktop/secrets/collection/collection/item_two";
	const gchar *paths[] = {
		path_item_one,
		path_item_two,

		/* This one is locked, and not returned */
		"/org/freedesktop/secrets/collection/second/item_one",
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
	g_assert_cmpstr (password, ==, "uno");

	value = g_hash_table_lookup (values, path_item_two);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "dos");

	g_hash_table_unref (values);
}

static void
test_secrets_for_paths_async (Test *test,
                              gconstpointer used)
{
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/collection/item_one";
	const gchar *path_item_two = "/org/freedesktop/secrets/collection/collection/item_two";
	const gchar *paths[] = {
		path_item_one,
		path_item_two,

		/* This one is locked, and not returned */
		"/org/freedesktop/secrets/collection/second/item_one",
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
	g_assert_cmpstr (password, ==, "uno");

	value = g_hash_table_lookup (values, path_item_two);
	g_assert (value != NULL);
	password = gsecret_value_get (value, &length);
	g_assert_cmpuint (length, ==, 3);
	g_assert_cmpstr (password, ==, "dos");

	g_hash_table_unref (values);
}

static void
test_delete_for_path_sync (Test *test,
                           gconstpointer used)

{
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/to_delete/item";
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
	const gchar *path_item_one = "/org/freedesktop/secrets/collection/to_delete/confirm";
	GError *error = NULL;
	gboolean ret;

	ret = gsecret_service_delete_path_sync (test->service, path_item_one, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
}

static void
test_delete_password_sync (Test *test,
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
test_delete_password_async (Test *test,
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
test_delete_password_locked (Test *test,
                           gconstpointer used)
{
	GError *error = NULL;
	gboolean ret;

	ret = gsecret_service_remove_sync (test->service, &DELETE_SCHEMA, NULL, &error,
	                                   "even", FALSE,
	                                   "string", "three",
	                                   "number", 3,
	                                   NULL);

	g_assert_no_error (error);
	g_assert (ret == TRUE);
}

static void
test_delete_password_no_match (Test *test,
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

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-service");
	g_type_init ();

	g_test_add_func ("/service/instance", test_instance);

	g_test_add ("/service/connect-sync", Test, "mock-service-normal.py", setup_mock, test_connect_sync, teardown_mock);
	g_test_add ("/service/connect-ensure-sync", Test, "mock-service-normal.py", setup_mock, test_connect_ensure_sync, teardown_mock);

	g_test_add ("/service/search-for-paths", Test, "mock-service-normal.py", setup, test_search_paths, teardown);
	g_test_add ("/service/search-for-paths-async", Test, "mock-service-normal.py", setup, test_search_paths_async, teardown);
	g_test_add ("/service/search-for-paths-nulls", Test, "mock-service-normal.py", setup, test_search_paths_nulls, teardown);

	g_test_add ("/service/secret-for-path", Test, "mock-service-normal.py", setup, test_secret_for_path, teardown);
	g_test_add ("/service/secret-for-path-plain", Test, "mock-service-only-plain.py", setup, test_secret_for_path, teardown);
	g_test_add ("/service/secret-for-path-async", Test, "mock-service-normal.py", setup, test_secret_for_path_async, teardown);
	g_test_add ("/service/secrets-for-paths", Test, "mock-service-normal.py", setup, test_secrets_for_paths, teardown);
	g_test_add ("/service/secrets-for-paths-async", Test, "mock-service-normal.py", setup, test_secrets_for_paths_async, teardown);

	g_test_add ("/service/delete-for-path", Test, "mock-service-delete.py", setup, test_delete_for_path_sync, teardown);
	g_test_add ("/service/delete-for-path-with-prompt", Test, "mock-service-delete.py", setup, test_delete_for_path_sync_prompt, teardown);
	g_test_add ("/service/delete-password-sync", Test, "mock-service-delete.py", setup, test_delete_password_sync, teardown);
	g_test_add ("/service/delete-password-async", Test, "mock-service-delete.py", setup, test_delete_password_async, teardown);
	g_test_add ("/service/delete-password-locked", Test, "mock-service-delete.py", setup, test_delete_password_locked, teardown);
	g_test_add ("/service/delete-password-no-match", Test, "mock-service-delete.py", setup, test_delete_password_no_match, teardown);

	return egg_tests_run_with_loop ();
}
