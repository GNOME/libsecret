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

#include "gsecret-item.h"
#include "gsecret-service.h"
#include "gsecret-private.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>
#include <stdlib.h>

static gchar *MOCK_NAME = "org.mock.Service";

typedef struct {
	GPid pid;
	GDBusConnection *connection;
	GSecretService *service;
} Test;

static void
setup (Test *test,
       gconstpointer data)
{
	GError *error = NULL;
	const gchar *mock_script = data;
	gchar *argv[] = {
		"python", (gchar *)mock_script,
		"--name", MOCK_NAME,
		NULL
	};

	g_spawn_async (SRCDIR, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, &test->pid, &error);
	g_assert_no_error (error);
	g_usleep (100 * 1000);

	test->connection = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &error);
	g_assert_no_error (error);

	test->service = _gsecret_service_bare_instance (test->connection, MOCK_NAME);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	g_clear_object (&test->service);
	g_clear_object (&test->connection);

	g_assert (test->pid);
	if (kill (test->pid, SIGTERM) < 0)
		g_error ("kill() failed: %s", g_strerror (errno));
	g_spawn_close_pid (test->pid);
}

static void
test_ensure (Test *test,
             gconstpointer unused)
{
	GError *error = NULL;
	const gchar *path;

	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, NULL);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, NULL);

	path = gsecret_service_ensure_session_sync (test->service, NULL, &error);
	g_assert_no_error (error);
	g_assert (path != NULL);
	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, path);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, "dh-ietf1024-sha256-aes128-cbc-pkcs7");
}

static void
test_ensure_twice (Test *test,
                   gconstpointer unused)
{
	GError *error = NULL;
	const gchar *path;

	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, NULL);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, NULL);

	path = gsecret_service_ensure_session_sync (test->service, NULL, &error);
	g_assert_no_error (error);
	g_assert (path != NULL);
	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, path);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, "dh-ietf1024-sha256-aes128-cbc-pkcs7");

	path = gsecret_service_ensure_session_sync (test->service, NULL, &error);
	g_assert_no_error (error);
	g_assert (path != NULL);
	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, path);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, "dh-ietf1024-sha256-aes128-cbc-pkcs7");
}

static void
test_ensure_plain (Test *test,
                   gconstpointer unused)
{
	GError *error = NULL;
	const gchar *path;

	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, NULL);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, NULL);

	path = gsecret_service_ensure_session_sync (test->service, NULL, &error);
	g_assert_no_error (error);

	g_assert (path != NULL);
	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, path);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, "plain");
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
}

static void
test_ensure_async (Test *test,
                   gconstpointer unused)
{
	GAsyncResult *result = NULL;
	GError *error = NULL;
	const gchar *path;

	gsecret_service_ensure_session (test->service, NULL, on_complete_get_result, &result);
	egg_test_wait_until (500);

	g_assert (G_IS_ASYNC_RESULT (result));
	path = gsecret_service_ensure_session_finish (test->service, result, &error);
	g_assert_no_error (error);

	g_assert (path != NULL);
	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, path);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, "plain");

	g_object_unref (result);
}

static void
test_ensure_async_twice (Test *test,
                         gconstpointer unused)
{
	GAsyncResult *result = NULL;
	GError *error = NULL;
	const gchar *path;

	gsecret_service_ensure_session (test->service, NULL, on_complete_get_result, &result);
	egg_test_wait_until (500);

	g_assert (G_IS_ASYNC_RESULT (result));
	path = gsecret_service_ensure_session_finish (test->service, result, &error);
	g_assert_no_error (error);

	g_assert (path != NULL);
	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, path);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, "plain");

	g_object_unref (result);
	result = NULL;

	gsecret_service_ensure_session (test->service, NULL, on_complete_get_result, &result);
	egg_test_wait_until (500);

	g_assert (G_IS_ASYNC_RESULT (result));
	path = gsecret_service_ensure_session_finish (test->service, result, &error);
	g_assert_no_error (error);

	g_assert (path != NULL);
	g_assert_cmpstr (gsecret_service_get_session_path (test->service), ==, path);
	g_assert_cmpstr (gsecret_service_get_session_algorithms (test->service), ==, "plain");

	g_object_unref (result);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-session");
	g_type_init ();

	g_test_add ("/session/ensure-aes", Test, "mock-service-normal.py", setup, test_ensure, teardown);
	g_test_add ("/session/ensure-twice", Test, "mock-service-normal.py", setup, test_ensure_twice, teardown);
	g_test_add ("/session/ensure-plain", Test, "mock-service-only-plain.py", setup, test_ensure_plain, teardown);
	g_test_add ("/session/ensure-async", Test, "mock-service-only-plain.py", setup, test_ensure_async, teardown);
	g_test_add ("/session/ensure-async-twice", Test, "mock-service-only-plain.py", setup, test_ensure_async_twice, teardown);

	return egg_tests_run_in_thread_with_loop ();
}
