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
	g_usleep (200 * 1000);

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

	ret = gsecret_service_search_paths_sync (test->service, attributes, NULL,
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

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-service");
	g_type_init ();

	g_test_add ("/service/search-paths", Test, "mock-service-normal.py", setup, test_search_paths, teardown);

	return egg_tests_run_in_thread_with_loop ();
}
