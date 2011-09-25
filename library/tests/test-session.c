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
setup_normal (Test *test,
              gconstpointer unused)
{
	GError *error = NULL;
	gchar *argv[] = {
		"python", "./mock-service-normal.py",
		"--name", MOCK_NAME,
		NULL
	};

	g_spawn_async (SRCDIR, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, &test->pid, &error);
	g_assert_no_error (error);

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
test_ensure_sync (Test *test,
                  gconstpointer unused)
{
	GError *error = NULL;
	const gchar *path;

	path = gsecret_service_ensure_session_sync (test->service, NULL, &error);
	g_assert_no_error (error);
	g_assert (path != NULL);
	g_printerr ("%s", path);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-session");
	g_type_init ();

	g_test_add ("/session/ensure-sync", Test, NULL, setup_normal, test_ensure_sync, teardown);

	return g_test_run ();
}
