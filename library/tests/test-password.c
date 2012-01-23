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

#include "gsecret-password.h"
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

typedef struct {
	GPid pid;
} Test;

static void
setup (Test *test,
       gconstpointer data)
{
	GError *error = NULL;
	const gchar *mock_script = data;

	mock_service_start (mock_script, &error);
	g_assert_no_error (error);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	mock_service_stop ();
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
test_delete_sync (Test *test,
                  gconstpointer used)
{
	GError *error = NULL;
	gboolean ret;

	ret = gsecret_password_remove_sync (&DELETE_SCHEMA, NULL, &error,
	                                    "even", FALSE,
	                                    "string", "one",
	                                    "number", 1,
	                                    NULL);

	g_assert_no_error (error);
	g_assert (ret == TRUE);
}

static void
test_delete_async (Test *test,
                   gconstpointer used)
{
	GError *error = NULL;
	GAsyncResult *result = NULL;
	gboolean ret;

	gsecret_password_remove (&DELETE_SCHEMA, NULL,
	                         on_complete_get_result, &result,
	                         "even", FALSE,
	                         "string", "one",
	                         "number", 1,
	                         NULL);

	g_assert (result == NULL);

	egg_test_wait ();

	ret = gsecret_password_remove_finish (result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_object_unref (result);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-password");
	g_type_init ();

	g_test_add ("/password/delete-sync", Test, "mock-service-delete.py", setup, test_delete_sync, teardown);
	g_test_add ("/password/delete-async", Test, "mock-service-delete.py", setup, test_delete_async, teardown);

	return egg_tests_run_with_loop ();
}
