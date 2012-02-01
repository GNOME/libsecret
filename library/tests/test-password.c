/* libsecret - GLib wrapper for Secret Service
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

#include "secret-password.h"
#include "secret-private.h"

#include "mock-service.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>
#include <stdlib.h>

static const SecretSchema PASSWORD_SCHEMA = {
	"org.mock.schema.Password",
	{
		{ "number", SECRET_ATTRIBUTE_INTEGER },
		{ "string", SECRET_ATTRIBUTE_STRING },
		{ "even", SECRET_ATTRIBUTE_BOOLEAN },
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
test_lookup_sync (Test *test,
                  gconstpointer used)
{
	gchar *password;
	GError *error = NULL;

	password = secret_password_lookup_sync (&PASSWORD_SCHEMA, NULL, &error,
	                                        "even", FALSE,
	                                        "string", "one",
	                                        "number", 1,
	                                        NULL);

	g_assert_no_error (error);
	g_assert_cmpstr (password, ==, "111");

	secret_password_free (password);
}

static void
test_lookup_async (Test *test,
                   gconstpointer used)
{
	GAsyncResult *result = NULL;
	GError *error = NULL;
	gchar *password;

	secret_password_lookup (&PASSWORD_SCHEMA, NULL, on_complete_get_result, &result,
	                        "even", FALSE,
	                        "string", "one",
	                        "number", 1,
	                        NULL);
	g_assert (result == NULL);

	egg_test_wait ();

	password = secret_password_lookup_finish (result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	g_assert_cmpstr (password, ==, "111");
	secret_password_free (password);
}

static void
test_store_sync (Test *test,
                  gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GError *error = NULL;
	gchar *password;
	gboolean ret;

	ret = secret_password_store_sync (&PASSWORD_SCHEMA, collection_path,
	                                  "Label here", "the password", NULL, &error,
	                                  "even", TRUE,
	                                  "string", "twelve",
	                                  "number", 12,
	                                  NULL);

	g_assert_no_error (error);
	g_assert (ret == TRUE);

	password = secret_password_lookup_sync (&PASSWORD_SCHEMA, NULL, &error,
	                                        "string", "twelve",
	                                        NULL);

	g_assert_no_error (error);
	g_assert_cmpstr (password, ==, "the password");

	secret_password_free (password);
}

static void
test_store_async (Test *test,
                  gconstpointer used)
{
	const gchar *collection_path = "/org/freedesktop/secrets/collection/english";
	GAsyncResult *result = NULL;
	GError *error = NULL;
	gchar *password;
	gboolean ret;

	secret_password_store (&PASSWORD_SCHEMA, collection_path, "Label here",
	                       "the password", NULL, on_complete_get_result, &result,
	                       "even", TRUE,
	                       "string", "twelve",
	                       "number", 12,
	                       NULL);
	g_assert (result == NULL);

	egg_test_wait ();

	ret = secret_password_store_finish (result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_object_unref (result);

	password = secret_password_lookup_sync (&PASSWORD_SCHEMA, NULL, &error,
	                                        "string", "twelve",
	                                        NULL);

	g_assert_no_error (error);
	g_assert_cmpstr (password, ==, "the password");

	secret_password_free (password);
}

static void
test_delete_sync (Test *test,
                  gconstpointer used)
{
	GError *error = NULL;
	gboolean ret;

	ret = secret_password_remove_sync (&PASSWORD_SCHEMA, NULL, &error,
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

	secret_password_remove (&PASSWORD_SCHEMA, NULL,
	                        on_complete_get_result, &result,
	                        "even", FALSE,
	                        "string", "one",
	                        "number", 1,
	                        NULL);

	g_assert (result == NULL);

	egg_test_wait ();

	ret = secret_password_remove_finish (result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_object_unref (result);
}

static void
test_password_free_null (void)
{
	secret_password_free (NULL);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-password");
	g_type_init ();

	g_test_add ("/password/lookup-sync", Test, "mock-service-normal.py", setup, test_lookup_sync, teardown);
	g_test_add ("/password/lookup-async", Test, "mock-service-normal.py", setup, test_lookup_async, teardown);

	g_test_add ("/password/store-sync", Test, "mock-service-normal.py", setup, test_store_sync, teardown);
	g_test_add ("/password/store-async", Test, "mock-service-normal.py", setup, test_store_async, teardown);

	g_test_add ("/password/delete-sync", Test, "mock-service-delete.py", setup, test_delete_sync, teardown);
	g_test_add ("/password/delete-async", Test, "mock-service-delete.py", setup, test_delete_async, teardown);

	g_test_add_func ("/password/free-null", test_password_free_null);

	return egg_tests_run_with_loop ();
}
