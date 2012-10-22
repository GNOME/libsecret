/* libsecret - GLib wrapper for Secret Service
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

#include "secret-collection.h"
#include "secret-item.h"
#include "secret-service.h"
#include "secret-paths.h"
#include "secret-private.h"

#include "mock-service.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>
#include <stdlib.h>

typedef struct {
	SecretService *service;
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
teardown_mock (Test *test,
               gconstpointer unused)
{
	secret_service_disconnect ();
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
test_get_sync (void)
{
	SecretService *service1;
	SecretService *service2;
	SecretService *service3;
	GError *error = NULL;

	/* Both these sohuld point to the same thing */

	service1 = secret_service_get_sync (SECRET_SERVICE_NONE, NULL, &error);
	g_assert_no_error (error);

	service2 = secret_service_get_sync (SECRET_SERVICE_NONE, NULL, &error);
	g_assert_no_error (error);

	g_assert (SECRET_IS_SERVICE (service1));
	g_assert (service1 == service2);

	g_object_unref (service1);
	g_assert (G_IS_OBJECT (service1));

	g_object_unref (service2);
	secret_service_disconnect ();
	egg_assert_not_object (service2);

	/* Services were disconnected, so this should create a new one */
	service3 = secret_service_get_sync (SECRET_SERVICE_NONE, NULL, &error);
	g_assert (SECRET_IS_SERVICE (service3));
	g_assert_no_error (error);

	g_object_unref (service3);
	secret_service_disconnect ();
	egg_assert_not_object (service3);
}

static void
test_get_async (void)
{
	SecretService *service1;
	SecretService *service2;
	SecretService *service3;
	GAsyncResult *result = NULL;
	GError *error = NULL;

	/* Both these sohuld point to the same thing */

	secret_service_get (SECRET_SERVICE_NONE, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);
	egg_test_wait ();
	service1 = secret_service_get_finish (result, &error);
	g_assert_no_error (error);
	g_clear_object (&result);

	secret_service_get (SECRET_SERVICE_NONE, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);
	egg_test_wait ();
	service2 = secret_service_get_finish (result, &error);
	g_assert_no_error (error);
	g_clear_object (&result);

	g_assert (SECRET_IS_SERVICE (service1));
	g_assert (service1 == service2);

	g_object_unref (service1);
	g_assert (G_IS_OBJECT (service1));

	g_object_unref (service2);
	secret_service_disconnect ();
	egg_assert_not_object (service2);

	/* Services were unreffed, so this should create a new one */
	secret_service_get (SECRET_SERVICE_NONE, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);
	egg_test_wait ();
	service3 = secret_service_get_finish (result, &error);
	g_assert_no_error (error);
	g_clear_object (&result);

	g_object_unref (service3);
	secret_service_disconnect ();
	egg_assert_not_object (service3);
}

static void
test_get_more_sync (Test *test,
                    gconstpointer data)
{
	SecretService *service;
	SecretService *service2;
	GError *error = NULL;
	const gchar *path;
	GList *collections;

	service = secret_service_get_sync (SECRET_SERVICE_NONE, NULL, &error);
	g_assert_no_error (error);

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_NONE);

	service2 = secret_service_get_sync (SECRET_SERVICE_LOAD_COLLECTIONS, NULL, &error);
	g_assert_no_error (error);

	g_assert (SECRET_IS_SERVICE (service));
	g_assert (service == service2);

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_LOAD_COLLECTIONS);
	collections = secret_service_get_collections (service);
	g_assert (collections != NULL);
	g_list_free_full (collections, g_object_unref);

	g_object_unref (service2);

	service2 = secret_service_get_sync (SECRET_SERVICE_OPEN_SESSION, NULL, &error);
	g_assert_no_error (error);

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_OPEN_SESSION | SECRET_SERVICE_LOAD_COLLECTIONS);
	path = secret_service_get_session_dbus_path (service);
	g_assert (path != NULL);

	g_object_unref (service2);

	g_object_unref (service);
	secret_service_disconnect ();
	egg_assert_not_object (service);
}

static void
test_get_more_async (Test *test,
                     gconstpointer data)
{
	GAsyncResult *result = NULL;
	SecretService *service;
	GError *error = NULL;
	const gchar *path;
	GList *collections;

	secret_service_get (SECRET_SERVICE_LOAD_COLLECTIONS | SECRET_SERVICE_OPEN_SESSION, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	service = secret_service_get_finish (result, &error);
	g_assert_no_error (error);
	g_object_unref (result);
	result = NULL;

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_OPEN_SESSION | SECRET_SERVICE_LOAD_COLLECTIONS);
	path = secret_service_get_session_dbus_path (service);
	g_assert (path != NULL);

	collections = secret_service_get_collections (service);
	g_assert (collections != NULL);
	g_list_free_full (collections, g_object_unref);

	g_object_unref (service);
	secret_service_disconnect ();
	egg_assert_not_object (service);

	/* Now get a session with just collections */

	secret_service_get (SECRET_SERVICE_LOAD_COLLECTIONS, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	service = secret_service_get_finish (result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_LOAD_COLLECTIONS);
	path = secret_service_get_session_dbus_path (service);
	g_assert (path == NULL);

	collections = secret_service_get_collections (service);
	g_assert (collections != NULL);
	g_list_free_full (collections, g_object_unref);

	g_object_unref (service);
	secret_service_disconnect ();
	egg_assert_not_object (service);
}

static void
test_new_sync (void)
{
	SecretService *service1;
	SecretService *service2;
	GError *error = NULL;

	/* Both these sohuld point to different things */

	service1 = secret_service_new_sync (SECRET_TYPE_SERVICE, NULL,
	                                    SECRET_SERVICE_NONE, NULL, &error);
	g_assert_no_error (error);

	service2 = secret_service_new_sync (SECRET_TYPE_SERVICE, NULL,
	                                    SECRET_SERVICE_NONE, NULL, &error);
	g_assert_no_error (error);

	g_assert (SECRET_IS_SERVICE (service1));
	g_assert (SECRET_IS_SERVICE (service2));
	g_assert (service1 != service2);

	g_object_unref (service1);
	egg_assert_not_object (service1);

	g_object_unref (service2);
	egg_assert_not_object (service2);
}

static void
test_new_async (void)
{
	SecretService *service1;
	SecretService *service2;
	GAsyncResult *result = NULL;
	GError *error = NULL;

	/* Both these sohuld point to different things */

	secret_service_new (SECRET_TYPE_SERVICE, NULL, SECRET_SERVICE_NONE,
	                    NULL, on_complete_get_result, &result);
	g_assert (result == NULL);
	egg_test_wait ();
	service1 = secret_service_new_finish (result, &error);
	g_assert_no_error (error);
	g_clear_object (&result);

	secret_service_new (SECRET_TYPE_SERVICE, NULL, SECRET_SERVICE_NONE, NULL,
	                    on_complete_get_result, &result);
	g_assert (result == NULL);
	egg_test_wait ();
	service2 = secret_service_new_finish (result, &error);
	g_assert_no_error (error);
	g_clear_object (&result);

	g_assert (SECRET_IS_SERVICE (service1));
	g_assert (SECRET_IS_SERVICE (service2));
	g_assert (service1 != service2);

	g_object_unref (service1);
	egg_assert_not_object (service1);

	g_object_unref (service2);
	egg_assert_not_object (service2);
}

static void
test_new_more_sync (Test *test,
                    gconstpointer data)
{
	SecretService *service;
	GError *error = NULL;
	const gchar *path;
	GList *collections;

	service = secret_service_new_sync (SECRET_TYPE_SERVICE, NULL, SECRET_SERVICE_NONE,
	                                   NULL, &error);
	g_assert_no_error (error);
	g_assert (SECRET_IS_SERVICE (service));

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_NONE);
	g_assert (secret_service_get_collections (service) == NULL);
	g_assert (secret_service_get_session_dbus_path (service) == NULL);

	g_object_unref (service);
	egg_assert_not_object (service);

	service = secret_service_new_sync (SECRET_TYPE_SERVICE, NULL,
	                                   SECRET_SERVICE_LOAD_COLLECTIONS, NULL, &error);
	g_assert_no_error (error);
	g_assert (SECRET_IS_SERVICE (service));

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_LOAD_COLLECTIONS);
	collections = secret_service_get_collections (service);
	g_assert (collections != NULL);
	g_list_free_full (collections, g_object_unref);
	g_assert (secret_service_get_session_dbus_path (service) == NULL);

	g_object_unref (service);
	egg_assert_not_object (service);

	service = secret_service_new_sync (SECRET_TYPE_SERVICE, NULL,
	                                   SECRET_SERVICE_OPEN_SESSION, NULL, &error);
	g_assert_no_error (error);
	g_assert (SECRET_IS_SERVICE (service));

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_OPEN_SESSION);
	g_assert (secret_service_get_collections (service) == NULL);
	path = secret_service_get_session_dbus_path (service);
	g_assert (path != NULL);

	g_object_unref (service);
	egg_assert_not_object (service);
}

static void
test_new_more_async (Test *test,
                     gconstpointer data)
{
	GAsyncResult *result = NULL;
	SecretService *service;
	GError *error = NULL;
	const gchar *path;
	GList *collections;

	secret_service_new (SECRET_TYPE_SERVICE, NULL,
	                    SECRET_SERVICE_LOAD_COLLECTIONS | SECRET_SERVICE_OPEN_SESSION, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	service = secret_service_new_finish (result, &error);
	g_assert_no_error (error);
	g_object_unref (result);
	result = NULL;

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_OPEN_SESSION | SECRET_SERVICE_LOAD_COLLECTIONS);
	path = secret_service_get_session_dbus_path (service);
	g_assert (path != NULL);

	collections = secret_service_get_collections (service);
	g_assert (collections != NULL);
	g_list_free_full (collections, g_object_unref);

	g_object_unref (service);
	egg_assert_not_object (service);

	/* Now get a session with just collections */

	secret_service_new (SECRET_TYPE_SERVICE, NULL, SECRET_SERVICE_LOAD_COLLECTIONS,
	                    NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	service = secret_service_new_finish (result, &error);
	g_assert_no_error (error);
	g_object_unref (result);

	g_assert_cmpuint (secret_service_get_flags (service), ==, SECRET_SERVICE_LOAD_COLLECTIONS);
	path = secret_service_get_session_dbus_path (service);
	g_assert (path == NULL);

	collections = secret_service_get_collections (service);
	g_assert (collections != NULL);
	g_list_free_full (collections, g_object_unref);

	g_object_unref (service);
	egg_assert_not_object (service);
}

static void
test_connect_async (Test *test,
                    gconstpointer used)
{
	GError *error = NULL;
	GAsyncResult *result = NULL;
	SecretService *service;
	const gchar *path;

	/* Passing false, not session */
	secret_service_get (SECRET_SERVICE_NONE, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	service = secret_service_get_finish (result, &error);
	g_assert (SECRET_IS_SERVICE (service));
	g_assert_no_error (error);
	g_object_unref (result);

	path = secret_service_get_session_dbus_path (service);
	g_assert (path == NULL);

	g_object_unref (service);
	secret_service_disconnect ();
	egg_assert_not_object (service);
}

static void
test_connect_ensure_async (Test *test,
                           gconstpointer used)
{
	GError *error = NULL;
	GAsyncResult *result = NULL;
	SecretService *service;
	const gchar *path;

	/* Passing true, ensures session is established */
	secret_service_get (SECRET_SERVICE_OPEN_SESSION, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	service = secret_service_get_finish (result, &error);
	g_assert_no_error (error);
	g_assert (SECRET_IS_SERVICE (service));
	g_object_unref (result);

	path = secret_service_get_session_dbus_path (service);
	g_assert (path != NULL);

	g_object_unref (service);
	secret_service_disconnect ();
	egg_assert_not_object (service);
}

static void
test_ensure_sync (Test *test,
                  gconstpointer used)
{
	GError *error = NULL;
	SecretService *service;
	SecretServiceFlags flags;
	gboolean ret;

	/* Passing true, ensures session is established */
	service = secret_service_new_sync (SECRET_TYPE_SERVICE, NULL,
	                                   SECRET_SERVICE_NONE, NULL, &error);
	g_assert_no_error (error);
	g_assert (service != NULL);

	flags = secret_service_get_flags (service);
	g_assert_cmpuint (flags, ==, SECRET_SERVICE_NONE);

	ret = secret_service_load_collections_sync (service, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	g_object_get (service, "flags", &flags, NULL);
	g_assert_cmpuint (flags, ==, SECRET_SERVICE_LOAD_COLLECTIONS);

	ret = secret_service_ensure_session_sync (service, NULL, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);

	flags = secret_service_get_flags (service);
	g_assert_cmpuint (flags, ==, SECRET_SERVICE_OPEN_SESSION | SECRET_SERVICE_LOAD_COLLECTIONS);

	g_object_unref (service);
	egg_assert_not_object (service);
}

static void
test_ensure_async (Test *test,
                   gconstpointer used)
{
	GAsyncResult *result = NULL;
	SecretServiceFlags flags;
	SecretService *service;
	GError *error = NULL;
	gboolean ret;

	/* Passing true, ensures session is established */
	service = secret_service_new_sync (SECRET_TYPE_SERVICE, NULL,
	                                   SECRET_SERVICE_NONE, NULL, &error);
	g_assert_no_error (error);
	g_assert (service != NULL);

	flags = secret_service_get_flags (service);
	g_assert_cmpuint (flags, ==, SECRET_SERVICE_NONE);

	secret_service_load_collections (service, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	ret = secret_service_load_collections_finish (service, result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_object_unref (result);
	result = NULL;

	g_object_get (service, "flags", &flags, NULL);
	g_assert_cmpuint (flags, ==, SECRET_SERVICE_LOAD_COLLECTIONS);

	secret_service_ensure_session (service, NULL, on_complete_get_result, &result);
	g_assert (result == NULL);

	egg_test_wait ();

	ret = secret_service_ensure_session_finish (service, result, &error);
	g_assert_no_error (error);
	g_assert (ret == TRUE);
	g_object_unref (result);
	result = NULL;

	flags = secret_service_get_flags (service);
	g_assert_cmpuint (flags, ==, SECRET_SERVICE_OPEN_SESSION | SECRET_SERVICE_LOAD_COLLECTIONS);

	g_object_unref (service);
	egg_assert_not_object (service);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-service");
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif

	g_test_add_func ("/service/get-sync", test_get_sync);
	g_test_add_func ("/service/get-async", test_get_async);
	g_test_add ("/service/get-more-sync", Test, "mock-service-normal.py", setup_mock, test_get_more_sync, teardown_mock);
	g_test_add ("/service/get-more-async", Test, "mock-service-normal.py", setup_mock, test_get_more_async, teardown_mock);

	g_test_add_func ("/service/new-sync", test_new_sync);
	g_test_add_func ("/service/new-async", test_new_async);
	g_test_add ("/service/new-more-sync", Test, "mock-service-normal.py", setup_mock, test_new_more_sync, teardown_mock);
	g_test_add ("/service/new-more-async", Test, "mock-service-normal.py", setup_mock, test_new_more_async, teardown_mock);

	g_test_add ("/service/connect-sync", Test, "mock-service-normal.py", setup_mock, test_connect_async, teardown_mock);
	g_test_add ("/service/connect-ensure-sync", Test, "mock-service-normal.py", setup_mock, test_connect_ensure_async, teardown_mock);
	g_test_add ("/service/ensure-sync", Test, "mock-service-normal.py", setup_mock, test_ensure_sync, teardown_mock);
	g_test_add ("/service/ensure-async", Test, "mock-service-normal.py", setup_mock, test_ensure_async, teardown_mock);

	return egg_tests_run_with_loop ();
}
