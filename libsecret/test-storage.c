/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2018 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */


#include "config.h"

#include "secret-storage.h"
#include "egg/egg-testing.h"

typedef struct {
	gchar *directory;
	GFile *file;
	GMainLoop *loop;
	SecretStorage *storage;
} Test;

static void
setup (Test *test,
       gconstpointer data)
{
	test->directory = egg_tests_create_scratch_directory (NULL, NULL);
	test->loop = g_main_loop_new (NULL, FALSE);
}

static void
teardown (Test *test,
	  gconstpointer data)
{
	egg_tests_remove_scratch_directory (test->directory);
	g_free (test->directory);
	g_clear_object (&test->file);
	g_main_loop_unref (test->loop);
	g_clear_object (&test->storage);
}

static void
on_new_async (GObject *source_object,
	      GAsyncResult *result,
	      gpointer user_data)
{
	GAsyncInitable *initable = G_ASYNC_INITABLE (source_object);
	Test *test = user_data;
	GError *error = NULL;

	test->storage = SECRET_STORAGE (g_async_initable_new_finish (initable, result, &error));
	g_main_loop_quit (test->loop);
}

static void
test_load_nonexistent (Test *test,
		       gconstpointer data)
{
	gchar *path = g_build_filename (test->directory, "nonexistent", NULL);
	test->file = g_file_new_for_path (path);
	g_free (path);
	g_async_initable_new_async (SECRET_TYPE_STORAGE, G_PRIORITY_DEFAULT,
				    NULL, on_new_async, test,
				    "file", test->file,
				    "password", "password",
				    NULL);
	g_main_loop_run (test->loop);
	g_assert_nonnull (test->storage);
}

static void
test_load (Test *test,
	   gconstpointer data)
{
	gchar *path = g_build_filename (test->directory, "store1", NULL);
	egg_tests_copy_scratch_file (test->directory,
				     SRCDIR "/test-store1.json");
	test->file = g_file_new_for_path (path);
	g_free (path);
	g_async_initable_new_async (SECRET_TYPE_STORAGE, G_PRIORITY_DEFAULT,
				    NULL, on_new_async, test,
				    "file", test->file,
				    "password", "password",
				    NULL);
	g_main_loop_run (test->loop);
	g_assert_nonnull (test->storage);
}

static void
on_store (GObject *source_object,
	  GAsyncResult *result,
	  gpointer user_data)
{
	SecretStorage *storage = SECRET_STORAGE (source_object);
	Test *test = user_data;
	gboolean ret;
	GError *error = NULL;

	ret = secret_storage_store_finish (storage, result, &error);
	g_assert_true (ret);
	g_assert_no_error (error);

	g_main_loop_quit (test->loop);
}

static void
test_store (Test *test,
	    gconstpointer data)
{
	gchar *path = g_build_filename (test->directory, "store1", NULL);
	GHashTable *attributes;
	SecretValue *value;

	test->file = g_file_new_for_path (path);
	g_free (path);
	g_async_initable_new_async (SECRET_TYPE_STORAGE, G_PRIORITY_DEFAULT,
				    NULL, on_new_async, test,
				    "file", test->file,
				    "password", "password",
				    NULL);
	g_main_loop_run (test->loop);
	g_assert_nonnull (test->storage);

	attributes = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (attributes, "attr1", "value1");
	g_hash_table_insert (attributes, "attr2", "value2");
	g_hash_table_insert (attributes, "attr3", "value3");

	value = secret_value_new ("secret", 6, "text/plain");
	secret_storage_store (test->storage, NULL, attributes,
			      SECRET_COLLECTION_DEFAULT,
			      "label",
			      value,
			      NULL,
			      on_store,
			      test);
	g_hash_table_unref (attributes);
	secret_value_unref (value);
	g_main_loop_run (test->loop);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/storage/load/nonexistent", Test, NULL, setup, test_load_nonexistent, teardown);
	g_test_add ("/storage/load", Test, NULL, setup, test_load, teardown);
	g_test_add ("/storage/store", Test, NULL, setup, test_store, teardown);

	return egg_tests_run_with_loop ();
}
