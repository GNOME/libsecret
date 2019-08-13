
#include "config.h"

#include "egg/egg-testing.h"
#include "secret-file-collection.h"
#include "secret-retrievable.h"
#include "secret-schema.h"

typedef struct {
	gchar *directory;
	GMainLoop *loop;
	SecretFileCollection *collection;
} Test;

static void
on_new_async (GObject *source_object,
	      GAsyncResult *result,
	      gpointer user_data)
{
	Test *test = user_data;
	GObject *object;
	GError *error = NULL;

	object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
					      result,
					      &error);
	test->collection = SECRET_FILE_COLLECTION (object);
	g_main_loop_quit (test->loop);
	g_assert_no_error (error);
}

static void
setup (Test *test,
       gconstpointer data)
{
	GFile *file;
	gchar *path;
	SecretValue *key;

	test->directory = egg_tests_create_scratch_directory (NULL, NULL);
	test->loop = g_main_loop_new (NULL, TRUE);

	path = g_build_filename (test->directory, "login", NULL);
	file = g_file_new_for_path (path);
	g_free (path);

	key = secret_value_new ("0123456789ABCDEF", -1, "text/plain");

	g_async_initable_new_async (SECRET_TYPE_FILE_COLLECTION,
				    G_PRIORITY_DEFAULT,
				    NULL,
				    on_new_async,
				    test,
				    "file", file,
				    "key", key,
				    NULL);

	g_main_loop_run (test->loop);
}

static void
teardown (Test *test,
          gconstpointer unused)
{
	egg_tests_remove_scratch_directory (test->directory);
	g_main_loop_unref (test->loop);
}

static void
test_init (Test *test,
	   gconstpointer unused)
{
}

static void
test_replace (Test *test,
	      gconstpointer unused)
{
	GHashTable *attributes;
	SecretValue *value;
	GError *error = NULL;
	gboolean ret;

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_insert (attributes, g_strdup ("foo"), g_strdup ("a"));
	g_hash_table_insert (attributes, g_strdup ("bar"), g_strdup ("b"));
	g_hash_table_insert (attributes, g_strdup ("baz"), g_strdup ("c"));

	value = secret_value_new ("test1", -1, "text/plain");
	ret = secret_file_collection_replace (test->collection,
					      attributes, "label", value,
					      &error);
	g_assert_no_error (error);
	g_assert_true (ret);
	secret_value_unref (value);

	value = secret_value_new ("test2", -1, "text/plain");
	ret = secret_file_collection_replace (test->collection,
					      attributes, "label", value,
					      &error);
	g_assert_no_error (error);
	g_assert_true (ret);
	secret_value_unref (value);
	g_hash_table_unref (attributes);
}

static void
test_search (Test *test,
	      gconstpointer unused)
{
	GHashTable *attributes;
	SecretValue *value;
	GError *error = NULL;
	GList *matches;
	gboolean ret;

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_insert (attributes, g_strdup ("foo"), g_strdup ("a"));
	g_hash_table_insert (attributes, g_strdup ("bar"), g_strdup ("b"));
	g_hash_table_insert (attributes, g_strdup ("baz"), g_strdup ("c"));

	value = secret_value_new ("test1", -1, "text/plain");
	ret = secret_file_collection_replace (test->collection,
					      attributes, "label", value,
					      &error);
	g_assert_no_error (error);
	g_assert_true (ret);
	secret_value_unref (value);

	g_hash_table_remove (attributes, "foo");

	value = secret_value_new ("test2", -1, "text/plain");
	ret = secret_file_collection_replace (test->collection,
					      attributes, "label", value,
					      &error);
	g_assert_no_error (error);
	g_assert_true (ret);
	secret_value_unref (value);

	matches = secret_file_collection_search (test->collection, attributes);
	g_assert_cmpint (g_list_length (matches), ==, 2);

	g_hash_table_unref (attributes);
}

static void
test_decrypt (Test *test,
	      gconstpointer unused)
{
	GHashTable *attributes;
	SecretValue *value;
	GError *error = NULL;
	GList *matches;
	SecretFileItem *item;
	const gchar *secret;
	gsize n_secret;
	gchar *label;
	gboolean ret;

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_insert (attributes, g_strdup ("foo"), g_strdup ("a"));
	g_hash_table_insert (attributes, g_strdup ("bar"), g_strdup ("b"));
	g_hash_table_insert (attributes, g_strdup ("baz"), g_strdup ("c"));

	value = secret_value_new ("test1", -1, "text/plain");
	ret = secret_file_collection_replace (test->collection,
					      attributes, "label", value,
					      &error);
	g_assert_no_error (error);
	g_assert_true (ret);
	secret_value_unref (value);

	matches = secret_file_collection_search (test->collection, attributes);
	g_assert_cmpint (g_list_length (matches), ==, 1);

	item = _secret_file_item_decrypt ((GVariant *)matches->data,
					  test->collection,
					  &error);
	g_assert_no_error (error);
	g_assert_nonnull (item);

	g_object_get (item, "label", &label, NULL);
	g_assert_cmpstr (label, ==, "label");

	value = secret_retrievable_retrieve_secret_sync (SECRET_RETRIEVABLE (item),
							 NULL,
							 &error);
	g_assert_no_error (error);

	secret = secret_value_get (value, &n_secret);
	g_assert_cmpstr (secret, ==, "test1");

	g_hash_table_unref (attributes);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-file-collection");
	g_test_add ("/file-collection/init", Test, NULL, setup, test_init, teardown);
	g_test_add ("/file-collection/replace", Test, NULL, setup, test_replace, teardown);
	g_test_add ("/file-collection/search", Test, NULL, setup, test_search, teardown);
	g_test_add ("/file-collection/decrypt", Test, NULL, setup, test_decrypt, teardown);

	return egg_tests_run_with_loop ();
}
