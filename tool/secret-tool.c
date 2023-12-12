/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2012 Red Hat Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "libsecret/secret-item.h"
#include "libsecret/secret-password.h"
#include "libsecret/secret-retrievable.h"
#include "libsecret/secret-value.h"
#include "libsecret/secret-service.h"
#include "libsecret/secret-paths.h"

#include <glib/gi18n.h>

#include <errno.h>
#include <locale.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define SECRET_ALIAS_PREFIX "/org/freedesktop/secrets/aliases/"
#define SECRET_COLLECTION_PREFIX "/org/freedesktop/secrets/collection/"

static gchar **attribute_args = NULL;
static gchar *store_label = NULL;
static gchar *store_collection = NULL;

/* secret-tool store --label="blah" --collection="xxxx" name:xxxx name:yyyy */
static const GOptionEntry STORE_OPTIONS[] = {
	{ "label", 'l', 0, G_OPTION_ARG_STRING, &store_label,
	  N_("the label for the new stored item"), NULL },
	{ "collection", 'c', 0, G_OPTION_ARG_STRING, &store_collection,
	  N_("the collection in which to place the stored item"), NULL },
	{ G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &attribute_args,
	  N_("attribute value pairs of item to lookup"), NULL },
	{ NULL }
};

/* secret-tool lookup name:xxxx yyyy:zzzz */
static const GOptionEntry LOOKUP_OPTIONS[] = {
	{ G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &attribute_args,
	  N_("attribute value pairs of item to lookup"), NULL },
	{ NULL }
};

/* secret-tool clear name:xxxx yyyy:zzzz */
static const GOptionEntry CLEAR_OPTIONS[] = {
	{ G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &attribute_args,
	  N_("attribute value pairs which match items to clear"), NULL },
	{ NULL }
};

/* secret-tool lock collections="xxxx" */
static const GOptionEntry COLLECTION_OPTIONS[] = {
	{ "collection", 'c', 0, G_OPTION_ARG_STRING, &store_collection,
	  N_("collection in which to lock"), NULL },
	{ NULL }
};

typedef int       (* SecretToolAction)          (int argc, char *argv[]);

static void       usage                         (void) G_GNUC_NORETURN;

static void
usage (void)
{
	g_printerr ("usage: secret-tool store --label='label' attribute value ...\n");
	g_printerr ("       secret-tool lookup attribute value ...\n");
	g_printerr ("       secret-tool clear attribute value ...\n");
	g_printerr ("       secret-tool search [--all] [--unlock] attribute value ...\n");
	g_printerr ("       secret-tool lock --collection='collection'\n");
	exit (2);
}

static gboolean
is_password_value (SecretValue *value)
{
	const gchar *content_type;
	const gchar *data;
	gsize length;

	content_type = secret_value_get_content_type (value);
	if (content_type && g_str_equal (content_type, "text/plain"))
		return TRUE;

	data = secret_value_get (value, &length);
	/* gnome-keyring-daemon used to return passwords like this, so support this, but validate */
	if (!content_type || g_str_equal (content_type, "application/octet-stream"))
		return g_utf8_validate (data, length, NULL);

	return FALSE;
}

static GHashTable *
attributes_from_arguments (gchar **args)
{
	GHashTable *attributes;

	if (args == NULL || args[0] == NULL) {
		g_printerr ("%s: must specify attribute and value pairs\n", g_get_prgname ());
		usage ();
	}

	attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	while (args[0] != NULL) {
		if (args[1] == NULL) {
			g_printerr ("%s: must specify attributes and values in pairs\n", g_get_prgname ());
			usage ();
		}

		g_hash_table_insert (attributes, g_strdup (args[0]), g_strdup (args[1]));
		args += 2;
	}

	return attributes;
}

static int
secret_tool_action_clear (int argc,
                          char *argv[])
{
	GError *error = NULL;
	GOptionContext *context;
	GHashTable *attributes;
	gboolean ret;

	context = g_option_context_new ("attribute value ...");
	g_option_context_add_main_entries (context, CLEAR_OPTIONS, GETTEXT_PACKAGE);
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_printerr ("%s\n", error->message);
		usage();
	}

	g_option_context_free (context);

	attributes = attributes_from_arguments (attribute_args);
	g_strfreev (attribute_args);

	ret = secret_password_clearv_sync (NULL, attributes, NULL, &error);

	g_hash_table_unref (attributes);

	if (!ret) {
		if (error != NULL) {
			g_printerr ("%s: %s\n", g_get_prgname (), error->message);
			g_error_free (error);
		}
		return 1;
	}

	return 0;
}

static void
write_password_data (SecretValue *value)
{
	const gchar *at;
	gsize length;
	int r;

	at = secret_value_get (value, &length);

	while (length > 0) {
		r = write (1, at, length);
		if (r == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				g_printerr ("%s: couldn't write password: %s\n",
				            g_get_prgname (), g_strerror (errno));
				exit (1);
			}
		} else {
			at += r;
			length -= r;
		}
	}
}

static void
write_password_stdout (SecretValue *value)
{
	if (!is_password_value (value)) {
		g_printerr ("%s: secret does not contain a textual password\n", g_get_prgname ());
		exit (1);
	}

	write_password_data (value);

	/* Add a new line if we're writing out to a tty */
	if (isatty (1))
		write (1, "\n", 1);
}

static int
secret_tool_action_lookup (int argc,
                           char *argv[])
{
	GError *error = NULL;
	GOptionContext *context;
	GHashTable *attributes;
	SecretValue *value = NULL;

	context = g_option_context_new ("attribute value ...");
	g_option_context_add_main_entries (context, LOOKUP_OPTIONS, GETTEXT_PACKAGE);
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_printerr ("%s\n", error->message);
		usage();
	}

	g_option_context_free (context);

	attributes = attributes_from_arguments (attribute_args);
	g_strfreev (attribute_args);

	value = secret_password_lookupv_binary_sync (NULL, attributes, NULL, &error);

	g_hash_table_unref (attributes);

	if (error != NULL) {
		g_printerr ("%s: %s\n", g_get_prgname (), error->message);
		g_error_free (error);
		return 1;
	}

	if (value == NULL)
		return 1;

	write_password_stdout (value);
	secret_value_unref (value);
	return 0;
}

static SecretValue *
read_password_stdin (void)
{
	gchar *password;
	gchar *at;
	gsize length = 0;
	gsize remaining = 8192;
	int r;

	at = password = g_malloc0 (remaining + 1);

	for (;;) {
		r = read (0, at, remaining);
		if (r == 0) {
			break;
		} else if (r < 0) {
			if (errno != EAGAIN && errno != EINTR) {
				g_printerr ("%s: couldn't read password: %s\n",
				            g_get_prgname (), g_strerror (errno));
				exit (1);
			}
		} else {
			/* TODO: This restriction is due purely to laziness. */
			if (r == remaining)
				g_printerr ("%s: password is too long\n", g_get_prgname ());
			at += r;
			remaining -= r;
			length += r;
		}
	}

	if (g_utf8_validate (password, -1, NULL)) {
		return secret_value_new_full (password, length, "text/plain",
	                              (GDestroyNotify)secret_password_free);
	} else {
		g_printerr ("%s: password not valid UTF-8\n", g_get_prgname ());
		exit (1);
	}
}

static SecretValue *
read_password_tty (void)
{
	gchar *password;

	password = getpass ("Password: ");
	return secret_value_new_full (password, -1, "text/plain",
	                              (GDestroyNotify)secret_password_wipe);
}

static int
secret_tool_action_store (int argc,
                          char *argv[])
{
	GError *error = NULL;
	GOptionContext *context;
	GHashTable *attributes;
	SecretValue *value;
	gchar *collection = NULL;
	gboolean ret;

	context = g_option_context_new ("attribute value ...");
	g_option_context_add_main_entries (context, STORE_OPTIONS, GETTEXT_PACKAGE);
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_printerr ("%s\n", error->message);
		usage();
	}

	g_option_context_free (context);

	if (store_label == NULL) {
		g_printerr ("%s: must specify a label for the new item\n", g_get_prgname ());
		usage ();
	}

	attributes = attributes_from_arguments (attribute_args);
	g_strfreev (attribute_args);

	if (store_collection) {
		/* TODO: Verify that the collection is a valid path or path element */
		if (g_str_has_prefix (store_collection, "/"))
			collection = g_strdup (store_collection);
		else
			collection = g_strconcat (SECRET_ALIAS_PREFIX, store_collection, NULL);
	}

	if (isatty (0))
		value = read_password_tty ();
	else
		value = read_password_stdin ();

	ret = secret_password_storev_binary_sync (NULL, attributes, collection, store_label, value, NULL, &error);
	secret_value_unref (value);

	g_hash_table_unref (attributes);
	g_free (store_label);
	g_free (store_collection);
	g_free (collection);

	if (!ret) {
		g_printerr ("%s: %s\n", g_get_prgname (), error->message);
		return 1;
	}

	return 0;
}

static void
print_item_when (const char *field,
                 guint64 when)
{
	GDateTime *dt;
	gchar *value;

	if (!when) {
		value = g_strdup ("");
	} else {
		dt = g_date_time_new_from_unix_utc (when);
		value = g_date_time_format (dt, "%Y-%m-%d %H:%M:%S");
		g_date_time_unref (dt);
	}

	g_print ("%s = %s\n", field, value);
	g_free (value);
}

static void
on_retrieve_secret (GObject *source_object,
		    GAsyncResult *res,
		    gpointer user_data)
{
	SecretRetrievable *item = SECRET_RETRIEVABLE (source_object);
	GMainLoop *loop = user_data;
	SecretValue *secret;
	GHashTableIter iter;
	GHashTable *attributes;
	const gchar *value, *key;
	guint64 when;
	gchar *label;
	const gchar *part;
	const gchar *path;
	GError *error;

	error = NULL;
	secret = secret_retrievable_retrieve_secret_finish (item, res, &error);
	if (!secret) {
		g_printerr ("%s: %s\n", g_get_prgname (), error->message);
		g_clear_error (&error);
	}

	if (G_IS_DBUS_PROXY (item)) {
		path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (item));
		g_return_if_fail (path != NULL);

		/* The item identifier */
		part = strrchr (path, '/');
		if (part == NULL)
			part = path;
		g_print ("[%s]\n", part);
	} else {
		g_print ("[no path]\n");
	}

	/* The label */
	label = secret_retrievable_get_label (item);
	g_print ("label = %s\n", label);
	g_free (label);

	if (secret) {
		/* The secret value */
		g_print ("secret = ");
		if (secret != NULL) {
			write_password_data (secret);
			secret_value_unref (secret);
		}
		g_print ("\n");
	}

	/* The dates */
	when = secret_retrievable_get_created (item);
	print_item_when ("created", when);
	when = secret_retrievable_get_modified (item);
	print_item_when ("modified", when);

	/* The attributes */
	attributes = secret_retrievable_get_attributes (item);
	value = g_hash_table_lookup (attributes, "xdg:schema");
	if (value)
		g_print ("schema = %s\n", value);

	g_hash_table_iter_init (&iter, attributes);
	while (g_hash_table_iter_next (&iter, (void **)&key, (void **)&value)) {
		if (strcmp (key, "xdg:schema") != 0)
			g_printerr ("attribute.%s = %s\n", key, value);
	}
	g_hash_table_unref (attributes);
	g_main_loop_quit (loop);
}

static int
secret_tool_action_search (int argc,
                           char *argv[])
{
	GError *error = NULL;
	GOptionContext *context;
	GHashTable *attributes;
	SecretSearchFlags flags;
	gboolean flag_all = FALSE;
	gboolean flag_unlock = FALSE;
	GList *items, *l;

	/* secret-tool lookup name xxxx yyyy zzzz */
	const GOptionEntry lookup_options[] = {
		{ "all", 'a', 0, G_OPTION_ARG_NONE, &flag_all,
		  N_("return all results, instead of just first one"), NULL },
		{ "unlock", 'a', 0, G_OPTION_ARG_NONE, &flag_unlock,
		  N_("unlock item results if necessary"), NULL },
		{ G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &attribute_args,
		  N_("attribute value pairs of item to lookup"), NULL },
		{ NULL }
	};

	context = g_option_context_new ("attribute value ...");
	g_option_context_add_main_entries (context, lookup_options, GETTEXT_PACKAGE);
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_printerr ("%s\n", error->message);
		usage();
	}

	g_option_context_free (context);

	attributes = attributes_from_arguments (attribute_args);
	g_strfreev (attribute_args);

	flags = SECRET_SEARCH_LOAD_SECRETS;
	if (flag_all)
		flags |= SECRET_SEARCH_ALL;
	if (flag_unlock)
		flags |= SECRET_SEARCH_UNLOCK;
	items = secret_password_searchv_sync (NULL, attributes, flags, NULL, &error);
	if (error == NULL) {
		GMainLoop *loop = g_main_loop_new (NULL, FALSE);

		for (l = items; l != NULL; l = g_list_next (l)) {
			SecretRetrievable *retrievable = SECRET_RETRIEVABLE (l->data);
			secret_retrievable_retrieve_secret (retrievable,
							    NULL,
							    on_retrieve_secret,
							    loop);
			g_main_loop_run (loop);
		}

		g_list_free_full (items, g_object_unref);
		g_main_loop_unref (loop);
	}

	g_hash_table_unref (attributes);

	if (error != NULL) {
		g_printerr ("%s: %s\n", g_get_prgname (), error->message);
		g_error_free (error);
		return 1;
	}

	return 0;
}

static int
secret_tool_action_lock (int argc,
                         char *argv[])
{
	int ret = 0;
	SecretService *service = NULL;
	GError *error = NULL;
	GOptionContext *context = NULL;
	GList *locked = NULL;
	GList *collections = NULL;
	SecretCollection *collection = NULL;

	service = secret_service_get_sync (SECRET_SERVICE_LOAD_COLLECTIONS, NULL, &error);
	if (error != NULL) {
		g_printerr ("%s: %s\n", g_get_prgname (), error->message);
		ret = 1;
		goto out;
	}

	context = g_option_context_new ("collections");
	g_option_context_add_main_entries (context, COLLECTION_OPTIONS, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, &error);

	if (store_collection != NULL) {
		char *collection_path = NULL;

		collection_path = g_strconcat (SECRET_COLLECTION_PREFIX, store_collection, NULL);
		collection = secret_collection_new_for_dbus_path_sync (service, collection_path, SECRET_COLLECTION_NONE, NULL, &error);
		g_free (store_collection);
		g_free (collection_path);

		if (error != NULL) {
			g_printerr ("%s: %s\n", g_get_prgname (), error->message);
			ret = 1;
			goto out;
		}

		if (secret_collection_get_locked (collection) || collection == NULL) {
			ret = 1;
			goto out;
		}

		collections = g_list_append (collections,
		                             g_steal_pointer (&collection));
	} else {
		collections = secret_service_get_collections (service);
	}

	secret_service_lock_sync (NULL, collections, 0, &locked, &error);
	if (error != NULL) {
		g_printerr ("%s: %s\n", g_get_prgname (), error->message);
		ret = 1;
		goto out;
	}

out:
	g_clear_object (&collection);
	g_clear_list (&collections, g_object_unref);
	g_clear_list (&locked, g_object_unref);
	g_clear_pointer (&context, g_option_context_free);
	g_clear_error (&error);
	g_clear_object (&service);
	return ret;
}

int
main (int argc,
      char *argv[])
{
	SecretToolAction action;

	setlocale (LC_ALL, "");

#ifdef ENABLE_NLS
	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
#endif

	if (argc < 2)
		usage();

	if (g_str_equal (argv[1], "store")) {
		action = secret_tool_action_store;
	} else if (g_str_equal (argv[1], "lookup")) {
		action = secret_tool_action_lookup;
	} else if (g_str_equal (argv[1], "clear")) {
		action = secret_tool_action_clear;
	} else if (g_str_equal (argv[1], "search")) {
		action = secret_tool_action_search;
	} else if (g_str_equal (argv[1], "lock")) {
		action = secret_tool_action_lock;
	} else {
		usage ();
	}

	argv[1] = argv[0];
	return (action) (argc - 1, argv + 1);
}
