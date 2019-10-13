/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *  
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "egg-testing.h"

#include <glib-object.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static const char HEXC[] = "0123456789ABCDEF";

gchar *
egg_test_escape_data (const guchar *data,
                      gsize n_data)
{
	GString *result;
	gchar c;
	gsize i;
	guchar j;

	g_assert_nonnull (data);

	result = g_string_sized_new (n_data * 2 + 1);
	for (i = 0; i < n_data; ++i) {
		c = data[i];
		if (g_ascii_isprint (c) && !strchr ("\n\r\v", c)) {
			g_string_append_c (result, c);
		} else {
			g_string_append (result, "\\x");
			j = c >> 4 & 0xf;
			g_string_append_c (result, HEXC[j]);
			j = c & 0xf;
			g_string_append_c (result, HEXC[j]);
		}
	}

	return g_string_free (result, FALSE);
}

void
egg_assertion_message_cmpmem (const char     *domain,
                              const char     *file,
                              int             line,
                              const char     *func,
                              const char     *expr,
                              gconstpointer   arg1,
                              gsize           n_arg1,
                              const char     *cmp,
                              gconstpointer   arg2,
                              gsize           n_arg2)
{
  char *a1, *a2, *s;
  a1 = arg1 ? egg_test_escape_data (arg1, n_arg1) : g_strdup ("NULL");
  a2 = arg2 ? egg_test_escape_data (arg2, n_arg2) : g_strdup ("NULL");
  s = g_strdup_printf ("assertion failed (%s): (%s %s %s)", expr, a1, cmp, a2);
  g_free (a1);
  g_free (a2);
  g_assertion_message (domain, file, line, func, s);
  g_free (s);
}

static void (*wait_stop_impl) (void);
static gboolean (*wait_until_impl) (int timeout);

void
egg_test_wait_stop (void)
{
	g_assert_nonnull (wait_stop_impl);
	(wait_stop_impl) ();
}

gboolean
egg_test_wait_until (int timeout)
{
	g_assert_nonnull (wait_until_impl);
	return (wait_until_impl) (timeout);
}

void
egg_test_wait_idle (void)
{
	GMainContext *context;

	g_assert_nonnull (wait_until_impl);

	context = g_main_context_get_thread_default ();
	while (g_main_context_iteration (context, FALSE));
}

static GMainLoop *wait_loop = NULL;

static void
loop_wait_stop (void)
{
	g_assert_nonnull (wait_loop);
	g_main_loop_quit (wait_loop);
}

static gboolean
on_loop_wait_timeout (gpointer data)
{
	gboolean *timed_out = data;
	*timed_out = TRUE;

	g_assert_nonnull (wait_loop);
	g_main_loop_quit (wait_loop);

	return TRUE; /* we remove this source later */
}

static gboolean
loop_wait_until (int timeout)
{
	gboolean timed_out = FALSE;
	guint source;

	g_assert_null (wait_loop);
	wait_loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);

	source = g_timeout_add (timeout, on_loop_wait_timeout, &timed_out);

	g_main_loop_run (wait_loop);

	g_source_remove (source);
	g_main_loop_unref (wait_loop);
	wait_loop = NULL;
	return !timed_out;
}

gint
egg_tests_run_with_loop (void)
{
	gint ret;

	wait_stop_impl = loop_wait_stop;
	wait_until_impl = loop_wait_until;

	ret = g_test_run ();

	wait_stop_impl = NULL;
	wait_until_impl = NULL;

	while (g_main_context_iteration (NULL, FALSE));

	return ret;
}

void
egg_tests_copy_scratch_file (const gchar *directory,
                             const gchar *filename)
{
	GError *error = NULL;
	gchar *basename;
	gchar *contents;
	gchar *destination;
	gsize length;

	g_assert (directory);

	g_file_get_contents (filename, &contents, &length, &error);
	g_assert_no_error (error);

	basename = g_path_get_basename (filename);
	destination = g_build_filename (directory, basename, NULL);
	g_free (basename);

	g_file_set_contents (destination, contents, length, &error);
	g_assert_no_error (error);
	g_free (destination);
	g_free (contents);
}

gchar *
egg_tests_create_scratch_directory (const gchar *file_to_copy,
                                    ...)
{
	gchar *basename;
	gchar *directory;
	va_list va;

	basename = g_path_get_basename (g_get_prgname ());
	directory = g_strdup_printf ("/tmp/scratch-%s.XXXXXX", basename);
	g_free (basename);

	if (!g_mkdtemp (directory))
		g_assert_not_reached ();

	va_start (va, file_to_copy);

	while (file_to_copy != NULL) {
		egg_tests_copy_scratch_file (directory, file_to_copy);
		file_to_copy = va_arg (va, const gchar *);
	}

	va_end (va);

	return directory;
}

void
egg_tests_remove_scratch_directory (const gchar *directory)
{
	gchar *argv[] = { "rm", "-rf", (gchar *)directory, NULL };
	GError *error = NULL;
	gint rm_status;

	g_assert_cmpstr (directory, !=, "");
	g_assert_cmpstr (directory, !=, "/");

	g_spawn_sync (NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL,
	              NULL, NULL, NULL, &rm_status, &error);
	g_assert_no_error (error);
	g_assert_cmpint (rm_status, ==, 0);
}
