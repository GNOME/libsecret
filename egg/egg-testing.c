/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "egg-testing.h"

#include <glib-object.h>

#include <valgrind/valgrind.h>

#include <errno.h>
#include <unistd.h>

static const char HEXC[] = "0123456789ABCDEF";

static gchar*
hex_dump (const guchar *data, gsize n_data)
{
	GString *result;
	gsize i;
	guchar j;

	g_assert (data);

	result = g_string_sized_new (n_data * 2 + 1);
	for (i = 0; i < n_data; ++i) {
		g_string_append (result, "\\x");

		j = data[i] >> 4 & 0xf;
		g_string_append_c (result, HEXC[j]);
		j = data[i] & 0xf;
		g_string_append_c (result, HEXC[j]);
	}

	return g_string_free (result, FALSE);
}

void
egg_assertion_not_object (const char *domain,
                          const char *file,
                          int         line,
                          const char *func,
                          const char *expr,
                          gpointer was_object)
{
	gchar *s;

	if (RUNNING_ON_VALGRIND)
		return;
	if (G_IS_OBJECT (was_object)) {
		s = g_strdup_printf ("assertion failed: %s is still referenced", expr);
		g_assertion_message (domain, file, line, func, s);
		g_free (s);
	}
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
  a1 = arg1 ? hex_dump (arg1, n_arg1) : g_strdup ("NULL");
  a2 = arg2 ? hex_dump (arg2, n_arg2) : g_strdup ("NULL");
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
	g_assert (wait_stop_impl != NULL);
	(wait_stop_impl) ();
}

gboolean
egg_test_wait_until (int timeout)
{
	g_assert (wait_until_impl != NULL);
	return (wait_until_impl) (timeout);
}

static GMainLoop *wait_loop = NULL;

static void
loop_wait_stop (void)
{
	g_assert (wait_loop != NULL);
	g_main_loop_quit (wait_loop);
}

static gboolean
on_loop_wait_timeout (gpointer data)
{
	gboolean *timed_out = data;
	*timed_out = TRUE;

	g_assert (wait_loop != NULL);
	g_main_loop_quit (wait_loop);

	return TRUE; /* we remove this source later */
}

static gboolean
loop_wait_until (int timeout)
{
	gboolean ret = FALSE;
	gboolean timed_out = FALSE;
	guint source;

	g_assert (wait_loop == NULL);
	wait_loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);

	source = g_timeout_add (timeout, on_loop_wait_timeout, &timed_out);

	g_main_loop_run (wait_loop);

	if (timed_out) {
		g_source_remove (source);
		ret = FALSE;
	} else {
		ret = TRUE;
	}

	g_main_loop_unref (wait_loop);
	wait_loop = NULL;
	return ret;
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
