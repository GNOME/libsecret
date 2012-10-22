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

#include "secret-attributes.h"

#include "egg/egg-testing.h"

#include <glib.h>

#include <errno.h>
#include <stdlib.h>

static const SecretSchema MOCK_SCHEMA = {
	"org.mock.Schema",
	SECRET_SCHEMA_NONE,
	{
		{ "number", SECRET_SCHEMA_ATTRIBUTE_INTEGER },
		{ "string", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ "even", SECRET_SCHEMA_ATTRIBUTE_BOOLEAN },
		{ "bad-type", -1 },
	}
};

static void
test_build (void)
{
	GHashTable *attributes;

	attributes = secret_attributes_build (&MOCK_SCHEMA,
	                                      "number", 4,
	                                      "string", "four",
	                                      "even", TRUE,
	                                      NULL);

	g_assert_cmpstr (g_hash_table_lookup (attributes, "number"), ==, "4");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "string"), ==, "four");
	g_assert_cmpstr (g_hash_table_lookup (attributes, "even"), ==, "true");

	g_hash_table_unref (attributes);
}

static void
test_build_unknown (void)
{
	GHashTable *attributes;

	if (g_test_trap_fork (0, G_TEST_TRAP_SILENCE_STDERR)) {
		attributes = secret_attributes_build (&MOCK_SCHEMA,
		                                      "invalid", "whee",
		                                      "string", "four",
		                                      "even", TRUE,
		                                      NULL);
		g_assert (attributes == NULL);
	}

	g_test_trap_assert_failed ();
	g_test_trap_assert_stderr ("*was not found in*");
}

static void
test_build_null_string (void)
{
	GHashTable *attributes;

	if (g_test_trap_fork (0, G_TEST_TRAP_SILENCE_STDERR)) {
		attributes = secret_attributes_build (&MOCK_SCHEMA,
		                                      "number", 4,
		                                      "string", NULL,
		                                      "even", TRUE,
		                                      NULL);
		g_assert (attributes == NULL);
	}

	g_test_trap_assert_failed ();
	g_test_trap_assert_stderr ("*attribute*NULL*");
}

static void
test_build_non_utf8_string (void)
{
	GHashTable *attributes;

	if (g_test_trap_fork (0, G_TEST_TRAP_SILENCE_STDERR)) {
		attributes = secret_attributes_build (&MOCK_SCHEMA,
		                                      "number", 4,
		                                      "string", "\xfftest",
		                                      "even", TRUE,
		                                      NULL);
		g_assert (attributes == NULL);
	}

	g_test_trap_assert_failed ();
	g_test_trap_assert_stderr ("*attribute*UTF-8*");
}

static void
test_build_bad_type (void)
{
	GHashTable *attributes;

	if (g_test_trap_fork (0, G_TEST_TRAP_SILENCE_STDERR)) {
		attributes = secret_attributes_build (&MOCK_SCHEMA,
		                                      "bad-type", "test",
		                                      NULL);
		g_assert (attributes == NULL);
	}

	g_test_trap_assert_failed ();
	g_test_trap_assert_stderr ("*invalid type*");
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-attributes");
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif

	g_test_add_func ("/attributes/build", test_build);
	g_test_add_func ("/attributes/build-unknown", test_build_unknown);
	g_test_add_func ("/attributes/build-null-string", test_build_null_string);
	g_test_add_func ("/attributes/build-non-utf8-string", test_build_non_utf8_string);
	g_test_add_func ("/attributes/build-bad-type", test_build_bad_type);

	return g_test_run ();
}
