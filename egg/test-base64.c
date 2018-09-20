/* test-base64.c: Test egg-base64.c

   Copyright (C) 2018 Red Hat, Inc.

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   see <http://www.gnu.org/licenses/>.

   Author: Daiki Ueno
*/

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "egg/egg-base64.h"
#include "egg/egg-testing.h"

static void
test_base64 (void)
{
	struct {
		const guchar *input;
		gsize length;
		const gchar *output;
	} tests[] = {
		{ (const guchar *) "", 0, "" },
		{ (const guchar *) "f", 1, "Zg" },
		{ (const guchar *) "fo", 2, "Zm8" },
		{ (const guchar *) "foo", 3, "Zm9v" },
		{ (const guchar *) "foob", 4, "Zm9vYg" },
		{ (const guchar *) "fooba", 5, "Zm9vYmE" },
		{ (const guchar *) "\xff\xee\xdd\xcc\xbb\xaa", 6, "_-7dzLuq" }
	};
	gsize i;

	for (i = 0; i < G_N_ELEMENTS (tests); i++) {
		gchar *output;
		guchar *input;
		gsize length;

		output = egg_base64_encode (tests[i].input, tests[i].length);
		g_assert_cmpstr (output, ==, tests[i].output);

		input = egg_base64_decode_inplace (output, &length);
		g_assert_cmpmem (input, length, tests[i].input, tests[i].length);
		g_free (output);
	}
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/base64/test-base64", test_base64);

	return g_test_run ();
}
