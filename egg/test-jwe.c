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

#include "egg/egg-jwe.h"
#include "egg/egg-base64.h"
#include "egg/egg-testing.h"

static void
test_symmetric_encrypt (void)
{
	const gchar *encoded = "7IYHpL3E0SApQ3Uk58_Liw";
	gchar *buffer = g_strdup (encoded);
	guchar *data;
	GBytes *key;
	gsize length;
	GError *error = NULL;
	JsonNode *root;

	data = egg_base64_decode_inplace (buffer, &length);
	key = g_bytes_new_take (data, length);
	root = egg_jwe_symmetric_encrypt ((const guchar *) "test test\n", 10, "A128GCM", key, &error);
	g_assert_nonnull (root);
	g_assert_no_error (error);

	data = egg_jwe_symmetric_decrypt (root, key, &length, &error);
	g_bytes_unref (key);
	json_node_unref (root);
	g_assert_nonnull (data);
	g_assert_no_error (error);
	g_assert_cmpmem (data, length, "test test\n", 10);
	g_free (data);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/jwe/test-symmetric-encrypt", test_symmetric_encrypt);

	return g_test_run ();
}
