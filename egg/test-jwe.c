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

#define PLAINTEXT "test test\n"
#define KEY "7IYHpL3E0SApQ3Uk58_Liw"
#define IV "aeZrw-VuRzycKDEu"
#define CIPHERTEXT "sWMnFnG4OcjdpA"
#define TAG "Jx1MqdYjb2n-0-zXTGUHZw"
#define PROTECTED "eyJlbmMiOiJBMTI4R0NNIn0"

#define MSG "{\"ciphertext\":\"" CIPHERTEXT "\"," \
	"\"encrypted_key\":\"\"," \
	"\"header\":{\"alg\":\"dir\"}," \
	"\"iv\":\"" IV "\"," \
	"\"protected\":\"" PROTECTED "\"," \
	"\"tag\":\"" TAG "\"}"

static void
test_symmetric_encrypt (void)
{
	gchar *buffer;
	guchar *key;
	gsize n_key;
	guchar *iv;
	gsize n_iv;
	GError *error;
	JsonNode *root;
	JsonObject *object;
	const gchar *string;

	buffer = g_strdup (KEY);
	key = egg_base64_decode_inplace (buffer, &n_key);
	buffer = g_strdup (IV);
	iv = egg_base64_decode_inplace (buffer, &n_iv);
	error = NULL;
	root = egg_jwe_symmetric_encrypt ((const guchar *) PLAINTEXT,
					  sizeof (PLAINTEXT)-1,
					  "A128GCM", key, n_key, iv, n_iv,
					  &error);
	g_assert_nonnull (root);
	g_assert_no_error (error);
	g_free (key);
	g_free (iv);

	object = json_node_get_object (root);
	g_assert_nonnull (object);

	string = json_object_get_string_member (object, "ciphertext");
	g_assert_cmpstr (string, ==, CIPHERTEXT);
	string = json_object_get_string_member (object, "iv");
	g_assert_cmpstr (string, ==, IV);
	string = json_object_get_string_member (object, "tag");
	g_assert_cmpstr (string, ==, TAG);
	string = json_object_get_string_member (object, "protected");
	g_assert_cmpstr (string, ==, PROTECTED);
	json_node_unref (root);
}

static void
test_symmetric_decrypt (void)
{
	JsonParser *parser;
	JsonNode *root;
	gchar *buffer;
	guchar *key;
	gsize n_key;
	guchar *plaintext;
	gsize n_plaintext;
	GError *error;
	gboolean ret;

	parser = json_parser_new ();
	error = NULL;
	ret = json_parser_load_from_data (parser, MSG, sizeof (MSG)-1, &error);
	g_assert_true (ret);
	g_assert_no_error (error);

	buffer = g_strdup (KEY);
	key = egg_base64_decode_inplace (buffer, &n_key);

	root = json_parser_steal_root (parser);
	g_object_unref (parser);

	error = NULL;
	plaintext = egg_jwe_symmetric_decrypt (root, key, n_key, &n_plaintext,
					       &error);
	g_assert_nonnull (plaintext);
	g_assert_no_error (error);

	g_free (key);
	json_node_unref (root);
	g_assert_nonnull (plaintext);
	g_assert_no_error (error);

	g_assert_cmpmem (plaintext, n_plaintext, PLAINTEXT, sizeof(PLAINTEXT)-1);
	g_free (plaintext);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/jwe/test-symmetric-encrypt", test_symmetric_encrypt);
	g_test_add_func ("/jwe/test-symmetric-decrypt", test_symmetric_decrypt);

	return g_test_run ();
}
