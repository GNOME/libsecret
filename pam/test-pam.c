/*
 * libsecret
 *
 * Copyright (C) 2023 GNOME Foundation Inc.
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
 * You should have received copies of the GNU General Public License and
 * the GNU Lesser General Public License along with this program.  If
 * not, see http://www.gnu.org/licenses/.
 *
 * Author: Dhanuka Warusadura
 */

#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>

#include <libpamtest.h>

#define SERVICE "pam-test-service"
#define BUFFER_SIZE 100

typedef struct {
        gchar *control_path;
        GSocketAddress *address;
        GSocketService *service;
        GThread *pam_test;
        gboolean success;
} Test;

static gchar dir_path[] = "/tmp/pam_test_XXXXXX";

static gboolean
is_bytes_exchanged (GSocketService *service,
                    GSocketConnection *connection,
                    GObject *source_object,
                    gpointer data)
{
        Test *test = data;
        GInputStream *input;
        GError *error = NULL;
        char buffer[BUFFER_SIZE + 1];

        g_printf ("Incoming signal detected\n");

        if (g_socket_service_is_active (service))
                test->success = TRUE;
        else
                return FALSE;

        input = g_io_stream_get_input_stream (G_IO_STREAM(connection));

        if (g_input_stream_read (input,
                                 buffer,
                                 BUFFER_SIZE,
                                 NULL,
                                 &error) > 0)
                return TRUE;
        else
                return FALSE;
}

static void
teardown (Test *test)
{
        g_assert_true (g_socket_service_is_active (test->service));
        g_thread_join (test->pam_test);
        g_socket_service_stop (test->service);
        g_assert_false (g_socket_service_is_active (test->service));

        g_object_unref (test->address);
        g_unlink (test->control_path);
        g_free (test->control_path);
        g_free (test);
        g_rmdir (dir_path);

        g_printf ("Teardown completed\n");
}

static void *
pam_auth_tests (gpointer data)
{
        Test *test = data;
        enum pamtest_err ret;

        g_printf ("Executing PAM auth tests\n");

        const char *auth_tokens[] = {
                "password",
                NULL
        };

        struct pamtest_conv_data conv_data = {
                .in_echo_off = auth_tokens
        };

        struct pam_testcase tests[] = {
                pam_test (PAMTEST_AUTHENTICATE, PAM_SUCCESS)
        };

        g_assert_true (g_socket_service_is_active (test->service));
        ret = run_pamtest (SERVICE, g_get_user_name (), &conv_data, tests, NULL);
        g_assert_cmpint (ret, ==, PAMTEST_ERR_OK);

        return NULL;
}

static void
mock_service (void)
{
        GError *error = NULL;
        Test *test;

        g_printf ("Starting mock service\n");

        test = g_malloc (sizeof (Test));
        test->success = FALSE;

        g_mkdtemp (dir_path);
        g_setenv ("GNOME_KEYRING_CONTROL", dir_path, TRUE);
        test->control_path = g_strconcat (dir_path, "/control", NULL);

        test->address = g_unix_socket_address_new (test->control_path);
        test->service = g_socket_service_new ();
        g_socket_service_stop (test->service);
        g_assert_false (g_socket_service_is_active (test->service));

        g_signal_connect (test->service,
                          "incoming",
                          G_CALLBACK (is_bytes_exchanged),
                          test);

        g_socket_listener_add_address (G_SOCKET_LISTENER (test->service),
                                       test->address,
                                       G_SOCKET_TYPE_STREAM,
                                       G_SOCKET_PROTOCOL_DEFAULT,
                                       NULL,
                                       NULL,
                                       &error);
        g_assert_no_error (error);

        g_socket_service_start (test->service);
        g_assert_true (g_socket_service_is_active (test->service));

        test->pam_test = g_thread_new ("pam_test", pam_auth_tests, test);

        do
                g_main_context_iteration (NULL, TRUE);
        while (!test->success);

        teardown (test);
}

int
main(int argc,
     char *argv[])
{
        g_test_init (&argc, &argv, NULL);
        g_test_add_func ("/pam/test_pam_authtok", mock_service);

        return g_test_run();
}
