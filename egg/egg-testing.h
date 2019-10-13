/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Stefan Walter
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

#ifndef EGG_TESTING_H_
#define EGG_TESTING_H_

#include <glib.h>
#include <string.h>

#define egg_assert_cmpsize(a, o, b) \
	g_assert_cmpuint ((guint)(a), o, (guint)(b))

#define egg_assert_cmpmem(a, na, cmp, b, nb) \
	do { gconstpointer __p1 = (a), __p2 = (b); gsize __n1 = (na), __n2 = (nb); \
	     if (__n1 cmp __n2 && memcmp (__p1, __p2, __n1) cmp 0) ; else \
	        egg_assertion_message_cmpmem (G_LOG_DOMAIN, __FILE__, __LINE__, \
	            G_STRFUNC, #a "[" #na"] " #cmp " " #b "[" #nb "]", \
                    __p1, __n1, #cmp, __p2, __n2); } while (0)

void       egg_assertion_message_cmpmem        (const char *domain, const char *file,
                                                int line, const char *func,
                                                const char *expr, gconstpointer arg1,
                                                gsize n_arg1, const char *cmp,
                                                gconstpointer arg2, gsize n_arg2);

gchar *    egg_test_escape_data                (const guchar *data,
                                                gsize size);

void       egg_test_wait_stop                  (void);

#define    egg_test_wait()                     g_assert_true (egg_test_wait_until (20000))

gboolean   egg_test_wait_until                 (int timeout);

void       egg_test_wait_idle                  (void);

gint       egg_tests_run_with_loop             (void);

void       egg_tests_copy_scratch_file         (const gchar *directory,
                                                const gchar *file_to_copy);

gchar *    egg_tests_create_scratch_directory  (const gchar *file_to_copy,
                                                ...) G_GNUC_NULL_TERMINATED;

void       egg_tests_remove_scratch_directory  (const gchar *directory);

#endif /* EGG_TESTING_H_ */
