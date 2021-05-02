/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
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
 * Author: Stef Walter <stefw@thewalter.net>
 */

#include "config.h"

#include "egg-libgcrypt.h"
#include "egg-secure-memory.h"

#include <glib.h>

#include <gcrypt.h>

#include <errno.h>

EGG_SECURE_DECLARE (libgcrypt);

static void
log_handler (gpointer unused, int unknown, const gchar *msg, va_list va)
{
	/* TODO: Figure out additional arguments */
	g_logv ("gcrypt", G_LOG_LEVEL_MESSAGE, msg, va);
}

static int 
no_mem_handler (gpointer unused, size_t sz, unsigned int unknown)
{
	/* TODO: Figure out additional arguments */
	g_error ("couldn't allocate %lu bytes of memory", 
	         (unsigned long int)sz);
	return 0;
}

static void
fatal_handler (gpointer unused, int unknown, const gchar *msg)
{
	/* TODO: Figure out additional arguments */
	g_log ("gcrypt", G_LOG_LEVEL_ERROR, "%s", msg);
}

#if GCRYPT_VERSION_NUMBER < 0x010600
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

void
egg_libgcrypt_initialize (void)
{
	static size_t gcrypt_initialized = 0;
	unsigned seed;

	if (g_once_init_enter (&gcrypt_initialized)) {
		
		/* Only initialize libgcrypt if it hasn't already been initialized */
		if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
#if GCRYPT_VERSION_NUMBER < 0x010600
			gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif
			gcry_check_version (LIBGCRYPT_VERSION);
			gcry_set_log_handler (log_handler, NULL);
			gcry_set_outofcore_handler (no_mem_handler, NULL);
			gcry_set_fatalerror_handler (fatal_handler, NULL);
			gcry_set_allocation_handler ((gcry_handler_alloc_t)g_malloc, 
			                             (gcry_handler_alloc_t)egg_secure_alloc, 
			                             egg_secure_check, 
			                             (gcry_handler_realloc_t)egg_secure_realloc, 
			                             egg_secure_free);
			gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
		}
		
		gcry_create_nonce (&seed, sizeof (seed));
		srand (seed);

		g_once_init_leave (&gcrypt_initialized, 1);
	}
}
