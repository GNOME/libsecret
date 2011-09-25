/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-secure-memory.h - library for allocating memory that is non-pageable

   Copyright (C) 2007 Stefan Walter

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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef EGG_SECURE_MEMORY_H
#define EGG_SECURE_MEMORY_H

#include <stdlib.h>

/* -------------------------------------------------------------------
 * Low Level Secure Memory 
 * 
 * IMPORTANT: This is pure vanila standard C, no glib. We need this 
 * because certain consumers of this protocol need to be built 
 * without linking in any special libraries. ie: the PKCS#11 module.
 * 
 * Thread locking
 * 
 * In order to use these functions in a module the following functions
 * must be defined somewhere, and provide appropriate locking for 
 * secure memory between threads:
 */
 
extern void   egg_memory_lock (void);

extern void   egg_memory_unlock (void);

/*
 * Allocation Fallbacks
 * 
 * If we cannot allocate secure memory, then this function
 * (defined elsewhere) will be called which has a chance to 
 * allocate other memory abort or do whatever.
 * 
 * Same call semantics as realloc with regard to NULL and zeros 
 */
extern void*  egg_memory_fallback (void *p, size_t length);

#define EGG_SECURE_GLIB_DEFINITIONS() \
	static GStaticMutex memory_mutex = G_STATIC_MUTEX_INIT; \
	void egg_memory_lock (void) \
		{ g_static_mutex_lock (&memory_mutex); } \
	void egg_memory_unlock (void) \
		{ g_static_mutex_unlock (&memory_mutex); } \
	void* egg_memory_fallback (void *p, size_t sz) \
		{ return g_realloc (p, sz); } \

/* 
 * Main functionality
 *  
 * Allocations return NULL on failure.
 */ 
 
#define EGG_SECURE_USE_FALLBACK     0x0001

#define EGG_SECURE_DECLARE(tag) \
	static inline void* egg_secure_alloc (size_t length) { \
		return egg_secure_alloc_full (G_STRINGIFY (tag), length, EGG_SECURE_USE_FALLBACK); \
	} \
	static inline void* egg_secure_realloc (void *p, size_t length) { \
		return egg_secure_realloc_full (G_STRINGIFY (tag), p, length, EGG_SECURE_USE_FALLBACK); \
	} \
	static inline void* egg_secure_strdup (const char *str) { \
		return egg_secure_strdup_full (G_STRINGIFY (tag), str, EGG_SECURE_USE_FALLBACK); \
	}

void*  egg_secure_alloc_full   (const char *tag, size_t length, int options);

void*  egg_secure_realloc_full (const char *tag, void *p, size_t length, int options);

void   egg_secure_free         (void* p); 

void   egg_secure_free_full    (void* p, int fallback); 

void   egg_secure_clear        (void *p, size_t length);

int    egg_secure_check        (const void* p); 

void   egg_secure_validate     (void);

char*  egg_secure_strdup_full  (const char *tag, const char *str, int options);

void   egg_secure_strclear     (char *str);

void   egg_secure_strfree      (char *str);

typedef struct {
	const char *tag;
	size_t request_length;
	size_t block_length;
} egg_secure_rec;

egg_secure_rec *   egg_secure_records    (unsigned int *count);

#endif /* EGG_SECURE_MEMORY_H */
