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
   see <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

/*
 * IMPORTANT: This is pure vanila standard C, no glib. We need this
 * because certain consumers of this protocol need to be built
 * without linking in any special libraries. ie: the PKCS#11 module.
 */

#include "config.h"

#include "egg-secure-memory.h"

#include <sys/types.h>
#include <sys/mman.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#ifdef WITH_VALGRIND
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>
#endif

#define DEBUG_SECURE_MEMORY 0

#if DEBUG_SECURE_MEMORY
#define DEBUG_ALLOC(msg, n) 	fprintf(stderr, "%s %lu bytes\n", msg, n);
#else
#define DEBUG_ALLOC(msg, n)
#endif

#define DEFAULT_BLOCK_SIZE 16384

/* Use our own assert to guarantee no glib allocations */
#ifndef ASSERT
#ifdef G_DISABLE_ASSERT
#define ASSERT(x)
#else
#define ASSERT(x) assert(x)
#endif
#endif

#define DO_LOCK() \
	EGG_SECURE_GLOBALS.lock ();

#define DO_UNLOCK() \
	EGG_SECURE_GLOBALS.unlock ();

static int show_warning = 1;
int egg_secure_warnings = 1;

/*
 * We allocate all memory in units of sizeof(void*). This
 * is our definition of 'word'.
 */
typedef void* word_t;

/* The amount of extra words we can allocate */
#define WASTE   4

/*
 * Track allocated memory or a free block. This structure is not stored
 * in the secure memory area. It is allocated from a pool of other
 * memory. See meta_pool_xxx ().
 */
typedef struct _Cell {
	word_t *words;          /* Pointer to secure memory */
	size_t n_words;         /* Amount of secure memory in words */
	size_t requested;       /* Amount actually requested by app, in bytes, 0 if unused */
	const char *tag;        /* Tag which describes the allocation */
	struct _Cell *next;     /* Next in memory ring */
	struct _Cell *prev;     /* Previous in memory ring */
} Cell;

/*
 * A block of secure memory. This structure is the header in that block.
 */
typedef struct _Block {
	word_t *words;              /* Actual memory hangs off here */
	size_t n_words;             /* Number of words in block */
	size_t n_used;              /* Number of used allocations */
	struct _Cell* used_cells;   /* Ring of used allocations */
	struct _Cell* unused_cells; /* Ring of unused allocations */
	struct _Block *next;        /* Next block in list */
} Block;

/* -----------------------------------------------------------------------------
 * UNUSED STACK
 */

static inline void
unused_push (void **stack, void *ptr)
{
	ASSERT (ptr);
	ASSERT (stack);
	*((void**)ptr) = *stack;
	*stack = ptr;
}

static inline void*
unused_pop (void **stack)
{
	void *ptr;
	ASSERT (stack);
	ptr = *stack;
	*stack = *(void**)ptr;
	return ptr;

}

static inline void*
unused_peek (void **stack)
{
	ASSERT (stack);
	return *stack;
}

/* -----------------------------------------------------------------------------
 * POOL META DATA ALLOCATION
 *
 * A pool for memory meta data. We allocate fixed size blocks. There are actually
 * two different structures stored in this pool: Cell and Block. Cell is allocated
 * way more often, and is bigger so we just allocate that size for both.
 */

/* Pool allocates this data type */
typedef union _Item {
		Cell cell;
		Block block;
} Item;

typedef struct _Pool {
	struct _Pool *next;    /* Next pool in list */
	size_t length;         /* Length in bytes of the pool */
	size_t used;           /* Number of cells used in pool */
	void *unused;          /* Unused stack of unused stuff */
	size_t n_items;        /* Total number of items in pool */
	Item items[1];         /* Actual items hang off here */
} Pool;

static void *
pool_alloc (void)
{
	Pool *pool;
	void *pages, *item;
	size_t len, i;

	if (!EGG_SECURE_GLOBALS.pool_version ||
	    strcmp (EGG_SECURE_GLOBALS.pool_version, EGG_SECURE_POOL_VER_STR) != 0) {
		if (show_warning && egg_secure_warnings)
			fprintf (stderr, "the secure memory pool version does not match the code '%s' != '%s'\n",
			         EGG_SECURE_GLOBALS.pool_version ? EGG_SECURE_GLOBALS.pool_version : "(null)",
			         EGG_SECURE_POOL_VER_STR);
		show_warning = 0;
		return NULL;
	}

	/* A pool with an available item */
	for (pool = EGG_SECURE_GLOBALS.pool_data; pool; pool = pool->next) {
		if (unused_peek (&pool->unused))
			break;
	}

	/* Create a new pool */
	if (pool == NULL) {
		len = getpagesize () * 2;
		pages = mmap (0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if (pages == MAP_FAILED)
			return NULL;

		/* Fill in the block header, and inlude in block list */
		pool = pages;
		pool->next = EGG_SECURE_GLOBALS.pool_data;
		EGG_SECURE_GLOBALS.pool_data = pool;
		pool->length = len;
		pool->used = 0;
		pool->unused = NULL;

		/* Fill block with unused items */
		pool->n_items = (len - sizeof (Pool)) / sizeof (Item);
		for (i = 0; i < pool->n_items; ++i)
			unused_push (&pool->unused, pool->items + i);

#ifdef WITH_VALGRIND
		VALGRIND_CREATE_MEMPOOL(pool, 0, 0);
#endif
	}

	++pool->used;
	ASSERT (unused_peek (&pool->unused));
	item = unused_pop (&pool->unused);

#ifdef WITH_VALGRIND
	VALGRIND_MEMPOOL_ALLOC (pool, item, sizeof (Item));
#endif

	return memset (item, 0, sizeof (Item));
}

static void
pool_free (void* item)
{
	Pool *pool, **at;
	char *ptr, *beg, *end;

	ptr = item;

	/* Find which block this one belongs to */
	for (at = (Pool **)&EGG_SECURE_GLOBALS.pool_data, pool = *at;
	     pool != NULL; at = &pool->next, pool = *at) {
		beg = (char*)pool->items;
		end = (char*)pool + pool->length - sizeof (Item);
		if (ptr >= beg && ptr <= end) {
			ASSERT ((ptr - beg) % sizeof (Item) == 0);
			break;
		}
	}

	/* Otherwise invalid meta */
	ASSERT (at);
	ASSERT (pool);
	ASSERT (pool->used > 0);

	/* No more meta cells used in this block, remove from list, destroy */
	if (pool->used == 1) {
		*at = pool->next;

#ifdef WITH_VALGRIND
		VALGRIND_DESTROY_MEMPOOL (pool);
#endif

		munmap (pool, pool->length);
		return;
	}

#ifdef WITH_VALGRIND
	VALGRIND_MEMPOOL_FREE (pool, item);
	VALGRIND_MAKE_MEM_UNDEFINED (item, sizeof (Item));
#endif

	--pool->used;
	memset (item, 0xCD, sizeof (Item));
	unused_push (&pool->unused, item);
}

#ifndef G_DISABLE_ASSERT

static int
pool_valid (void* item)
{
	Pool *pool;
	char *ptr, *beg, *end;

	ptr = item;

	/* Find which block this one belongs to */
	for (pool = EGG_SECURE_GLOBALS.pool_data; pool; pool = pool->next) {
		beg = (char*)pool->items;
		end = (char*)pool + pool->length - sizeof (Item);
		if (ptr >= beg && ptr <= end)
			return (pool->used && (ptr - beg) % sizeof (Item) == 0);
	}

	return 0;
}

#endif /* G_DISABLE_ASSERT */

/* -----------------------------------------------------------------------------
 * SEC ALLOCATION
 *
 * Each memory cell begins and ends with a pointer to its metadata. These are also
 * used as guards or red zones. Since they're treated as redzones by valgrind we
 * have to jump through a few hoops before reading and/or writing them.
 */

static inline size_t
sec_size_to_words (size_t length)
{
	return (length % sizeof (void*) ? 1 : 0) + (length / sizeof (void*));
}

static inline void
sec_write_guards (Cell *cell)
{
#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_UNDEFINED (cell->words, sizeof (word_t));
	VALGRIND_MAKE_MEM_UNDEFINED (cell->words + cell->n_words - 1, sizeof (word_t));
#endif

	((void**)cell->words)[0] = (void*)cell;
	((void**)cell->words)[cell->n_words - 1] = (void*)cell;

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_NOACCESS (cell->words, sizeof (word_t));
	VALGRIND_MAKE_MEM_NOACCESS (cell->words + cell->n_words - 1, sizeof (word_t));
#endif
}

static inline void
sec_check_guards (Cell *cell)
{
#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_DEFINED (cell->words, sizeof (word_t));
	VALGRIND_MAKE_MEM_DEFINED (cell->words + cell->n_words - 1, sizeof (word_t));
#endif

	ASSERT(((void**)cell->words)[0] == (void*)cell);
	ASSERT(((void**)cell->words)[cell->n_words - 1] == (void*)cell);

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_NOACCESS (cell->words, sizeof (word_t));
	VALGRIND_MAKE_MEM_NOACCESS (cell->words + cell->n_words - 1, sizeof (word_t));
#endif
}

static void
sec_insert_cell_ring (Cell **ring, Cell *cell)
{
	ASSERT (ring);
	ASSERT (cell);
	ASSERT (cell != *ring);
	ASSERT (cell->next == NULL);
	ASSERT (cell->prev == NULL);

	/* Insert back into the mix of available memory */
	if (*ring) {
		cell->next = (*ring)->next;
		cell->prev = *ring;
		cell->next->prev = cell;
		cell->prev->next = cell;
	} else {
		cell->next = cell;
		cell->prev = cell;
	}

	*ring = cell;
	ASSERT (cell->next->prev == cell);
	ASSERT (cell->prev->next == cell);
}

static void
sec_remove_cell_ring (Cell **ring, Cell *cell)
{
	ASSERT (ring);
	ASSERT (*ring);
	ASSERT (cell->next);
	ASSERT (cell->prev);

	ASSERT (cell->next->prev == cell);
	ASSERT (cell->prev->next == cell);

	if (cell == *ring) {
		/* The last meta? */
		if (cell->next == cell) {
			ASSERT (cell->prev == cell);
			*ring = NULL;

		/* Just pointing to this meta */
		} else {
			ASSERT (cell->prev != cell);
			*ring = cell->next;
		}
	}

	cell->next->prev = cell->prev;
	cell->prev->next = cell->next;
	cell->next = cell->prev = NULL;

	ASSERT (*ring != cell);
}

static inline void*
sec_cell_to_memory (Cell *cell)
{
	return cell->words + 1;
}

static inline int
sec_is_valid_word (Block *block, word_t *word)
{
	return (word >= block->words && word < block->words + block->n_words);
}

static inline void
sec_clear_undefined (void *memory,
                     size_t from,
                     size_t to)
{
	char *ptr = memory;
	ASSERT (from <= to);
#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_UNDEFINED (ptr + from, to - from);
#endif
	memset (ptr + from, 0, to - from);
#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_UNDEFINED (ptr + from, to - from);
#endif
}
static inline void
sec_clear_noaccess (void *memory, size_t from, size_t to)
{
	char *ptr = memory;
	ASSERT (from <= to);
#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_UNDEFINED (ptr + from, to - from);
#endif
	memset (ptr + from, 0, to - from);
#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_NOACCESS (ptr + from, to - from);
#endif
}

static Cell*
sec_neighbor_before (Block *block, Cell *cell)
{
	word_t *word;

	ASSERT (cell);
	ASSERT (block);

	word = cell->words - 1;
	if (!sec_is_valid_word (block, word))
		return NULL;

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_DEFINED (word, sizeof (word_t));
#endif

	cell = *word;
	sec_check_guards (cell);

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_NOACCESS (word, sizeof (word_t));
#endif

	return cell;
}

static Cell*
sec_neighbor_after (Block *block, Cell *cell)
{
	word_t *word;

	ASSERT (cell);
	ASSERT (block);

	word = cell->words + cell->n_words;
	if (!sec_is_valid_word (block, word))
		return NULL;

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_DEFINED (word, sizeof (word_t));
#endif

	cell = *word;
	sec_check_guards (cell);

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_NOACCESS (word, sizeof (word_t));
#endif

	return cell;
}

static void*
sec_alloc (Block *block,
           const char *tag,
           size_t length)
{
	Cell *cell, *other;
	size_t n_words;
	void *memory;

	ASSERT (block);
	ASSERT (length);
	ASSERT (tag);

	if (!block->unused_cells)
		return NULL;

	/*
	 * Each memory allocation is aligned to a pointer size, and
	 * then, sandwidched between two pointers to its meta data.
	 * These pointers also act as guards.
	 *
	 * We allocate memory in units of sizeof (void*)
	 */

	n_words = sec_size_to_words (length) + 2;

	/* Look for a cell of at least our required size */
	cell = block->unused_cells;
	while (cell->n_words < n_words) {
		cell = cell->next;
		if (cell == block->unused_cells) {
			cell = NULL;
			break;
		}
	}

	if (!cell)
		return NULL;

	ASSERT (cell->tag == NULL);
	ASSERT (cell->requested == 0);
	ASSERT (cell->prev);
	ASSERT (cell->words);
	sec_check_guards (cell);

	/* Steal from the cell if it's too long */
	if (cell->n_words > n_words + WASTE) {
		other = pool_alloc ();
		if (!other)
			return NULL;
		other->n_words = n_words;
		other->words = cell->words;
		cell->n_words -= n_words;
		cell->words += n_words;

		sec_write_guards (other);
		sec_write_guards (cell);

		cell = other;
	}

	if (cell->next)
		sec_remove_cell_ring (&block->unused_cells, cell);

	++block->n_used;
	cell->tag = tag;
	cell->requested = length;
	sec_insert_cell_ring (&block->used_cells, cell);
	memory = sec_cell_to_memory (cell);

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_UNDEFINED (memory, length);
#endif

	return memset (memory, 0, length);
}

static void*
sec_free (Block *block, void *memory)
{
	Cell *cell, *other;
	word_t *word;

	ASSERT (block);
	ASSERT (memory);

	word = memory;
	--word;

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_DEFINED (word, sizeof (word_t));
#endif

	/* Lookup the meta for this memory block (using guard pointer) */
	ASSERT (sec_is_valid_word (block, word));
	ASSERT (pool_valid (*word));
	cell = *word;

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_DEFINED (cell->words, cell->n_words * sizeof (word_t));
#endif

	sec_check_guards (cell);
	sec_clear_noaccess (memory, 0, cell->requested);

	sec_check_guards (cell);
	ASSERT (cell->requested > 0);
	ASSERT (cell->tag != NULL);

	/* Remove from the used cell ring */
	sec_remove_cell_ring (&block->used_cells, cell);

	/* Find previous unallocated neighbor, and merge if possible */
	other = sec_neighbor_before (block, cell);
	if (other && other->requested == 0) {
		ASSERT (other->tag == NULL);
		ASSERT (other->next && other->prev);
		other->n_words += cell->n_words;
		sec_write_guards (other);
		pool_free (cell);
		cell = other;
	}

	/* Find next unallocated neighbor, and merge if possible */
	other = sec_neighbor_after (block, cell);
	if (other && other->requested == 0) {
		ASSERT (other->tag == NULL);
		ASSERT (other->next && other->prev);
		other->n_words += cell->n_words;
		other->words = cell->words;
		if (cell->next)
			sec_remove_cell_ring (&block->unused_cells, cell);
		sec_write_guards (other);
		pool_free (cell);
		cell = other;
	}

	/* Add to the unused list if not already there */
	if (!cell->next)
		sec_insert_cell_ring (&block->unused_cells, cell);

	cell->tag = NULL;
	cell->requested = 0;
	--block->n_used;
	return NULL;
}

static void
memcpy_with_vbits (void *dest,
                   void *src,
                   size_t length)
{
#ifdef WITH_VALGRIND
	int vbits_setup = 0;
	void *vbits = NULL;

	if (RUNNING_ON_VALGRIND) {
		vbits = malloc (length);
		if (vbits != NULL)
			vbits_setup = VALGRIND_GET_VBITS (src, vbits, length);
		VALGRIND_MAKE_MEM_DEFINED (src, length);
	}
#endif

	memcpy (dest, src, length);

#ifdef WITH_VALGRIND
	if (vbits_setup == 1) {
		VALGRIND_SET_VBITS (dest, vbits, length);
		VALGRIND_SET_VBITS (src, vbits, length);
	}
	free (vbits);
#endif
}

static void*
sec_realloc (Block *block,
             const char *tag,
             void *memory,
             size_t length)
{
	Cell *cell, *other;
	word_t *word;
	size_t n_words;
	size_t valid;
	void *alloc;

	/* Standard realloc behavior, should have been handled elsewhere */
	ASSERT (memory != NULL);
	ASSERT (length > 0);
	ASSERT (tag != NULL);

	/* Dig out where the meta should be */
	word = memory;
	--word;

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_DEFINED (word, sizeof (word_t));
#endif

	ASSERT (sec_is_valid_word (block, word));
	ASSERT (pool_valid (*word));
	cell = *word;

	/* Validate that it's actually for real */
	sec_check_guards (cell);
	ASSERT (cell->requested > 0);
	ASSERT (cell->tag != NULL);

	/* The amount of valid data */
	valid = cell->requested;

	/* How many words we actually want */
	n_words = sec_size_to_words (length) + 2;

	/* Less memory is required than is in the cell */
	if (n_words <= cell->n_words) {

		/* TODO: No shrinking behavior yet */
		cell->requested = length;
		alloc = sec_cell_to_memory (cell);

		/*
		 * Even though we may be reusing the same cell, that doesn't
		 * mean that the allocation is shrinking. It could have shrunk
		 * and is now expanding back some.
		 */
		if (length < valid)
			sec_clear_undefined (alloc, length, valid);

		return alloc;
	}

	/* Need braaaaaiiiiiinsss... */
	while (cell->n_words < n_words) {

		/* See if we have a neighbor who can give us some memory */
		other = sec_neighbor_after (block, cell);
		if (!other || other->requested != 0)
			break;

		/* Eat the whole neighbor if not too big */
		if (n_words - cell->n_words + WASTE >= other->n_words) {
			cell->n_words += other->n_words;
			sec_write_guards (cell);
			sec_remove_cell_ring (&block->unused_cells, other);
			pool_free (other);

		/* Steal from the neighbor */
		} else {
			other->words += n_words - cell->n_words;
			other->n_words -= n_words - cell->n_words;
			sec_write_guards (other);
			cell->n_words = n_words;
			sec_write_guards (cell);
		}
	}

	if (cell->n_words >= n_words) {
		cell->requested = length;
		cell->tag = tag;
		alloc = sec_cell_to_memory (cell);
		sec_clear_undefined (alloc, valid, length);
		return alloc;
	}

	/* That didn't work, try alloc/free */
	alloc = sec_alloc (block, tag, length);
	if (alloc) {
		memcpy_with_vbits (alloc, memory, valid);
		sec_free (block, memory);
	}

	return alloc;
}


static size_t
sec_allocated (Block *block, void *memory)
{
	Cell *cell;
	word_t *word;

	ASSERT (block);
	ASSERT (memory);

	word = memory;
	--word;

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_DEFINED (word, sizeof (word_t));
#endif

	/* Lookup the meta for this memory block (using guard pointer) */
	ASSERT (sec_is_valid_word (block, word));
	ASSERT (pool_valid (*word));
	cell = *word;

	sec_check_guards (cell);
	ASSERT (cell->requested > 0);
	ASSERT (cell->tag != NULL);

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_NOACCESS (word, sizeof (word_t));
#endif

	return cell->requested;
}

static void
sec_validate (Block *block)
{
	Cell *cell;
	word_t *word, *last;

#ifdef WITH_VALGRIND
	if (RUNNING_ON_VALGRIND)
		return;
#endif

	word = block->words;
	last = word + block->n_words;

	for (;;) {
		ASSERT (word < last);

		ASSERT (sec_is_valid_word (block, word));
		ASSERT (pool_valid (*word));
		cell = *word;

		/* Validate that it's actually for real */
		sec_check_guards (cell);

		/* Is it an allocated block? */
		if (cell->requested > 0) {
			ASSERT (cell->tag != NULL);
			ASSERT (cell->next != NULL);
			ASSERT (cell->prev != NULL);
			ASSERT (cell->next->prev == cell);
			ASSERT (cell->prev->next == cell);
			ASSERT (cell->requested <= (cell->n_words - 2) * sizeof (word_t));

		/* An unused block */
		} else {
			ASSERT (cell->tag == NULL);
			ASSERT (cell->next != NULL);
			ASSERT (cell->prev != NULL);
			ASSERT (cell->next->prev == cell);
			ASSERT (cell->prev->next == cell);
		}

		word += cell->n_words;
		if (word == last)
			break;
	}
}

/* -----------------------------------------------------------------------------
 * LOCKED MEMORY
 */

static void*
sec_acquire_pages (size_t *sz,
                   const char *during_tag)
{
	void *pages;
	unsigned long pgsize;

	ASSERT (sz);
	ASSERT (*sz);
	ASSERT (during_tag);

	/* Make sure sz is a multiple of the page size */
	pgsize = getpagesize ();
	*sz = (*sz + pgsize -1) & ~(pgsize - 1);

#if defined(HAVE_MLOCK)
	pages = mmap (0, *sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (pages == MAP_FAILED) {
		if (show_warning && egg_secure_warnings)
			fprintf (stderr, "couldn't map %lu bytes of memory (%s): %s\n",
			         (unsigned long)*sz, during_tag, strerror (errno));
		show_warning = 0;
		return NULL;
	}

	if (mlock (pages, *sz) < 0) {
		if (show_warning && egg_secure_warnings && errno != EPERM) {
			fprintf (stderr, "couldn't lock %lu bytes of memory (%s): %s\n",
			         (unsigned long)*sz, during_tag, strerror (errno));
			show_warning = 0;
		}
		munmap (pages, *sz);
		return NULL;
	}

	DEBUG_ALLOC ("gkr-secure-memory: new block ", *sz);

	show_warning = 1;
	return pages;

#else
	if (show_warning && egg_secure_warnings)
		fprintf (stderr, "your system does not support private memory");
	show_warning = 0;
	return NULL;
#endif

}

static void
sec_release_pages (void *pages, size_t sz)
{
	ASSERT (pages);
	ASSERT (sz % getpagesize () == 0);

#if defined(HAVE_MLOCK)
	if (munlock (pages, sz) < 0 && egg_secure_warnings)
		fprintf (stderr, "couldn't unlock private memory: %s\n", strerror (errno));

	if (munmap (pages, sz) < 0 && egg_secure_warnings)
		fprintf (stderr, "couldn't unmap private anonymous memory: %s\n", strerror (errno));

	DEBUG_ALLOC ("gkr-secure-memory: freed block ", sz);

#else
	ASSERT (FALSE);
#endif
}

/* -----------------------------------------------------------------------------
 * MANAGE DIFFERENT BLOCKS
 */

static Block *all_blocks = NULL;

static Block*
sec_block_create (size_t size,
                  const char *during_tag)
{
	Block *block;
	Cell *cell;

	ASSERT (during_tag);

	/* We can force all all memory to be malloced */
	if (getenv ("SECMEM_FORCE_FALLBACK"))
		return NULL;

	block = pool_alloc ();
	if (!block)
		return NULL;

	cell = pool_alloc ();
	if (!cell) {
		pool_free (block);
		return NULL;
	}

	/* The size above is a minimum, we're free to go bigger */
	if (size < DEFAULT_BLOCK_SIZE)
		size = DEFAULT_BLOCK_SIZE;

	block->words = sec_acquire_pages (&size, during_tag);
	block->n_words = size / sizeof (word_t);
	if (!block->words) {
		pool_free (block);
		pool_free (cell);
		return NULL;
	}

#ifdef WITH_VALGRIND
	VALGRIND_MAKE_MEM_DEFINED (block->words, size);
#endif

	/* The first cell to allocate from */
	cell->words = block->words;
	cell->n_words = block->n_words;
	cell->requested = 0;
	sec_write_guards (cell);
	sec_insert_cell_ring (&block->unused_cells, cell);

	block->next = all_blocks;
	all_blocks = block;

	return block;
}

static void
sec_block_destroy (Block *block)
{
	Block *bl, **at;
	Cell *cell;

	ASSERT (block);
	ASSERT (block->words);
	ASSERT (block->n_used == 0);

	/* Remove from the list */
	for (at = &all_blocks, bl = *at; bl; at = &bl->next, bl = *at) {
		if (bl == block) {
			*at = block->next;
			break;
		}
	}

	/* Must have been found */
	ASSERT (bl == block);
	ASSERT (block->used_cells == NULL);

	/* Release all the meta data cells */
	while (block->unused_cells) {
		cell = block->unused_cells;
		sec_remove_cell_ring (&block->unused_cells, cell);
		pool_free (cell);
	}

	/* Release all pages of secure memory */
	sec_release_pages (block->words, block->n_words * sizeof (word_t));

	pool_free (block);
}

/* ------------------------------------------------------------------------
 * PUBLIC FUNCTIONALITY
 */

void*
egg_secure_alloc_full (const char *tag,
                       size_t length,
                       int flags)
{
	Block *block;
	void *memory = NULL;

	if (tag == NULL)
		tag = "?";

	if (length > 0xFFFFFFFF / 2) {
		if (egg_secure_warnings)
			fprintf (stderr, "tried to allocate an insane amount of memory: %lu\n",
			         (unsigned long)length);
		return NULL;
	}

	/* Can't allocate zero bytes */
	if (length == 0)
		return NULL;

	DO_LOCK ();

		for (block = all_blocks; block; block = block->next) {
			memory = sec_alloc (block, tag, length);
			if (memory)
				break;
		}

		/* None of the current blocks have space, allocate new */
		if (!memory) {
			block = sec_block_create (length, tag);
			if (block)
				memory = sec_alloc (block, tag, length);
		}

#ifdef WITH_VALGRIND
		if (memory != NULL)
			VALGRIND_MALLOCLIKE_BLOCK (memory, length, sizeof (void*), 1);
#endif

	DO_UNLOCK ();

	if (!memory && (flags & EGG_SECURE_USE_FALLBACK) && EGG_SECURE_GLOBALS.fallback != NULL) {
		memory = EGG_SECURE_GLOBALS.fallback (NULL, length);
		if (memory) /* Our returned memory is always zeroed */
			memset (memory, 0, length);
	}

	if (!memory)
		errno = ENOMEM;

	return memory;
}

void*
egg_secure_realloc_full (const char *tag,
                         void *memory,
                         size_t length,
                         int flags)
{
	Block *block = NULL;
	size_t previous = 0;
	int donew = 0;
	void *alloc = NULL;

	if (tag == NULL)
		tag = "?";

	if (length > 0xFFFFFFFF / 2) {
		if (egg_secure_warnings)
			fprintf (stderr, "tried to allocate an insane amount of memory: %lu\n",
			         (unsigned long)length);
		return NULL;
	}

	if (memory == NULL)
		return egg_secure_alloc_full (tag, length, flags);
	if (!length) {
		egg_secure_free_full (memory, flags);
		return NULL;
	}

	DO_LOCK ();

		/* Find out where it belongs to */
		for (block = all_blocks; block; block = block->next) {
			if (sec_is_valid_word (block, memory)) {
				previous = sec_allocated (block, memory);

#ifdef WITH_VALGRIND
				/* Let valgrind think we are unallocating so that it'll validate */
				VALGRIND_FREELIKE_BLOCK (memory, sizeof (word_t));
#endif

				alloc = sec_realloc (block, tag, memory, length);

#ifdef WITH_VALGRIND
				/* Now tell valgrind about either the new block or old one */
				VALGRIND_MALLOCLIKE_BLOCK (alloc ? alloc : memory,
				                           alloc ? length : previous,
				                           sizeof (word_t), 1);
#endif
				break;
			}
		}

		/* If it didn't work we may need to allocate a new block */
		if (block && !alloc)
			donew = 1;

		if (block && block->n_used == 0)
			sec_block_destroy (block);

	DO_UNLOCK ();

	if (!block) {
		if ((flags & EGG_SECURE_USE_FALLBACK) && EGG_SECURE_GLOBALS.fallback) {
			/*
			 * In this case we can't zero the returned memory,
			 * because we don't know what the block size was.
			 */
			return EGG_SECURE_GLOBALS.fallback (memory, length);
		} else {
			if (egg_secure_warnings)
				fprintf (stderr, "memory does not belong to secure memory pool: 0x%08lx\n",
				         (unsigned long)memory);
			ASSERT (0 && "memory does does not belong to secure memory pool");
			return NULL;
		}
	}

	if (donew) {
		alloc = egg_secure_alloc_full (tag, length, flags);
		if (alloc) {
			memcpy_with_vbits (alloc, memory, previous);
			egg_secure_free_full (memory, flags);
		}
	}

	if (!alloc)
		errno = ENOMEM;

	return alloc;
}

void
egg_secure_free (void *memory)
{
	egg_secure_free_full (memory, EGG_SECURE_USE_FALLBACK);
}

void
egg_secure_free_full (void *memory, int flags)
{
	Block *block = NULL;

	if (memory == NULL)
		return;

	DO_LOCK ();

		/* Find out where it belongs to */
		for (block = all_blocks; block; block = block->next) {
			if (sec_is_valid_word (block, memory))
				break;
		}

#ifdef WITH_VALGRIND
		/* We like valgrind's warnings, so give it a first whack at checking for errors */
		if (block != NULL || !(flags & EGG_SECURE_USE_FALLBACK))
			VALGRIND_FREELIKE_BLOCK (memory, sizeof (word_t));
#endif

		if (block != NULL) {
			sec_free (block, memory);
			if (block->n_used == 0)
				sec_block_destroy (block);
		}

	DO_UNLOCK ();

	if (!block) {
		if ((flags & EGG_SECURE_USE_FALLBACK) && EGG_SECURE_GLOBALS.fallback) {
			EGG_SECURE_GLOBALS.fallback (memory, 0);
		} else {
			if (egg_secure_warnings)
				fprintf (stderr, "memory does not belong to secure memory pool: 0x%08lx\n",
				         (unsigned long)memory);
			ASSERT (0 && "memory does does not belong to secure memory pool");
		}
	}
}

int
egg_secure_check (const void *memory)
{
	Block *block = NULL;

	DO_LOCK ();

		/* Find out where it belongs to */
		for (block = all_blocks; block; block = block->next) {
			if (sec_is_valid_word (block, (word_t*)memory))
				break;
		}

	DO_UNLOCK ();

	return block == NULL ? 0 : 1;
}

void
egg_secure_validate (void)
{
	Block *block = NULL;

	DO_LOCK ();

		for (block = all_blocks; block; block = block->next)
			sec_validate (block);

	DO_UNLOCK ();
}


static egg_secure_rec *
records_for_ring (Cell *cell_ring,
                  egg_secure_rec *records,
                  unsigned int *count,
                  unsigned int *total)
{
	egg_secure_rec *new_rec;
	unsigned int allocated = *count;
	Cell *cell;

	cell = cell_ring;
	do {
		if (*count >= allocated) {
			new_rec = realloc (records, sizeof (egg_secure_rec) * (allocated + 32));
			if (new_rec == NULL) {
				*count = 0;
				free (records);
				return NULL;
			} else {
				records = new_rec;
				allocated += 32;
			}
		}

		if (cell != NULL) {
			records[*count].request_length = cell->requested;
			records[*count].block_length = cell->n_words * sizeof (word_t);
			records[*count].tag = cell->tag;
			(*count)++;
			(*total) += cell->n_words;
			cell = cell->next;
		}
	} while (cell != NULL && cell != cell_ring);

	return records;
}

egg_secure_rec *
egg_secure_records (unsigned int *count)
{
	egg_secure_rec *records = NULL;
	Block *block = NULL;
	unsigned int total;

	*count = 0;

	DO_LOCK ();

		for (block = all_blocks; block != NULL; block = block->next) {
			total = 0;

			records = records_for_ring (block->unused_cells, records, count, &total);
			if (records == NULL)
				break;
			records = records_for_ring (block->used_cells, records, count, &total);
			if (records == NULL)
				break;

			/* Make sure this actualy accounts for all memory */
			ASSERT (total == block->n_words);
		}

	DO_UNLOCK ();

	return records;
}

char*
egg_secure_strdup_full (const char *tag,
                        const char *str,
                        int options)
{
	size_t len;
	char *res;

	if (!str)
		return NULL;

	len = strlen (str) + 1;
	res = (char *)egg_secure_alloc_full (tag, len, options);
	strcpy (res, str);
	return res;
}

char *
egg_secure_strndup_full (const char *tag,
                         const char *str,
                         size_t length,
                         int options)
{
	size_t len;
	char *res;
	const char *end;

	if (!str)
		return NULL;

	end = memchr (str, '\0', length);
	if (end != NULL)
		length = (end - str);
	len = length + 1;
	res = (char *)egg_secure_alloc_full (tag, len, options);
	memcpy (res, str, len);
	return res;
}

void
egg_secure_clear (void *p, size_t length)
{
	volatile char *vp;

	if (p == NULL)
		return;

        vp = (volatile char*)p;
        while (length) {
	        *vp = 0xAA;
	        vp++;
	        length--;
	}
}

void
egg_secure_strclear (char *str)
{
	if (!str)
		return;
	egg_secure_clear ((unsigned char*)str, strlen (str));
}

void
egg_secure_strfree (char *str)
{
	/*
	 * If we're using unpageable 'secure' memory, then the free call
	 * should zero out the memory, but because on certain platforms
	 * we may be using normal memory, zero it out here just in case.
	 */

	egg_secure_strclear (str);
	egg_secure_free_full (str, EGG_SECURE_USE_FALLBACK);
}
