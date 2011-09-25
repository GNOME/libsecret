/* GSecret - GLib wrapper for Secret Service
 *
 * Copyright 2011 Collabora Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 */


#include "config.h"

#include "gsecret-item.h"
#include "gsecret-service.h"

#include <glib.h>

static void
test_initial (void)
{
	GType type;

	type = gsecret_service_get_type ();
	type += gsecret_item_get_type ();
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_set_prgname ("test-other");

	g_test_add_func ("/initial", test_initial);

	return g_test_run ();
}
