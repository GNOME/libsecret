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

#ifndef EGG_HEX_H_
#define EGG_HEX_H_

#include <glib.h>

gpointer              egg_hex_decode                         (const gchar *data,
                                                              gssize n_data,
                                                              gsize *n_decoded);

gpointer              egg_hex_decode_full                    (const gchar *data,
                                                              gssize n_data,
                                                              const gchar *delim,
                                                              guint group,
                                                              gsize *n_decoded);

gchar*                egg_hex_encode                         (gconstpointer data,
                                                              gsize n_data);

gchar*                egg_hex_encode_full                    (gconstpointer data,
                                                              gsize n_data,
                                                              gboolean upper_case,
                                                              const gchar *delim,
                                                              guint group);

#endif /* EGG_HEX_H_ */
