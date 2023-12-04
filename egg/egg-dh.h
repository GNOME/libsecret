/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
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

#ifndef EGG_DH_H_
#define EGG_DH_H_

#include <glib.h>

typedef struct egg_dh_params egg_dh_params;
typedef struct egg_dh_pubkey egg_dh_pubkey;
typedef struct egg_dh_privkey egg_dh_privkey;

typedef struct egg_dh_group {
	const gchar *name;
	guint bits;
	const guchar *prime;
	gsize n_prime;
	const guchar base[1];
	gsize n_base;
} egg_dh_group;

extern const egg_dh_group egg_dh_groups[];

egg_dh_params *egg_dh_default_params        (const gchar *name);

gboolean       egg_dh_default_params_raw    (const gchar *name,
                                             gconstpointer *prime,
                                             gsize *n_prime,
                                             gconstpointer *base,
                                             gsize *n_base);

gboolean       egg_dh_gen_pair              (egg_dh_params *params,
                                             guint bits,
                                             egg_dh_pubkey **pub,
                                             egg_dh_privkey **priv);

GBytes        *egg_dh_gen_secret            (egg_dh_pubkey *peer,
                                             egg_dh_privkey *priv,
                                             egg_dh_params *prime);

void           egg_dh_params_free           (egg_dh_params *params);
void           egg_dh_pubkey_free           (egg_dh_pubkey *pubkey);
void           egg_dh_privkey_free          (egg_dh_privkey *privkey);

GBytes        *egg_dh_pubkey_export         (const egg_dh_pubkey *pubkey);
egg_dh_pubkey *egg_dh_pubkey_new_from_bytes (const egg_dh_params *params,
					     GBytes *bytes);

#endif /* EGG_DH_H_ */
