/* libsecret - TSS interface for libsecret
 *
 * Copyright (C) 2021 Dhanuka Warusadura
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 *
 * Author: Dhanuka Warusadura
*/

#ifndef EGG_TPM2_H_
#define EGG_TPM2_H_

#include <glib.h>
#include <gio/gio.h>

typedef struct EggTpm2Context EggTpm2Context;

EggTpm2Context *egg_tpm2_initialize               (GError **);
void           egg_tpm2_finalize                  (EggTpm2Context *);
GBytes         *egg_tpm2_generate_master_password (EggTpm2Context *,
		                                   GError **);
GBytes         *egg_tpm2_decrypt_master_password  (EggTpm2Context *,
		                                   GBytes *,
						   GError **);

#endif
