/*
 * libsecret
 *
 * Copyright (C) 2018 Red Hat, Inc.
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
 * Author: Daiki Ueno
 */

#ifndef EGG_JWE_H_
#define EGG_JWE_H_

#include <json-glib/json-glib.h>

JsonNode *
egg_jwe_symmetric_encrypt (const guchar  *input,
                           gsize          n_input,
                           const gchar   *enc,
                           GBytes        *key,
                           GError       **error);

guchar *
egg_jwe_symmetric_decrypt (JsonNode  *root,
                           GBytes    *key,
                           gsize     *length,
                           GError   **error);

#endif
