/* libsecret - GLib wrapper for Secret Service
 *
 * Copyright 2019 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Daiki Ueno
 */

#ifndef EGG_KEYRING1_H_
#define EGG_KEYRING1_H_

#include <glib.h>

#define SALT_SIZE 32
#define ITERATION_COUNT 100000

#define MAC_SIZE 32

#define CIPHER_BLOCK_SIZE 16
#define KEY_SIZE 16
#define IV_SIZE CIPHER_BLOCK_SIZE

void     egg_keyring1_create_nonce  (guint8 *nonce,
                                     gsize nonce_size);

GBytes  *egg_keyring1_derive_key    (const char *password,
				     gsize n_password,
                                     GBytes *salt,
                                     guint32 iteration_count);

gboolean egg_keyring1_calculate_mac (GBytes *key,
                                     const guint8 *value,
				     gsize n_value,
                                     guint8 *buffer);

gboolean egg_keyring1_verify_mac    (GBytes *key,
                                     const guint8 *value,
				     gsize n_value,
                                     const guint8 *data);

gboolean egg_keyring1_decrypt       (GBytes *key,
                                     guint8 *data,
                                     gsize n_data);

gboolean egg_keyring1_encrypt       (GBytes *key,
                                     guint8 *data,
                                     gsize n_data);

#endif /* EGG_KEYRING1_H_ */
