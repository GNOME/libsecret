/* libsecret - Test TSS interface for libsecret
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

#include "egg-tpm2.h"

void
test_egg_tpm2_generate_master_password(void)
{
	EggTpm2Context *context;
	GBytes *result;

	GError *error = NULL;
	g_assert_no_error(error);
	context = egg_tpm2_initialize(&error);
	g_assert_nonnull(context);
	result = egg_tpm2_generate_master_password(context, &error);
	g_assert_nonnull(result);
	egg_tpm2_finalize(context);
	g_bytes_unref(result);
}

void
test_egg_tpm2_decrypt_master_password(void)
{
	EggTpm2Context *context;
	GBytes *result, *decrypted1, *decrypted2;

	GError *error = NULL;
	g_assert_no_error(error);
	context = egg_tpm2_initialize(&error);
	g_assert_nonnull(context);
	result = egg_tpm2_generate_master_password(context, &error);
	g_assert_nonnull(result);
	egg_tpm2_finalize(context);

	context = egg_tpm2_initialize(&error);
	decrypted1 = egg_tpm2_decrypt_master_password(context, result,
						      &error);
	g_assert_nonnull(decrypted1);
	decrypted2 = egg_tpm2_decrypt_master_password(context, result,
						      &error);
	g_assert_nonnull(decrypted2);
	g_assert(g_bytes_equal(decrypted1, decrypted2));
	egg_tpm2_finalize(context);
	g_bytes_unref(result);
	g_bytes_unref(decrypted1);
	g_bytes_unref(decrypted2);
}

int
main (int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func(
			"/tpm/test_egg_tpm2_generate_master_password",
			test_egg_tpm2_generate_master_password);
	g_test_add_func(
			"/tpm/test_egg_tpm2_decrypt_master_password",
			test_egg_tpm2_decrypt_master_password);

	return g_test_run();
}
