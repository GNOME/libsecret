/*
 * libsecret
 *
 * Copyright (C) 2024 Red Hat, Inc.
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "egg-fips.h"

#include <gnutls/gnutls.h>

EggFipsMode
egg_fips_get_mode (void)
{
	return gnutls_fips140_mode_enabled ();
}

void
egg_fips_set_mode (EggFipsMode mode)
{
	gnutls_fips140_set_mode (mode, GNUTLS_FIPS140_SET_MODE_THREAD);
}
