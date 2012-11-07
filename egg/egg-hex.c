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

#include "config.h"

#include "egg-hex.h"

#include <string.h>

static const char HEXC_UPPER[] = "0123456789ABCDEF";
static const char HEXC_LOWER[] = "0123456789abcdef";

gpointer
egg_hex_decode (const gchar *data, gssize n_data, gsize *n_decoded)
{
	return egg_hex_decode_full (data, n_data, 0, 1, n_decoded);
}

gpointer
egg_hex_decode_full (const gchar *data,
                     gssize n_data,
                     const gchar *delim,
                     guint group,
                     gsize *n_decoded)
{
	guchar *result;
	guchar *decoded;
	gsize n_delim;
	gushort j;
	gint state = 0;
	gint part = 0;
	const gchar* pos;

	g_return_val_if_fail (data || !n_data, NULL);
	g_return_val_if_fail (n_decoded, NULL);
	g_return_val_if_fail (group >= 1, NULL);

	if (n_data == -1)
		n_data = strlen (data);
	n_delim = delim ? strlen (delim) : 0;
	decoded = result = g_malloc0 ((n_data / 2) + 1);
	*n_decoded = 0;

	while (n_data > 0 && state == 0) {

		if (decoded != result && delim) {
			if (n_data < n_delim || memcmp (data, delim, n_delim) != 0) {
				state = -1;
				break;
			}

			data += n_delim;
			n_data -= n_delim;
		}

		while (part < group && n_data > 0) {

			/* Find the position */
			pos = strchr (HEXC_UPPER, g_ascii_toupper (*data));
			if (pos == 0) {
				if (n_data > 0)
					state = -1;
				break;
			}

			j = pos - HEXC_UPPER;
			if(!state) {
				*decoded = (j & 0xf) << 4;
				state = 1;
			} else {
				*decoded |= (j & 0xf);
				(*n_decoded)++;
				decoded++;
				state = 0;
				part++;
			}

			++data;
			--n_data;
		}

		part = 0;
	}

	/* Parsing error */
	if (state != 0) {
		g_free (result);
		result = NULL;
	}

	return result;
}

gchar*
egg_hex_encode (gconstpointer data, gsize n_data)
{
	return egg_hex_encode_full (data, n_data, TRUE, NULL, 0);
}

gchar*
egg_hex_encode_full (gconstpointer data,
                     gsize n_data,
                     gboolean upper_case,
                     const gchar *delim,
                     guint group)
{
	GString *result;
	const gchar *input;
	const char *hexc;
	gsize bytes;
	guchar j;

	g_return_val_if_fail (data || !n_data, NULL);

	input = data;
	hexc = upper_case ? HEXC_UPPER : HEXC_LOWER;

	result = g_string_sized_new (n_data * 2 + 1);
	bytes = 0;

	while (n_data > 0) {

		if (delim && group && bytes && (bytes % group) == 0)
			g_string_append (result, delim);

		j = *(input) >> 4 & 0xf;
		g_string_append_c (result, hexc[j]);

		j = *(input++) & 0xf;
		g_string_append_c (result, hexc[j]);

		++bytes;
		--n_data;
	}

	/* Make sure still null terminated */
	return g_string_free (result, FALSE);
}

