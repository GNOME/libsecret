/* egg-base64.c - Base64 encoding/decoding
 *
 *  Copyright (C) 2006 Alexander Larsson <alexl@redhat.com>
 *  Copyright (C) 2000-2003 Ximian Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 * This is based on code in camel, written by:
 *    Michael Zucchi <notzed@ximian.com>
 *    Jeffrey Stedfast <fejj@ximian.com>
 */

#include "config.h"

#include <string.h>

#include "egg-base64.h"

/* This is a copy of glib/glib/gbase64.c.  The only difference is that
   this version uses URL- and filename-safe alphabets as described in
   RFC4848 and omits padding and line breaks, for the use with JWE.  */

static const char base64_alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static gsize
egg_base64_encode_step (const guchar *in,
			gsize         len,
			gchar        *out,
			gint         *state,
			gint         *save)
{
  char *outptr;
  const guchar *inptr;

  g_return_val_if_fail (in != NULL, 0);
  g_return_val_if_fail (out != NULL, 0);
  g_return_val_if_fail (state != NULL, 0);
  g_return_val_if_fail (save != NULL, 0);

  if (len <= 0)
    return 0;

  inptr = in;
  outptr = out;

  if (len + ((char *) save) [0] > 2)
    {
      const guchar *inend = in+len-2;
      int c1, c2, c3;
      int already;

      already = *state;

      switch (((char *) save) [0])
        {
        case 1:
          c1 = ((unsigned char *) save) [1];
          goto skip1;
        case 2:
          c1 = ((unsigned char *) save) [1];
          c2 = ((unsigned char *) save) [2];
          goto skip2;
        }

      /*
       * yes, we jump into the loop, no i'm not going to change it,
       * it's beautiful!
       */
      while (inptr < inend)
        {
          c1 = *inptr++;
        skip1:
          c2 = *inptr++;
        skip2:
          c3 = *inptr++;
          *outptr++ = base64_alphabet [ c1 >> 2 ];
          *outptr++ = base64_alphabet [ c2 >> 4 |
                                        ((c1&0x3) << 4) ];
          *outptr++ = base64_alphabet [ ((c2 &0x0f) << 2) |
                                        (c3 >> 6) ];
          *outptr++ = base64_alphabet [ c3 & 0x3f ];
        }

      ((char *)save)[0] = 0;
      len = 2 - (inptr - inend);
      *state = already;
    }

  if (len>0)
    {
      char *saveout;

      /* points to the slot for the next char to save */
      saveout = & (((char *)save)[1]) + ((char *)save)[0];

      /* len can only be 0 1 or 2 */
      switch(len)
        {
        case 2: *saveout++ = *inptr++;
        case 1: *saveout++ = *inptr++;
        }
      ((char *)save)[0] += len;
    }

  return outptr - out;
}

static gsize
egg_base64_encode_close (gchar *out,
                         gint  *state,
                         gint  *save)
{
  int c1, c2;
  char *outptr = out;

  g_return_val_if_fail (out != NULL, 0);
  g_return_val_if_fail (state != NULL, 0);
  g_return_val_if_fail (save != NULL, 0);

  c1 = ((unsigned char *) save) [1];
  c2 = ((unsigned char *) save) [2];

  switch (((char *) save) [0])
    {
    case 2:
      outptr [0] = base64_alphabet [ c1 >> 2 ];
      outptr [1] = base64_alphabet [ c2 >> 4 | ( (c1&0x3) << 4 ) ];
      outptr [2] = base64_alphabet[ ( (c2 &0x0f) << 2 ) ];
      g_assert (outptr [2] != 0);
      outptr += 3;
      break;
    case 1:
      outptr [0] = base64_alphabet [ c1 >> 2 ];
      outptr [1] = base64_alphabet [ ( (c1&0x3) << 4 ) ];
      outptr += 2;
      break;
    }

  *save = 0;
  *state = 0;

  return outptr - out;
}

gchar *
egg_base64_encode (const guchar *data,
		   gsize         len)
{
  gchar *out;
  gint state = 0, outlen;
  gint save = 0;

  g_return_val_if_fail (data != NULL || len == 0, NULL);

  /* We can use a smaller limit here, since we know the saved state is 0,
     +1 is needed for trailing \0, also check for unlikely integer overflow */
  if (len >= ((G_MAXSIZE - 1) / 4 - 1) * 3)
    g_error("%s: input too large for Base64 encoding (%"G_GSIZE_FORMAT" chars)",
        G_STRLOC, len);

  out = g_malloc ((len / 3 + 1) * 4 + 1);

  outlen = egg_base64_encode_step (data, len, out, &state, &save);
  outlen += egg_base64_encode_close (out + outlen, &state, &save);
  out[outlen] = '\0';

  return (gchar *) out;
}

static const unsigned char mime_base64_rank[256] = {
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255, 62,255,255,
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255,
  255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255, 63,
  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};

static gsize
egg_base64_decode_step (const gchar  *in,
			gsize         len,
			guchar       *out)
{
  const guchar *inptr;
  guchar *outptr;
  const guchar *inend;
  guchar c, rank;
  guchar last[2];
  unsigned int v;
  int i;

  g_return_val_if_fail (in != NULL, 0);
  g_return_val_if_fail (out != NULL, 0);

  if (len <= 0)
    return 0;

  inend = (const guchar *)in+len;
  outptr = out;

  /* convert 4 base64 bytes to 3 normal bytes */
  v=0;
  i=0;

  last[0] = last[1] = 0;

  inptr = (const guchar *)in;
  while (inptr < inend)
    {
      c = *inptr++;
      rank = mime_base64_rank [c];
      if (rank != 0xff)
        {
          last[1] = last[0];
          last[0] = c;
          v = (v<<6) | rank;
          i++;
          if (i==4)
            {
              *outptr++ = v>>16;
	      *outptr++ = v>>8;
	      *outptr++ = v;
              i=0;
            }
        }
    }

  if (i > 0)
    {
      v <<= 6*(4-i);
      *outptr++ = v>>16;
      if (i == 3)
	*outptr++ = v>>8;
    }

  return outptr - out;
}

guchar *
egg_base64_decode_inplace (gchar *text,
			   gsize *out_len)
{
  gint input_length;

  g_return_val_if_fail (text != NULL, NULL);
  g_return_val_if_fail (out_len != NULL, NULL);

  input_length = strlen (text);

  *out_len = egg_base64_decode_step (text, input_length, (guchar *) text);

  return (guchar *) text;
}
