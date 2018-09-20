/* egg-base64.h - Base64 coding functions
 *
 *  Copyright (C) 2005  Alexander Larsson <alexl@redhat.com>
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
 */

#ifndef __EGG_BASE64_H__
#define __EGG_BASE64_H__

#include <glib.h>

G_BEGIN_DECLS

gchar*  egg_base64_encode         (const guchar *data,
                                   gsize         len) G_GNUC_MALLOC;
guchar *egg_base64_decode_inplace (gchar        *text,
                                   gsize        *out_len);


G_END_DECLS

#endif /* __EGG_BASE64_H__ */
