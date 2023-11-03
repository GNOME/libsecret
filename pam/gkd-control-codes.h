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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __GKD_CONTROL_CODES_H__
#define __GKD_CONTROL_CODES_H__

enum {
	GKD_CONTROL_OP_INITIALIZE,
	GKD_CONTROL_OP_UNLOCK,
	GKD_CONTROL_OP_CHANGE,
	GKD_CONTROL_OP_QUIT
};

enum {
	GKD_CONTROL_RESULT_OK,
	GKD_CONTROL_RESULT_DENIED,
	GKD_CONTROL_RESULT_FAILED,
	GKD_CONTROL_RESULT_NO_DAEMON
};

#endif /* __GKD_CONTROL_CODES_H__ */
