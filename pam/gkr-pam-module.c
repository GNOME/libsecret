/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pam-module.h - A PAM module for unlocking the keyring

   Copyright (C) 2007 Stef Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

/* 
 * Inspired by pam_keyring:
 *   W. Michael Petullo <mike@flyn.org>
 *   Jonathan Nettleton <jon.nettleton@gmail.com>
 */

#include "config.h"
#include "gkr-pam.h"
#include "gkd-control-codes.h"

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#if defined(ENABLE_NLS) && defined(__linux__)
#include <libintl.h>
#define gkr_pam_gettext(msgid) dgettext ("Linux-PAM", msgid)
#else
#define gkr_pam_gettext(msgid) (msgid)
#endif /* ENABLE_NLS */

enum {
	ARG_AUTO_START          = 1 << 0,
	ARG_IGNORE_SERVICE      = 1 << 1,
	ARG_USE_AUTHTOK	        = 1 << 2
};

#define ENV_CONTROL             "GNOME_KEYRING_CONTROL"

#define MAX_CONTROL_SIZE	(sizeof(((struct sockaddr_un *)0)->sun_path))

/* read & write ends of a pipe */
#define  READ_END   0
#define  WRITE_END  1

/* pre-set file descriptors */
#define  STDIN   0
#define  STDOUT  1
#define  STDERR  2

/* Linux/BSD compatibility */
#ifndef PAM_AUTHTOK_RECOVER_ERR
#define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
#endif

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

/* -----------------------------------------------------------------------------
 * HELPERS 
 */

static void
free_password (char *password)
{
	volatile char *vp;
	size_t len;
	
	if (!password)
		return;

	/* Defeats some optimizations */		
	len = strlen (password);
	memset (password, 0xAA, len);
	memset (password, 0xBB, len);

	/* Defeats others */
        vp = (volatile char*)password;
        while (*vp) 
        	*(vp++) = 0xAA;

	free (password);
}

/* check for list match. */
static int
evaluate_inlist (const char *needle, const char *haystack)
{
	const char *item;
	const char *remaining;

	if (!needle)
		return 0;

	remaining = haystack;

	for (;;) {
		item = strstr (remaining, needle);
		if (item == NULL)
			break;

		/* is it really the start of an item in the list? */
		if (item == haystack || *(item - 1) == ',') {
			item += strlen (needle);
			/* is item really needle? */
			if (*item == '\0' || *item == ',')
                                return 1;
		}

                remaining = strchr (item, ',');
                if (remaining == NULL)
                        break;

		/* skip ',' */
		++remaining;
        }

        return 0;
}

/* -----------------------------------------------------------------------------
 * DAEMON MANAGEMENT 
 */

static const char*
get_any_env (pam_handle_t *ph, const char *name)
{
	const char *env;
	
	assert (name);
	
	/* We only return non-empty variables */
	
	/* 
	 * Some PAMs decide to strdup the return value, not sure 
	 * how we can detect this.
	 */
	env = pam_getenv (ph, name);
	if (env && env[0]) 
		return env;
		
	env = getenv (name);
	if (env && env[0])
		return env;
		
	return NULL;
}

static void
cleanup_free_password (pam_handle_t *ph, void *data, int pam_end_status)
{
	free_password (data);
}

/* control must be at least MAX_CONTROL_SIZE */
static int
get_control_file (pam_handle_t *ph, char *control)
{
	const char *control_root;
	const char *suffix;

	control_root = get_any_env (ph, ENV_CONTROL);
	if (control_root == NULL) {
		control_root = get_any_env (ph, "XDG_RUNTIME_DIR");
		if (control_root == NULL)
			return GKD_CONTROL_RESULT_NO_DAEMON;
		suffix = "/keyring/control";
	} else {
		suffix = "/control";
	}

	if (strlen (control_root) + strlen (suffix) + 1 > MAX_CONTROL_SIZE) {
		syslog (GKR_LOG_ERR, "gkr-pam: address is too long for unix socket path: %s/%s",
			control, suffix);
		return GKD_CONTROL_RESULT_FAILED;
	}

	strcpy (control, control_root);
	strcat (control, suffix);

	return GKD_CONTROL_RESULT_OK;
}

static int
unlock_keyring (pam_handle_t *ph,
                struct passwd *pwd,
                const char *password)
{
	char control[MAX_CONTROL_SIZE];
	int res;
	const char *argv[2];
	
	assert (pwd);

	res = get_control_file(ph, control);
	if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: unable to locate daemon control file");
		return PAM_SERVICE_ERR;
	}

	argv[0] = password;

	res = gkr_pam_client_run_operation (pwd, control, GKD_CONTROL_OP_UNLOCK,
					    (argv[0] == NULL) ? 0 : 1, argv);
	/* An error unlocking */
	if (res == GKD_CONTROL_RESULT_NO_DAEMON) {
		return PAM_SERVICE_ERR;
	} else if (res == GKD_CONTROL_RESULT_DENIED) {
		syslog (GKR_LOG_ERR, "gkr-pam: the password for the login keyring was invalid.");
		return PAM_SERVICE_ERR;
	} else if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't unlock the login keyring.");
		return PAM_SERVICE_ERR;
	}

	syslog (GKR_LOG_INFO, "gkr-pam: unlocked login keyring");
	return PAM_SUCCESS;
}

static int
change_keyring_password (pam_handle_t *ph,
                         struct passwd *pwd,
                         const char *password,
                         const char *original)
{
	char control[MAX_CONTROL_SIZE];
	const char *argv[3];
	int res;

	assert (pwd);
	assert (password);
	assert (original);

	res = get_control_file(ph, control);
	if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: unable to locate daemon control file");
		return PAM_SERVICE_ERR;
	}

	argv[0] = original;
	argv[1] = password;
	
	res = gkr_pam_client_run_operation (pwd, control, GKD_CONTROL_OP_CHANGE, 2, argv);

	if (res == GKD_CONTROL_RESULT_NO_DAEMON) {
		return PAM_SERVICE_ERR;
	/* No keyring, not an error. Will be created at initial authenticate. */
	} else if (res == GKD_CONTROL_RESULT_DENIED) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't change password for the login keyring: the passwords didn't match.");
		return PAM_SERVICE_ERR;
	} else if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't change password for the login keyring.");
		return PAM_SERVICE_ERR;
	}

	syslog (GKR_LOG_NOTICE, "gkr-pam: changed password for login keyring");
	return PAM_SUCCESS;
}

/* -----------------------------------------------------------------------------
 * PAM STUFF
 */

static int
prompt_password (pam_handle_t *ph)
{
	const struct pam_conv *conv;
	struct pam_message msg;
	struct pam_response *resp;
	const struct pam_message *msgs[1];
	const void *item;
	char *password;
	int ret;

	/* Get the conversation function */
	ret = pam_get_item (ph, PAM_CONV, &item);
	if (ret != PAM_SUCCESS)
		return ret;

	/* Setup a message */
	memset (&msg, 0, sizeof (msg));
	memset (&resp, 0, sizeof (resp));
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = gkr_pam_gettext ("Password: ");
	msgs[0] = &msg;
	
	/* Call away */
	conv = (const struct pam_conv*)item;
	ret = (conv->conv) (1, msgs, &resp, conv->appdata_ptr);
	if (ret != PAM_SUCCESS)
		return ret;
	
	password = resp[0].resp;
	free (resp);
	
	if (password == NULL) 
		return PAM_CONV_ERR;
		
	/* Store it away for later use */
	ret = pam_set_item (ph, PAM_AUTHTOK, password);
	free_password (password);

	if (ret == PAM_SUCCESS)
		ret = pam_get_item (ph, PAM_AUTHTOK, &item); 

	return ret;
}

static uint 
parse_args (pam_handle_t *ph, int argc, const char **argv)
{
	uint args = 0;
	const void *svc;
	int only_if_len;
	int i;

	svc = NULL;
	if (pam_get_item (ph, PAM_SERVICE, &svc) != PAM_SUCCESS)
		svc = NULL;

	only_if_len = strlen ("only_if=");

	/* Parse the arguments */
	for (i = 0; i < argc; i++) {
		if (strcmp (argv[i], "auto_start") == 0) {
			args |= ARG_AUTO_START;

		} else if (strncmp (argv[i], "only_if=", only_if_len) == 0) {
			const char *value = argv[i] + only_if_len;
			if (!evaluate_inlist (svc, value))
				args |= ARG_IGNORE_SERVICE;

		} else if (strcmp (argv[i], "use_authtok") == 0) {
			args |= ARG_USE_AUTHTOK;

		} else {
			syslog (GKR_LOG_WARN, "gkr-pam: invalid option: %s",
				argv[i]);
		}
	}
	
	return args;
}

static int
stash_password_for_session (pam_handle_t *ph,
                            const char *password)
{
	if (pam_set_data (ph, "gkr_system_authtok", strdup (password),
	                  cleanup_free_password) != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: error stashing password for session");
		return PAM_AUTHTOK_RECOVER_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *ph, int unused, int argc, const char **argv)
{
	struct passwd *pwd;
	const char *user, *password;
	uint args;
	int ret;
	
	args = parse_args (ph, argc, argv);

	if (args & ARG_IGNORE_SERVICE)
		return PAM_SUCCESS;
		
	/* Figure out and/or prompt for the user name */
	ret = pam_get_user (ph, &user, NULL);
	if (ret != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the user name: %s", 
		        pam_strerror (ph, ret));
		return PAM_SERVICE_ERR;
	}
	
	pwd = getpwnam (user);
	if (!pwd) {
		syslog (GKR_LOG_ERR, "gkr-pam: error looking up user information");
		return PAM_SERVICE_ERR;
	}
		
	/* Look up the password */
	ret = pam_get_authtok (ph, PAM_AUTHTOK, &password, NULL);
	if (ret != PAM_SUCCESS || password == NULL) {
		if (ret == PAM_SUCCESS)
			syslog (GKR_LOG_WARN, "gkr-pam: no password is available for user");
		else
			syslog (GKR_LOG_WARN, "gkr-pam: no password is available for user: %s", 
			        pam_strerror (ph, ret));
		return PAM_SUCCESS;
	}

	ret = unlock_keyring (ph, pwd, password);
	if (ret != PAM_SUCCESS) {
                ret = stash_password_for_session (ph, password);
		syslog (GKR_LOG_INFO, "gkr-pam: stashed password to try later in open session");
	}

	return ret;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	const char *user = NULL, *password = NULL;
	struct passwd *pwd;
	int ret;
	uint args;

	args = parse_args (ph, argc, argv);

	if (args & ARG_IGNORE_SERVICE)
		return PAM_SUCCESS;

	/* Figure out the user name */
	ret = pam_get_user (ph, &user, NULL);
	if (ret != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the user name: %s", 
		        pam_strerror (ph, ret));
		return PAM_SERVICE_ERR;
	}

	pwd = getpwnam (user);
	if (!pwd) {
		syslog (GKR_LOG_ERR, "gkr-pam: error looking up user information for: %s", user);
		return PAM_SERVICE_ERR;
	}

	/* Get the stored authtok here */
	if (pam_get_data (ph, "gkr_system_authtok", (const void**)&password) != PAM_SUCCESS) {
		/* 
		 * No password, no worries, maybe this (PAM using) application 
		 * didn't do authentication, or is hopeless and wants to call 
		 * different PAM callbacks from different processes.
		 * 
		 * No use complaining
		 */
		password = NULL;
	}
	
	if (args & ARG_AUTO_START || password) {
		ret = unlock_keyring (ph, pwd, password);
		if (ret != PAM_SUCCESS)
                        return PAM_SERVICE_ERR;
	}

	/* Destroy the stored authtok once it has been used */
	if (password && pam_set_data (ph, "gkr_system_authtok", NULL, NULL) != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: error destroying the password");
		return PAM_SERVICE_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * ph, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;	
}

static int
pam_chauthtok_preliminary (pam_handle_t *ph, struct passwd *pwd)
{
	/* 
	 * If a super-user is changing a user's password then pam_unix.so
	 * doesn't prompt for the user's current password, which means we 
	 * won't have access to that password to change the keyring password.
	 * 
	 * So we could prompt for the current user's password except that 
	 * most software is broken in this regard, and doesn't use the 
	 * prompts properly. 
	 * 
	 * In addition how would we verify the user's password? We could 
	 * verify it against the Gnome Keyring, but if it is mismatched
	 * from teh UNIX password then that would be super confusing.
	 * 
	 * So we opt, just to send NULL along with the change password 
	 * request and have the user type in their current GNOME Keyring
	 * password at an explanatory prompt.
	 */

	return PAM_IGNORE;
}

static int
pam_chauthtok_update (pam_handle_t *ph, struct passwd *pwd, uint args)
{
	const char *password, *original;
	int ret;

	ret = pam_get_authtok (ph, PAM_AUTHTOK, &password, NULL);
	if (ret != PAM_SUCCESS)
		password = NULL;

	ret = pam_get_authtok (ph, PAM_OLDAUTHTOK, &original, NULL);
	if (ret != PAM_SUCCESS || original == NULL) {
		syslog (GKR_LOG_WARN, "gkr-pam: couldn't update the login keyring password: %s",
		        "no old password was entered");
		if (password)
			stash_password_for_session (ph, password);
		return PAM_IGNORE;
	}
		
	if (password == NULL) {
		/* No password was set, and we can't prompt for it */
		if (args & ARG_USE_AUTHTOK) {
			syslog (GKR_LOG_ERR, "gkr-pam: no password set, and use_authtok was specified");
			return PAM_AUTHTOK_RECOVER_ERR;
		}

		/* No password was entered, prompt for it */
		ret = prompt_password (ph);
		if (ret != PAM_SUCCESS) {
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the password from user: %s", 
			        pam_strerror (ph, ret));
			return PAM_AUTH_ERR;
		}
		ret = pam_get_authtok (ph, PAM_AUTHTOK, &password, NULL);
		if (ret != PAM_SUCCESS || password == NULL) {
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the password from user: %s", 
			        ret == PAM_SUCCESS ? "password was null" : pam_strerror (ph, ret));
			return PAM_AUTHTOK_RECOVER_ERR;
		}
	}

	ret = change_keyring_password (ph, pwd, password, original);
	if (ret != PAM_SUCCESS) {
                /* Store the password for our session handler */
		stash_password_for_session (ph, password);
                syslog (GKR_LOG_INFO, "gkr-pam: stashed password to try later in open session");
        }

	return ret;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	/* Nothing to do, but we have to have this function exported */
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	const char *user;
	struct passwd *pwd;
	uint args;
	int ret;
	
	args = parse_args (ph, argc, argv);

	if (args & ARG_IGNORE_SERVICE)
		return PAM_SUCCESS;

	/* Figure out and/or prompt for the user name */
	ret = pam_get_user (ph, &user, NULL);
	if (ret != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the user name: %s", 
		        pam_strerror (ph, ret));
		return PAM_SERVICE_ERR;
	}
	
	pwd = getpwnam (user);
	if (!pwd) {
		syslog (GKR_LOG_ERR, "gkr-pam: error looking up user information for: %s", user);
		return PAM_SERVICE_ERR;
	}

	if (flags & PAM_PRELIM_CHECK) 
		return pam_chauthtok_preliminary (ph, pwd);
	else if (flags & PAM_UPDATE_AUTHTOK)
		return pam_chauthtok_update (ph, pwd, args);
	else 
		return PAM_IGNORE;
}
