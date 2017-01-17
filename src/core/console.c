/*
 * libcutil -- An utility toolkit.
 *
 * Copyright (C) 2016 - 2017, JYD, Inc.
 *
 * seanchann <xqzhou@bj-jyd.cn>
 *
 * See docs/ for more information about
 * the libcutil project.
 *
 * This program belongs to JYD, Inc. JYD, Inc reserves all rights
 */

#include "asterisk.h"

#include "asterisk/_private.h"
#include "console.h"

#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/un.h>
#include <histedit.h>
#include <fcntl.h>


#include "asterisk/paths.h"
#include "asterisk/lock.h"
#include "asterisk/localtime.h"
#include "asterisk/term.h"
/*#include "asterisk/threadstorage.h"*/
/*#include "asterisk/strings.h"*/
#include "asterisk/utils.h"
#include "asterisk/cli.h"
#include "asterisk/poll-compat.h"
#include "elhelper.h"
#include "daemon.h"
#include "astcore_dummy.h"


/*! \brief Welcome message when starting a CLI interface */
#define WELCOME_MESSAGE \
    ast_verbose("libcutil console interface %s, Copyright (C) 2016 - 2017, JYD, Inc. and others.\n" \
                "Created by seanchann.zhou <xqzhou@bj-jyd.cn>\n" \
                "=========================================================================\n", ast_get_version()) \


static struct ast_str *prompt = NULL;
int option_verbose;				/*!< Verbosity level */
int option_debug;				/*!< Debug level */
int ast_verb_sys_level;

static int ast_socket = -1;		/*!< UNIX Socket for allowing remote control */
static int ast_consock = -1;		/*!< UNIX Socket for controlling another asterisk */

static char ast_config_AST_CTL_PERMISSIONS[PATH_MAX];
static char ast_config_AST_CTL_OWNER[PATH_MAX] = "\0";
static char ast_config_AST_CTL_GROUP[PATH_MAX] = "\0";
static char ast_config_AST_CTL[PATH_MAX] = "cutil.ctl";

#define AST_MAX_CONNECTS 128

#define ASTERISK_PROMPT "*CLI> "


struct console {
	int fd;				/*!< File descriptor */
	int p[2];			/*!< Pipe */
	pthread_t t;			/*!< Thread of handler */
	int mute;			/*!< Is the console muted for logs */
	int uid;			/*!< Remote user ID. */
	int gid;			/*!< Remote group ID. */
	int levels[NUMLOGLEVELS];	/*!< Which log levels are enabled for the console */
	/*! Verbosity level of this console. */
	int option_verbose;
};
struct console consoles[AST_MAX_CONNECTS];
static pthread_t consolethread = AST_PTHREADT_NULL;


static char *remotehostname;


static void destroy_match_list(char **match_list, int matches)
{
	if (match_list) {
		int idx;

		for (idx = 0; idx < matches; ++idx) {
			ast_free(match_list[idx]);
		}
		ast_free(match_list);
	}
}

static char **ast_el_strtoarr(char *buf)
{
	char *retstr;
	char **match_list = NULL;
	char **new_list;
	size_t match_list_len = 1;
	int matches = 0;

	while ((retstr = strsep(&buf, " "))) {
		if (!strcmp(retstr, AST_CLI_COMPLETE_EOF)) {
			break;
		}
		if (matches + 1 >= match_list_len) {
			match_list_len <<= 1;
			new_list = ast_realloc(match_list, match_list_len * sizeof(char *));
			if (!new_list) {
				destroy_match_list(match_list, matches);
				return NULL;
			}
			match_list = new_list;
		}

		retstr = ast_strdup(retstr);
		if (!retstr) {
			destroy_match_list(match_list, matches);
			return NULL;
		}
		match_list[matches++] = retstr;
	}

	if (!match_list) {
		return NULL;
	}

	if (matches >= match_list_len) {
		new_list = ast_realloc(match_list, (match_list_len + 1) * sizeof(char *));
		if (!new_list) {
			destroy_match_list(match_list, matches);
			return NULL;
		}
		match_list = new_list;
	}

	match_list[matches] = NULL;

	return match_list;
}

static int ast_el_sort_compare(const void *i1, const void *i2)
{
	char *s1, *s2;

	s1 = ((char **)i1)[0];
	s2 = ((char **)i2)[0];

	return strcasecmp(s1, s2);
}

static int ast_cli_display_match_list(char **matches, int len, int max)
{
	int i, idx, limit, count;
	int screenwidth = 0;
	int numoutput = 0, numoutputline = 0;

	screenwidth = ast_get_termcols(STDOUT_FILENO);

	/* find out how many entries can be put on one line, with two spaces between strings */
	limit = screenwidth / (max + 2);
	if (limit == 0)
		limit = 1;

	/* how many lines of output */
	count = len / limit;
	if (count * limit < len)
		count++;

	idx = 1;

	qsort(&matches[0], (size_t)(len), sizeof(char *), ast_el_sort_compare);

	for (; count > 0; count--) {
		numoutputline = 0;
		for (i = 0; i < limit && matches[idx]; i++, idx++) {

			/* Don't print dupes */
			if ( (matches[idx+1] != NULL && strcmp(matches[idx], matches[idx+1]) == 0 ) ) {
				i--;
				ast_free(matches[idx]);
				matches[idx] = NULL;
				continue;
			}

			numoutput++;
			numoutputline++;
			fprintf(stdout, "%-*s  ", max, matches[idx]);
			ast_free(matches[idx]);
			matches[idx] = NULL;
		}
		if (numoutputline > 0)
			fprintf(stdout, "\n");
	}

	return numoutput;
}

static void send_rasterisk_connect_commands(void)
{
	char buf[80];

	/*
	 * Tell the server asterisk instance about the verbose level
	 * initially desired.
	 */
	if (option_verbose) {
		snprintf(buf, sizeof(buf), "core set verbose atleast %d silent", option_verbose);
		fdsend(ast_consock, buf);
	}

	if (option_debug) {
		snprintf(buf, sizeof(buf), "core set debug atleast %d", option_debug);
		fdsend(ast_consock, buf);
	}

	if (!ast_opt_mute) {
		fdsend(ast_consock, "logger mute silent");
	} else {
		printf("log and verbose output currently muted ('logger mute' to unmute)\n");
	}
}


int console_quit(pthread_t main_thread)
{
  ast_el_write_default_histfile();
  if (consolethread == AST_PTHREADT_NULL || consolethread == pthread_self()) {
    /* Only end if we are the consolethread, otherwise there's a race with that thread. */
    ast_el_uninitialize();
  } else if (main_thread == pthread_self()) {
    if (consolethread != AST_PTHREADT_NULL) {
      pthread_kill(consolethread, SIGURG);
    }
  }
  return 0;
}

int console_check_quit(void)
{
  int ret = 0;
  if ((consolethread != AST_PTHREADT_NULL) && (consolethread != pthread_self())) {
    ret = 1;
    pthread_kill(consolethread, SIGURG);
  }

  return ret;
}

/*!
 * \brief enable or disable a logging level to a specified console
 */
void ast_console_toggle_loglevel(int fd, int level, int state)
{
	int x;

	if (level >= NUMLOGLEVELS) {
		level = NUMLOGLEVELS - 1;
	}

	for (x = 0;x < AST_MAX_CONNECTS; x++) {
		if (fd == consoles[x].fd) {
			/*
			 * Since the logging occurs when levels are false, set to
			 * flipped iinput because this function accepts 0 as off and 1 as on
			 */
			consoles[x].levels[level] = state ? 0 : 1;
			return;
		}
	}
}

/*!
 * \brief mute or unmute a console from logging
 */
void ast_console_toggle_mute(int fd, int silent)
{
	int x;
	for (x = 0;x < AST_MAX_CONNECTS; x++) {
		if (fd == consoles[x].fd) {
			if (consoles[x].mute) {
				consoles[x].mute = 0;
				if (!silent)
					ast_cli(fd, "Console is not muted anymore.\n");
			} else {
				consoles[x].mute = 1;
				if (!silent)
					ast_cli(fd, "Console is muted.\n");
			}
			return;
		}
	}
	ast_cli(fd, "Couldn't find remote console.\n");
}


/*!
 * \brief log the string to all attached network console clients
 */
static void ast_network_puts_mutable(const char *string, int level, int sublevel)
{
	int x;

	for (x = 0; x < AST_MAX_CONNECTS; ++x) {
		if (consoles[x].fd < 0
			|| consoles[x].mute
			|| consoles[x].levels[level]
			|| (level == __LOG_VERBOSE && consoles[x].option_verbose < sublevel)) {
			continue;
		}
		fdprint(consoles[x].p[1], string);
	}
}

/*!
 * \brief log the string to the root console, and all attached
 * network console clients
 */
void ast_console_puts_mutable(const char *string, int level)
{
	ast_console_puts_mutable_full(string, level, 0);
}


static int console_print(const char *s);

void ast_console_puts_mutable_full(const char *message, int level, int sublevel)
{
	/* Send to the root console */
	console_print(message);

	/* Wake up a poll()ing console */
	if (ast_opt_console && consolethread != AST_PTHREADT_NULL) {
		pthread_kill(consolethread, SIGURG);
	}

	/* Send to any network console clients */
	ast_network_puts_mutable(message, level, sublevel);
}



static void set_header(char *outbuf, int maxout, char level)
{
	const char *cmp;
	char date[40];

	switch (level) {
	case 0: cmp = NULL;
		break;
	case 1: cmp = VERBOSE_PREFIX_1;
		break;
	case 2: cmp = VERBOSE_PREFIX_2;
		break;
	case 3: cmp = VERBOSE_PREFIX_3;
		break;
	default: cmp = VERBOSE_PREFIX_4;
		break;
	}

	if (ast_opt_timestamp) {
		struct ast_tm tm;
		struct timeval now = ast_tvnow();
		ast_localtime(&now, &tm, NULL);
		ast_strftime(date, sizeof(date), ast_logger_get_dateformat(), &tm);
	}

	snprintf(outbuf, maxout, "%s%s%s%s%s%s",
		ast_opt_timestamp ? "[" : "",
		ast_opt_timestamp ? date : "",
		ast_opt_timestamp ? "] " : "",
		cmp ? ast_term_color(COLOR_GRAY, 0) : "",
		cmp ? cmp : "",
		cmp ? ast_term_reset() : "");
}

struct console_state_data {
	char verbose_line_level;
};

static int console_state_init(void *ptr)
{
	struct console_state_data *state = ptr;
	state->verbose_line_level = 0;
	return 0;
}

AST_THREADSTORAGE_CUSTOM(console_state, console_state_init, ast_free_ptr);


static int console_print(const char *s)
{
	struct console_state_data *state =
		ast_threadstorage_get(&console_state, sizeof(*state));

	char prefix[80];
	const char *c;
	int num, res = 0;
	unsigned int newline;

	do {
		if (VERBOSE_HASMAGIC(s)) {

			/* always use the given line's level, otherwise
			   we'll use the last line's level */
			state->verbose_line_level = VERBOSE_MAGIC2LEVEL(s);

			/* move past magic */
			s++;

			set_header(prefix, sizeof(prefix), state->verbose_line_level);
		} else {
			*prefix = '\0';
		}
		c = s;

		/* for a given line separate on verbose magic, newline, and eol */
		if ((s = strchr(c, '\n'))) {
			++s;
			newline = 1;
		} else {
			s = strchr(c, '\0');
			newline = 0;
		}

		/* check if we should write this line after calculating begin/end
		   so we process the case of a higher level line embedded within
		   two lower level lines */
		if (state->verbose_line_level > option_verbose) {
			continue;
		}

		if (!ast_strlen_zero(prefix)) {
			fputs(prefix, stdout);
		}

		num = s - c;
		if (fwrite(c, sizeof(char), num, stdout) < num) {
			break;
		}

		if (!res) {
			/* if at least some info has been written
			   we'll want to return true */
			res = 1;
		}
	} while (*s);

	if (newline) {
		/* if ending on a newline then reset last level to zero
		    since what follows may be not be logging output */
		state->verbose_line_level = 0;
	}

	if (res) {
		fflush(stdout);
	}

	return res;
}

static pthread_t lthread;


/*!
 * \brief read() function supporting the reception of user credentials.
 *
 * \param fd Socket file descriptor.
 * \param buffer Receive buffer.
 * \param size 'buffer' size.
 * \param con Console structure to set received credentials
 * \retval -1 on error
 * \retval the number of bytes received on success.
 */
static int read_credentials(int fd, char *buffer, size_t size, struct console *con)
{
#if defined(SO_PEERCRED)
#ifdef HAVE_STRUCT_SOCKPEERCRED_UID
#define HAVE_STRUCT_UCRED_UID
	struct sockpeercred cred;
#else
	struct ucred cred;
#endif
	socklen_t len = sizeof(cred);
#endif
#if defined(HAVE_GETPEEREID)
	uid_t uid;
	gid_t gid;
#else
	int uid, gid;
#endif
	int result;

	result = read(fd, buffer, size);
	if (result < 0) {
		return result;
	}

#if defined(SO_PEERCRED) && (defined(HAVE_STRUCT_UCRED_UID) || defined(HAVE_STRUCT_UCRED_CR_UID))
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len)) {
		return result;
	}
#if defined(HAVE_STRUCT_UCRED_UID)
	uid = cred.uid;
	gid = cred.gid;
#else /* defined(HAVE_STRUCT_UCRED_CR_UID) */
	uid = cred.cr_uid;
	gid = cred.cr_gid;
#endif /* defined(HAVE_STRUCT_UCRED_UID) */

#elif defined(HAVE_GETPEEREID)
	if (getpeereid(fd, &uid, &gid)) {
		return result;
	}
#else
	return result;
#endif
	con->uid = uid;
	con->gid = gid;

	return result;
}

/* This is the thread running the remote console on the main process. */
static void *netconsole(void *vconsole)
{
	struct console *con = vconsole;
	char hostname[MAXHOSTNAMELEN] = "";
	char inbuf[512];
	char outbuf[512];
	const char * const end_buf = inbuf + sizeof(inbuf);
	char *start_read = inbuf;
	int res;
	struct pollfd fds[2];

	if (gethostname(hostname, sizeof(hostname)-1))
		ast_copy_string(hostname, "<Unknown>", sizeof(hostname));
	snprintf(outbuf, sizeof(outbuf), "%s/%ld/%s\n", hostname, (long)mainpid(), ast_get_version());
	fdprint(con->fd, outbuf);
	ast_verb_console_register(&con->option_verbose);
	for (;;) {
		fds[0].fd = con->fd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = con->p[0];
		fds[1].events = POLLIN;
		fds[1].revents = 0;

		res = ast_poll(fds, 2, -1);
		if (res < 0) {
			if (errno != EINTR)
				ast_log(LOG_WARNING, "poll returned < 0: %s\n", strerror(errno));
			continue;
		}
		if (fds[0].revents) {
			int cmds_read, bytes_read;
			if ((bytes_read = read_credentials(con->fd, start_read, end_buf - start_read, con)) < 1) {
				break;
			}
			/* XXX This will only work if it is the first command, and I'm not sure fixing it is worth the effort. */
			if (strncmp(inbuf, "cli quit after ", 15) == 0) {
				ast_cli_command_multiple_full(con->uid, con->gid, con->fd, bytes_read - 15, inbuf + 15);
				break;
			}
			/* ast_cli_command_multiple_full will only process individual commands terminated by a
			 * NULL and not trailing partial commands. */
			if (!(cmds_read = ast_cli_command_multiple_full(con->uid, con->gid, con->fd, bytes_read + start_read - inbuf, inbuf))) {
				/* No commands were read. We either have a short read on the first command
				 * with space left, or a command that is too long */
				if (start_read + bytes_read < end_buf) {
					start_read += bytes_read;
				} else {
					ast_log(LOG_ERROR, "Command too long! Skipping\n");
					start_read = inbuf;
				}
				continue;
			}
			if (start_read[bytes_read - 1] == '\0') {
				/* The read ended on a command boundary, start reading again at the head of inbuf */
				start_read = inbuf;
				continue;
			}
			/* If we get this far, we have left over characters that have not been processed.
			 * Advance to the character after the last command read by ast_cli_command_multiple_full.
			 * We are guaranteed to have at least cmds_read NULLs */
			while (cmds_read-- && (start_read = strchr(start_read, '\0'))) {
				start_read++;
			}
			memmove(inbuf, start_read, end_buf - start_read);
			start_read = end_buf - start_read + inbuf;
		}
		if (fds[1].revents) {
			res = read_credentials(con->p[0], outbuf, sizeof(outbuf), con);
			if (res < 1) {
				ast_log(LOG_ERROR, "read returned %d\n", res);
				break;
			}
			res = write(con->fd, outbuf, res);
			if (res < 1)
				break;
		}
	}
	ast_verb_console_unregister();
	if (!ast_opt_hide_connect) {
		ast_verb(3, "Remote UNIX connection disconnected\n");
	}
	close(con->fd);
	close(con->p[0]);
	close(con->p[1]);
	con->fd = -1;

	return NULL;
}


static void *listener(void *unused)
{
	struct sockaddr_un sunaddr;
	int s;
	socklen_t len;
	int x;
	int flags;
	struct pollfd fds[1];
	for (;;) {
		if (ast_socket < 0)
			return NULL;
		fds[0].fd = ast_socket;
		fds[0].events = POLLIN;
		s = ast_poll(fds, 1, -1);
		pthread_testcancel();
		if (s < 0) {
			if (errno != EINTR)
				ast_log(LOG_WARNING, "poll returned error: %s\n", strerror(errno));
			continue;
		}
		len = sizeof(sunaddr);
		s = accept(ast_socket, (struct sockaddr *)&sunaddr, &len);
		if (s < 0) {
			if (errno != EINTR)
				ast_log(LOG_WARNING, "Accept returned %d: %s\n", s, strerror(errno));
		} else {
#if defined(SO_PASSCRED)
			int sckopt = 1;
			/* turn on socket credentials passing. */
			if (setsockopt(s, SOL_SOCKET, SO_PASSCRED, &sckopt, sizeof(sckopt)) < 0) {
				ast_log(LOG_WARNING, "Unable to turn on socket credentials passing\n");
			} else
#endif
			{
				for (x = 0; x < AST_MAX_CONNECTS; x++) {
					if (consoles[x].fd >= 0) {
						continue;
					}
					if (socketpair(AF_LOCAL, SOCK_STREAM, 0, consoles[x].p)) {
						ast_log(LOG_ERROR, "Unable to create pipe: %s\n", strerror(errno));
						fdprint(s, "Server failed to create pipe\n");
						close(s);
						break;
					}
					flags = fcntl(consoles[x].p[1], F_GETFL);
					fcntl(consoles[x].p[1], F_SETFL, flags | O_NONBLOCK);
					consoles[x].mute = 1; /* Default is muted, we will un-mute if necessary */
					/* Default uid and gid to -2, so then in cli.c/cli_has_permissions() we will be able
					   to know if the user didn't send the credentials. */
					consoles[x].uid = -2;
					consoles[x].gid = -2;
					/* Server default of remote console verbosity level is OFF. */
					consoles[x].option_verbose = 0;
					consoles[x].fd = s;
					if (ast_pthread_create_detached_background(&consoles[x].t, NULL, netconsole, &consoles[x])) {
						consoles[x].fd = -1;
						ast_log(LOG_ERROR, "Unable to spawn thread to handle connection: %s\n", strerror(errno));
						close(consoles[x].p[0]);
						close(consoles[x].p[1]);
						fdprint(s, "Server failed to spawn thread\n");
						close(s);
					}
					break;
				}
				if (x >= AST_MAX_CONNECTS) {
					fdprint(s, "No more connections allowed\n");
					ast_log(LOG_WARNING, "No more connections allowed\n");
					close(s);
				} else if ((consoles[x].fd > -1) && (!ast_opt_hide_connect)) {
					ast_verb(3, "Remote UNIX connection\n");
				}
			}
		}
	}
	return NULL;
}


static int ast_makesocket(void)
{
	struct sockaddr_un sunaddr;
	int res;
	int x;
	uid_t uid = -1;
	gid_t gid = -1;

	for (x = 0; x < AST_MAX_CONNECTS; x++)
		consoles[x].fd = -1;
	unlink(ast_config_AST_SOCKET);
	ast_socket = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (ast_socket < 0) {
		ast_log(LOG_WARNING, "Unable to create control socket: %s\n", strerror(errno));
		return -1;
	}
	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_LOCAL;
	ast_copy_string(sunaddr.sun_path, ast_config_AST_SOCKET, sizeof(sunaddr.sun_path));
	res = bind(ast_socket, (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (res) {
		ast_log(LOG_WARNING, "Unable to bind socket to %s: %s\n", ast_config_AST_SOCKET, strerror(errno));
		close(ast_socket);
		ast_socket = -1;
		return -1;
	}
	res = listen(ast_socket, 2);
	if (res < 0) {
		ast_log(LOG_WARNING, "Unable to listen on socket %s: %s\n", ast_config_AST_SOCKET, strerror(errno));
		close(ast_socket);
		ast_socket = -1;
		return -1;
	}

	if (ast_pthread_create_background(&lthread, NULL, listener, NULL)) {
		ast_log(LOG_WARNING, "Unable to create listener thread.\n");
		close(ast_socket);
		return -1;
	}

	if (!ast_strlen_zero(ast_config_AST_CTL_OWNER)) {
		struct passwd *pw;
		if ((pw = getpwnam(ast_config_AST_CTL_OWNER)) == NULL)
			ast_log(LOG_WARNING, "Unable to find uid of user %s\n", ast_config_AST_CTL_OWNER);
		else
			uid = pw->pw_uid;
	}

	if (!ast_strlen_zero(ast_config_AST_CTL_GROUP)) {
		struct group *grp;
		if ((grp = getgrnam(ast_config_AST_CTL_GROUP)) == NULL)
			ast_log(LOG_WARNING, "Unable to find gid of group %s\n", ast_config_AST_CTL_GROUP);
		else
			gid = grp->gr_gid;
	}

	if (chown(ast_config_AST_SOCKET, uid, gid) < 0)
		ast_log(LOG_WARNING, "Unable to change ownership of %s: %s\n", ast_config_AST_SOCKET, strerror(errno));

	if (!ast_strlen_zero(ast_config_AST_CTL_PERMISSIONS)) {
		unsigned int p1;
		mode_t p;
		sscanf(ast_config_AST_CTL_PERMISSIONS, "%30o", &p1);
		p = p1;
		if ((chmod(ast_config_AST_SOCKET, p)) < 0)
			ast_log(LOG_WARNING, "Unable to change file permissions of %s: %s\n", ast_config_AST_SOCKET, strerror(errno));
	}

	return 0;
}


static int ast_tryconnect(void)
{
	struct sockaddr_un sunaddr;
	int res;
	ast_consock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (ast_consock < 0) {
		fprintf(stderr, "Unable to create socket: %s\n", strerror(errno));
		return 0;
	}
	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_LOCAL;
	ast_copy_string(sunaddr.sun_path, ast_config_AST_SOCKET, sizeof(sunaddr.sun_path));
	res = connect(ast_consock, (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (res) {
		close(ast_consock);
		ast_consock = -1;
		return 0;
	} else
		return 1;
}

static char *cli_complete(EditLine *editline, int ch)
{
	int len = 0;
	char *ptr;
	int nummatches = 0;
	char **matches;
	int retval = CC_ERROR;
	char buf[2048], savechr;
	int res;

	LineInfo *lf = (LineInfo *)el_line(editline);

	savechr = *(char *)lf->cursor;
	*(char *)lf->cursor = '\0';
	ptr = (char *)lf->cursor;
	if (ptr) {
		while (ptr > lf->buffer) {
			if (isspace(*ptr)) {
				ptr++;
				break;
			}
			ptr--;
		}
	}

	len = lf->cursor - ptr;

	if (ast_opt_remote) {
		snprintf(buf, sizeof(buf), "_COMMAND NUMMATCHES \"%s\" \"%s\"", lf->buffer, ptr);
		fdsend(ast_consock, buf);
		if ((res = read(ast_consock, buf, sizeof(buf) - 1)) < 0) {
			return (char*)(CC_ERROR);
		}
		buf[res] = '\0';
		nummatches = atoi(buf);

		if (nummatches > 0) {
			char *mbuf;
			char *new_mbuf;
			int mlen = 0, maxmbuf = 2048;

			/* Start with a 2048 byte buffer */
			if (!(mbuf = ast_malloc(maxmbuf))) {
				*((char *) lf->cursor) = savechr;
				return (char *)(CC_ERROR);
			}
			snprintf(buf, sizeof(buf), "_COMMAND MATCHESARRAY \"%s\" \"%s\"", lf->buffer, ptr);
			fdsend(ast_consock, buf);
			res = 0;
			mbuf[0] = '\0';
			while (!strstr(mbuf, AST_CLI_COMPLETE_EOF) && res != -1) {
				if (mlen + 1024 > maxmbuf) {
					/* Every step increment buffer 1024 bytes */
					maxmbuf += 1024;
					new_mbuf = ast_realloc(mbuf, maxmbuf);
					if (!new_mbuf) {
						ast_free(mbuf);
						*((char *) lf->cursor) = savechr;
						return (char *)(CC_ERROR);
					}
					mbuf = new_mbuf;
				}
				/* Only read 1024 bytes at a time */
				res = read(ast_consock, mbuf + mlen, 1024);
				if (res > 0)
					mlen += res;
			}
			mbuf[mlen] = '\0';

			matches = ast_el_strtoarr(mbuf);
			ast_free(mbuf);
		} else
			matches = (char **) NULL;
	} else {
		char **p, *oldbuf=NULL;
		nummatches = 0;
		matches = ast_cli_completion_matches((char *)lf->buffer,ptr);
		for (p = matches; p && *p; p++) {
			if (!oldbuf || strcmp(*p,oldbuf))
				nummatches++;
			oldbuf = *p;
		}
	}

	if (matches) {
		int i;
		int matches_num, maxlen, match_len;

		if (matches[0][0] != '\0') {
			el_deletestr(editline, (int) len);
			el_insertstr(editline, matches[0]);
			retval = CC_REFRESH;
		}

		if (nummatches == 1) {
			/* Found an exact match */
			el_insertstr(editline, " ");
			retval = CC_REFRESH;
		} else {
			/* Must be more than one match */
			for (i = 1, maxlen = 0; matches[i]; i++) {
				match_len = strlen(matches[i]);
				if (match_len > maxlen)
					maxlen = match_len;
			}
			matches_num = i - 1;
			if (matches_num >1) {
				fprintf(stdout, "\n");
				ast_cli_display_match_list(matches, nummatches, maxlen);
				retval = CC_REDISPLAY;
			} else {
				el_insertstr(editline," ");
				retval = CC_REFRESH;
			}
		}
		for (i = 0; matches[i]; i++)
			ast_free(matches[i]);
		ast_free(matches);
	}

	*((char *) lf->cursor) = savechr;

	return (char *)(long)retval;
}


static char *cli_prompt(EditLine *editline)
{
	char tmp[100];
	char *pfmt;
	int color_used = 0;
	static int cli_prompt_changes = 0;
	struct passwd *pw;
	struct group *gr;

	if (prompt == NULL) {
		prompt = ast_str_create(100);
	} else if (!cli_prompt_changes) {
		return ast_str_buffer(prompt);
	} else {
		ast_str_reset(prompt);
	}

	if ((pfmt = getenv("ASTERISK_PROMPT"))) {
		char *t = pfmt;
		struct timeval ts = ast_tvnow();
		while (*t != '\0') {
			if (*t == '%') {
				char hostname[MAXHOSTNAMELEN] = "";
				int i, which;
				struct ast_tm tm = { 0, };
				int fgcolor = COLOR_WHITE, bgcolor = COLOR_BLACK;

				t++;
				switch (*t) {
				case 'C': /* color */
					t++;
					if (sscanf(t, "%30d;%30d%n", &fgcolor, &bgcolor, &i) == 2) {
						ast_term_color_code(&prompt, fgcolor, bgcolor);
						t += i - 1;
					} else if (sscanf(t, "%30d%n", &fgcolor, &i) == 1) {
						ast_term_color_code(&prompt, fgcolor, 0);
						t += i - 1;
					}

					/* If the color has been reset correctly, then there's no need to reset it later */
					color_used = ((fgcolor == COLOR_WHITE) && (bgcolor == COLOR_BLACK)) ? 0 : 1;
					break;
				case 'd': /* date */
					if (ast_localtime(&ts, &tm, NULL)) {
						ast_strftime(tmp, sizeof(tmp), "%Y-%m-%d", &tm);
						ast_str_append(&prompt, 0, "%s", tmp);
						cli_prompt_changes++;
					}
					break;
				case 'g': /* group */
					if ((gr = getgrgid(getgid()))) {
						ast_str_append(&prompt, 0, "%s", gr->gr_name);
					}
					break;
				case 'h': /* hostname */
					if (!gethostname(hostname, sizeof(hostname) - 1)) {
						ast_str_append(&prompt, 0, "%s", hostname);
					} else {
						ast_str_append(&prompt, 0, "%s", "localhost");
					}
					break;
				case 'H': /* short hostname */
					if (!gethostname(hostname, sizeof(hostname) - 1)) {
						char *dotptr;
						if ((dotptr = strchr(hostname, '.'))) {
							*dotptr = '\0';
						}
						ast_str_append(&prompt, 0, "%s", hostname);
					} else {
						ast_str_append(&prompt, 0, "%s", "localhost");
					}
					break;
#ifdef HAVE_GETLOADAVG
				case 'l': /* load avg */
					t++;
					if (sscanf(t, "%30d", &which) == 1 && which > 0 && which <= 3) {
						double list[3];
						getloadavg(list, 3);
						ast_str_append(&prompt, 0, "%.2f", list[which - 1]);
						cli_prompt_changes++;
					}
					break;
#endif
				case 's': /* Asterisk system name (from asterisk.conf) */
					ast_str_append(&prompt, 0, "%s", ast_config_AST_SYSTEM_NAME);
					break;
				case 't': /* time */
					if (ast_localtime(&ts, &tm, NULL)) {
						ast_strftime(tmp, sizeof(tmp), "%H:%M:%S", &tm);
						ast_str_append(&prompt, 0, "%s", tmp);
						cli_prompt_changes++;
					}
					break;
				case 'u': /* username */
					if ((pw = getpwuid(getuid()))) {
						ast_str_append(&prompt, 0, "%s", pw->pw_name);
					}
					break;
				case '#': /* process console or remote? */
					ast_str_append(&prompt, 0, "%c", ast_opt_remote ? '>' : '#');
					break;
				case '%': /* literal % */
					ast_str_append(&prompt, 0, "%c", '%');
					break;
				case '\0': /* % is last character - prevent bug */
					t--;
					break;
				}
			} else {
				ast_str_append(&prompt, 0, "%c", *t);
			}
			t++;
		}
		if (color_used) {
			/* Force colors back to normal at end */
			ast_term_color_code(&prompt, 0, 0);
		}
	} else {
		ast_str_set(&prompt, 0, "%s%s",
			remotehostname ? remotehostname : "",
			ASTERISK_PROMPT);
	}

	return ast_str_buffer(prompt);
}



#ifdef HAVE_LIBEDIT_IS_UNICODE
static int ast_el_read_char(EditLine *editline, wchar_t *cp)
#else
static int ast_el_read_char(EditLine *editline, char *cp)
#endif
{
	int num_read = 0;
	int lastpos = 0;
	struct pollfd fds[2];
	int res;
	int max;
#define EL_BUF_SIZE 512
	char buf[EL_BUF_SIZE];

	for (;;) {
		max = 1;
		fds[0].fd = ast_consock;
		fds[0].events = POLLIN;
		if (!ast_opt_exec) {
			fds[1].fd = STDIN_FILENO;
			fds[1].events = POLLIN;
			max++;
		}
		res = ast_poll(fds, max, -1);
		if (res < 0) {
			/*if (sig_flags.need_quit || sig_flags.need_quit_handler)*/
			if (sig_need_quit() || sig_need_quit_handler())
				break;
			if (errno == EINTR)
				continue;
			fprintf(stderr, "poll failed: %s\n", strerror(errno));
			break;
		}

		if (!ast_opt_exec && fds[1].revents) {
			char c = '\0';
			num_read = read(STDIN_FILENO, &c, 1);
			if (num_read < 1) {
				break;
			} else {
#ifdef 	HAVE_LIBEDIT_IS_UNICODE
				*cp = btowc(c);
#else
				*cp = c;
#endif
				return (num_read);
			}
		}
		if (fds[0].revents) {
			res = read(ast_consock, buf, sizeof(buf) - 1);
			/* if the remote side disappears exit */
			if (res < 1) {
				fprintf(stderr, "\nDisconnected from Asterisk server\n");
				if (!ast_opt_reconnect) {
					quit_handler(0, SHUTDOWN_FAST, 0);
				} else {
					int tries;
					int reconnects_per_second = 20;
					fprintf(stderr, "Attempting to reconnect for 30 seconds\n");
					for (tries = 0; tries < 30 * reconnects_per_second; tries++) {
						if (ast_tryconnect()) {
							fprintf(stderr, "Reconnect succeeded after %.3f seconds\n", 1.0 / reconnects_per_second * tries);
							printf("%s", term_quit());
							WELCOME_MESSAGE;
							send_rasterisk_connect_commands();
							break;
						} else
							usleep(1000000 / reconnects_per_second);
					}
					if (tries >= 30 * reconnects_per_second) {
						fprintf(stderr, "Failed to reconnect for 30 seconds.  Quitting.\n");
						quit_handler(0, SHUTDOWN_FAST, 0);
					}
				}
				continue;
			}

			buf[res] = '\0';

			/* Write over the CLI prompt */
			if (!ast_opt_exec && !lastpos) {
				if (write(STDOUT_FILENO, "\r[0K", 5) < 0) {
				}
			}

			console_print(buf);

			if ((res < EL_BUF_SIZE - 1) && ((buf[res-1] == '\n') || (res >= 2 && buf[res-2] == '\n'))) {
#ifdef 	HAVE_LIBEDIT_IS_UNICODE
				*cp = btowc(CC_REFRESH);
#else
				*cp = CC_REFRESH;
#endif
				return(1);
			} else {
				lastpos = 1;
			}
		}
	}

#ifdef 	HAVE_LIBEDIT_IS_UNICODE
	*cp = btowc('\0');
#else
	*cp = '\0';
#endif

	return (0);
}


/* This is the main console CLI command handler.  Run by the main() thread. */
void consolehandler(const char *s)
{
	printf("%s", term_end());
	fflush(stdout);

	/* Called when readline data is available */
	if (!ast_all_zeros(s))
		ast_el_add_history(s);
	/* The real handler for bang */
	if (s[0] == '!') {
		if (s[1])
			ast_safe_system(s+1);
		else
			ast_safe_system(getenv("SHELL") ? getenv("SHELL") : "/bin/sh");
	} else
		ast_cli_command(STDOUT_FILENO, s);
}

int console_set_el_gchar_fn(void)
{
  return ast_el_set_gchar_handler(ast_el_read_char);
}

const char* console_el_get_buf(int *num)
{
  return ast_el_get_buf(num);
}

int console_set_thread(pthread_t thread)
{
  consolethread = thread;
  return 0;
}

int console_el_init(void)
{
  ast_el_initialize_wrap(cli_prompt,cli_complete);

  ast_el_read_default_histfile();
  return 0;
}

int console_initialize(void)
{
  return ast_makesocket();
}


int console_uninitialize(void)
{
  if (ast_socket > -1) {
		pthread_cancel(lthread);
		close(ast_socket);
		ast_socket = -1;
		unlink(ast_config_AST_SOCKET);
		pthread_kill(lthread, SIGURG);
		pthread_join(lthread, NULL);
	}
	if (ast_consock > -1)
		close(ast_consock);

  return 0;
}
