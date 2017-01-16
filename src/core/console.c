#include "asterisk.h"

#include "asterisk/_private.h"

#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/un.h>
#include <histedit.h>


#include "asterisk/paths.h"
#include "asterisk/lock.h"
#include "asterisk/localtime.h"
#include "asterisk/term.h"
/*#include "asterisk/threadstorage.h"*/
/*#include "asterisk/strings.h"*/
#include "asterisk/utils.h"
#include "el_api.h"

static struct ast_str *prompt = NULL;
int option_verbose;				/*!< Verbosity level */
int option_debug;				/*!< Debug level */
int ast_verb_sys_level;

static int ast_consock = -1;

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
