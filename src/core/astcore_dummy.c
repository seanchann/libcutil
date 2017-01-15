/*
 * libcutil -- An utility toolkit.
 *
 * Copyright (C) 2016 - 2017, JYD, Inc.
 *
 * seanchann <seanchann@foxmail.com>
 *
 * See docs/ for more information about
 * the libcutil project.
 *
 * This program belongs to JYD, Inc. JYD, Inc reserves all rights
 */

 #include "asterisk.h"

#include "asterisk/_private.h"


/* we define here the variables so to better agree on the prototype */
#include "asterisk/paths.h"
#include "asterisk/options.h"
#include "asterisk/utils.h"
#include "asterisk/term.h"


struct ast_atexit {
	void (*func)(void);
	int is_cleanup;
	AST_LIST_ENTRY(ast_atexit) list;
};

static AST_LIST_HEAD_STATIC(atexits, ast_atexit);

struct ast_flags cutil_options = { AST_DEFAULT_OPTIONS };

int option_verbose;				/*!< Verbosity level */
int option_debug;				/*!< Debug level */

#if !defined(LOW_MEMORY)
struct thread_list_t {
	AST_RWLIST_ENTRY(thread_list_t) list;
	char *name;
	pthread_t id;
	int lwp;
};

static AST_RWLIST_HEAD_STATIC(thread_list, thread_list_t);

#define AST_MAX_CONNECTS 128

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


/* Sending messages from the daemon back to the display requires _excluding_ the terminating NULL */
static int fdprint(int fd, const char *s)
{
	return write(fd, s, strlen(s));
}


void ast_register_thread(char *name)
{
	struct thread_list_t *new = ast_calloc(1, sizeof(*new));

	if (!new)
		return;

	ast_assert(multi_thread_safe);
	new->id = pthread_self();
	new->lwp = ast_get_tid();
	new->name = name; /* steal the allocated memory for the thread name */
	AST_RWLIST_WRLOCK(&thread_list);
	AST_RWLIST_INSERT_HEAD(&thread_list, new, list);
	AST_RWLIST_UNLOCK(&thread_list);
}

void ast_unregister_thread(void *id)
{
	struct thread_list_t *x;

	AST_RWLIST_WRLOCK(&thread_list);
	AST_RWLIST_TRAVERSE_SAFE_BEGIN(&thread_list, x, list) {
		if ((void *) x->id == id) {
			AST_RWLIST_REMOVE_CURRENT(list);
			break;
		}
	}
	AST_RWLIST_TRAVERSE_SAFE_END;
	AST_RWLIST_UNLOCK(&thread_list);
	if (x) {
		ast_free(x->name);
		ast_free(x);
	}
}
#endif


static void ast_run_atexits(int run_cleanups)
{
	struct ast_atexit *ae;

	AST_LIST_LOCK(&atexits);
	while ((ae = AST_LIST_REMOVE_HEAD(&atexits, list))) {
		if (ae->func && (!ae->is_cleanup || run_cleanups)) {
			ae->func();
		}
		ast_free(ae);
	}
	AST_LIST_UNLOCK(&atexits);
}

static void __ast_unregister_atexit(void (*func)(void))
{
	struct ast_atexit *ae;

	AST_LIST_TRAVERSE_SAFE_BEGIN(&atexits, ae, list) {
		if (ae->func == func) {
			AST_LIST_REMOVE_CURRENT(list);
			ast_free(ae);
			break;
		}
	}
	AST_LIST_TRAVERSE_SAFE_END;
}

static int register_atexit(void (*func)(void), int is_cleanup)
{
	struct ast_atexit *ae;

	ae = ast_calloc(1, sizeof(*ae));
	if (!ae) {
		return -1;
	}
	ae->func = func;
	ae->is_cleanup = is_cleanup;

	AST_LIST_LOCK(&atexits);
	__ast_unregister_atexit(func);
	AST_LIST_INSERT_HEAD(&atexits, ae, list);
	AST_LIST_UNLOCK(&atexits);

	return 0;
}

int ast_register_atexit(void (*func)(void))
{
	return register_atexit(func, 0);
}

int ast_register_cleanup(void (*func)(void))
{
	return register_atexit(func, 1);
}

void ast_unregister_atexit(void (*func)(void))
{
	AST_LIST_LOCK(&atexits);
	__ast_unregister_atexit(func);
	AST_LIST_UNLOCK(&atexits);
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
