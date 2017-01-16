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

#undef sched_setscheduler
#undef setpriority

#include <stdlib.h>         /* for closefrom(3) */
#ifndef HAVE_CLOSEFROM
#include <dirent.h>         /* for opendir(3)   */
#endif


/* we define here the variables so to better agree on the prototype */
#include "asterisk/paths.h"
#include "asterisk/options.h"
#include "asterisk/utils.h"
#include "asterisk/term.h"
#include "asterisk/cli.h"


struct ast_atexit {
	void (*func)(void);
	int is_cleanup;
	AST_LIST_ENTRY(ast_atexit) list;
};

static AST_LIST_HEAD_STATIC(atexits, ast_atexit);

struct ast_flags cutil_options = { AST_DEFAULT_OPTIONS };

struct _cfg_paths {
	char config_dir[PATH_MAX];
	char log_dir[PATH_MAX];
	char system_name[128];
	char socket_path[PATH_MAX];
};

static struct _cfg_paths cfg_paths;

const char *ast_config_AST_CONFIG_DIR	= cfg_paths.config_dir;
const char *ast_config_AST_LOG_DIR  = cfg_paths.log_dir;
const char *ast_config_AST_SYSTEM_NAME	= cfg_paths.system_name;
const char *ast_config_AST_SOCKET	= cfg_paths.socket_path;






#if !defined(LOW_MEMORY)
struct thread_list_t {
	AST_RWLIST_ENTRY(thread_list_t) list;
	char *name;
	pthread_t id;
	int lwp;
};

static AST_RWLIST_HEAD_STATIC(thread_list, thread_list_t);


struct timeval ast_startuptime;
struct timeval ast_lastreloadtime;


void ast_close_fds_above_n(int n)
{
	closefrom(n + 1);
}

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




/*! \brief NULL handler so we can collect the child exit status */
static void _null_sig_handler(int sig)
{
}

static struct sigaction null_sig_handler = {
	.sa_handler = _null_sig_handler,
	.sa_flags = SA_RESTART,
};

AST_MUTEX_DEFINE_STATIC(safe_system_lock);
/*! \brief Keep track of how many threads are currently trying to wait*() on
 *  a child process
 */
static unsigned int safe_system_level = 0;
static struct sigaction safe_system_prev_handler;

void ast_replace_sigchld(void)
{
	unsigned int level;

	ast_mutex_lock(&safe_system_lock);
	level = safe_system_level++;

	/* only replace the handler if it has not already been done */
	if (level == 0) {
		sigaction(SIGCHLD, &null_sig_handler, &safe_system_prev_handler);
	}

	ast_mutex_unlock(&safe_system_lock);
}

void ast_unreplace_sigchld(void)
{
	unsigned int level;

	ast_mutex_lock(&safe_system_lock);
	level = --safe_system_level;

	/* only restore the handler if we are the last one */
	if (level == 0) {
		sigaction(SIGCHLD, &safe_system_prev_handler, NULL);
	}

	ast_mutex_unlock(&safe_system_lock);
}



int ast_safe_system(const char *s)
{
	pid_t pid;
	int res;
	int status;

#if defined(HAVE_WORKING_FORK) || defined(HAVE_WORKING_VFORK)
	ast_replace_sigchld();

#ifdef HAVE_WORKING_FORK
	pid = fork();
#else
	pid = vfork();
#endif

	if (pid == 0) {
#ifdef HAVE_CAP
		cap_t cap = cap_from_text("cap_net_admin-eip");

		if (cap_set_proc(cap)) {
			/* Careful with order! Logging cannot happen after we close FDs */
			ast_log(LOG_WARNING, "Unable to remove capabilities.\n");
		}
		cap_free(cap);
#endif
#ifdef HAVE_WORKING_FORK
		if (ast_opt_high_priority)
			ast_set_priority(0);
		/* Close file descriptors and launch system command */
		ast_close_fds_above_n(STDERR_FILENO);
#endif
		execl("/bin/sh", "/bin/sh", "-c", s, (char *) NULL);
		_exit(1);
	} else if (pid > 0) {
		for (;;) {
			res = waitpid(pid, &status, 0);
			if (res > -1) {
				res = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
				break;
			} else if (errno != EINTR)
				break;
		}
	} else {
		ast_log(LOG_WARNING, "Fork failed: %s\n", strerror(errno));
		res = -1;
	}

	ast_unreplace_sigchld();
#else /* !defined(HAVE_WORKING_FORK) && !defined(HAVE_WORKING_VFORK) */
	res = -1;
#endif

	return res;
}



/*! \brief We set ourselves to a high priority, that we might pre-empt
 * everything else.  If your PBX has heavy activity on it, this is a
 * good thing.
 */
int ast_set_priority(int pri)
{
	struct sched_param sched;
	memset(&sched, 0, sizeof(sched));
#ifdef __linux__
	if (pri) {
		sched.sched_priority = 10;
		if (sched_setscheduler(0, SCHED_RR, &sched)) {
			ast_log(LOG_WARNING, "Unable to set high priority\n");
			return -1;
		} else
			ast_verb(1, "Set to realtime thread\n");
	} else {
		sched.sched_priority = 0;
		/* According to the manpage, these parameters can never fail. */
		sched_setscheduler(0, SCHED_OTHER, &sched);
	}
#else
	if (pri) {
		if (setpriority(PRIO_PROCESS, 0, -10) == -1) {
			ast_log(LOG_WARNING, "Unable to set high priority\n");
			return -1;
		} else
			ast_verb(1, "Set to high priority\n");
	} else {
		/* According to the manpage, these parameters can never fail. */
		setpriority(PRIO_PROCESS, 0, 0);
	}
#endif
	return 0;
}
