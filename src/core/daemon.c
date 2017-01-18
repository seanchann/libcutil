#include "asterisk.h"

#include "asterisk/_private.h"

#include "daemon.h"

#include <histedit.h>

#include "asterisk/paths.h"
#include "asterisk/utils.h"
#include "asterisk/io.h"
#include "asterisk/poll-compat.h"
#include "asterisk/term.h"
#include "console.h"
#include "elhelper.h"
#include "astcore_dummy.h"


static int sig_alert_pipe[2] = { -1, -1 };
static struct {
	 unsigned int need_reload:1;
	 unsigned int need_quit:1;
	 unsigned int need_quit_handler:1;
} sig_flags;

static shutdown_nice_t shuttingdown = NOT_SHUTTING_DOWN;


static pthread_t mon_sig_flags;

pid_t ast_mainpid;

int show_version(void)
{
	printf("Asterisk %s\n", ast_get_version());
	return 0;
}

/*! \brief Set an X-term or screen title */
static void set_title(char *text)
{
	if (getenv("TERM") && strstr(getenv("TERM"), "xterm"))
		fprintf(stdout, "\033]2;%s\007", text);
}

static void set_icon(char *text)
{
	if (getenv("TERM") && strstr(getenv("TERM"), "xterm"))
		fprintf(stdout, "\033]1;%s\007", text);
}


pid_t mainpid(void)
{
	return ast_mainpid;
}

unsigned int sig_need_quit(void)
{
	return sig_flags.need_quit;
}

unsigned int sig_need_quit_handler(void)
{
	return sig_flags.need_quit_handler;
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


static int can_safely_quit(shutdown_nice_t niceness, int restart)
{
	int waited = 0;

	/* Check if someone else isn't already doing this. */
	ast_mutex_lock(&safe_system_lock);
	if (shuttingdown != NOT_SHUTTING_DOWN && niceness >= shuttingdown) {
		/* Already in progress and other request was less nice. */
		ast_mutex_unlock(&safe_system_lock);
		ast_verbose("Ignoring asterisk %s request, already in progress.\n", restart ? "restart" : "shutdown");
		return 0;
	}
	shuttingdown = niceness;
	ast_mutex_unlock(&safe_system_lock);


	/* Re-acquire lock and check if someone changed the niceness, in which
	 * case someone else has taken over the shutdown.
	 */
	ast_mutex_lock(&safe_system_lock);
	if (shuttingdown != niceness) {
		if (shuttingdown == NOT_SHUTTING_DOWN && ast_opt_console) {
			ast_verb(0, "Asterisk %s cancelled.\n", restart ? "restart" : "shutdown");
		}
		ast_mutex_unlock(&safe_system_lock);
		return 0;
	}

	if (niceness >= SHUTDOWN_REALLY_NICE) {
		shuttingdown = SHUTTING_DOWN;
		ast_mutex_unlock(&safe_system_lock);

		/* No more Mr. Nice guy.  We are committed to shutting down now. */
		//do shutdow

		ast_mutex_lock(&safe_system_lock);
	}
	shuttingdown = SHUTTING_DOWN_FINAL;
	ast_mutex_unlock(&safe_system_lock);

	if (niceness >= SHUTDOWN_NORMAL && waited) {
		/*
		 * We were not idle.  Give things in progress a chance to
		 * recognize the final shutdown phase.
		 */
		sleep(1);
	}
	return 1;
}

/*! Called when exiting is certain. */
static void really_quit(int num, shutdown_nice_t niceness, int restart)
{
	int active_channels;
	struct ast_json *json_object = NULL;
	int run_cleanups = niceness >= SHUTDOWN_NICE;


	if (!restart) {
		ast_sd_notify("STOPPING=1");
	}
	if (ast_opt_console || (ast_opt_remote && !ast_opt_exec)) {
		#if 0
		ast_el_write_default_histfile();
		if (consolethread == AST_PTHREADT_NULL || consolethread == pthread_self()) {
			/* Only end if we are the consolethread, otherwise there's a race with that thread. */
			if (el != NULL) {
				el_end(el);
			}
			if (el_hist != NULL) {
				history_end(el_hist);
			}
		} else if (mon_sig_flags == pthread_self()) {
			if (consolethread != AST_PTHREADT_NULL) {
				pthread_kill(consolethread, SIGURG);
			}
		}
		#else
		console_quit(mon_sig_flags);
		#endif
	}

	/* Don't publish messages if we're a remote console - we won't have all of the Stasis
	 * topics or message types
	 */
	if (!ast_opt_remote) {
		json_object = ast_json_pack("{s: s, s: s}",
				"Shutdown", active_channels ? "Uncleanly" : "Cleanly",
				"Restart", restart ? "True" : "False");
		ast_json_unref(json_object);
		json_object = NULL;
	}

	ast_verb(0, "Executing last minute cleanups\n");
	ast_run_atexits(run_cleanups);

	ast_debug(1, "libcutil ending (%d).\n", num);
#if 0
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
#else
	console_uninitialize();
#endif


	if (!ast_opt_remote)
		unlink(ast_config_AST_PID);
	if (sig_alert_pipe[0])
		close(sig_alert_pipe[0]);
	if (sig_alert_pipe[1])
		close(sig_alert_pipe[1]);
	printf("%s", term_quit());
#if 0
	if (restart) {
		int i;
		ast_verb(0, "Preparing for Asterisk restart...\n");
		/* Mark all FD's for closing on exec */
		for (i = 3; i < 32768; i++) {
			fcntl(i, F_SETFD, FD_CLOEXEC);
		}
		ast_verb(0, "Asterisk is now restarting...\n");
		restartnow = 1;

		/* close logger */
		close_logger();
		clean_time_zones();

		/* If there is a consolethread running send it a SIGHUP
		   so it can execvp, otherwise we can do it ourselves */
		if ((consolethread != AST_PTHREADT_NULL) && (consolethread != pthread_self())) {
			pthread_kill(consolethread, SIGHUP);
			/* Give the signal handler some time to complete */
			sleep(2);
		} else
			execvp(_argv[0], _argv);

	} else {

		/* close logger */
		close_logger();
		clean_time_zones();
	}
#else
	/* close logger */
	close_logger();
	clean_time_zones();
#endif

	exit(0);
}



void quit_handler(int num, shutdown_nice_t niceness, int restart)
{
	if (can_safely_quit(niceness, restart)) {
		really_quit(num, niceness, restart);
		/* No one gets here. */
	}
	/* It wasn't our time. */
}

/*! \brief Urgent handler
 *
 * Called by soft_hangup to interrupt the poll, read, or other
 * system call.  We don't actually need to do anything though.
 * Remember: Cannot EVER ast_log from within a signal handler
 */
static void _urg_handler(int num)
{
	return;
}

static struct sigaction urg_handler = {
	.sa_handler = _urg_handler,
};

static void _hup_handler(int num)
{
	int a = 0, save_errno = errno;
	printf("Received HUP signal -- Reloading configs\n");
#if 0
	if (restartnow)
		execvp(_argv[0], _argv);
	sig_flags.need_reload = 1;
	if (sig_alert_pipe[1] != -1) {
		if (write(sig_alert_pipe[1], &a, sizeof(a)) < 0) {
			fprintf(stderr, "hup_handler: write() failed: %s\n", strerror(errno));
		}
	}
	errno = save_errno;
#endif
}

static struct sigaction hup_handler = {
	.sa_handler = _hup_handler,
	.sa_flags = SA_RESTART,
};

static void _child_handler(int sig)
{
	/* Must not ever ast_log or ast_verbose within signal handler */
	int n, status, save_errno = errno;

	/*
	 * Reap all dead children -- not just one
	 */
	for (n = 0; waitpid(-1, &status, WNOHANG) > 0; n++)
		;
	if (n == 0 && option_debug)
		printf("Huh?  Child handler, but nobody there?\n");
	errno = save_errno;
}

static struct sigaction child_handler = {
	.sa_handler = _child_handler,
	.sa_flags = SA_RESTART,
};


static void __quit_handler(int num)
{
	int a = 0;
	sig_flags.need_quit = 1;
	if (sig_alert_pipe[1] != -1) {
		if (write(sig_alert_pipe[1], &a, sizeof(a)) < 0) {
			fprintf(stderr, "quit_handler: write() failed: %s\n", strerror(errno));
		}
	}
	/* There is no need to restore the signal handler here, since the app
	 * is going to exit */
}



static struct sigaction ignore_sig_handler = {
	.sa_handler = SIG_IGN,
};


static void *monitor_sig_flags(void *unused)
{
	for (;;) {
		struct pollfd p = { sig_alert_pipe[0], POLLIN, 0 };
		int a;
		ast_poll(&p, 1, -1);
		if (sig_flags.need_quit) {
			sig_flags.need_quit = 0;
			if(console_check_quit()){
				sig_flags.need_quit_handler = 1;
			}else{
				quit_handler(0, SHUTDOWN_NORMAL, 0);
			}
		}
		if (read(sig_alert_pipe[0], &a, sizeof(a)) != sizeof(a)) {
		}
	}

	return NULL;
}


static inline void check_init(int init_result, const char *name)
{
	if (init_result) {
		printf("%s initialization failed.\n%s", name, term_quit());
		ast_run_atexits(0);
		exit(init_result == -2 ? 2 : 1);
	}
}

void daemon_run(int isroot, const char *runuser, const char *rungroup)
{
	sigset_t sigs;
	int num;
	char *buf;

	ast_mainpid = getpid();

  /* Initialize the terminal.  Since all processes have been forked,
  * we can now start using the standard log messages.
  */
  ast_term_init();
  printf("%s", term_end());
  fflush(stdout);


  ast_json_init();
  threadstorage_init();
  check_init(init_logger(), "Logger");

	if (ast_opt_console) {
		console_el_init();
	}


  if (ast_opt_no_fork) {
		console_set_thread(pthread_self());
	}

  /* GCC 4.9 gives a bogus "right-hand operand of comma expression has
	 * no effect" warning */
	(void) sigemptyset(&sigs);
	(void) sigaddset(&sigs, SIGHUP);
	(void) sigaddset(&sigs, SIGTERM);
	(void) sigaddset(&sigs, SIGINT);
	(void) sigaddset(&sigs, SIGPIPE);
	(void) sigaddset(&sigs, SIGWINCH);
	pthread_sigmask(SIG_BLOCK, &sigs, NULL);
	sigaction(SIGURG, &urg_handler, NULL);
	signal(SIGINT, __quit_handler);
	signal(SIGTERM, __quit_handler);
	sigaction(SIGHUP, &hup_handler, NULL);
	sigaction(SIGPIPE, &ignore_sig_handler, NULL);

  if (ast_opt_console) {
    /* Console stuff now... */
    /* Register our quit function */
    char title[256];
    char hostname[MAXHOSTNAMELEN] = "";

    if (gethostname(hostname, sizeof(hostname) - 1)) {
      ast_copy_string(hostname, "<Unknown>", sizeof(hostname));
    }

    ast_pthread_create_detached(&mon_sig_flags, NULL, monitor_sig_flags, NULL);

    set_icon("Asterisk");
    snprintf(title, sizeof(title), "Asterisk Console on '%s' (pid %ld)", hostname, (long)ast_mainpid);
    set_title(title);

    /*el_set(el, EL_GETCFN, ast_el_read_char);*/
		console_set_el_gchar_fn();

    for (;;) {
      if (sig_flags.need_quit || sig_flags.need_quit_handler) {
        quit_handler(0, SHUTDOWN_FAST, 0);
        break;
      }
      /*buf = (char *) el_gets(el, &num);*/
			buf = console_el_get_buf(&num);

      if (!buf && write(1, "", 1) < 0)
        return; /* quit */

      if (buf) {
        if (buf[strlen(buf)-1] == '\n')
          buf[strlen(buf)-1] = '\0';

        consolehandler(buf);
      }
    }
  }

  /* Stall until a quit signal is given */
  monitor_sig_flags(NULL);
}
