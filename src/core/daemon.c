
#include "asterisk.h"

#include <histedit.h>

#include "asterisk/utils.h"
#include "el_api.h"

static pthread_t mon_sig_flags;


pid_t ast_mainpid;

static int sig_alert_pipe[2] = { -1, -1 };
static struct {
	 unsigned int need_reload:1;
	 unsigned int need_quit:1;
	 unsigned int need_quit_handler:1;
} sig_flags;


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
			if (sig_flags.need_quit || sig_flags.need_quit_handler)
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
	if (restartnow)
		execvp(_argv[0], _argv);
	sig_flags.need_reload = 1;
	if (sig_alert_pipe[1] != -1) {
		if (write(sig_alert_pipe[1], &a, sizeof(a)) < 0) {
			fprintf(stderr, "hup_handler: write() failed: %s\n", strerror(errno));
		}
	}
	errno = save_errno;
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
			if ((consolethread != AST_PTHREADT_NULL) && (consolethread != pthread_self())) {
				sig_flags.need_quit_handler = 1;
				pthread_kill(consolethread, SIGURG);
			} else {
				quit_handler(0, SHUTDOWN_NORMAL, 0);
			}
		}
		if (read(sig_alert_pipe[0], &a, sizeof(a)) != sizeof(a)) {
		}
	}

	return NULL;
}

static void asterisk_daemon(int isroot, const char *runuser, const char *rungroup)
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
		if (el_hist == NULL || el == NULL)
			ast_el_initialize();
		ast_el_read_default_histfile();
	}


  if (ast_opt_no_fork) {
		consolethread = pthread_self();
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

    el_set(el, EL_GETCFN, ast_el_read_char);

    for (;;) {
      if (sig_flags.need_quit || sig_flags.need_quit_handler) {
        quit_handler(0, SHUTDOWN_FAST, 0);
        break;
      }
      buf = (char *) el_gets(el, &num);

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
