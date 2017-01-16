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

#include <signal.h>

#include "log/logger.h"
#include "asterisk/poll-compat.h"


static char *_argv[256];







int main(int argc, char *argv[])
{
  int isroot = 1, rundir_exists = 0;
	const char *runuser = NULL, *rungroup = NULL;
	struct rlimit l;
	static const char *getopt_settings = "dhRrx:Vv";

	/* Remember original args for restart */
	if (argc > ARRAY_LEN(_argv) - 1) {
		fprintf(stderr, "Truncating argument size to %d\n", (int)ARRAY_LEN(_argv) - 1);
		argc = ARRAY_LEN(_argv) - 1;
	}
	for (x = 0; x < argc; x++)
		_argv[x] = argv[x];
	_argv[x] = NULL;

	if (geteuid() != 0)
		isroot = 0;

  /* if the progname is rtest_logutil consider it a remote console */
	if (argv[0] && (strstr(argv[0], "rtest_logutil")) != NULL) {
		ast_set_flag(&cutil_options, AST_OPT_FLAG_NO_FORK | AST_OPT_FLAG_REMOTE);
	}


  /* Process command-line options that effect asterisk.conf load. */
	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case 'd':
			option_debug++;
			break;
		case 'h':
			show_cli_help();
			exit(0);
		case 'R':
		case 'r':
		case 'x':
			/* ast_opt_remote is checked during config load.  This is only part of what
			 * these options do, see the second loop for the rest of the actions. */
			ast_set_flag(&ast_options, AST_OPT_FLAG_REMOTE);
			break;
		case 'V':
			show_version();
			exit(0);
		case 'v':
			option_verbose++;
			break;
		case '?':
			exit(1);
		}
	}


  /* For remote connections, change the name of the remote connection.
	 * We do this for the benefit of init scripts (which need to know if/when
	 * the main asterisk process has died yet). */
	if (ast_opt_remote) {
		strcpy(argv[0], "rasterisk");
		for (x = 1; x < argc; x++) {
			argv[x] = argv[0] + 10;
		}
	}

  if (isroot) {
    ast_set_priority(ast_opt_high_priority);
  }

  if (ast_tryconnect()) {
		/* One is already running */
		if (ast_opt_remote) {
			multi_thread_safe = 1;
			if (ast_opt_exec) {
				ast_remotecontrol(xarg);
				quit_handler(0, SHUTDOWN_FAST, 0);
				exit(0);
			}
			ast_term_init();
			printf("%s", term_end());
			fflush(stdout);

			print_intro_message(runuser, rungroup);
			printf("%s", term_quit());
			ast_remotecontrol(NULL);
			quit_handler(0, SHUTDOWN_FAST, 0);
			exit(0);
		} else {
			fprintf(stderr, "Asterisk already running on %s.  Use 'asterisk -r' to connect.\n", ast_config_AST_SOCKET);
			printf("%s", term_quit());
			exit(1);
		}
	} else if (ast_opt_remote || ast_opt_exec) {
		fprintf(stderr, "Unable to connect to remote asterisk (does %s exist?)\n", ast_config_AST_SOCKET);
		printf("%s", term_quit());
		exit(1);
	}


  ast_log(LOG_NOTICE,"test %s level log\r\n", "notice");
  return 0;
}
