/*
 *
 * seanchann <xqzhou@bj-jyd.cn>
 *
 * See docs/ for more information about
 * the  project.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include "libcutil.h"

#include <signal.h>

#include "libcutil/logger.h"
#include "libcutil/poll-compat.h"
#include "libcutil/utils.h"
#include "libcutil/api.h"
#include "libcutil/cli.h"

static char *_argv[256];
#define RUN_DIR "/var/run/testcutil"

static char *handle_cli_test(struct ast_cli_entry *e, int cmd,
                             struct ast_cli_args *a) {
  switch (cmd) {
    case CLI_INIT:
      e->command = "test show debug";
      e->usage =
          "Usage: test show debug\n"
          "       List current debug level\n";
      return NULL;

    case CLI_GENERATE:
      return NULL;
  }

  cutil_log(LOG_NOTICE, "get debug level\r\n");
  ast_cli(a->fd, "current debug leve %d\n", libcutil_get_option_debug());

  return CLI_SUCCESS;
}

static struct ast_cli_entry cli_test[] = {
    AST_CLI_DEFINE(handle_cli_test, "get logger debug level"),
};

static int show_cli_help(void) {
  printf("test_logutil, Copyright (C) 2017 - 2018, JYD, Inc. and others.\n");
  printf("Usage: test_logutil [OPTIONS]\n");
  printf("Valid Options:\n");
  printf("   -c              Provide console CLI\n");
  printf(
      "   -d              Increase debugging (multiple d's = more "
      "debugging)\n");
  printf("   -h              This help screen\n");
  printf("   -r              Connect to test_logutil on this machine\n");
  printf(
      "   -R              Same as -r, except attempt to reconnect if "
      "disconnected\n");
  printf(
      "   -v              Increase verbosity (multiple v's = more verbose)\n");
  printf("   -X              Enable use of #exec in asterisk.conf\n");
  printf("\n");
  return 0;
}

static void exit_handle(void) {
  printf("exit program. clean up resource\r\n");

  ast_cli_unregister_multiple(cli_test, ARRAY_LEN(cli_test));
}

static void fully_booted_event_cb(void) {
  ast_verbose("libcutil fully booted\r\n");

  /* register the logger cli commands */
  ast_cli_register_multiple(cli_test, ARRAY_LEN(cli_test));

  init_restful_mod();

  ast_register_atexit(exit_handle);
}

int main(int argc, char *argv[]) {
  int isroot = 1, rundir_exists = 0;
  const char *runuser = NULL, *rungroup = NULL;
  int x;
  static const char *getopt_settings = "cdhgRrx:Vv";
  int c;

  printf("init library  \r\n");

  libcutil_set_option_debug(5);
  libcutil_set_option_verbose(5);
  libcutil_set_config_run_user("root");
  libcutil_set_config_run_group("root");

  libcutil_set_config_run_dir(RUN_DIR);

  libcutil_set_config_log_dir("/var/log");
  libcutil_logger_append_logfiles_line("full",
                                       "notice,warning,error,debug,verbose");

  /* Remember original args for restart */
  if (argc > ARRAY_LEN(_argv) - 1) {
    fprintf(stderr, "Truncating argument size to %d\n",
            (int)ARRAY_LEN(_argv) - 1);
    argc = ARRAY_LEN(_argv) - 1;
  }

  for (x = 0; x < argc; x++) _argv[x] = argv[x];
  _argv[x] = NULL;

  /* if the progname is rtest_logutil consider it a remote console */
  if (argv[0] && ((strstr(argv[0], "rtest_logutil")) != NULL)) {
    libcutil_enable_remote();
  }

  /* Process command-line options that effect asterisk.conf load. */
  while ((c = getopt(argc, argv, getopt_settings)) != -1) {
    switch (c) {
      case 'd':
        libcutil_set_option_debug(libcutil_get_option_debug() + 1);
        break;

      case 'h':

        show_cli_help();
        exit(0);

      case 'R':
      case 'r':
      case 'x':

        /* ast_opt_remote is checked during config load.  This is only part
           of
           what
         * these options do, see the second loop for the rest of the actions.
         */
        libcutil_enable_remote();
        break;

      case 'V':
        show_version();
        exit(0);

      case 'v':
        libcutil_set_option_verbose(libcutil_get_option_verbose() + 1);
        break;

      case 'c':
        libcutil_enable_console();
        break;

      case 'g':
        libcutil_enable_coredump();
        break;

      case '?':
        exit(1);
    }
  }

  libcutil_process(fully_booted_event_cb);

  return 0;
}
