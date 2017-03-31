/*
 * Copyright (C) 2016 - 2017, JYD, Inc.
 *
 * seanchann <xqzhou@bj-jyd.cn>
 *
 * See docs/ for more information about
 * the  project.
 *
 * This program belongs to JYD, Inc. JYD, Inc reserves all rights
 */

#include "libcutil.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>
#include <sys/prctl.h>
#include <pwd.h>


#include "libcutil/term.h"
#include "libcutil/utils.h"
#include "libcutil/linkedlists.h"
#include "internal.h"

struct logger_files_line {
  char chan_name[64];
  char chan_value[128];
  int  index;

  // refer logger files line
  AST_LIST_ENTRY(logger_files_line) list; /*!< Linked list information */
};

struct logger_config {
  char                                date_format[64];
  char                                use_callids[16];
  char                                append_hostname[16];
  enum libcuti_logger_rotate_strategy rotate_strategy;

  int line_count;
  AST_LIST_HEAD_NOLOCK(, logger_files_line) lines;
};


struct libcutil {
  char config_CONFIG_DIR[PATH_MAX];
  char config_LOG_DIR[PATH_MAX];
  char config_SYSTEM_NAME[PATH_MAX];
  char config_SOCKET[PATH_MAX];
  char config_PID[PATH_MAX];
  char config_RUN_DIR[PATH_MAX];
  char config_RUN_USER[PATH_MAX];
  char config_RUN_GROUP[PATH_MAX];


  /*log configure*/
  int option_verbose;

  /*!< Debugging */
  int option_debug;
  int ast_verb_sys_level;

  struct ast_flags options;
  struct timeval   ast_startuptime;
  struct timeval   ast_lastreloadtime;


  /*!< UNIX Socket for allowing remote control */
  int ast_socket;

  /*!< UNIX Socket for controlling another asterisk*/
  int ast_consock;


  /*ctl files*/

  // console permissions eg 0700 ,0660
  char config_CTL_PERMISSIONS[32];

  // console owner user
  char config_CTL_OWNER[32];

  // console group
  char config_CTL_GROUP[32];

  // console ctl file name
  char config_CTL[64];

  char remotehostname[128];

  struct logger_config *logger_cfg;
};

static struct libcutil *g_libcutil = NULL;

void __attribute__((constructor)) libcutil_init(void)
{
  printf("init library  \r\n");

  if (!g_libcutil) {
    g_libcutil = calloc(1, sizeof(struct libcutil));

    if (g_libcutil) {
      g_libcutil->ast_socket  = -1;
      g_libcutil->ast_consock = -1;

      snprintf(g_libcutil->config_CTL_PERMISSIONS,
               sizeof(g_libcutil->config_CTL_PERMISSIONS), "0600");

      snprintf(g_libcutil->config_CTL, sizeof(g_libcutil->config_CTL),
               "cutil.ctl");

      g_libcutil->logger_cfg = calloc(1, sizeof(struct logger_config));

      if (g_libcutil->logger_cfg) {
        struct logger_files_line *console_line =
          calloc(1, sizeof(struct logger_files_line));

        if (!console_line) {
          goto err;
        }

        snprintf(console_line->chan_name,
                 sizeof(console_line->chan_name),
                 "console");
        snprintf(console_line->chan_value,
                 sizeof(console_line->chan_value),
                 "notice,warning,error");

        AST_LIST_HEAD_INIT_NOLOCK(&g_libcutil->logger_cfg->lines);
        AST_LIST_INSERT_TAIL(&g_libcutil->logger_cfg->lines, console_line, list);
        g_libcutil->logger_cfg->line_count++;

        snprintf(g_libcutil->logger_cfg->date_format,
                 sizeof(g_libcutil->logger_cfg->date_format), "%%F %%T.%%3q");
        snprintf(g_libcutil->logger_cfg->use_callids,
                 sizeof(g_libcutil->logger_cfg->use_callids), "no");

        snprintf(g_libcutil->logger_cfg->append_hostname,
                 sizeof(g_libcutil->logger_cfg->append_hostname), "yes");

        g_libcutil->logger_cfg->rotate_strategy = LOGGER_ROTATE_STRATEGY_ROTATE;
      } else {
        goto err;
      }
    } else {
      goto err;
    }
  }

  return;

err:
  fprintf(stderr,
          "Unable to calloc any more memory for libcutil\n");
  exit(1);
}

void __attribute__((destructor)) libcutil_free(void)
{
  if (g_libcutil) {
    if (g_libcutil->logger_cfg) {
      struct logger_files_line *current = NULL;


      while ((current =
                AST_LIST_REMOVE_HEAD(&g_libcutil->logger_cfg->lines, list))) {
        free(current);
      }

      free(g_libcutil->logger_cfg);
    }

    free(g_libcutil);
  }
  g_libcutil = NULL;
}

static struct libcutil* libcutil_instance(void)
{
  return g_libcutil;
}

const char* libcutil_get_config_dir(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_CONFIG_DIR;
}

void libcutil_set_config_dir(const char *dir)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->config_CONFIG_DIR,
           sizeof(instance->config_CONFIG_DIR),
           "%s",
           dir);
}

const char* libcutil_get_config_log_dir(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_LOG_DIR;
}

void libcutil_set_config_log_dir(const char *dir)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->config_LOG_DIR, sizeof(instance->config_LOG_DIR), "%s", dir);
}

const char* libcutil_get_config_system_name(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_SYSTEM_NAME;
}

void libcutil_set_config_system_name(const char *system_name)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->config_SYSTEM_NAME,
           sizeof(instance->config_SYSTEM_NAME),
           "%s",
           system_name);
}

const char* libcutil_get_config_socket(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_SOCKET;
}

int libcutil_set_config_socket(void)
{
  struct libcutil *instance = libcutil_instance();

  // set default sockcet
  if (!ast_strlen_zero(libcutil_get_config_run_dir())) {
    snprintf(instance->config_SOCKET,
             sizeof(instance->config_SOCKET),
             "%s/cutil.ctl", libcutil_get_config_run_dir());
    return 0;
  }

  return -1;
}

const char* libcutil_get_config_pid(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_PID;
}

int libcutil_test_option(enum cutil_option_flags flag)
{
  struct libcutil *instance = libcutil_instance();

  return ast_test_flag(&instance->options, flag);
}

int libcutil_get_option_debug(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->option_debug;
}

void libcutil_set_option_debug(int level)
{
  struct libcutil *instance = libcutil_instance();

  instance->option_debug = level;
}

int libcutil_get_option_verbose(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->option_verbose;
}

void libcutil_set_option_verbose(int level)
{
  struct libcutil *instance = libcutil_instance();

  instance->option_verbose = level;
}

int libcutil_get_option_verbose_sys_level(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->ast_verb_sys_level;
}

void libcutil_set_option_verbose_sys_level(int level)
{
  struct libcutil *instance = libcutil_instance();

  instance->ast_verb_sys_level = level;
}

struct timeval libcutil_get_startup_time(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->ast_startuptime;
}

struct timeval libcutil_get_lastreload_time(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->ast_lastreloadtime;
}

int libcutil_get_consock(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->ast_consock;
}

void libcutil_set_consock(int fd)
{
  struct libcutil *instance = libcutil_instance();

  instance->ast_consock = fd;
}

void libcutil_set_socket(int fd)
{
  struct libcutil *instance = libcutil_instance();

  instance->ast_socket = fd;
}

int libcutil_get_socket(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->ast_socket;
}

const char* libcutil_get_ctl_permissions(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_CTL_PERMISSIONS;
}

void libcutil_set_ctl_permissions(char *permissions)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->config_CTL_PERMISSIONS,
           sizeof(instance->config_CTL_PERMISSIONS), "%s", permissions);
}

const char* libcutil_get_ctl_owner(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_CTL_OWNER;
}

const char* libcutil_get_ctl_group(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_CTL_GROUP;
}

const char* libcutil_get_ctl_filename(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_CTL;
}

const char* libcutil_get_remotehostname(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->remotehostname;
}

void libcutil_set_remotehostname(const char *hostname)
{
  struct libcutil *instance = libcutil_instance();
}

const char* libcutil_get_config_run_user(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_RUN_USER;
}

void libcutil_set_config_run_user(const char *run_user)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->config_RUN_USER,
           sizeof(instance->config_RUN_USER),
           "%s",
           run_user);
}

const char* libcutil_get_config_run_group(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_RUN_GROUP;
}

void libcutil_set_config_run_group(const char *run_group)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->config_RUN_GROUP,
           sizeof(instance->config_RUN_GROUP),
           "%s",
           run_group);
}

// libcutil_enable_console enable console when program start
// default not start a console when main up.
void libcutil_enable_console(void)
{
  struct libcutil *instance = libcutil_instance();

  ast_set_flag(&instance->options, AST_OPT_FLAG_NO_FORK | AST_OPT_FLAG_CONSOLE);
}

void libcutil_enable_remote(void)
{
  struct libcutil *instance = libcutil_instance();

  ast_set_flag(&instance->options, AST_OPT_FLAG_NO_FORK | AST_OPT_FLAG_REMOTE);
}

const char* libcutil_get_config_run_dir(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_RUN_DIR;
}

void libcutil_set_config_run_dir(const char *dir)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->config_RUN_DIR, sizeof(instance->config_RUN_DIR), "%s", dir);
}

// ses strftime(3) for details. eg '%F %T' is ISO 8601 date format
void libcutil_logger_set_date_format(char *dataformat)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->logger_cfg->date_format,
           sizeof(instance->logger_cfg->date_format), "%s", dataformat);
}

const char* libcutil_logger_get_date_format(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->logger_cfg->date_format;
}

// This makes  write callids to log messages.value is yes or no
void libcutil_logger_set_use_callids(char *flags)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->logger_cfg->use_callids,
           sizeof(instance->logger_cfg->use_callids), "%s", flags);
}

const char* libcutil_logger_get_use_callids(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->logger_cfg->use_callids;
}

// This appends the hostname to the name of the log files..value is yes or no
void libcutil_logger_set_appendhostname(char *flags)
{
  struct libcutil *instance = libcutil_instance();

  snprintf(instance->logger_cfg->append_hostname,
           sizeof(instance->logger_cfg->append_hostname), "%s", flags);
}

const char* libcutil_logger_get_appendhostname(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->logger_cfg->append_hostname;
}

void libcutil_logger_set_rotate_strategy(
  enum libcuti_logger_rotate_strategy strategy)
{
  struct libcutil *instance = libcutil_instance();

  instance->logger_cfg->rotate_strategy = strategy;
}

enum libcuti_logger_rotate_strategy libcutil_logger_get_rotate_strategy(
  void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->logger_cfg->rotate_strategy;
}

void libcutil_logger_append_logfiles_line(char *name, char *value)
{
  struct libcutil *instance              = libcutil_instance();
  struct logger_files_line *console_line =
    calloc(1, sizeof(struct logger_files_line));

  if (!console_line) {
    return;
  }

  snprintf(console_line->chan_name,
           sizeof(console_line->chan_name),
           "%s", name);

  snprintf(console_line->chan_value,
           sizeof(console_line->chan_value),
           "%s", value);
  console_line->index = ++instance->logger_cfg->line_count;
  AST_LIST_INSERT_TAIL(&instance->logger_cfg->lines, console_line, list);
}

void libcutil_logger_create_log_channel(logger_channel_cb cb)
{
  struct libcutil *instance = libcutil_instance();
  struct logger_files_line *cfg;


  AST_LIST_TRAVERSE(&instance->logger_cfg->lines, cfg, list) {
    cb(cfg->chan_name, cfg->chan_value, cfg->index, 0);
  }
}

static void print_intro_message(const char *runuser, const char *rungroup)
{
  if (ast_opt_console || libcutil_get_option_verbose() ||
      (ast_opt_remote && !ast_opt_exec)) {
    WELCOME_MESSAGE;

    if (runuser) {
      ast_verbose("Running as user '%s'\n", runuser);
    }

    if (rungroup) {
      ast_verbose("Running under group '%s'\n", rungroup);
    }
  }
}

static void _child_handler(int sig)
{
  /* Must not ever ast_log or ast_verbose within signal handler */
  int n, status, save_errno = errno;

  /*
   * Reap all dead children -- not just one
   */
  for (n = 0; waitpid(-1, &status, WNOHANG) > 0; n++) ;

  if ((n == 0) &&
      libcutil_get_option_debug()) printf(
      "Huh?  Child handler, but nobody there?\n");
  errno = save_errno;
}

static struct sigaction child_handler = {
  .sa_handler = _child_handler,
  .sa_flags   = SA_RESTART,
};


/*libcutil_process when lib init done. call this function in your main loop*/
void libcutil_process(void)
{
  int isroot = 1, rundir_exists = 0;
  const char *runuser = NULL, *rungroup = NULL;
  char *xarg = NULL;
  int   x;


  if (geteuid() != 0) isroot = 0;

  /* Must install this signal handler up here to ensure that if the canary
   * fails to execute that it doesn't kill the Asterisk process.
   */
  sigaction(SIGCHLD, &child_handler, NULL);

  /* It's common on some platforms to clear /var/run at boot.  Create the
   * socket file directory before we drop privileges. */
  if (mkdir(libcutil_get_config_run_dir(), 0755)) {
    if (errno == EEXIST) {
      rundir_exists = 1;
      libcutil_set_config_socket();
    } else {
      fprintf(stderr,
              "Unable to create socket file directory.  Remote consoles will not be able to connect! (%s)\n",
              strerror(x));
      exit(1);
    }
  }

  if ((!rungroup) &&
      !ast_strlen_zero(libcutil_get_config_run_group())) rungroup =
      libcutil_get_config_run_group();


  if ((!runuser) &&
      !ast_strlen_zero(libcutil_get_config_run_user())) runuser =
      libcutil_get_config_run_user();


#ifndef __CYGWIN__

  if (isroot) {
    ast_set_priority(ast_opt_high_priority);
  }

  if (isroot && rungroup) {
    struct group *gr;
    gr = getgrnam(rungroup);

    if (!gr) {
      fprintf(stderr, "No such group '%s'!\n", rungroup);
      exit(1);
    }

    if (!rundir_exists && chown(libcutil_get_config_run_dir(), -1, gr->gr_gid)) {
      fprintf(stderr,
              "Unable to chgrp run directory to %d (%s)\n",
              (int)gr->gr_gid,
              rungroup);
    }

    if (setgid(gr->gr_gid)) {
      fprintf(stderr, "Unable to setgid to %d (%s)\n", (int)gr->gr_gid, rungroup);
      exit(1);
    }

    if (setgroups(0, NULL)) {
      fprintf(stderr, "Unable to drop unneeded groups\n");
      exit(1);
    }
  }

  if (runuser && !ast_opt_remote) {
  # ifdef HAVE_CAP
    int has_cap = 1;
  # endif /* HAVE_CAP */
    struct passwd *pw;
    pw = getpwnam(runuser);

    if (!pw) {
      fprintf(stderr, "No such user '%s'!\n", runuser);
      exit(1);
    }

    if (chown(libcutil_get_config_run_dir(), pw->pw_uid, -1)) {
      fprintf(stderr,
              "Unable to chown run directory to %d (%s)\n",
              (int)pw->pw_uid,
              runuser);
    }
  # ifdef HAVE_CAP

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) {
      ast_log(LOG_WARNING, "Unable to keep capabilities.\n");
      has_cap = 0;
    }
  # endif /* HAVE_CAP */

    if (!isroot && (pw->pw_uid != geteuid())) {
      fprintf(stderr,
              "main started as nonroot, but runuser '%s' requested.\n",
              runuser);
      exit(1);
    }

    if (!rungroup) {
      if (setgid(pw->pw_gid)) {
        fprintf(stderr, "Unable to setgid to %d!\n", (int)pw->pw_gid);
        exit(1);
      }

      if (isroot && initgroups(pw->pw_name, pw->pw_gid)) {
        fprintf(stderr, "Unable to init groups for '%s'\n", runuser);
        exit(1);
      }
    }

    if (setuid(pw->pw_uid)) {
      fprintf(stderr, "Unable to setuid to %d (%s)\n", (int)pw->pw_uid, runuser);
      exit(1);
    }
  # ifdef HAVE_CAP

    if (has_cap) {
      cap_t cap;

      cap = cap_from_text("cap_net_admin=eip");

      if (cap_set_proc(cap)) {
        fprintf(stderr, "Unable to install capabilities.\n");
      }

      if (cap_free(cap)) {
        fprintf(stderr, "Unable to drop capabilities.\n");
      }
    }
  # endif /* HAVE_CAP */
  }

  #endif  /* __CYGWIN__ */

  #ifdef linux

  if (geteuid() && ast_opt_dump_core) {
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
      fprintf(stderr,
              "Unable to set the process for core dumps after changing to a non-root user. %s\n",
              strerror(errno));
    }
  }
  #endif /* ifdef linux */


  if (ast_tryconnect()) {
    /* One is already running */
    if (ast_opt_remote) {
      printf("in remote\r\n");
      enable_multi_thread_safe();

      if (ast_opt_exec) {
        ast_remotecontrol(xarg);
        shutdown_fast_wrap(0, 0);
        exit(0);
      }
      printf("in term\r\n");
      ast_term_init();
      printf("init term done\r\n");
      printf("%s", term_end());
      fflush(stdout);

      printf("in term 222\r\n");
      print_intro_message(runuser, rungroup);
      printf("%s", term_quit());
      ast_remotecontrol(NULL);
      shutdown_fast_wrap(0, 0);
      exit(0);
    } else {
      fprintf(stderr,
              "already running on %s.  get your help for connect.\n",
              libcutil_get_config_socket());
      printf("%s", term_quit());
      exit(1);
    }
  } else if (ast_opt_remote || ast_opt_exec) {
    fprintf(stderr,
            "Unable to connect to remote asterisk (does %s exist?)\n",
            libcutil_get_config_socket());
    printf("%s", term_quit());
    exit(1);
  }


  daemon_run(isroot, runuser, rungroup);
}
