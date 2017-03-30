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


#include "libcutil/utils.h"
#include "internal.h"

struct libcutil {
  char config_CONFIG_DIR[PATH_MAX];
  char config_LOG_DIR[PATH_MAX];
  char config_SYSTEM_NAME[PATH_MAX];
  char config_SOCKET[PATH_MAX];
  char config_PID[PATH_MAX];
  char config_RUN_DIR[PATH_MAX];

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
};

static struct libcutil *g_libcutil = NULL;

// struct _cfg_paths {
//   char config_dir[PATH_MAX];
//   char log_dir[PATH_MAX];
//   char system_name[128];
//   char socket_path[PATH_MAX];
//   char pid_path[PATH_MAX];
// };
//
// static struct _cfg_paths cfg_paths;
//
// const char *ast_config_AST_CONFIG_DIR  = cfg_paths.config_dir;
// const char *ast_config_AST_LOG_DIR     = cfg_paths.log_dir;
// const char *ast_config_AST_SYSTEM_NAME = cfg_paths.system_name;
// const char *ast_config_AST_SOCKET      = cfg_paths.socket_path;
// const char *ast_config_AST_PID         = cfg_paths.pid_path;


void __attribute__((constructor)) libcutil_init(void)
{
  printf("init library  \r\n");

  if (!g_libcutil) {
    g_libcutil              = calloc(1, sizeof(struct libcutil));
    g_libcutil->ast_socket  = -1;
    g_libcutil->ast_consock = -1;

    snprintf(g_libcutil->config_CTL_PERMISSIONS,
             sizeof(g_libcutil->config_CTL_PERMISSIONS), "0600");

    snprintf(g_libcutil->config_CTL, sizeof(g_libcutil->config_CTL),
             "cutil.ctl");

    printf("start daemon  \r\n");
    daemon_run(0, "seanchann", "seanchann");
  }
}

void __attribute__((destructor)) libcutil_free(void)
{
  if (g_libcutil) {
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

const char* libcutil_get_config_log_dir(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_LOG_DIR;
}

const char* libcutil_get_config_system_name(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_SYSTEM_NAME;
}

const char* libcutil_get_config_socket(void)
{
  struct libcutil *instance = libcutil_instance();

  return instance->config_SOCKET;
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
    } else {
      fprintf(stderr,
              "Unable to create socket file directory.  Remote consoles will not be able to connect! (%s)\n",
              strerror(x));
    }
  }

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
              "Asterisk started as nonroot, but runuser '%s' requested.\n",
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
      enable_multi_thread_safe();

      if (ast_opt_exec) {
        ast_remotecontrol(xarg);
        shutdown_fast_wrap(0, 0);
        exit(0);
      }
      ast_term_init();
      printf("%s", term_end());
      fflush(stdout);

      print_intro_message(runuser, rungroup);
      printf("%s", term_quit());
      ast_remotecontrol(NULL);
      shutdown_fast_wrap(0, 0);
      exit(0);
    } else {
      fprintf(stderr,
              "Asterisk already running on %s.  Use 'asterisk -r' to connect.\n",
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
