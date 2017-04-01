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


#include "libcutil/term.h"
#include "libcutil/utils.h"
#include "libcutil/linkedlists.h"

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

void libcutil_enable_coredump(void)
{
  struct libcutil *instance = libcutil_instance();

  ast_set_flag(&instance->options, AST_OPT_FLAG_DUMP_CORE);
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
