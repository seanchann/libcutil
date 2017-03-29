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

#include "libcutil/utils.h"

struct libcutil {
  const char *config_CONFIG_DIR;
  const char *config_LOG_DIR;
  const char *config_SYSTEM_NAME;
  const char *config_SOCKET;
  const char *config_PID;

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
  if (!g_libcutil) {
    g_libcutil              = calloc(1, sizeof(struct libcutil));
    g_libcutil->ast_socket  = -1;
    g_libcutil->ast_consock = -1;
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
