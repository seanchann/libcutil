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

  struct ast_flags options;
  struct timeval   ast_startuptime;
  struct timeval   ast_lastreloadtime;
};

static struct libcutil *g_libcutil = NULL;

void __attribute__((constructor)) libcutil_init(void)
{
  if (!g_libcutil) {
    g_libcutil = calloc(1, sizeof(struct libcutil));
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
