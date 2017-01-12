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
#include "log/logger.h"


int main()
{
  ast_log(LOG_NOTICE,"test %s level log\r\n", "notice");
  return 0;
}
