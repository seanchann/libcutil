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

#include "libcutil/restful.h"


void init_restful_mod(void)
{
  struct http_server_config config;

  config.enabled = 1;
  snprintf(config.bindaddr,
           sizeof(config.bindaddr), "0.0.0.0");
  snprintf(config.bindport,
           sizeof(config.bindport), "19080");
  snprintf(config.prefix, sizeof(config.prefix), "cutiltest");
  snprintf(config.server_name, sizeof(config.server_name), "restful test server");
  //snprintf(config.redirect, sizeof(config.redirect), "/redirect /cutiltest/httpstatus");
  config.tlsenable = 0;


  ast_http_init(&config);
}
