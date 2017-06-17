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

#include "libcutil/logger.h"

#include "libcutil/http.h"
#include "libcutil/restful.h"
#include "resources/resource_test.h"


static void rest_test_list_cb(
  struct ast_tcptls_session_instance *ser,
  struct ast_variable                *get_params,
  struct ast_variable                *path_vars,
  struct ast_variable                *headers,
  struct ast_json                    *body,
  struct ast_ari_response            *response)
{
  struct rest_test_list_var_args args = {};

  rest_test_list(headers, &args, response);

fin: __attribute__((unused))
  return;
}

/*! \brief REST handler for /api-docs/channels.json */
static struct stasis_rest_handlers test = {
  .path_segment = "test",
  .callbacks    = {
    [AST_HTTP_GET] = rest_test_list_cb,
  },
  .num_children =      0,
  .children     = {}
};


void init_restful_mod(void)
{
  struct http_server_config   config;
  struct ast_ari_conf_general general;
  struct ast_ari_conf_user    user;

  config.enabled = 1;
  snprintf(config.bindaddr,
           sizeof(config.bindaddr), "0.0.0.0");
  snprintf(config.bindport,
           sizeof(config.bindport), "19080");
  snprintf(config.prefix,      sizeof(config.prefix),      "cutiltest");
  snprintf(config.server_name, sizeof(config.server_name), "restful test server");

  // snprintf(config.redirect, sizeof(config.redirect), "/redirect
  // /cutiltest/httpstatus");
  config.tlsenable = 0;

  ast_http_init(&config);


  if(ast_string_field_init(&general, 64)){
    cutil_log(LOG_ERROR,"init string field error.\r\n");
    return;
  }

  general.format = AST_JSON_PRETTY;
  general.enabled = 1;

  user.username = calloc(32, sizeof(char));
  snprintf(user.username, 32, "seanchann");
  user.read_only = 0;

  user.password_format = ARI_PASSWORD_FORMAT_CRYPT;
  //snprintf(user.password, sizeof(user.password),"123456");
  snprintf(user.password, sizeof(user.password),"$6$fKHnOFhuMcDWRvb.$0qK7oPBL7OIxsGeLEK8XWpKwc8TulXP20cw06jB8lAttulKSt/fYgLVcq1ZOy8agyyksSrdNGNm9fbKROZvcL1");

  // user.password_format = ARI_PASSWORD_FORMAT_PLAIN;
  // snprintf(user.password, sizeof(user.password),"123456");


  if (cutil_restful_init(&general, &user, 1)) {
    cutil_log(LOG_ERROR, "restful server init error.\r\n");
    return;
  }


  if (ast_ari_add_handler(&test)) {
    cutil_log(LOG_ERROR, "add restful  test resource error.\r\n");
  }

  free(user.username);
}
