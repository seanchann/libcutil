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

#ifndef _RESOURCE_TEST_H
#define _RESOURCE_TEST_H

#include "libcutil.h"

#include "libcutil/restful.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif // if defined(__cplusplus) || defined(c_plusplus)

struct rest_acl_get_var_args{
};
void rest_acl_get(struct ast_variable *headers, struct rest_acl_get_var_args *args, struct ast_ari_response *response);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif // if defined(__cplusplus) || defined(c_plusplus)

#endif // ifndef _RESOURCE_TEST_H
