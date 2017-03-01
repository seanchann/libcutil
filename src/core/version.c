/*
 * libcutil -- An utility toolkit.
 *
 * Copyright (C) 2016 - 2017, JYD, Inc.
 *
 * seanchann <xqzhou@bj-jyd.cn>
 *
 * See docs/ for more information about
 * the libcutil project.
 *
 * This program belongs to JYD, Inc. JYD, Inc reserves all rights
 */

#include "libcutil.h"

#include "libcutil/ast_version.h"

static const char asterisk_version[] = "1.0.0-master";

static const char asterisk_version_num[] = "10";

static const char asterisk_build_opts[] = "";

const char *ast_get_version(void)
{
	return asterisk_version;
}

const char *ast_get_version_num(void)
{
	return asterisk_version_num;
}

const char *ast_get_build_opts(void)
{
	return asterisk_build_opts;
}
