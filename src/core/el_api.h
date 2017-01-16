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

#ifndef _CUTIL_LOGGER_H
#define _CUTIL_LOGGER_H



#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

int ast_el_initialize(void);
void ast_el_write_default_histfile(void);
void ast_el_read_default_histfile(void);
int ast_el_read_history(const char *filename);
int ast_el_write_history(const char *filename);
int ast_el_add_history(const char *buf);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
