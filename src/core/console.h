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

#ifndef _CONSOLE_H
#define _CONSOLE_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

int console_initialize(void);
int console_uninitialize(void);

int console_el_init(void);

//quit console thread and clean up el
//return 0 : success
int console_quit(pthread_t main_thread);

int console_check_quit(void);

int console_set_thread(pthread_t thread);

int console_el_set_gchar_fn(void);
const char* console_el_get_buf(int *);

void consolehandler(const char *s);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
