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



 #ifndef _ASTCORE_DUMMMY_H
 #define _ASTCORE_DUMMMY_H

 #if defined(__cplusplus) || defined(c_plusplus)
 extern "C" {
 #endif

void ast_run_atexits(int run_cleanups);

int fdprint(int fd, const char *s);
int fdsend(int fd, const char *s);

int ast_safe_system(const char *s);

int ast_all_zeros(const char *s);
#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
