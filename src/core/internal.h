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

#ifndef _INTERNAL_H
#define _INTERNAL_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif // if defined(__cplusplus) || defined(c_plusplus)

void daemon_run(int         isroot,
                const char *runuser,
                const char *rungroup);
void shutdown_fast_wrap(int num,
                        int restart);
void enable_multi_thread_safe(void);
int  ast_tryconnect(void);


void ast_remotecontrol(char *data);

#if defined(__cplusplus) || defined(c_plusplus)
}

#endif // if defined(__cplusplus) || defined(c_plusplus)

#endif // ifndef _INTERNAL_H