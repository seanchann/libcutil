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

#ifndef _DAEMON_H
#define _DAEMON_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

unsigned int sig_need_quit(void);
unsigned int sig_need_quit_handler(void);



typedef enum {
	/*! Normal operation */
	NOT_SHUTTING_DOWN,
	/*! Committed to shutting down.  Final phase */
	SHUTTING_DOWN_FINAL,
	/*! Committed to shutting down.  Initial phase */
	SHUTTING_DOWN,
	/*!
	 * Valid values for quit_handler() niceness below.
	 * These shutdown/restart levels can be cancelled.
	 *
	 * Remote console exit right now
	 */
	SHUTDOWN_FAST,
	/*! core stop/restart now */
	SHUTDOWN_NORMAL,
	/*! core stop/restart gracefully */
	SHUTDOWN_NICE,
	/*! core stop/restart when convenient */
	SHUTDOWN_REALLY_NICE
} shutdown_nice_t;

//quit clean up all resource and exec shutdown
void quit_handler(int num, shutdown_nice_t niceness, int restart);


void ast_replace_sigchld(void);
void ast_unreplace_sigchld(void);

pid_t mainpid(void);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
