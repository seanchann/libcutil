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

int         libcutil_set_config_socket(void);
const char* libcutil_get_config_pid(void);

int         libcutil_get_consock(void);
void        libcutil_set_consock(int fd);

int         libcutil_get_socket(void);
void        libcutil_set_socket(int fd);


typedef int (*logger_channel_cb)(const char *channel,
                                 const char *components,
                                 int         lineno,
                                 int         dynamic);
void libcutil_logger_create_log_channel(logger_channel_cb cb);
#if defined(__cplusplus) || defined(c_plusplus)
}
#endif  // if defined(__cplusplus) || defined(c_plusplus)


 #endif // ifndef _INTERNAL_H
