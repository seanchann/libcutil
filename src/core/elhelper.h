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

#ifndef _ELHELPER_H
#define _ELHELPER_H


#include "editline/histedit.h"


#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

typedef char (*el_prompt)(EditLine *editline);
typedef char* (*el_complete)(EditLine *editline, int ch);
/*int ast_el_initialize(el_prompt prompt);*/
int ast_el_initialize_wrap(el_prompt prompt, el_complete complete);
int ast_el_uninitialize(void);
void ast_el_write_default_histfile(void);
void ast_el_read_default_histfile(void);
int ast_el_read_history(const char *filename);
int ast_el_write_history(const char *filename);
int ast_el_add_history(const char *buf);

typedef int (*getchar_handler) (EditLine *editline, char *cp);
int ast_el_set_gchar_handler(getchar_handler getc);
const char* ast_el_get_buf(int*);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
