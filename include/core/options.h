/*
 * libcutil -- An utility toolkit.
 *
 * Copyright (C) 2016 - 2017, JYD, Inc.
 *
 * seanchann <seanchann@foxmail.com>
 *
 * See docs/ for more information about the libcutil project.
 *
 * This program belongs to JYD, Inc. JYD, Inc reserves all rights
 */


#ifndef _CUTIL_OPTIONS_H
#define _CUTIL_OPTIONS_H


#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

/*! \ingroup main_options */
enum cutil_option_flags {
  /*! Remote console */
  AST_OPT_FLAG_REMOTE = (1 << 0),
  /*! Execute an program CLI command upon startup */
  AST_OPT_FLAG_EXEC = (1 << 1),
  /*! Console mode */
  AST_OPT_FLAG_CONSOLE = (1 << 2),
  /*! Force black background */
  AST_OPT_FLAG_FORCE_BLACK_BACKGROUND = (1 << 3),
  /*! Terminal colors should be adjusted for a light-colored background */
  AST_OPT_FLAG_LIGHT_BACKGROUND = (1 << 4),
  /*! Don't use termcap colors */
  AST_OPT_FLAG_NO_COLOR = (1 << 5),
  /*! Reference Debugging */
  AST_OPT_FLAG_REF_DEBUG = (1 << 6),
};

extern int option_verbose;
extern int option_debug;		/*!< Debugging */

#define ast_opt_remote			ast_test_flag(&cutil_options, AST_OPT_FLAG_REMOTE)
#define ast_opt_exec			ast_test_flag(&cutil_options, AST_OPT_FLAG_EXEC)
#define ast_opt_no_color		ast_test_flag(&cutil_options, AST_OPT_FLAG_NO_COLOR)
#define ast_opt_console			ast_test_flag(&cutil_options, AST_OPT_FLAG_CONSOLE)
#define ast_opt_light_background	ast_test_flag(&cutil_options, AST_OPT_FLAG_LIGHT_BACKGROUND)
#define ast_opt_force_black_background	ast_test_flag(&cutil_options, AST_OPT_FLAG_FORCE_BLACK_BACKGROUND)
#define ast_opt_ref_debug           ast_test_flag(&cutil_options, AST_OPT_FLAG_REF_DEBUG)

extern struct ast_flags cutil_options;


#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _CUTIL_OPTIONS_H */
