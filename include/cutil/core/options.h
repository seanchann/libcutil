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
  /*! Trascode via signed linear */
  AST_OPT_FLAG_TRANSCODE_VIA_SLIN = (1 << 7),
  /*! Display timestamp in CLI verbose output */
  AST_OPT_FLAG_TIMESTAMP = (1 << 14),
  /*! Allow \#exec in config files */
  AST_OPT_FLAG_EXEC_INCLUDES = (1 << 15),
  /*! Run in realtime Linux priority */
  AST_OPT_FLAG_HIGH_PRIORITY = (1 << 16),
  /*! Do not fork() */
  AST_OPT_FLAG_NO_FORK = (1 << 17),
};

/*! These are the options that set by default when Asterisk starts */
#define AST_DEFAULT_OPTIONS AST_OPT_FLAG_TRANSCODE_VIA_SLIN

extern int option_verbose;
extern int option_debug;		/*!< Debugging */

#define ast_opt_remote			ast_test_flag(&cutil_options, AST_OPT_FLAG_REMOTE)
#define ast_opt_exec			ast_test_flag(&cutil_options, AST_OPT_FLAG_EXEC)
#define ast_opt_no_color		ast_test_flag(&cutil_options, AST_OPT_FLAG_NO_COLOR)
#define ast_opt_console			ast_test_flag(&cutil_options, AST_OPT_FLAG_CONSOLE)
#define ast_opt_light_background	ast_test_flag(&cutil_options, AST_OPT_FLAG_LIGHT_BACKGROUND)
#define ast_opt_force_black_background	ast_test_flag(&cutil_options, AST_OPT_FLAG_FORCE_BLACK_BACKGROUND)
#define ast_opt_ref_debug           ast_test_flag(&cutil_options, AST_OPT_FLAG_REF_DEBUG)
#define ast_opt_transcode_via_slin	ast_test_flag(&cutil_options, AST_OPT_FLAG_TRANSCODE_VIA_SLIN)
#define ast_opt_timestamp		ast_test_flag(&cutil_options, AST_OPT_FLAG_TIMESTAMP)
#define ast_opt_exec_includes		ast_test_flag(&cutil_options, AST_OPT_FLAG_EXEC_INCLUDES)
#define ast_opt_high_priority		ast_test_flag(&cutil_options, AST_OPT_FLAG_HIGH_PRIORITY)
#define ast_opt_no_fork			ast_test_flag(&cutil_options, AST_OPT_FLAG_NO_FORK)


extern struct ast_flags cutil_options;
extern struct timeval ast_startuptime;
extern struct timeval ast_lastreloadtime;


#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _CUTIL_OPTIONS_H */
