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
};

extern int option_verbose;
extern int option_debug;		/*!< Debugging */

#define ast_opt_remote			ast_test_flag(&cutil_options, AST_OPT_FLAG_REMOTE)
#define ast_opt_exec			ast_test_flag(&cutil_options, AST_OPT_FLAG_EXEC)

extern struct ast_flags cutil_options;


#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _CUTIL_OPTIONS_H */
