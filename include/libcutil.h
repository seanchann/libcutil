/*
 * Asterisk -- An open source telephony toolkit.
 *
 * General Definitions for Asterisk top level program
 *
 * Copyright (C) 1999-2006, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 */

/*! \file
 * \brief Asterisk main include file. File version handling, generic pbx
 * functions.
 */

#ifndef _LIBCUTIL_H
#define _LIBCUTIL_H

#include "libcutil_autoconfig.h"

#if !defined(NO_MALLOC_DEBUG) && !defined(STANDALONE) && !defined(STANDALONE2) && \
  defined(MALLOC_DEBUG)
# include "asterisk/astmm.h"
#endif // if !defined(NO_MALLOC_DEBUG) && !defined(STANDALONE) &&
// !defined(STANDALONE2) && defined(MALLOC_DEBUG)

#include "libcutil/compat.h"


/* Default to allowing the umask or filesystem ACLs to determine actual file
 * creation permissions
 */
#ifndef AST_DIR_MODE
# define AST_DIR_MODE 0777
#endif // ifndef AST_DIR_MODE
#ifndef AST_FILE_MODE
# define AST_FILE_MODE 0666
#endif // ifndef AST_FILE_MODE

/* Make sure PATH_MAX is defined on platforms (HURD) that don't define it.
 * Also be sure to handle the case of a path larger than PATH_MAX
 * (err safely) in the code.
 */
#ifndef PATH_MAX
# define PATH_MAX 4096
#endif // ifndef PATH_MAX


#define DEFAULT_LANGUAGE "en"

#define DEFAULT_SAMPLE_RATE 8000
#define DEFAULT_SAMPLES_PER_MS  ((DEFAULT_SAMPLE_RATE) / 1000)
#define setpriority     __PLEASE_USE_ast_set_priority_INSTEAD_OF_setpriority__
#define sched_setscheduler \
  __PLEASE_USE_ast_set_priority_INSTEAD_OF_sched_setscheduler__

#if defined(DEBUG_FD_LEAKS) && !defined(STANDALONE) && !defined(STANDALONE2) && \
  !defined(STANDALONE_AEL)

/* These includes are all about ordering */
# include <stdio.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/socket.h>
# include <fcntl.h>

# define open(a, ...) __ast_fdleak_open(__FILE__,            \
                                        __LINE__,            \
                                        __PRETTY_FUNCTION__, \
                                        a,                   \
                                        __VA_ARGS__)
# define pipe(a) __ast_fdleak_pipe(a, __FILE__, __LINE__, __PRETTY_FUNCTION__)
# define socket(a, b, c) __ast_fdleak_socket(a,        \
                                             b,        \
                                             c,        \
                                             __FILE__, \
                                             __LINE__, \
                                             __PRETTY_FUNCTION__)
# define close(a) __ast_fdleak_close(a)
# define fopen(a, b) __ast_fdleak_fopen(a,        \
                                        b,        \
                                        __FILE__, \
                                        __LINE__, \
                                        __PRETTY_FUNCTION__)
# define fclose(a) __ast_fdleak_fclose(a)
# define dup2(a, b) __ast_fdleak_dup2(a,        \
                                      b,        \
                                      __FILE__, \
                                      __LINE__, \
                                      __PRETTY_FUNCTION__)
# define dup(a) __ast_fdleak_dup(a, __FILE__, __LINE__, __PRETTY_FUNCTION__)

# if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
# endif // if defined(__cplusplus) || defined(c_plusplus)
int __ast_fdleak_open(const char *file,
                      int         line,
                      const char *func,
                      const char *path,
                      int         flags,
                      ...);
int __ast_fdleak_pipe(int        *fds,
                      const char *file,
                      int         line,
                      const char *func);
int __ast_fdleak_socket(int         domain,
                        int         type,
                        int         protocol,
                        const char *file,
                        int         line,
                        const char *func);
int   __ast_fdleak_close(int fd);
FILE* __ast_fdleak_fopen(const char *path,
                         const char *mode,
                         const char *file,
                         int         line,
                         const char *func);
int __ast_fdleak_fclose(FILE *ptr);
int __ast_fdleak_dup2(int         oldfd,
                      int         newfd,
                      const char *file,
                      int         line,
                      const char *func);
int __ast_fdleak_dup(int         oldfd,
                     const char *file,
                     int         line,
                     const char *func);
# if defined(__cplusplus) || defined(c_plusplus)
}
# endif // if defined(__cplusplus) || defined(c_plusplus)
#endif   // if defined(DEBUG_FD_LEAKS) && !defined(STANDALONE) &&
// !defined(STANDALONE2) && !defined(STANDALONE_AEL)

int  ast_set_priority(int); /*!< Provided by asterisk.c */
int  ast_fd_init(void);     /*!< Provided by astfd.c */
int  ast_pbx_init(void);    /*!< Provided by pbx.c */

/*!
 * \brief Register a function to be executed before Asterisk exits.
 * \param func The callback function to use.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 *
 * \note This function should be rarely used in situations where
 * something must be shutdown to avoid corruption, excessive data
 * loss, or when external programs must be stopped.  All other
 * cleanup in the core should use ast_register_cleanup.
 */
int  ast_register_atexit(void (*func)(void));

/*!
 * \since 11.9
 * \brief Register a function to be executed before Asterisk gracefully exits.
 *
 * If Asterisk is immediately shutdown (core stop now, or sending the TERM
 * signal), the callback is not run. When the callbacks are run, they are run in
 * sequence with ast_register_atexit() callbacks, in the reverse order of
 * registration.
 *
 * \param func The callback function to use.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int  ast_register_cleanup(void (*func)(void));

/*!
 * \brief Unregister a function registered with ast_register_atexit().
 * \param func The callback function to unregister.
 */
void ast_unregister_atexit(void (*func)(void));

/*!
 * \brief Cancel an existing shutdown and return to normal operation.
 *
 * \note Shutdown can be cancelled while the server is waiting for
 * any existing channels to be destroyed before shutdown becomes
 * irreversible.
 *
 * \return non-zero if shutdown cancelled.
 */
int  ast_cancel_shutdown(void);

/*!
 * \details
 * The server is preventing new channel creation in preparation for
 * shutdown and may actively be releasing resources.  The shutdown
 * process may be canceled by ast_cancel_shutdown() if it is not too
 * late.
 *
 * \note The preparation to shutdown phase can be quite lengthy
 * if we are gracefully shutting down.  How long existing calls will
 * last is not up to us.
 *
 * \return non-zero if the server is preparing to or actively shutting down.
 */
int  ast_shutting_down(void);

/*!
 * \return non-zero if the server is actively shutting down.
 * \since 13.3.0
 *
 * \details
 * The server is releasing resources and unloading modules.
 * It won't be long now.
 */
int  ast_shutdown_final(void);

#ifdef MTX_PROFILE
# define HAVE_MTX_PROFILE /* used in lock.h */
#endif  /* MTX_PROFILE */

/*!
 * \brief support for event profiling
 *
 * (note, this must be documented a lot more)
 * ast_add_profile allocates a generic 'counter' with a given name,
 * which can be shown with the command 'core show profile &lt;name&gt;'
 *
 * The counter accumulates positive or negative values supplied by
 * \see ast_add_profile(), dividing them by the 'scale' value passed in the
 * create call, and also counts the number of 'events'.
 * Values can also be taked by the TSC counter on ia32 architectures,
 * in which case you can mark the start of an event calling ast_mark(id, 1)
 * and then the end of the event with ast_mark(id, 0).
 * For non-i386 architectures, these two calls return 0.
 */
int     ast_add_profile(const char *,
                        uint64_t scale);
int64_t ast_profile(int, int64_t);
int64_t ast_mark(int,
                 int start1_stop0);

/*! \brief
 * Definition of various structures that many asterisk files need,
 * but only because they need to know that the type exists.
 *
 */

struct ast_channel;
struct ast_frame;
struct ast_module;
struct ast_variable;
struct ast_str;
struct ast_sched_context;

/* Some handy macros for turning a preprocessor token into (effectively) a
   quoted string */
#define __stringify_1(x) # x
#define __stringify(x) __stringify_1(x)


#if 0
# if defined(AST_IN_CORE)           \
  || (!defined(AST_MODULE_SELF_SYM) \
  && (defined(STANDALONE) || defined(STANDALONE2) || defined(AST_NOT_MODULE)))

#  define AST_MODULE_SELF NULL

# elif defined(AST_MODULE_SELF_SYM)

/*! Retreive the 'struct ast_module *' for the current module. */
#  define AST_MODULE_SELF AST_MODULE_SELF_SYM()

struct ast_module;

/* Internal/forward declaration, AST_MODULE_SELF should be used instead. */
struct ast_module* AST_MODULE_SELF_SYM(void);

# else // if defined(AST_IN_CORE) || (!defined(AST_MODULE_SELF_SYM) &&
// (defined(STANDALONE) || defined(STANDALONE2) ||
// defined(AST_NOT_MODULE)))

#  error "Externally compiled modules must declare AST_MODULE_SELF_SYM."

# endif // if defined(AST_IN_CORE) || (!defined(AST_MODULE_SELF_SYM) &&
// (defined(STANDALONE) || defined(STANDALONE2) ||
// defined(AST_NOT_MODULE)))
#else  // if 0
# define AST_MODULE_SELF NULL
#endif // if 0

#ifdef NOT_USE

/*!
 * \brief Retrieve the PBX UUID
 * \param pbx_uuid A buffer of at least AST_UUID_STR_LEN (36 + 1) size to
 * receive the UUID
 * \param length The buffer length
 */
int ast_pbx_uuid_get(char *pbx_uuid,
                     int   length);
#endif // ifdef NOT_USE

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

  /*! Display timestamp in CLI verbose output */
  AST_OPT_FLAG_TIMESTAMP = (1 << 14),

  /*! Allow \#exec in config files */
  AST_OPT_FLAG_EXEC_INCLUDES = (1 << 15),

  /*! Run in realtime Linux priority */
  AST_OPT_FLAG_HIGH_PRIORITY = (1 << 16),

  /*! Do not fork() */
  AST_OPT_FLAG_NO_FORK = (1 << 17),

  /*! Reconnect */
  AST_OPT_FLAG_RECONNECT = (1 << 18),

  /*! Hide remote console connect messages on console */
  AST_OPT_FLAG_HIDE_CONSOLE_CONNECT = (1 << 19),

  /*! Disable log/verbose output to remote consoles */
  AST_OPT_FLAG_MUTE = (1 << 20),
};


const char   * libcutil_get_config_dir(void);
const char   * libcutil_get_config_log_dir(void);
const char   * libcutil_get_config_system_name(void);
const char   * libcutil_get_config_socket(void);
const char   * libcutil_get_config_pid(void);

int            libcutil_get_option_debug(void);
void           libcutil_set_option_debug(int level);

int            libcutil_get_option_verbose(void);
void           libcutil_set_option_verbose(int level);

int            libcutil_get_option_verbose_sys_level(void);
void           libcutil_set_option_verbose_sys_level(int level);

struct timeval libcutil_get_startup_time(void);
struct timeval libcutil_get_lastreload_time(void);
int            libcutil_test_option(enum cutil_option_flags flag);

int            libcutil_get_consock(void);
void           libcutil_set_consock(int fd);

int            libcutil_get_socket(void);
void           libcutil_set_socket(int fd);

const char   * libcutil_get_ctl_permissions(void);
void           libcutil_set_ctl_permissions(char *permissions);

const char   * libcutil_get_remotehostname(void);

const char   * libcutil_get_ctl_owner(void);
const char   * libcutil_get_ctl_group(void);
const char   * libcutil_get_ctl_filename(void);


void           libcutil_enable_console(void);
void           libcutil_enable_remote(void);


#define ast_opt_remote                  libcutil_test_option(AST_OPT_FLAG_REMOTE)
#define ast_opt_exec                    libcutil_test_option(AST_OPT_FLAG_EXEC)
#define ast_opt_no_color                libcutil_test_option(AST_OPT_FLAG_NO_COLOR)
#define ast_opt_console                 libcutil_test_option(AST_OPT_FLAG_CONSOLE)
#define ast_opt_light_background        libcutil_test_option( \
    AST_OPT_FLAG_LIGHT_BACKGROUND)
#define ast_opt_force_black_background  libcutil_test_option( \
    AST_OPT_FLAG_FORCE_BLACK_BACKGROUND)
#define ast_opt_ref_debug           libcutil_test_option(AST_OPT_FLAG_REF_DEBUG)
#define ast_opt_timestamp               libcutil_test_option( \
    AST_OPT_FLAG_TIMESTAMP)
#define ast_opt_exec_includes           libcutil_test_option( \
    AST_OPT_FLAG_EXEC_INCLUDES)
#define ast_opt_high_priority           libcutil_test_option( \
    AST_OPT_FLAG_HIGH_PRIORITY)
#define ast_opt_no_fork                 libcutil_test_option(AST_OPT_FLAG_NO_FORK)
#define ast_opt_reconnect               libcutil_test_option( \
    AST_OPT_FLAG_RECONNECT)
#define ast_opt_hide_connect            libcutil_test_option( \
    AST_OPT_FLAG_HIDE_CONSOLE_CONNECT)
#define ast_opt_mute                    libcutil_test_option(AST_OPT_FLAG_MUTE)


/*libcutil init and free api.not use "-nonstartfiles" or "-nostdlib" for build
   flag*/
void __attribute__((constructor)) libcutil_init(void);
void __attribute__((destructor))  libcutil_free(void);

#endif /* _LIBCUTIL_H */
