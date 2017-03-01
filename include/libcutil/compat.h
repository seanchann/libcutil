/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999-2006, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 */

/*! \file
 * \brief General Definitions for Asterisk top level program
 * Included by asterisk.h to handle platform-specific issues
 * especially those related to header files.
 */

#ifndef _COMPAT_H
#define _COMPAT_H

/* IWYU pragma: private, include "asterisk.h" */
/* IWYU pragma: begin_exports */

#include "libcutil/compiler.h"

#ifndef __STDC_VERSION__

/* flex output wants to find this defined. */
# define __STDC_VERSION__ 0
#endif // ifndef __STDC_VERSION__

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif // ifdef HAVE_INTTYPES_H

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif // ifdef HAVE_LIMITS_H

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif // ifdef HAVE_UNISTD_H

#ifdef HAVE_STDDEF_H
# include <stddef.h>
#endif // ifdef HAVE_STDDEF_H

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif // ifdef HAVE_STDINT_H

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif // ifdef HAVE_SYS_TYPES_H

#include <stdarg.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif // ifdef HAVE_STDLIB_H

#ifdef HAVE_ALLOCA_H
# include <alloca.h> /* not necessarily present - could be in stdlib */
#elif defined(HAVE_ALLOCA) && defined(__MINGW32__)
# include <malloc.h> /* see if it is here... */
#endif // ifdef HAVE_ALLOCA_H

#include <stdio.h>   /* this is always present */

#ifdef HAVE_STRING_H
# include <string.h>
#endif // ifdef HAVE_STRING_H

#ifndef AST_POLL_COMPAT
# include <poll.h>
#else // ifndef AST_POLL_COMPAT
# include "libcutil/poll-compat.h"
#endif // ifndef AST_POLL_COMPAT

#ifndef HAVE_LLONG_MAX
# define LLONG_MAX       9223372036854775807LL
#endif // ifndef HAVE_LLONG_MAX

#ifndef HAVE_CLOSEFROM
void closefrom(int lowfd);
#endif // ifndef HAVE_CLOSEFROM

#if !defined(HAVE_ASPRINTF) && !defined(__AST_DEBUG_MALLOC)
int __attribute__((format(printf, 2, 3))) asprintf(char      **str,
                                                   const char *fmt,
                                                   ...);
#endif // if !defined(HAVE_ASPRINTF) && !defined(__AST_DEBUG_MALLOC)

#ifndef HAVE_FFSLL
int ffsll(long long n);
#endif // ifndef HAVE_FFSLL

#ifndef HAVE_GETLOADAVG
int getloadavg(double *list,
               int     nelem);
#endif // ifndef HAVE_GETLOADAVG

#ifndef HAVE_HTONLL
uint64_t htonll(uint64_t host64);
#endif // ifndef HAVE_HTONLL

#ifndef HAVE_MKDTEMP
char* mkdtemp(char *template_s);
#endif // ifndef HAVE_MKDTEMP

#ifndef HAVE_NTOHLL
uint64_t ntohll(uint64_t net64);
#endif // ifndef HAVE_NTOHLL

#ifndef HAVE_SETENV
int setenv(const char *name,
           const char *value,
           int         overwrite);
#endif // ifndef HAVE_SETENV

#ifndef HAVE_STRCASESTR
char* strcasestr(const char *,
                 const char *);
#endif // ifndef HAVE_STRCASESTR

#if !defined(HAVE_STRNDUP) && !defined(__AST_DEBUG_MALLOC)
char *strndup(const char *, size_t);
#endif // if !defined(HAVE_STRNDUP) && !defined(__AST_DEBUG_MALLOC)

#ifndef HAVE_STRNLEN
size_t strnlen(const char *, size_t);
#endif // ifndef HAVE_STRNLEN

#ifndef HAVE_STRSEP
char* strsep(char      **str,
             const char *delims);
#endif // ifndef HAVE_STRSEP

#ifndef HAVE_STRTOQ
uint64_t strtoq(const char *nptr,
                char      **endptr,
                int         base);
#endif // ifndef HAVE_STRTOQ

#ifndef HAVE_UNSETENV
int unsetenv(const char *name);
#endif // ifndef HAVE_UNSETENV

#if !defined(HAVE_VASPRINTF) && !defined(__AST_DEBUG_MALLOC)
int __attribute__((format(printf, 2, 0))) vasprintf(char      **strp,
                                                    const char *fmt,
                                                    va_list     ap);
#endif // if !defined(HAVE_VASPRINTF) && !defined(__AST_DEBUG_MALLOC)

#ifndef HAVE_TIMERSUB
void timersub(struct timeval *tvend,
              struct timeval *tvstart,
              struct timeval *tvdiff);
#endif // ifndef HAVE_TIMERSUB

#define strlcat __use__ast_str__functions_not__strlcat__
#define strlcpy __use__ast_copy_string__not__strlcpy__

#include <errno.h>

#ifdef SOLARIS
# define __BEGIN_DECLS
# define __END_DECLS

# ifndef __P
#  define __P(p) p
# endif // ifndef __P

# include <alloca.h>
# include <strings.h>
# include <string.h>
# include <pthread.h>
# include <sys/stat.h>
# include <signal.h>
# include <netinet/in.h>
# include <sys/loadavg.h>
# include <dat/dat_platform_specific.h>

# ifndef BYTE_ORDER
#  define LITTLE_ENDIAN   1234
#  define BIG_ENDIAN      4321

#  ifdef __sparc__
#   define BYTE_ORDER      BIG_ENDIAN
#  else // ifdef __sparc__
#   define BYTE_ORDER      LITTLE_ENDIAN
#  endif // ifdef __sparc__
# endif // ifndef BYTE_ORDER

# ifndef __BYTE_ORDER
#  define __LITTLE_ENDIAN LITTLE_ENDIAN
#  define __BIG_ENDIAN BIG_ENDIAN
#  define __BYTE_ORDER BYTE_ORDER
# endif // ifndef __BYTE_ORDER

# ifndef __BIT_TYPES_DEFINED__
#  define __BIT_TYPES_DEFINED__
typedef unsigned char  u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int   u_int32_t;
typedef unsigned int   uint;
# endif // ifndef __BIT_TYPES_DEFINED__

#endif /* SOLARIS */

#ifdef __CYGWIN__
# define _WIN32_WINNT 0x0500
# ifndef INET_ADDRSTRLEN
#  define INET_ADDRSTRLEN  16
# endif // ifndef INET_ADDRSTRLEN
# ifndef INET6_ADDRSTRLEN
#  define INET6_ADDRSTRLEN 46
# endif // ifndef INET6_ADDRSTRLEN
#endif /* __CYGWIN__ */

#ifdef __CYGWIN__
typedef unsigned long long uint64_t;
#endif // ifdef __CYGWIN__

/* glob compat stuff */
#if defined(__Darwin__) || defined(__CYGWIN__)
# define GLOB_ABORTED GLOB_ABEND
#endif // if defined(__Darwin__) || defined(__CYGWIN__)
#include <glob.h>
#if !defined(HAVE_GLOB_NOMAGIC) || !defined(HAVE_GLOB_BRACE)
# define MY_GLOB_FLAGS   GLOB_NOCHECK
#else // if !defined(HAVE_GLOB_NOMAGIC) || !defined(HAVE_GLOB_BRACE)
# define MY_GLOB_FLAGS   (GLOB_NOMAGIC | GLOB_BRACE)
#endif // if !defined(HAVE_GLOB_NOMAGIC) || !defined(HAVE_GLOB_BRACE)

#ifndef HAVE_ROUNDF
# ifdef HAVE_ROUND
#  define roundf(x) ((float)round(x))
# else // ifdef HAVE_ROUND
float roundf(float x);
# endif // ifdef HAVE_ROUND
#endif // ifndef HAVE_ROUNDF

#ifndef INFINITY
# define INFINITY (1.0 / 0.0)
#endif // ifndef INFINITY

#ifndef NAN
# define NAN (0.0 / 0.0)
#endif // ifndef NAN

/* IWYU pragma: end_exports */
#endif // ifndef _COMPAT_H
