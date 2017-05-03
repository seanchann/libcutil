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

#include "libcutil.h"

#include "libcutil/_private.h"

#undef sched_setscheduler
#undef setpriority

#include <stdlib.h>  /* for closefrom(3) */
#include <signal.h>
#ifndef HAVE_CLOSEFROM
# include <dirent.h> /* for opendir(3)   */
#endif /* ifndef HAVE_CLOSEFROM */

#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/un.h>
#include <histedit.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>

#ifdef linux
# include <sys/prctl.h>
#endif /* ifdef linux */


/* we define here the variables so to better agree on the prototype */
#include "libcutil/utils.h"
#include "libcutil/term.h"
#include "libcutil/cli.h"
#include "libcutil/poll-compat.h"
#include "elhelper.h"
#include "libcutil/lock.h"
#include "libcutil/localtime.h"
#include "libcutil/term.h"
#include "libcutil/ast_version.h"
#include "internal.h"

struct ast_atexit {
  void (*func)(void);
  int  is_cleanup;
  AST_LIST_ENTRY(ast_atexit) list;
};

static AST_LIST_HEAD_STATIC(atexits, ast_atexit);


#if !defined(LOW_MEMORY)
struct thread_list_t {
  AST_RWLIST_ENTRY(thread_list_t) list;
  char     *name;
  pthread_t id;
  int       lwp;
};

static AST_RWLIST_HEAD_STATIC(thread_list, thread_list_t);


/*console prompt string. set env(CUTIL_PROMPT) will be overried default*/
# define CUTIL_PROMPT "*CLI> "

static struct ast_str *prompt = NULL;


# define AST_MAX_CONNECTS 128


struct console {
  int       fd;                   /*!< File descriptor */
  int       p[2];                 /*!< Pipe */
  pthread_t t;                    /*!< Thread of handler */
  int       mute;                 /*!< Is the console muted for logs */
  int       uid;                  /*!< Remote user ID. */
  int       gid;                  /*!< Remote group ID. */
  int       levels[NUMLOGLEVELS]; /*!< Which log levels are enabled for the
                                     console */

  /*! Verbosity level of this console. */
  int option_verbose;
};
struct console   consoles[AST_MAX_CONNECTS];
static pthread_t consolethread = AST_PTHREADT_NULL;
static pthread_t lthread;

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

static int sig_alert_pipe[2] = { -1, -1 };
static struct {
  unsigned int need_reload       : 1;
  unsigned int need_quit         : 1;
  unsigned int need_quit_handler : 1;
} sig_flags;

static shutdown_nice_t shuttingdown = NOT_SHUTTING_DOWN;


static pthread_t mon_sig_flags;

pid_t ast_mainpid;

static int multi_thread_safe;


/*! \brief Welcome message when starting a CLI interface */
# define WELCOME_MESSAGE                                                                          \
  ast_verbose("LibCutil %s console interface, Copyright (C) 2016 - 2017, JYD, Inc. and others.\n" \
              "Created by seanchann.zhou <xqzhou@bj-jyd.cn>\n"                                    \
              "=========================================================================\n",      \
              ast_get_version())                                                                  \



static int console_print(const char *s);


pid_t      mainpid(void)
{
  return ast_mainpid;
}

unsigned int sig_need_quit(void)
{
  return sig_flags.need_quit;
}

unsigned int sig_need_quit_handler(void)
{
  return sig_flags.need_quit_handler;
}

/*! \brief NULL handler so we can collect the child exit status */
static void _null_sig_handler(int sig)
{}

static struct sigaction null_sig_handler = {
  .sa_handler = _null_sig_handler,
  .sa_flags   = SA_RESTART,
};


/*!
 * \brief read() function supporting the reception of user credentials.
 *
 * \param fd Socket file descriptor.
 * \param buffer Receive buffer.
 * \param size 'buffer' size.
 * \param con Console structure to set received credentials
 * \retval -1 on error
 * \retval the number of bytes received on success.
 */
static int read_credentials(int fd, char *buffer, size_t size,
                            struct console *con)
{
# if defined(SO_PEERCRED)
#  ifdef HAVE_STRUCT_SOCKPEERCRED_UID
#   define HAVE_STRUCT_UCRED_UID
  struct sockpeercred cred;
#  else /* ifdef HAVE_STRUCT_SOCKPEERCRED_UID */
  struct ucred cred;
#  endif  /* ifdef HAVE_STRUCT_SOCKPEERCRED_UID */
  socklen_t len = sizeof(cred);
# endif /* if defined(SO_PEERCRED) */
# if defined(HAVE_GETPEEREID)
  uid_t uid;
  gid_t gid;
# else /* if defined(HAVE_GETPEEREID) */
  int uid, gid;
# endif  /* if defined(HAVE_GETPEEREID) */
  int result;

  result = read(fd, buffer, size);

  if (result < 0) {
    return result;
  }

# if defined(SO_PEERCRED) && (defined(HAVE_STRUCT_UCRED_UID) || \
  defined(HAVE_STRUCT_UCRED_CR_UID))

  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len)) {
    return result;
  }
#  if defined(HAVE_STRUCT_UCRED_UID)
  uid = cred.uid;
  gid = cred.gid;
#  else /* defined(HAVE_STRUCT_UCRED_CR_UID) */
  uid = cred.cr_uid;
  gid = cred.cr_gid;
#  endif  /* defined(HAVE_STRUCT_UCRED_UID) */

# elif defined(HAVE_GETPEEREID)

  if (getpeereid(fd, &uid, &gid)) {
    return result;
  }
# else /* if defined(SO_PEERCRED) && (defined(HAVE_STRUCT_UCRED_UID) ||
          defined(HAVE_STRUCT_UCRED_CR_UID)) */
  return result;

# endif  /* if defined(SO_PEERCRED) && (defined(HAVE_STRUCT_UCRED_UID) ||
            defined(HAVE_STRUCT_UCRED_CR_UID)) */
  con->uid = uid;
  con->gid = gid;

  return result;
}

/* This is the thread running the remote console on the main process. */
static void* netconsole(void *vconsole)
{
  struct console *con           = vconsole;
  char hostname[MAXHOSTNAMELEN] = "";
  char inbuf[512];
  char outbuf[512];
  const char *const end_buf = inbuf + sizeof(inbuf);
  char *start_read          = inbuf;
  int   res;
  struct pollfd fds[2];

  if (gethostname(hostname, sizeof(hostname) - 1)) ast_copy_string(hostname,
                                                                   "<Unknown>",
                                                                   sizeof(hostname));



  snprintf(outbuf, sizeof(outbuf), "%s/%ld/%s\n", hostname,
           (long)mainpid(), ast_get_version());
  fdprint(con->fd, outbuf);
  ast_verb_console_register(&con->option_verbose);

  for (;;) {
    fds[0].fd      = con->fd;
    fds[0].events  = POLLIN;
    fds[0].revents = 0;
    fds[1].fd      = con->p[0];
    fds[1].events  = POLLIN;
    fds[1].revents = 0;

    res = ast_poll(fds, 2, -1);

    if (res < 0) {
      if (errno != EINTR) ast_log(LOG_WARNING,
                                  "poll returned < 0: %s\n",
                                  strerror(errno));
      continue;
    }

    if (fds[0].revents) {
      int cmds_read, bytes_read;


      if ((bytes_read =
             read_credentials(con->fd, start_read, end_buf - start_read,
                              con)) < 1) {
        break;
      }

      /* XXX This will only work if it is the first command, and I'm not sure
         fixing it is worth the effort. */
      if (strncmp(inbuf, "cli quit after ", 15) == 0) {
        ast_cli_command_multiple_full(con->uid,
                                      con->gid,
                                      con->fd,
                                      bytes_read - 15,
                                      inbuf + 15);
        break;
      }

      /* ast_cli_command_multiple_full will only process individual commands
         terminated by a
       * NULL and not trailing partial commands. */
      if (!(cmds_read =
              ast_cli_command_multiple_full(con->uid, con->gid, con->fd,
                                            bytes_read + start_read - inbuf,
                                            inbuf))) {
        /* No commands were read. We either have a short read on the first
           command
         * with space left, or a command that is too long */
        if (start_read + bytes_read < end_buf) {
          start_read += bytes_read;
        } else {
          ast_log(LOG_ERROR, "Command too long! Skipping\n");
          start_read = inbuf;
        }
        continue;
      }

      if (start_read[bytes_read - 1] == '\0') {
        /* The read ended on a command boundary, start reading again at the head
           of inbuf */
        start_read = inbuf;
        continue;
      }

      /* If we get this far, we have left over characters that have not been
         processed.
       * Advance to the character after the last command read by
       * ast_cli_command_multiple_full.
       * We are guaranteed to have at least cmds_read NULLs */
      while (cmds_read-- && (start_read = strchr(start_read, '\0'))) {
        start_read++;
      }
      memmove(inbuf, start_read, end_buf - start_read);
      start_read = end_buf - start_read + inbuf;
    }

    if (fds[1].revents) {
      res = read_credentials(con->p[0], outbuf, sizeof(outbuf), con);

      if (res < 1) {
        ast_log(LOG_ERROR, "read returned %d\n", res);
        break;
      }
      res = write(con->fd, outbuf, res);

      if (res < 1) break;
    }
  }
  ast_verb_console_unregister();

  if (!ast_opt_hide_connect) {
    ast_verb(3, "Remote UNIX connection disconnected\n");
  }

  close(con->fd);
  close(con->p[0]);
  close(con->p[1]);
  con->fd = -1;

  return NULL;
}

static void* listener(void *unused)
{
  struct sockaddr_un sunaddr;
  int s;
  socklen_t len;
  int x;
  int flags;
  struct pollfd fds[1];

  for (;;) {
    if (libcutil_get_socket() < 0) return NULL;

    fds[0].fd     = libcutil_get_socket();
    fds[0].events = POLLIN;
    s             = ast_poll(fds, 1, -1);
    pthread_testcancel();

    if (s < 0) {
      if (errno != EINTR) ast_log(LOG_WARNING,
                                  "poll returned error: %s\n",
                                  strerror(errno));
      continue;
    }
    len = sizeof(sunaddr);
    s   = accept(libcutil_get_socket(), (struct sockaddr *)&sunaddr, &len);

    if (s < 0) {
      if (errno != EINTR) ast_log(LOG_WARNING,
                                  "Accept returned %d: %s\n",
                                  s,
                                  strerror(errno));
    } else {
# if defined(SO_PASSCRED)
      int sckopt = 1;

      /* turn on socket credentials passing. */
      if (setsockopt(s, SOL_SOCKET, SO_PASSCRED, &sckopt, sizeof(sckopt)) < 0) {
        ast_log(LOG_WARNING, "Unable to turn on socket credentials passing\n");
      } else
# endif /* if defined(SO_PASSCRED) */
      {
        for (x = 0; x < AST_MAX_CONNECTS; x++) {
          if (consoles[x].fd >= 0) {
            continue;
          }

          if (socketpair(AF_LOCAL, SOCK_STREAM, 0, consoles[x].p)) {
            ast_log(LOG_ERROR, "Unable to create pipe: %s\n", strerror(errno));
            fdprint(s, "Server failed to create pipe\n");
            close(s);
            break;
          }
          flags = fcntl(consoles[x].p[1], F_GETFL);
          fcntl(consoles[x].p[1], F_SETFL, flags | O_NONBLOCK);
          consoles[x].mute = 1; /* Default is muted, we will un-mute if
                                   necessary */

          /* Default uid and gid to -2, so then in cli.c/cli_has_permissions()
             we will be able
             to know if the user didn't send the credentials. */
          consoles[x].uid = -2;
          consoles[x].gid = -2;

          /* Server default of remote console verbosity level is OFF. */
          consoles[x].option_verbose = 0;
          consoles[x].fd             = s;


          if (ast_pthread_create_detached_background(&consoles[x].t, NULL,
                                                     netconsole, &consoles[x])) {
            consoles[x].fd = -1;
            ast_log(LOG_ERROR,
                    "Unable to spawn thread to handle connection: %s\n",
                    strerror(errno));
            close(consoles[x].p[0]);
            close(consoles[x].p[1]);
            fdprint(s, "Server failed to spawn thread\n");
            close(s);
          }
          break;
        }

        if (x >= AST_MAX_CONNECTS) {
          fdprint(s, "No more connections allowed\n");
          ast_log(LOG_WARNING, "No more connections allowed\n");
          close(s);
        } else if ((consoles[x].fd > -1) && (!ast_opt_hide_connect)) {
          ast_verb(3, "Remote UNIX connection\n");
        }
      }
    }
  }
  return NULL;
}

static int ast_makesocket(void)
{
  struct sockaddr_un sunaddr;
  int   res;
  int   x;
  uid_t uid = -1;
  gid_t gid = -1;

  for (x = 0; x < AST_MAX_CONNECTS; x++) consoles[x].fd = -1;
  unlink(libcutil_get_config_socket());
  libcutil_set_socket(socket(PF_LOCAL, SOCK_STREAM, 0));

  ast_log(LOG_NOTICE,
          "bind local socket %s fd %d\r\n",
          libcutil_get_config_socket(),
          libcutil_get_socket());

  if (libcutil_get_socket() < 0) {
    ast_log(LOG_WARNING, "Unable to create control socket: %s\n",
            strerror(errno));
    return -1;
  }
  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_LOCAL;
  ast_copy_string(sunaddr.sun_path,
                  libcutil_get_config_socket(),
                  sizeof(sunaddr.sun_path));
  res = bind(libcutil_get_socket(), (struct sockaddr *)&sunaddr, sizeof(sunaddr));

  if (res) {
    ast_log(LOG_WARNING,
            "Unable to bind socket to %s: %s\n",
            libcutil_get_config_socket(),
            strerror(errno));
    close(libcutil_get_socket());
    libcutil_set_socket(-1);
    return -1;
  }
  res = listen(libcutil_get_socket(), 2);

  if (res < 0) {
    ast_log(LOG_WARNING,
            "Unable to listen on socket %s: %s\n",
            libcutil_get_config_socket(),
            strerror(errno));
    close(libcutil_get_socket());
    libcutil_set_socket(-1);
    return -1;
  }

  if (ast_pthread_create_background(&lthread, NULL, listener, NULL)) {
    ast_log(LOG_WARNING, "Unable to create listener thread.\n");
    close(libcutil_get_socket());
    return -1;
  }

  if (!ast_strlen_zero(libcutil_get_ctl_owner())) {
    struct passwd *pw;

    if ((pw = getpwnam(libcutil_get_ctl_owner())) == NULL) ast_log(LOG_WARNING,
                                                                   "Unable to find uid of user %s\n",
                                                                   libcutil_get_ctl_owner());



    else uid = pw->pw_uid;
  }

  if (!ast_strlen_zero(libcutil_get_ctl_group())) {
    struct group *grp;

    if ((grp = getgrnam(libcutil_get_ctl_group())) == NULL) ast_log(LOG_WARNING,
                                                                    "Unable to find gid of group %s\n",
                                                                    libcutil_get_ctl_group());



    else gid = grp->gr_gid;
  }

  if (chown(libcutil_get_config_socket(), uid, gid) < 0) ast_log(LOG_WARNING,
                                                                 "Unable to change ownership of %s: %s\n",
                                                                 libcutil_get_config_socket(),
                                                                 strerror(errno));



  if (!ast_strlen_zero(libcutil_get_ctl_permissions())) {
    unsigned int p1;
    mode_t p;
    char   permissions[PATH_MAX];
    sscanf(permissions, "%30o", &p1);
    libcutil_set_ctl_permissions(permissions);
    p = p1;

    if ((chmod(libcutil_get_config_socket(), p)) < 0) ast_log(LOG_WARNING,
                                                              "Unable to change file permissions of %s: %s\n",
                                                              libcutil_get_config_socket(),
                                                              strerror(errno));
  }

  return 0;
}

static int ast_tryconnect(void)
{
  struct sockaddr_un sunaddr;
  int res;

  libcutil_set_consock(socket(PF_LOCAL, SOCK_STREAM, 0));


  if (libcutil_get_consock() < 0) {
    fprintf(stderr, "Unable to create socket: %s\n", strerror(errno));
    return 0;
  }
  memset(&sunaddr, 0, sizeof(sunaddr));
  sunaddr.sun_family = AF_LOCAL;
  ast_copy_string(sunaddr.sun_path,
                  libcutil_get_config_socket(),
                  sizeof(sunaddr.sun_path));
  res =
    connect(libcutil_get_consock(), (struct sockaddr *)&sunaddr, sizeof(sunaddr));

  if (res) {
    close(libcutil_get_consock());
    libcutil_set_consock(-1);
    return 0;
  } else return 1;
}

static void send_rasterisk_connect_commands(void)
{
  char buf[80];

  /*
   * Tell the server asterisk instance about the verbose level
   * initially desired.
   */
  if (libcutil_get_option_verbose()) {
    snprintf(buf,
             sizeof(buf),
             "core set verbose atleast %d silent",
             libcutil_get_option_verbose());
    fdsend(libcutil_get_consock(), buf);
  }

  if (libcutil_get_option_debug()) {
    snprintf(buf,
             sizeof(buf),
             "core set debug atleast %d",
             libcutil_get_option_debug());
    fdsend(libcutil_get_consock(), buf);
  }

  if (!ast_opt_mute) {
    fdsend(libcutil_get_consock(), "logger mute silent");
  } else {
    printf("log and verbose output currently muted ('logger mute' to unmute)\n");
  }
}

static int ast_el_sort_compare(const void *i1, const void *i2)
{
  char *s1, *s2;

  s1 = ((char **)i1)[0];
  s2 = ((char **)i2)[0];

  return strcasecmp(s1, s2);
}

static int ast_cli_display_match_list(char **matches, int len, int max)
{
  int i, idx, limit, count;
  int screenwidth = 0;
  int numoutput = 0, numoutputline = 0;

  screenwidth = ast_get_termcols(STDOUT_FILENO);

  /* find out how many entries can be put on one line, with two spaces between
     strings */
  limit = screenwidth / (max + 2);

  if (limit == 0) limit = 1;

  /* how many lines of output */
  count = len / limit;

  if (count * limit < len) count++;

  idx = 1;

  qsort(&matches[0], (size_t)(len), sizeof(char *), ast_el_sort_compare);

  for (; count > 0; count--) {
    numoutputline = 0;

    for (i = 0; i < limit && matches[idx]; i++, idx++) {
      /* Don't print dupes */
      if (((matches[idx + 1] != NULL) &&
           (strcmp(matches[idx], matches[idx + 1]) == 0))) {
        i--;
        ast_free(matches[idx]);
        matches[idx] = NULL;
        continue;
      }

      numoutput++;
      numoutputline++;
      fprintf(stdout, "%-*s  ", max, matches[idx]);
      ast_free(matches[idx]);
      matches[idx] = NULL;
    }

    if (numoutputline > 0) fprintf(stdout, "\n");
  }

  return numoutput;
}

static void destroy_match_list(char **match_list, int matches)
{
  if (match_list) {
    int idx;

    for (idx = 0; idx < matches; ++idx) {
      ast_free(match_list[idx]);
    }
    ast_free(match_list);
  }
}

static char** ast_el_strtoarr(char *buf)
{
  char  *retstr;
  char **match_list = NULL;
  char **new_list;
  size_t match_list_len = 1;
  int    matches        = 0;

  while ((retstr = strsep(&buf, " "))) {
    if (!strcmp(retstr, AST_CLI_COMPLETE_EOF)) {
      break;
    }

    if (matches + 1 >= match_list_len) {
      match_list_len <<= 1;
      new_list         = ast_realloc(match_list, match_list_len * sizeof(char *));

      if (!new_list) {
        destroy_match_list(match_list, matches);
        return NULL;
      }
      match_list = new_list;
    }

    retstr = ast_strdup(retstr);

    if (!retstr) {
      destroy_match_list(match_list, matches);
      return NULL;
    }
    match_list[matches++] = retstr;
  }

  if (!match_list) {
    return NULL;
  }

  if (matches >= match_list_len) {
    new_list = ast_realloc(match_list, (match_list_len + 1) * sizeof(char *));

    if (!new_list) {
      destroy_match_list(match_list, matches);
      return NULL;
    }
    match_list = new_list;
  }

  match_list[matches] = NULL;

  return match_list;
}

static char* cli_complete(EditLine *editline, int ch)
{
  int len = 0;
  char  *ptr;
  int    nummatches = 0;
  char **matches;
  int    retval = CC_ERROR;
  char   buf[2048], savechr;
  int    res;


  LineInfo *lf = (LineInfo *)el_line(editline);

  savechr             = *(char *)lf->cursor;
  *(char *)lf->cursor = '\0';
  ptr                 = (char *)lf->cursor;

  if (ptr) {
    while (ptr > lf->buffer) {
      if (isspace(*ptr)) {
        ptr++;
        break;
      }
      ptr--;
    }
  }

  len = lf->cursor - ptr;

  if (ast_opt_remote) {
    snprintf(buf,
             sizeof(buf),
             "_COMMAND NUMMATCHES \"%s\" \"%s\"",
             lf->buffer,
             ptr);
    fdsend(libcutil_get_consock(), buf);

    if ((res = read(libcutil_get_consock(), buf, sizeof(buf) - 1)) < 0) {
      return (char *)(CC_ERROR);
    }
    buf[res]   = '\0';
    nummatches = atoi(buf);

    if (nummatches > 0) {
      char *mbuf;
      char *new_mbuf;
      int   mlen = 0, maxmbuf = 2048;

      /* Start with a 2048 byte buffer */
      if (!(mbuf = ast_malloc(maxmbuf))) {
        *((char *)lf->cursor) = savechr;
        return (char *)(CC_ERROR);
      }
      snprintf(buf,
               sizeof(buf),
               "_COMMAND MATCHESARRAY \"%s\" \"%s\"",
               lf->buffer,
               ptr);
      fdsend(libcutil_get_consock(), buf);
      res     = 0;
      mbuf[0] = '\0';

      while (!strstr(mbuf, AST_CLI_COMPLETE_EOF) && res != -1) {
        if (mlen + 1024 > maxmbuf) {
          /* Every step increment buffer 1024 bytes */
          maxmbuf += 1024;
          new_mbuf = ast_realloc(mbuf, maxmbuf);

          if (!new_mbuf) {
            ast_free(mbuf);
            *((char *)lf->cursor) = savechr;
            return (char *)(CC_ERROR);
          }
          mbuf = new_mbuf;
        }

        /* Only read 1024 bytes at a time */
        res = read(libcutil_get_consock(), mbuf + mlen, 1024);

        if (res > 0) mlen += res;
      }
      mbuf[mlen] = '\0';

      matches = ast_el_strtoarr(mbuf);
      ast_free(mbuf);
    } else matches = (char **)NULL;
  } else {
    char **p, *oldbuf = NULL;
    nummatches = 0;
    matches    = ast_cli_completion_matches((char *)lf->buffer, ptr);

    for (p = matches; p && *p; p++) {
      if (!oldbuf || strcmp(*p, oldbuf)) nummatches++;
      oldbuf = *p;
    }
  }

  if (matches) {
    int i;
    int matches_num, maxlen, match_len;

    if (matches[0][0] != '\0') {
      el_deletestr(editline, (int)len);
      el_insertstr(editline, matches[0]);
      retval = CC_REFRESH;
    }

    if (nummatches == 1) {
      /* Found an exact match */
      el_insertstr(editline, " ");
      retval = CC_REFRESH;
    } else {
      /* Must be more than one match */
      for (i = 1, maxlen = 0; matches[i]; i++) {
        match_len = strlen(matches[i]);

        if (match_len > maxlen) maxlen = match_len;
      }
      matches_num = i - 1;

      if (matches_num > 1) {
        fprintf(stdout, "\n");
        ast_cli_display_match_list(matches, nummatches, maxlen);
        retval = CC_REDISPLAY;
      } else {
        el_insertstr(editline, " ");
        retval = CC_REFRESH;
      }
    }

    for (i = 0; matches[i]; i++) ast_free(matches[i]);
    ast_free(matches);
  }

  *((char *)lf->cursor) = savechr;

  return (char *)(long)retval;
}

static char* cli_prompt(EditLine *editline)
{
  char  tmp[100];
  char *pfmt;
  int   color_used              = 0;
  static int cli_prompt_changes = 0;
  struct passwd *pw;
  struct group  *gr;

  if (prompt == NULL) {
    prompt = ast_str_create(100);
  } else if (!cli_prompt_changes) {
    return ast_str_buffer(prompt);
  } else {
    ast_str_reset(prompt);
  }

  if ((pfmt = getenv("CUTIL_PROMPT"))) {
    char *t           = pfmt;
    struct timeval ts = ast_tvnow();

    while (*t != '\0') {
      if (*t == '%') {
        char hostname[MAXHOSTNAMELEN] = "";
        int  i, which;
        struct ast_tm tm = { 0, };
        int fgcolor = COLOR_WHITE, bgcolor = COLOR_BLACK;

        t++;

        switch (*t) {
        case 'C': /* color */
          t++;

          if (sscanf(t, "%30d;%30d%n", &fgcolor, &bgcolor, &i) == 2) {
            ast_term_color_code(&prompt, fgcolor, bgcolor);
            t += i - 1;
          } else if (sscanf(t, "%30d%n", &fgcolor, &i) == 1) {
            ast_term_color_code(&prompt, fgcolor, 0);
            t += i - 1;
          }

          /* If the color has been reset correctly, then there's no need to
             reset it later */
          color_used =
            ((fgcolor == COLOR_WHITE) && (bgcolor == COLOR_BLACK)) ? 0 : 1;
          break;

        case 'd': /* date */

          if (ast_localtime(&ts, &tm, NULL)) {
            ast_strftime(tmp, sizeof(tmp), "%Y-%m-%d", &tm);
            ast_str_append(&prompt, 0, "%s", tmp);
            cli_prompt_changes++;
          }
          break;

        case 'g': /* group */

          if ((gr = getgrgid(getgid()))) {
            ast_str_append(&prompt, 0, "%s", gr->gr_name);
          }
          break;

        case 'h': /* hostname */

          if (!gethostname(hostname, sizeof(hostname) - 1)) {
            ast_str_append(&prompt, 0, "%s", hostname);
          } else {
            ast_str_append(&prompt, 0, "%s", "localhost");
          }
          break;

        case 'H': /* short hostname */

          if (!gethostname(hostname, sizeof(hostname) - 1)) {
            char *dotptr;

            if ((dotptr = strchr(hostname, '.'))) {
              *dotptr = '\0';
            }
            ast_str_append(&prompt, 0, "%s", hostname);
          } else {
            ast_str_append(&prompt, 0, "%s", "localhost");
          }
          break;

# ifdef HAVE_GETLOADAVG
        case 'l': /* load avg */
          t++;

          if ((sscanf(t, "%30d", &which) == 1) && (which > 0) && (which <= 3)) {
            double list[3];
            getloadavg(list, 3);
            ast_str_append(&prompt, 0, "%.2f", list[which - 1]);
            cli_prompt_changes++;
          }
          break;

# endif /* ifdef HAVE_GETLOADAVG */
        case 's': /* Asterisk system name (from asterisk.conf) */
          ast_str_append(&prompt, 0, "%s", libcutil_get_config_system_name());
          break;

        case 't': /* time */

          if (ast_localtime(&ts, &tm, NULL)) {
            ast_strftime(tmp, sizeof(tmp), "%H:%M:%S", &tm);
            ast_str_append(&prompt, 0, "%s", tmp);
            cli_prompt_changes++;
          }
          break;

        case 'u': /* username */

          if ((pw = getpwuid(getuid()))) {
            ast_str_append(&prompt, 0, "%s", pw->pw_name);
          }
          break;

        case '#': /* process console or remote? */
          ast_str_append(&prompt, 0, "%c", ast_opt_remote ? '>' : '#');
          break;

        case '%': /* literal % */
          ast_str_append(&prompt, 0, "%c", '%');
          break;

        case '\0': /* % is last character - prevent bug */
          t--;
          break;
        }
      } else {
        ast_str_append(&prompt, 0, "%c", *t);
      }
      t++;
    }

    if (color_used) {
      /* Force colors back to normal at end */
      ast_term_color_code(&prompt, 0, 0);
    }
  } else {
    ast_str_set(&prompt, 0, "%s%s",
                !ast_strlen_zero(
                  libcutil_get_remotehostname()) ? libcutil_get_remotehostname() : "",
                CUTIL_PROMPT);
  }

  return ast_str_buffer(prompt);
}

# ifdef HAVE_LIBEDIT_IS_UNICODE
static int ast_el_read_char(EditLine *editline, wchar_t *cp)
# else /* ifdef HAVE_LIBEDIT_IS_UNICODE */
static int ast_el_read_char(EditLine * editline, char * cp)
# endif  /* ifdef HAVE_LIBEDIT_IS_UNICODE */
{
  int num_read = 0;
  int lastpos  = 0;
  struct pollfd fds[2];
  int res;
  int max;

# define EL_BUF_SIZE 512
  char buf[EL_BUF_SIZE];

  for (;;) {
    max           = 1;
    fds[0].fd     = libcutil_get_consock();
    fds[0].events = POLLIN;

    if (!ast_opt_exec) {
      fds[1].fd     = STDIN_FILENO;
      fds[1].events = POLLIN;
      max++;
    }
    res = ast_poll(fds, max, -1);


    if (res < 0) {
      /*if (sig_flags.need_quit || sig_flags.need_quit_handler)*/
      if (sig_need_quit() || sig_need_quit_handler()) break;

      if (errno == EINTR) continue;
      fprintf(stderr, "poll failed: %s\n", strerror(errno));
      break;
    }

    if (!ast_opt_exec && fds[1].revents) {
      char c = '\0';
      num_read = read(STDIN_FILENO, &c, 1);


      if (num_read < 1) {
        break;
      } else {
# ifdef  HAVE_LIBEDIT_IS_UNICODE
        *cp = btowc(c);
# else /* ifdef  HAVE_LIBEDIT_IS_UNICODE */
        *cp = c;
# endif  /* ifdef  HAVE_LIBEDIT_IS_UNICODE */
        return num_read;
      }
    }

    if (fds[0].revents) {
      res = read(libcutil_get_consock(), buf, sizeof(buf) - 1);

      /* if the remote side disappears exit */
      if (res < 1) {
        fprintf(stderr, "\nDisconnected from LibCutil CLI server\n");

        if (!ast_opt_reconnect) {
          quit_handler(0, SHUTDOWN_FAST, 0);
        } else {
          int tries;
          int reconnects_per_second = 20;
          fprintf(stderr, "Attempting to reconnect for 30 seconds\n");

          for (tries = 0; tries < 30 * reconnects_per_second; tries++) {
            if (ast_tryconnect()) {
              fprintf(stderr,
                      "Reconnect succeeded after %.3f seconds\n",
                      1.0 / reconnects_per_second * tries);
              printf("%s", term_quit());
              WELCOME_MESSAGE;
              send_rasterisk_connect_commands();
              break;
            } else usleep(1000000 / reconnects_per_second);
          }

          if (tries >= 30 * reconnects_per_second) {
            fprintf(stderr, "Failed to reconnect for 30 seconds.  Quitting.\n");
            quit_handler(0, SHUTDOWN_FAST, 0);
          }
        }
        continue;
      }

      buf[res] = '\0';

      /* Write over the CLI prompt */
      if (!ast_opt_exec && !lastpos) {
        if (write(STDOUT_FILENO, "\r[0K", 5) < 0) {}
      }

      console_print(buf);

      if ((res < EL_BUF_SIZE - 1) &&
          ((buf[res - 1] == '\n') || ((res >= 2) && (buf[res - 2] == '\n')))) {
# ifdef  HAVE_LIBEDIT_IS_UNICODE
        *cp = btowc(CC_REFRESH);
# else /* ifdef  HAVE_LIBEDIT_IS_UNICODE */
        *cp = CC_REFRESH;
# endif  /* ifdef  HAVE_LIBEDIT_IS_UNICODE */
        return 1;
      } else {
        lastpos = 1;
      }
    }
  }

# ifdef  HAVE_LIBEDIT_IS_UNICODE
  *cp = btowc('\0');
# else /* ifdef  HAVE_LIBEDIT_IS_UNICODE */
  *cp = '\0';
# endif  /* ifdef  HAVE_LIBEDIT_IS_UNICODE */

  return 0;
}

/* This is the main console CLI command handler.  Run by the main() thread. */
void consolehandler(const char *s)
{
  printf("%s", ast_insteadof_term_end());
  fflush(stdout);

  /* Called when readline data is available */
  if (!ast_all_zeros(s)) ast_el_add_history(s);

  /* The real handler for bang */
  if (s[0] == '!') {
    if (s[1]) ast_safe_system(s + 1);
    else ast_safe_system(getenv("SHELL") ? getenv("SHELL") : "/bin/sh");
  } else ast_cli_command(STDOUT_FILENO, s);
}

int console_set_el_gchar_fn(void)
{
  return ast_el_set_gchar_handler(ast_el_read_char);
}

const char* console_el_get_buf(int *num)
{
  return ast_el_get_buf(num);
}

int console_el_init(void)
{
  ast_el_initialize_wrap(cli_prompt, cli_complete);

  ast_el_read_default_histfile();
  return 0;
}

void ast_close_fds_above_n(int n)
{
  closefrom(n + 1);
}

/* Sending messages from the daemon back to the display requires _excluding_ the
   terminating NULL */
int fdprint(int fd, const char *s)
{
  return write(fd, s, strlen(s));
}

/* Sending commands from consoles back to the daemon requires a terminating NULL
 */
int fdsend(int fd, const char *s)
{
  return write(fd, s, strlen(s) + 1);
}

void ast_register_thread(char *name)
{
  struct thread_list_t *new = ast_calloc(1, sizeof(*new));

  if (!new) return;

  ast_assert(multi_thread_safe);
  new->id   = pthread_self();
  new->lwp  = ast_get_tid();
  new->name = name; /* steal the allocated memory for the thread name */
  AST_RWLIST_WRLOCK(&thread_list);
  AST_RWLIST_INSERT_HEAD(&thread_list, new, list);
  AST_RWLIST_UNLOCK(&thread_list);
}

void ast_unregister_thread(void *id)
{
  struct thread_list_t *x;

  AST_RWLIST_WRLOCK(&thread_list);
  AST_RWLIST_TRAVERSE_SAFE_BEGIN(&thread_list, x, list) {
    if ((void *)x->id == id) {
      AST_RWLIST_REMOVE_CURRENT(list);
      break;
    }
  }
  AST_RWLIST_TRAVERSE_SAFE_END;
  AST_RWLIST_UNLOCK(&thread_list);

  if (x) {
    ast_free(x->name);
    ast_free(x);
  }
}

#endif /* if !defined(LOW_MEMORY) */


void ast_run_atexits(int run_cleanups)
{
  struct ast_atexit *ae;

  AST_LIST_LOCK(&atexits);

  while ((ae = AST_LIST_REMOVE_HEAD(&atexits, list))) {
    if (ae->func && (!ae->is_cleanup || run_cleanups)) {
      ae->func();
    }
    ast_free(ae);
  }
  AST_LIST_UNLOCK(&atexits);
}

static void __ast_unregister_atexit(void (*func)(void))
{
  struct ast_atexit *ae;

  AST_LIST_TRAVERSE_SAFE_BEGIN(&atexits, ae, list) {
    if (ae->func == func) {
      AST_LIST_REMOVE_CURRENT(list);
      ast_free(ae);
      break;
    }
  }
  AST_LIST_TRAVERSE_SAFE_END;
}

static int register_atexit(void (*func)(void), int is_cleanup)
{
  struct ast_atexit *ae;

  ae = ast_calloc(1, sizeof(*ae));

  if (!ae) {
    return -1;
  }
  ae->func       = func;
  ae->is_cleanup = is_cleanup;

  AST_LIST_LOCK(&atexits);
  __ast_unregister_atexit(func);
  AST_LIST_INSERT_HEAD(&atexits, ae, list);
  AST_LIST_UNLOCK(&atexits);

  return 0;
}

int ast_register_atexit(void (*func)(void))
{
  return register_atexit(func, 0);
}

int ast_register_cleanup(void (*func)(void))
{
  return register_atexit(func, 1);
}

void ast_unregister_atexit(void (*func)(void))
{
  AST_LIST_LOCK(&atexits);
  __ast_unregister_atexit(func);
  AST_LIST_UNLOCK(&atexits);
}

int ast_safe_system(const char *s)
{
  pid_t pid;
  int   res;
  int   status;

#if defined(HAVE_WORKING_FORK) || defined(HAVE_WORKING_VFORK)
  ast_replace_sigchld();

# ifdef HAVE_WORKING_FORK
  pid = fork();
# else /* ifdef HAVE_WORKING_FORK */
  pid = vfork();
# endif  /* ifdef HAVE_WORKING_FORK */

  if (pid == 0) {
# ifdef HAVE_CAP
    cap_t cap = cap_from_text("cap_net_admin-eip");

    if (cap_set_proc(cap)) {
      /* Careful with order! Logging cannot happen after we close FDs */
      ast_log(LOG_WARNING, "Unable to remove capabilities.\n");
    }
    cap_free(cap);
# endif /* ifdef HAVE_CAP */
# ifdef HAVE_WORKING_FORK

    if (ast_opt_high_priority) ast_set_priority(0);

    /* Close file descriptors and launch system command */
    ast_close_fds_above_n(STDERR_FILENO);
# endif /* ifdef HAVE_WORKING_FORK */
    execl("/bin/sh", "/bin/sh", "-c", s, (char *)NULL);
    _exit(1);
  } else if (pid > 0) {
    for (;;) {
      res = waitpid(pid, &status, 0);

      if (res > -1) {
        res = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        break;
      } else if (errno != EINTR) break;
    }
  } else {
    ast_log(LOG_WARNING, "Fork failed: %s\n", strerror(errno));
    res = -1;
  }

  ast_unreplace_sigchld();
#else /* !defined(HAVE_WORKING_FORK) && !defined(HAVE_WORKING_VFORK) */
  res = -1;
#endif  /* if defined(HAVE_WORKING_FORK) || defined(HAVE_WORKING_VFORK) */

  return res;
}

/*! \brief We set ourselves to a high priority, that we might pre-empt
 * everything else.  If your PBX has heavy activity on it, this is a
 * good thing.
 */
int ast_set_priority(int pri)
{
  struct sched_param sched;

  memset(&sched, 0, sizeof(sched));
#ifdef __linux__

  if (pri) {
    sched.sched_priority = 10;

    if (sched_setscheduler(0, SCHED_RR, &sched)) {
      ast_log(LOG_WARNING, "Unable to set high priority\n");
      return -1;
    } else ast_verb(1, "Set to realtime thread\n");
  } else {
    sched.sched_priority = 0;

    /* According to the manpage, these parameters can never fail. */
    sched_setscheduler(0, SCHED_OTHER, &sched);
  }
#else /* ifdef __linux__ */

  if (pri) {
    if (setpriority(PRIO_PROCESS, 0, -10) == -1) {
      ast_log(LOG_WARNING, "Unable to set high priority\n");
      return -1;
    } else ast_verb(1, "Set to high priority\n");
  } else {
    /* According to the manpage, these parameters can never fail. */
    setpriority(PRIO_PROCESS, 0, 0);
  }
#endif /* ifdef __linux__ */
  return 0;
}

int ast_all_zeros(const char *s)
{
  while (*s) {
    if (*s > 32) return 0;

    s++;
  }
  return 1;
}

int show_version(void)
{
  printf("LibCutil CLI %s\n", ast_get_version());
  return 0;
}

/*! \brief Set an X-term or screen title */
static void set_title(char *text)
{
  if (getenv("TERM") && strstr(getenv("TERM"), "xterm")) fprintf(stdout,
                                                                 "\033]2;%s\007",
                                                                 text);
}

static void set_icon(char *text)
{
  if (getenv("TERM") && strstr(getenv("TERM"), "xterm")) fprintf(stdout,
                                                                 "\033]1;%s\007",
                                                                 text);
}

AST_MUTEX_DEFINE_STATIC(safe_system_lock);

/*! \brief Keep track of how many threads are currently trying to wait*() on
 *  a child process
 */
static unsigned int safe_system_level = 0;
static struct sigaction safe_system_prev_handler;

void ast_replace_sigchld(void)
{
  unsigned int level;

  ast_mutex_lock(&safe_system_lock);
  level = safe_system_level++;

  /* only replace the handler if it has not already been done */
  if (level == 0) {
    sigaction(SIGCHLD, &null_sig_handler, &safe_system_prev_handler);
  }

  ast_mutex_unlock(&safe_system_lock);
}

void ast_unreplace_sigchld(void)
{
  unsigned int level;

  ast_mutex_lock(&safe_system_lock);
  level = --safe_system_level;

  /* only restore the handler if we are the last one */
  if (level == 0) {
    sigaction(SIGCHLD, &safe_system_prev_handler, NULL);
  }

  ast_mutex_unlock(&safe_system_lock);
}

static int can_safely_quit(shutdown_nice_t niceness, int restart)
{
  int waited = 0;

  /* Check if someone else isn't already doing this. */
  ast_mutex_lock(&safe_system_lock);

  if ((shuttingdown != NOT_SHUTTING_DOWN) && (niceness >= shuttingdown)) {
    /* Already in progress and other request was less nice. */
    ast_mutex_unlock(&safe_system_lock);
    ast_verbose("Ignoring LibCutil %s request, already in progress.\n",
                restart ? "restart" : "shutdown");
    return 0;
  }
  shuttingdown = niceness;
  ast_mutex_unlock(&safe_system_lock);


  /* Re-acquire lock and check if someone changed the niceness, in which
   * case someone else has taken over the shutdown.
   */
  ast_mutex_lock(&safe_system_lock);

  if (shuttingdown != niceness) {
    if ((shuttingdown == NOT_SHUTTING_DOWN) && ast_opt_console) {
      ast_verb(0, "LibCutil %s cancelled.\n", restart ? "restart" : "shutdown");
    }
    ast_mutex_unlock(&safe_system_lock);
    return 0;
  }

  if (niceness >= SHUTDOWN_REALLY_NICE) {
    shuttingdown = SHUTTING_DOWN;
    ast_mutex_unlock(&safe_system_lock);

    /* No more Mr. Nice guy.  We are committed to shutting down now. */

    // do shutdow

    ast_mutex_lock(&safe_system_lock);
  }
  shuttingdown = SHUTTING_DOWN_FINAL;
  ast_mutex_unlock(&safe_system_lock);

  if ((niceness >= SHUTDOWN_NORMAL) && waited) {
    /*
     * We were not idle.  Give things in progress a chance to
     * recognize the final shutdown phase.
     */
    sleep(1);
  }
  return 1;
}

/*! Called when exiting is certain. */
static void really_quit(int num, shutdown_nice_t niceness, int restart)
{
  int active_channels;
  struct ast_json *json_object = NULL;
  int run_cleanups             = niceness >= SHUTDOWN_NICE;


  if (!restart) {
    ast_sd_notify("STOPPING=1");
  }

  if (ast_opt_console || (ast_opt_remote && !ast_opt_exec)) {
    ast_el_write_default_histfile();

    if ((consolethread == AST_PTHREADT_NULL) ||
        (consolethread == pthread_self())) {
      /* Only end if we are the consolethread, otherwise there's a race with
         that thread. */

      // if (el != NULL) {
      //   el_end(el);
      // }
      //
      // if (el_hist != NULL) {
      //   history_end(el_hist);
      // }
      ast_el_uninitialize();
    } else if (mon_sig_flags == pthread_self()) {
      if (consolethread != AST_PTHREADT_NULL) {
        pthread_kill(consolethread, SIGURG);
      }
    }
  }

  /* Don't publish messages if we're a remote console - we won't have all of the
     Stasis
   * topics or message types
   */
  if (!ast_opt_remote) {
    json_object = ast_json_pack("{s: s, s: s}",
                                "Shutdown",
                                active_channels ? "Uncleanly" : "Cleanly",
                                "Restart",
                                restart ? "True" : "False");
    ast_json_unref(json_object);
    json_object = NULL;
  }

  ast_verb(0, "Executing last minute cleanups\n");
  ast_run_atexits(run_cleanups);

  if (libcutil_get_socket() > -1) {
    pthread_cancel(lthread);
    close(libcutil_get_socket());
    libcutil_set_socket(-1);
    unlink(libcutil_get_socket());
    pthread_kill(lthread, SIGURG);
    pthread_join(lthread, NULL);
  }

  if (libcutil_get_socket() > -1) close(libcutil_get_socket());


  if (!ast_opt_remote) unlink(libcutil_get_config_pid());

  if (sig_alert_pipe[0]) close(sig_alert_pipe[0]);

  if (sig_alert_pipe[1]) close(sig_alert_pipe[1]);
  printf("%s", term_quit());

#if 0

  if (restart) {
    int i;
    ast_verb(0, "Preparing for Asterisk restart...\n");

    /* Mark all FD's for closing on exec */
    for (i = 3; i < 32768; i++) {
      fcntl(i, F_SETFD, FD_CLOEXEC);
    }
    ast_verb(0, "Asterisk is now restarting...\n");
    restartnow = 1;

    /* close logger */
    close_logger();
    clean_time_zones();

    /* If there is a consolethread running send it a SIGHUP
       so it can execvp, otherwise we can do it ourselves */
    if ((consolethread != AST_PTHREADT_NULL) &&
        (consolethread != pthread_self())) {
      pthread_kill(consolethread, SIGHUP);

      /* Give the signal handler some time to complete */
      sleep(2);
    } else execvp(_argv[0], _argv);
  } else {
    /* close logger */
    close_logger();
    clean_time_zones();
  }
#else /* if 0 */

  /* close logger */
  close_logger();
  clean_time_zones();
#endif /* if 0 */

  exit(0);
}

void quit_handler(int num, shutdown_nice_t niceness, int restart)
{
  if (can_safely_quit(niceness, restart)) {
    really_quit(num, niceness, restart);

    /* No one gets here. */
  }

  /* It wasn't our time. */
}

void shutdown_fast_wrap(int num,  int restart)
{
  if (can_safely_quit(SHUTDOWN_FAST, restart)) {
    really_quit(num, SHUTDOWN_FAST, restart);

    /* No one gets here. */
  }

  /* It wasn't our time. */
}

/*! \brief Urgent handler
 *
 * Called by soft_hangup to interrupt the poll, read, or other
 * system call.  We don't actually need to do anything though.
 * Remember: Cannot EVER ast_log from within a signal handler
 */
static void _urg_handler(int num)
{}

static struct sigaction urg_handler = {
  .sa_handler = _urg_handler,
};

static void _hup_handler(int num)
{
  int a = 0, save_errno = errno;

  printf("Received HUP signal -- Reloading configs\n");
#if 0

  if (restartnow) execvp(_argv[0], _argv);
  sig_flags.need_reload = 1;

  if (sig_alert_pipe[1] != -1) {
    if (write(sig_alert_pipe[1], &a, sizeof(a)) < 0) {
      fprintf(stderr, "hup_handler: write() failed: %s\n", strerror(errno));
    }
  }
  errno = save_errno;
#endif /* if 0 */
}

static struct sigaction hup_handler = {
  .sa_handler = _hup_handler,
  .sa_flags   = SA_RESTART,
};

static void _child_handler(int sig)
{
  /* Must not ever ast_log or ast_verbose within signal handler */
  int n, status, save_errno = errno;

  /*
   * Reap all dead children -- not just one
   */
  for (n = 0; waitpid(-1, &status, WNOHANG) > 0; n++) ;

  if ((n == 0) &&
      libcutil_get_option_debug()) printf(
      "Huh?  Child handler, but nobody there?\n");
  errno = save_errno;
}

static struct sigaction child_handler = {
  .sa_handler = _child_handler,
  .sa_flags   = SA_RESTART,
};


static void __quit_handler(int num)
{
  int a = 0;

  sig_flags.need_quit = 1;

  if (sig_alert_pipe[1] != -1) {
    if (write(sig_alert_pipe[1], &a, sizeof(a)) < 0) {
      fprintf(stderr, "quit_handler: write() failed: %s\n", strerror(errno));
    }
  }

  /* There is no need to restore the signal handler here, since the app
   * is going to exit */
}

static struct sigaction ignore_sig_handler = {
  .sa_handler = SIG_IGN,
};


static void* monitor_sig_flags(void *unused)
{
  for (;;) {
    struct pollfd p = { sig_alert_pipe[0], POLLIN, 0 };
    int a;
    ast_poll(&p, 1, -1);

    if (sig_flags.need_quit) {
      sig_flags.need_quit = 0;

      if ((consolethread != AST_PTHREADT_NULL) &&
          (consolethread != pthread_self())) {
        sig_flags.need_quit_handler = 1;
        pthread_kill(consolethread, SIGURG);
      } else {
        quit_handler(0, SHUTDOWN_NORMAL, 0);
      }
    }

    if (read(sig_alert_pipe[0], &a, sizeof(a)) != sizeof(a)) {}
  }

  return NULL;
}

static inline void check_init(int init_result, const char *name)
{
  if (init_result) {
    printf("%s initialization failed.\n%s", name, term_quit());
    ast_run_atexits(0);
    exit(init_result == -2 ? 2 : 1);
  }
}

/*!
 * \brief enable or disable a logging level to a specified console
 */
void ast_console_toggle_loglevel(int fd, int level, int state)
{
  int x;

  if (level >= NUMLOGLEVELS) {
    level = NUMLOGLEVELS - 1;
  }

  for (x = 0; x < AST_MAX_CONNECTS; x++) {
    if (fd == consoles[x].fd) {
      /*
       * Since the logging occurs when levels are false, set to
       * flipped iinput because this function accepts 0 as off and 1 as on
       */
      consoles[x].levels[level] = state ? 0 : 1;
      return;
    }
  }
}

/*!
 * \brief mute or unmute a console from logging
 */
void ast_console_toggle_mute(int fd, int silent)
{
  int x;

  for (x = 0; x < AST_MAX_CONNECTS; x++) {
    if (fd == consoles[x].fd) {
      if (consoles[x].mute) {
        consoles[x].mute = 0;

        if (!silent) ast_cli(fd, "Console is not muted anymore.\n");
      } else {
        consoles[x].mute = 1;

        if (!silent) ast_cli(fd, "Console is muted.\n");
      }
      return;
    }
  }
  ast_cli(fd, "Couldn't find remote console.\n");
}

/*!
 * \brief log the string to all attached network console clients
 */
static void ast_network_puts_mutable(const char *string, int level, int sublevel)
{
  int x;

  for (x = 0; x < AST_MAX_CONNECTS; ++x) {
    if ((consoles[x].fd < 0)
        || consoles[x].mute
        || consoles[x].levels[level]
        || ((level == __LOG_VERBOSE) &&
            (consoles[x].option_verbose < sublevel))) {
      continue;
    }
    fdprint(consoles[x].p[1], string);
  }
}

/*!
 * \brief log the string to the root console, and all attached
 * network console clients
 */
void ast_console_puts_mutable(const char *string, int level)
{
  ast_console_puts_mutable_full(string, level, 0);
}

void ast_console_puts_mutable_full(const char *message,
                                   int         level,
                                   int         sublevel)
{
  /* Send to the root console */
  console_print(message);

  /* Wake up a poll()ing console */
  if (ast_opt_console && (consolethread != AST_PTHREADT_NULL)) {
    pthread_kill(consolethread, SIGURG);
  }

  /* Send to any network console clients */
  ast_network_puts_mutable(message, level, sublevel);
}

static void set_header(char *outbuf, int maxout, char level)
{
  const char *cmp;
  char date[40];

  switch (level) {
  case 0: cmp = NULL;
    break;

  case 1: cmp = VERBOSE_PREFIX_1;
    break;

  case 2: cmp = VERBOSE_PREFIX_2;
    break;

  case 3: cmp = VERBOSE_PREFIX_3;
    break;

  default: cmp = VERBOSE_PREFIX_4;
    break;
  }

  if (ast_opt_timestamp) {
    struct ast_tm  tm;
    struct timeval now = ast_tvnow();
    ast_localtime(&now, &tm, NULL);
    ast_strftime(date, sizeof(date), ast_logger_get_dateformat(), &tm);
  }

  snprintf(outbuf, maxout, "%s%s%s%s%s%s",
           ast_opt_timestamp ? "[" : "",
           ast_opt_timestamp ? date : "",
           ast_opt_timestamp ? "] " : "",
           cmp ? ast_term_color(COLOR_GRAY, 0) : "",
           cmp ? cmp : "",
           cmp ? ast_term_reset() : "");
}

struct console_state_data {
  char verbose_line_level;
};

static int console_state_init(void *ptr)
{
  struct console_state_data *state = ptr;

  state->verbose_line_level = 0;
  return 0;
}

AST_THREADSTORAGE_CUSTOM(console_state, console_state_init, ast_free_ptr);


static int console_print(const char *s)
{
  struct console_state_data *state =
    ast_threadstorage_get(&console_state, sizeof(*state));

  char prefix[80];
  const char *c;
  int num, res = 0;
  unsigned int newline;

  do {
    if (VERBOSE_HASMAGIC(s)) {
      /* always use the given line's level, otherwise
         we'll use the last line's level */
      state->verbose_line_level = VERBOSE_MAGIC2LEVEL(s);

      /* move past magic */
      s++;

      set_header(prefix, sizeof(prefix), state->verbose_line_level);
    } else {
      *prefix = '\0';
    }
    c = s;

    /* for a given line separate on verbose magic, newline, and eol */
    if ((s = strchr(c, '\n'))) {
      ++s;
      newline = 1;
    } else {
      s       = strchr(c, '\0');
      newline = 0;
    }

    /* check if we should write this line after calculating begin/end
       so we process the case of a higher level line embedded within
       two lower level lines */
    if (state->verbose_line_level > libcutil_get_option_verbose()) {
      continue;
    }

    if (!ast_strlen_zero(prefix)) {
      fputs(prefix, stdout);
    }

    num = s - c;

    if (fwrite(c, sizeof(char), num, stdout) < num) {
      break;
    }

    if (!res) {
      /* if at least some info has been written
         we'll want to return true */
      res = 1;
    }
  } while (*s);

  if (newline) {
    /* if ending on a newline then reset last level to zero
        since what follows may be not be logging output */
    state->verbose_line_level = 0;
  }

  if (res) {
    fflush(stdout);
  }

  return res;
}

static void daemon_run(int                isroot,
                       const char        *runuser,
                       const char        *rungroup,
                       fully_booted_event fully_booted)
{
  sigset_t sigs;
  int      num;
  char    *buf;

  ast_mainpid = getpid();

  /* Initialize the terminal.  Since all processes have been forked,
   * we can now start using the standard log messages.
   */
  ast_term_init();
  printf("%s", ast_insteadof_term_end());
  fflush(stdout);


  ast_json_init();
  threadstorage_init();
  check_init(init_logger(), "Logger");
  ast_builtins_init();

  if (ast_opt_console) {
    console_el_init();
  }


  if (ast_opt_no_fork) {
    consolethread = pthread_self();
  }

  ast_makesocket();

  /* GCC 4.9 gives a bogus "right-hand operand of comma expression has
   * no effect" warning */
  (void)sigemptyset(&sigs);
  (void)sigaddset(&sigs, SIGHUP);
  (void)sigaddset(&sigs, SIGTERM);
  (void)sigaddset(&sigs, SIGINT);
  (void)sigaddset(&sigs, SIGPIPE);
  (void)sigaddset(&sigs, SIGWINCH);
  pthread_sigmask(SIG_BLOCK, &sigs, NULL);
  sigaction(SIGURG, &urg_handler, NULL);
  signal(SIGINT,  __quit_handler);
  signal(SIGTERM, __quit_handler);
  sigaction(SIGHUP,  &hup_handler,        NULL);
  sigaction(SIGPIPE, &ignore_sig_handler, NULL);


  fully_booted();

  if (ast_opt_console) {
    /* Console stuff now... */
    /* Register our quit function */
    char title[256];
    char hostname[MAXHOSTNAMELEN] = "";

    if (gethostname(hostname, sizeof(hostname) - 1)) {
      ast_copy_string(hostname, "<Unknown>", sizeof(hostname));
    }

    ast_pthread_create_detached(&mon_sig_flags, NULL, monitor_sig_flags, NULL);

    set_icon("LibCutil");
    snprintf(title,
             sizeof(title),
             "LibCutil Console on '%s' (pid %ld)",
             hostname,
             (long)ast_mainpid);
    set_title(title);

    /*el_set(el, EL_GETCFN, ast_el_read_char);*/
    console_set_el_gchar_fn();

    for (;;) {
      if (sig_flags.need_quit || sig_flags.need_quit_handler) {
        quit_handler(0, SHUTDOWN_FAST, 0);
        break;
      }

      /*buf = (char *) el_gets(el, &num);*/
      buf = console_el_get_buf(&num);

      if (!buf && (write(1, "", 1) < 0)) return;  /* quit */

      if (buf) {
        if (buf[strlen(buf) - 1] == '\n') buf[strlen(buf) - 1] = '\0';

        consolehandler(buf);
      }
    }
  }

  /* Stall until a quit signal is given */
  monitor_sig_flags(NULL);
}

static void __remote_quit_handler(int num)
{
  sig_flags.need_quit = 1;
}

static int remoteconsolehandler(const char *s)
{
  int ret = 0;

  /* Called when readline data is available */
  if (!ast_all_zeros(s)) ast_el_add_history(s);

  while (isspace(*s)) {
    s++;
  }

  /* The real handler for bang */
  if (s[0] == '!') {
    if (s[1]) ast_safe_system(s + 1);
    else ast_safe_system(getenv("SHELL") ? getenv("SHELL") : "/bin/sh");
    ret = 1;
  } else if (((strncasecmp(s, "quit",
                           4) == 0) || (strncasecmp(s, "exit", 4) == 0)) &&
             ((s[4] == '\0') || isspace(s[4]))) {
    quit_handler(0, SHUTDOWN_FAST, 0);
    ret = 1;
  } else if (s[0]) {
    char *shrunk = ast_strdupa(s);
    char *cur;
    char *prev;

    /*
     * Remove duplicate spaces from shrunk for matching purposes.
     *
     * shrunk has at least one character in it to start with or we
     * couldn't get here.
     */
    for (prev = shrunk, cur = shrunk + 1; *cur; ++cur) {
      if ((*prev == ' ') && (*cur == ' ')) {
        /* Skip repeated space delimiter. */
        continue;
      }
      *++prev = *cur;
    }
    *++prev = '\0';

    if (strncasecmp(shrunk, "core set verbose ", 17) == 0) {
      /*
       * We need to still set the rasterisk option_verbose in case we are
       * talking to an earlier version which doesn't prefilter verbose
       * levels.  This is really a compromise as we should always take
       * whatever the server sends.
       */

      if (!strncasecmp(shrunk + 17, "off", 3)) {
        ast_verb_console_set(0);
      } else {
        int verbose_new;
        int atleast;

        atleast = 8;

        if (strncasecmp(shrunk + 17, "atleast ", atleast)) {
          atleast = 0;
        }

        if (sscanf(shrunk + 17 + atleast, "%30d", &verbose_new) == 1) {
          if (!atleast || (ast_verb_console_get() < verbose_new)) {
            ast_verb_console_set(verbose_new);
          }
        }
      }
    }
  }

  return ret;
}

static void ast_remotecontrol(char *data)
{
  char  buf[256] = "";
  int   res;
  char *hostname;
  char *cpid;
  char *version;
  int   pid;
  char *stringp = NULL;

  char *ebuf;
  int   num = 0;

  ast_term_init();
  printf("%s", ast_insteadof_term_end());
  fflush(stdout);


  memset(&sig_flags, 0, sizeof(sig_flags));
  signal(SIGINT,  __remote_quit_handler);
  signal(SIGTERM, __remote_quit_handler);
  signal(SIGHUP,  __remote_quit_handler);


  if (read(libcutil_get_consock(), buf, sizeof(buf) - 1) < 0) {
    ast_log(LOG_ERROR, "read() failed: %s\n", strerror(errno));
    return;
  }

  if (data) {
    char  prefix[] = "cli quit after ";
    char *tmp      = ast_alloca(strlen(data) + strlen(prefix) + 1);
    sprintf(tmp, "%s%s", prefix, data);

    if (write(libcutil_get_consock(), tmp, strlen(tmp) + 1) < 0) {
      ast_log(LOG_ERROR, "write() failed: %s\n", strerror(errno));

      if (sig_flags.need_quit || sig_flags.need_quit_handler) {
        return;
      }
    }
  }
  stringp  = buf;
  hostname = strsep(&stringp, "/");
  cpid     = strsep(&stringp, "/");
  version  = strsep(&stringp, "\n");

  if (!version) version = "<Version Unknown>";
  stringp = hostname;
  strsep(&stringp, ".");

  if (cpid) pid = atoi(cpid);
  else pid = -1;

  if (!data) {
    send_rasterisk_connect_commands();
  }


  if (ast_opt_exec && data) { /* hack to print output then exit if asterisk -rx
                                 is used */
    int linefull = 1, prev_linefull = 1, prev_line_verbose = 0;
    struct pollfd fds;
    fds.fd      = libcutil_get_consock();
    fds.events  = POLLIN;
    fds.revents = 0;

    while (ast_poll(&fds, 1, 60000) > 0) {
      char buffer[512] = "", *curline = buffer, *nextline;
      int  not_written = 1;

      if (sig_flags.need_quit || sig_flags.need_quit_handler) {
        break;
      }

      if (read(libcutil_get_consock(), buffer, sizeof(buffer) - 1) <= 0) {
        break;
      }

      do {
        prev_linefull = linefull;

        if ((nextline = strchr(curline, '\n'))) {
          linefull = 1;
          nextline++;
        } else {
          linefull = 0;
          nextline = strchr(curline, '\0');
        }

        /* Skip verbose lines */

        /* Prev line full? | Line is verbose | Last line verbose? | Print
         * TRUE            | TRUE*           | TRUE               | FALSE
         * TRUE            | TRUE*           | FALSE              | FALSE
         * TRUE            | FALSE*          | TRUE               | TRUE
         * TRUE            | FALSE*          | FALSE              | TRUE
         * FALSE           | TRUE            | TRUE*              | FALSE
         * FALSE           | TRUE            | FALSE*             | TRUE
         * FALSE           | FALSE           | TRUE*              | FALSE
         * FALSE           | FALSE           | FALSE*             | TRUE
         */
        if ((!prev_linefull && !prev_line_verbose) ||
            (prev_linefull && (*curline > 0))) {
          prev_line_verbose = 0;
          not_written       = 0;

          if (write(STDOUT_FILENO, curline, nextline - curline) < 0) {
            ast_log(LOG_WARNING, "write() failed: %s\n", strerror(errno));
          }
        } else {
          prev_line_verbose = 1;
        }
        curline = nextline;
      } while (!ast_strlen_zero(curline));

      /* No non-verbose output in 60 seconds. */
      if (not_written) {
        break;
      }
    }
    return;
  }

  ast_verbose("Connected to LibCutil CLI %s currently running on %s (pid = %d)\n",
              version,
              hostname,
              pid);
  libcutil_set_remotehostname(hostname);


  ast_el_initialize_wrap(cli_prompt, cli_complete);
  ast_el_read_default_histfile();

  console_set_el_gchar_fn();

  for (;;) {
    ebuf = console_el_get_buf(&num);

    if (sig_flags.need_quit || sig_flags.need_quit_handler) {
      break;
    }

    if (!ebuf && (write(1, "", 1) < 0)) break;

    if (!ast_strlen_zero(ebuf)) {
      if (ebuf[strlen(ebuf) - 1] == '\n') ebuf[strlen(ebuf) - 1] = '\0';

      if (!remoteconsolehandler(ebuf)) {
        res = write(libcutil_get_consock(), ebuf, strlen(ebuf) + 1);

        if (res < 1) {
          ast_log(LOG_WARNING, "Unable to write: %s\n", strerror(errno));
          break;
        }
      }
    }
  }
  printf("\nDisconnected from LibCutil CLI server\n");
}

static void enable_multi_thread_safe(void)
{
  multi_thread_safe = 1;
}

static void print_intro_message(const char *runuser, const char *rungroup)
{
  if (ast_opt_console || libcutil_get_option_verbose() ||
      (ast_opt_remote && !ast_opt_exec)) {
    WELCOME_MESSAGE;

    if (runuser) {
      ast_verbose("Running as user '%s'\n", runuser);
    }

    if (rungroup) {
      ast_verbose("Running under group '%s'\n", rungroup);
    }
  }
}

/*libcutil_process when lib init done. call this function in your main loop*/
void libcutil_process(fully_booted_event event_handle)
{
  int isroot = 1, rundir_exists = 0;
  const char *runuser = NULL, *rungroup = NULL;
  char *xarg = NULL;
  int   x;


  if (geteuid() != 0) isroot = 0;

  /* Must install this signal handler up here to ensure that if the canary
   * fails to execute that it doesn't kill the Asterisk process.
   */
  sigaction(SIGCHLD, &child_handler, NULL);

  /* It's common on some platforms to clear /var/run at boot.  Create the
   * socket file directory before we drop privileges. */
  if (mkdir(libcutil_get_config_run_dir(), 0755)) {
    if (errno == EEXIST) {
      rundir_exists = 1;
    } else {
      fprintf(stderr,
              "Unable to create socket file directory.  Remote consoles will not be able to connect! (%s)\n",
              strerror(x));
      exit(1);
    }
  }

  // set config socket
  libcutil_set_config_socket();

  if ((!rungroup) &&
      !ast_strlen_zero(libcutil_get_config_run_group())) rungroup =
      libcutil_get_config_run_group();


  if ((!runuser) &&
      !ast_strlen_zero(libcutil_get_config_run_user())) runuser =
      libcutil_get_config_run_user();


#ifndef __CYGWIN__

  if (isroot) {
    ast_set_priority(ast_opt_high_priority);
  }

  if (isroot && rungroup) {
    struct group *gr;
    gr = getgrnam(rungroup);

    if (!gr) {
      fprintf(stderr, "No such group '%s'!\n", rungroup);
      exit(1);
    }

    if (!rundir_exists && chown(libcutil_get_config_run_dir(), -1, gr->gr_gid)) {
      fprintf(stderr,
              "Unable to chgrp run directory to %d (%s)\n",
              (int)gr->gr_gid,
              rungroup);
    }

    if (setgid(gr->gr_gid)) {
      fprintf(stderr, "Unable to setgid to %d (%s)\n", (int)gr->gr_gid, rungroup);
      exit(1);
    }

    if (setgroups(0, NULL)) {
      fprintf(stderr, "Unable to drop unneeded groups\n");
      exit(1);
    }
  }

  if (runuser && !ast_opt_remote) {
  # ifdef HAVE_CAP
    int has_cap = 1;
  # endif /* HAVE_CAP */
    struct passwd *pw;
    pw = getpwnam(runuser);

    if (!pw) {
      fprintf(stderr, "No such user '%s'!\n", runuser);
      exit(1);
    }

    if (chown(libcutil_get_config_run_dir(), pw->pw_uid, -1)) {
      fprintf(stderr,
              "Unable to chown run directory to %d (%s)\n",
              (int)pw->pw_uid,
              runuser);
    }
  # ifdef HAVE_CAP

    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) {
      ast_log(LOG_WARNING, "Unable to keep capabilities.\n");
      has_cap = 0;
    }
  # endif /* HAVE_CAP */

    if (!isroot && (pw->pw_uid != geteuid())) {
      fprintf(stderr,
              "main started as nonroot, but runuser '%s' requested.\n",
              runuser);
      exit(1);
    }

    if (!rungroup) {
      if (setgid(pw->pw_gid)) {
        fprintf(stderr, "Unable to setgid to %d!\n", (int)pw->pw_gid);
        exit(1);
      }

      if (isroot && initgroups(pw->pw_name, pw->pw_gid)) {
        fprintf(stderr, "Unable to init groups for '%s'\n", runuser);
        exit(1);
      }
    }

    if (setuid(pw->pw_uid)) {
      fprintf(stderr, "Unable to setuid to %d (%s)\n", (int)pw->pw_uid, runuser);
      exit(1);
    }
  # ifdef HAVE_CAP

    if (has_cap) {
      cap_t cap;

      cap = cap_from_text("cap_net_admin=eip");

      if (cap_set_proc(cap)) {
        fprintf(stderr, "Unable to install capabilities.\n");
      }

      if (cap_free(cap)) {
        fprintf(stderr, "Unable to drop capabilities.\n");
      }
    }
  # endif /* HAVE_CAP */
  }

  #endif   /* __CYGWIN__ */

  #ifdef linux

  if (geteuid() && ast_opt_dump_core) {
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
      fprintf(stderr,
              "Unable to set the process for core dumps after changing to a non-root user. %s\n",
              strerror(errno));
    }
  }
  #endif /* ifdef linux */


  if (ast_tryconnect()) {
    /* One is already running */
    if (ast_opt_remote) {
      enable_multi_thread_safe();

      if (ast_opt_exec) {
        ast_remotecontrol(xarg);
        shutdown_fast_wrap(0, 0);
        exit(0);
      }
      ast_term_init();
      printf("%s", ast_insteadof_term_end());
      fflush(stdout);

      print_intro_message(runuser, rungroup);

      printf("%s", term_quit());

      ast_remotecontrol(NULL);
      shutdown_fast_wrap(0, 0);
      exit(0);
    } else {
      fprintf(stderr,
              "already running on %s.  get your help for connect.\n",
              libcutil_get_config_socket());
      printf("%s", term_quit());
      exit(1);
    }
  } else if (ast_opt_remote || ast_opt_exec) {
    fprintf(stderr,
            "Unable to connect to remote LibCutil CLI (does %s exist?)\n",
            libcutil_get_config_socket());
    printf("%s", term_quit());
    exit(1);
  }


  daemon_run(isroot, runuser, rungroup, event_handle);
}
