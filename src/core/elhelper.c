/*
 *
 * seanchann <xqzhou@bj-jyd.cn>
 *
 * See docs/ for more information about
 * the  project.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include "libcutil.h"

#include "elhelper.h"

#include <stdlib.h>
#include "libcutil/utils.h"

#define MAX_HISTORY_COMMAND_LENGTH 256

static History *el_hist;
static EditLine *el;
static el_prompt prompt_handler;
static el_complete complete_handler;

static int ast_el_initialize();

int ast_el_add_history(const char *buf) {
  HistEvent ev;
  char *stripped_buf;

  if ((el_hist == NULL) || (el == NULL)) {
    ast_el_initialize();
  }

  if (strlen(buf) > (MAX_HISTORY_COMMAND_LENGTH - 1)) {
    return 0;
  }

  stripped_buf = ast_strip(ast_strdupa(buf));

  /* HISTCONTROL=ignoredups */
  if (!history(el_hist, &ev, H_FIRST) && (strcmp(ev.str, stripped_buf) == 0)) {
    return 0;
  }

  return history(el_hist, &ev, H_ENTER, stripped_buf);
}

int ast_el_write_history(const char *filename) {
  HistEvent ev;

  if ((el_hist == NULL) || (el == NULL)) ast_el_initialize();

  return history(el_hist, &ev, H_SAVE, filename);
}

int ast_el_read_history(const char *filename) {
  HistEvent ev;

  if ((el_hist == NULL) || (el == NULL)) {
    ast_el_initialize();
  }

  return history(el_hist, &ev, H_LOAD, filename);
}

void ast_el_read_default_histfile(void) {
  char histfile[80] = "";
  const char *home = getenv("HOME");

  if (!ast_strlen_zero(home)) {
    snprintf(histfile, sizeof(histfile), "%s/.asterisk_history", home);
    ast_el_read_history(histfile);
  }
}

void ast_el_write_default_histfile(void) {
  char histfile[80] = "";
  const char *home = getenv("HOME");

  if (!ast_strlen_zero(home)) {
    snprintf(histfile, sizeof(histfile), "%s/.asterisk_history", home);
    ast_el_write_history(histfile);
  }
}

static int ast_el_initialize() {
  HistEvent ev;
  char *editor, *editrc = getenv("EDITRC");

  if (!(editor = getenv("AST_EDITMODE"))) {
    if (!(editor = getenv("AST_EDITOR"))) {
      editor = "emacs";
    }
  }

  if (el != NULL) el_end(el);

  if (el_hist != NULL) history_end(el_hist);

  el = el_init("asterisk", stdin, stdout, stderr);
  el_set(el, EL_PROMPT, prompt_handler);

  el_set(el, EL_EDITMODE, 1);
  el_set(el, EL_EDITOR, editor);
  el_hist = history_init();

  if (!el || !el_hist) return -1;

  /* setup history with 100 entries */
  history(el_hist, &ev, H_SETSIZE, 100);

  el_set(el, EL_HIST, history, el_hist);

  el_set(el, EL_ADDFN, "ed-complete", "Complete argument", complete_handler);

  /* Bind <tab> to command completion */
  el_set(el, EL_BIND, "^I", "ed-complete", NULL);

  /* Bind ? to command completion */
  el_set(el, EL_BIND, "?", "ed-complete", NULL);

  /* Bind ^D to redisplay */
  el_set(el, EL_BIND, "^D", "ed-redisplay", NULL);

  /* Bind Delete to delete char left */
  el_set(el, EL_BIND, "\\e[3~", "ed-delete-next-char", NULL);

  /* Bind Home and End to move to line start and end */
  el_set(el, EL_BIND, "\\e[1~", "ed-move-to-beg", NULL);
  el_set(el, EL_BIND, "\\e[4~", "ed-move-to-end", NULL);

  /* Bind C-left and C-right to move by word (not all terminals) */
  el_set(el, EL_BIND, "\\eOC", "vi-next-word", NULL);
  el_set(el, EL_BIND, "\\eOD", "vi-prev-word", NULL);

  if (editrc) {
    el_source(el, editrc);
  }

  return 0;
}

int ast_el_set_gchar_handler(getchar_handler getc) {
  el_set(el, EL_GETCFN, getc);
  return 0;
}

const char *ast_el_get_buf(int *num) { return (char *)el_gets(el, num); }

int ast_el_initialize_wrap(el_prompt prompt, el_complete complete) {
  if ((el_hist == NULL) || (el == NULL)) {
    prompt_handler = prompt;
    complete_handler = complete;
    ast_el_initialize();
  }

  return 0;
}

int ast_el_uninitialize(void) {
  if (el != NULL) {
    el_end(el);
  }

  if (el_hist != NULL) {
    history_end(el_hist);
  }
  return 0;
}
