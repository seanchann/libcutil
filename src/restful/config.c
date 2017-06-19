/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Digium, Inc.
 *
 * David M. Lee, II <dlee@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Config framework stuffz for ARI.
 * \author David M. Lee, II <dlee@digium.com>
 */

#include "libcutil.h"


// #include "libcutil/config_options.h"
#include "libcutil/http_websocket.h"
#include "libcutil/restful.h"
#include "internal.h"


/*! \brief Locking container for safe configuration access. */
static AO2_GLOBAL_OBJ_STATIC(confs);


/*! \brief Destructor for \ref ast_ari_conf_user */
static void user_dtor(void *obj)
{
  struct ast_ari_conf_user *user = obj;

  ast_debug(3, "Disposing of user %s\n", user->username);
  ast_free(user->username);
}

/*! \brief Allocate an \ref ast_ari_conf_user for config parsing */
static void* user_alloc(const char *cat)
{
  RAII_VAR(struct ast_ari_conf_user *, user, NULL, ao2_cleanup);

  if (!cat) {
    return NULL;
  }

  ast_debug(3, "Allocating user %s\n", cat);

  user = ao2_alloc_options(sizeof(*user), user_dtor,
                           AO2_ALLOC_OPT_LOCK_NOLOCK);

  if (!user) {
    return NULL;
  }

  user->username = ast_strdup(cat);

  if (!user->username) {
    return NULL;
  }

  ao2_ref(user, +1);
  return user;
}

/*! \brief Sorting function for use with red/black tree */
static int user_sort_cmp(const void *obj_left, const void *obj_right, int flags)
{
  const struct ast_ari_conf_user *user_left  = obj_left;
  const struct ast_ari_conf_user *user_right = obj_right;
  const char *key_right                      = obj_right;
  int cmp;

  switch (flags & OBJ_SEARCH_MASK) {
  case OBJ_SEARCH_OBJECT:
    key_right = user_right->username;

  /* Fall through */
  case OBJ_SEARCH_KEY:
    cmp = strcasecmp(user_left->username, key_right);
    break;

  case OBJ_SEARCH_PARTIAL_KEY:

    /*
     * We could also use a partial key struct containing a length
     * so strlen() does not get called for every comparison instead.
     */
    cmp = strncasecmp(user_left->username, key_right, strlen(key_right));
    break;

  default:

    /* Sort can only work on something with a full or partial key. */
    ast_assert(0);
    cmp = 0;
    break;
  }
  return cmp;
}

/*! \brief \ref aco_type item_find function */
static void* user_find(struct ao2_container *tmp_container, const char *cat)
{
  if (!cat) {
    return NULL;
  }

  return ao2_find(tmp_container, cat, OBJ_SEARCH_KEY);
}

static void conf_general_dtor(void *obj)
{
  struct ast_ari_conf_general *general = obj;

  ast_string_field_free_memory(general);
}

/*! \brief \ref ast_ari_conf destructor. */
static void conf_destructor(void *obj)
{
  struct ast_ari_conf *cfg = obj;

  ao2_cleanup(cfg->general);
  ao2_cleanup(cfg->users);
}

/*! \brief Allocate an \ref ast_ari_conf for config parsing */
static void* conf_alloc(void)
{
  struct ast_ari_conf *cfg;

  cfg = ao2_alloc_options(sizeof(*cfg), conf_destructor,
                          AO2_ALLOC_OPT_LOCK_NOLOCK);

  if (!cfg) {
    return NULL;
  }

  cfg->general = ao2_alloc_options(sizeof(*cfg->general), conf_general_dtor,
                                   AO2_ALLOC_OPT_LOCK_NOLOCK);

  cfg->users = ao2_container_alloc_rbtree(AO2_ALLOC_OPT_LOCK_NOLOCK,
                                          AO2_CONTAINER_ALLOC_OPT_DUPS_REPLACE,
                                          user_sort_cmp,
                                          NULL);

  if (!cfg->users
      || !cfg->general
      || ast_string_field_init(cfg->general, 64)) {
    ao2_ref(cfg, -1);
    return NULL;
  }

  return cfg;
}

struct ast_ari_conf* ast_ari_config_get(void)
{
  struct ast_ari_conf *res = ao2_global_obj_ref(confs);

  if (!res) {
    ast_log(LOG_ERROR,
            "Error obtaining config. no configuration.\n");
  }
  return res;
}

struct ast_ari_conf_user* ast_ari_config_validate_user(const char *username,
                                                       const char *password)
{
  RAII_VAR(struct ast_ari_conf *,      conf, NULL, ao2_cleanup);
  RAII_VAR(struct ast_ari_conf_user *, user, NULL, ao2_cleanup);
  int is_valid = 0;

  conf = ast_ari_config_get();

  if (!conf) {
    return NULL;
  }

  user = ao2_find(conf->users, username, OBJ_SEARCH_KEY);

  if (!user) {
    cutil_log(LOG_NOTICE, "validate user. notfound\r\n");
    return NULL;
  }

  if (ast_strlen_zero(user->password)) {
    ast_log(LOG_WARNING,
            "User '%s' missing password; authentication failed\n",
            user->username);
    return NULL;
  }

  switch (user->password_format) {
  case ARI_PASSWORD_FORMAT_PLAIN:
    is_valid = strcmp(password, user->password) == 0;
    break;

  case ARI_PASSWORD_FORMAT_CRYPT:
    is_valid = ast_crypt_validate(password, user->password);
    break;
  }

  if (!is_valid) {
    return NULL;
  }

  ao2_ref(user, +1);
  return user;
}

/*! \brief Callback to validate a user object */
static int validate_user_cb(void *obj, void *arg, int flags)
{
  struct ast_ari_conf_user *user = obj;

  if (ast_strlen_zero(user->password)) {
    ast_log(LOG_WARNING, "User '%s' missing password\n",
            user->username);
  }

  return 0;
}

void cutil_restful_config_destroy(void)
{
  ao2_global_obj_release(confs);
}

int cutil_restful_config_init(struct ast_ari_conf_general *general,
                              struct ast_ari_conf_user    *user_list,
                              size_t                       user_list_len)
{
  struct ast_ari_conf *pending_conf = conf_alloc();
  int i                             = 0;
  struct ast_ari_conf_user *user    = NULL;

  if (!pending_conf) {
    cutil_log(LOG_ERROR, "alloc conf failed.\r\n");
    return -1;
  }

  pending_conf->general->enabled = general->enabled;

  if (!ast_strlen_zero(general->auth_realm)) {
    ast_copy_string(pending_conf->general->auth_realm,
                    general->auth_realm,
                    sizeof(pending_conf->general->auth_realm));
  }

  ast_string_fields_copy(pending_conf->general,
                         general);

  pending_conf->general->write_timeout = general->write_timeout;
  pending_conf->general->format        = general->format;


  for (i = 0; i < user_list_len; i++) {
    user = user_alloc(user_list[i].username);

    if (!user) {
      continue;
    }

    user->read_only = user_list[i].read_only;
    ast_copy_string(user->password,  user_list[i].password,
                    sizeof(user->password));
    user->password_format = user_list[i].password_format;
    ast_copy_string(user->resources, user_list[i].resources,
                    sizeof(user->resources));
    ao2_link(pending_conf->users, user);
  }

  if (pending_conf->general->enabled) {
    if (ao2_container_count(pending_conf->users) == 0) {
      ast_log(LOG_ERROR, "No configured users for ARI\n");
    } else {
      ao2_callback(pending_conf->users, OBJ_NODATA, validate_user_cb, NULL);
    }
  }

  ao2_global_obj_replace_unref(confs, pending_conf);


  return 0;
}
