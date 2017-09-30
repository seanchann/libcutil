/*
* Copyright (C) 2016
*
* seanchann <xqzhou@bj-jyd.cn>
*
* See docs/ for more information about
* the  project.
*
* This program belongs to JYD, Inc. JYD, Inc reserves all rights
*/

#include "libcutil.h"

#include "libcutil/_private.h"
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>

#include "libcutil/kvdb.h"
#include "libcutil/cli.h"
#include "libcutil/utils.h"

#define MAX_DB_FIELD 256

static void db_sync(struct kvdb *handle);

#define DEFINE_SQL_STATEMENT(stmt, sql) \
  static sqlite3_stmt *stmt;            \
  const char stmt##_sql[] = sql;

DEFINE_SQL_STATEMENT(put_stmt,
                     "INSERT OR REPLACE INTO astdb (key, value) VALUES (?, ?)")
DEFINE_SQL_STATEMENT(get_stmt, "SELECT value FROM astdb WHERE key=?")
DEFINE_SQL_STATEMENT(del_stmt, "DELETE FROM astdb WHERE key=?")
DEFINE_SQL_STATEMENT(deltree_stmt,
                     "DELETE FROM astdb WHERE key || '/' LIKE ? || '/' || '%'")
DEFINE_SQL_STATEMENT(deltree_all_stmt, "DELETE FROM astdb")
DEFINE_SQL_STATEMENT(gettree_stmt,
                     "SELECT key, value FROM astdb WHERE key || '/' LIKE ? || "
                     "'/' || '%' ORDER BY key")
DEFINE_SQL_STATEMENT(gettree_all_stmt,
                     "SELECT key, value FROM astdb ORDER BY key")
DEFINE_SQL_STATEMENT(
    showkey_stmt,
    "SELECT key, value FROM astdb WHERE key LIKE '%' || '/' || ? ORDER BY key")
DEFINE_SQL_STATEMENT(create_astdb_stmt,
                     "CREATE TABLE IF NOT EXISTS astdb(key VARCHAR(256), value "
                     "VARCHAR(256), PRIMARY KEY(key))")

static int init_stmt(struct kvdb *handle, sqlite3_stmt **stmt, const char *sql,
                     size_t len) {
  ast_mutex_lock(&handle->dblock);
  if (sqlite3_prepare(handle->db, sql, len, stmt, NULL) != SQLITE_OK) {
    ast_log(LOG_WARNING, "Couldn't prepare statement '%s': %s\n", sql,
            sqlite3_errmsg(handle->db));
    ast_mutex_unlock(&handle->dblock);
    return -1;
  }
  ast_mutex_unlock(&handle->dblock);

  return 0;
}

/*! \internal
 * \brief Clean up the prepared SQLite3 statement
 * \note dblock should already be locked prior to calling this method
 */
static int clean_stmt(struct kvdb *handle, sqlite3_stmt **stmt,
                      const char *sql) {
  if (sqlite3_finalize(*stmt) != SQLITE_OK) {
    ast_log(LOG_WARNING, "Couldn't finalize statement '%s': %s\n", sql,
            sqlite3_errmsg(handle->db));
    *stmt = NULL;
    return -1;
  }
  *stmt = NULL;
  return 0;
}

/*! \internal
 * \brief Clean up all prepared SQLite3 statements
 * \note dblock should already be locked prior to calling this method
 */
static void clean_statements(struct kvdb *handle) {
  clean_stmt(handle, &get_stmt, get_stmt_sql);
  clean_stmt(handle, &del_stmt, del_stmt_sql);
  clean_stmt(handle, &deltree_stmt, deltree_stmt_sql);
  clean_stmt(handle, &deltree_all_stmt, deltree_all_stmt_sql);
  clean_stmt(handle, &gettree_stmt, gettree_stmt_sql);
  clean_stmt(handle, &gettree_all_stmt, gettree_all_stmt_sql);
  clean_stmt(handle, &showkey_stmt, showkey_stmt_sql);
  clean_stmt(handle, &put_stmt, put_stmt_sql);
  clean_stmt(handle, &create_astdb_stmt, create_astdb_stmt_sql);
}

static int init_statements(struct kvdb *handle) {
  /* Don't initialize create_astdb_statment here as the astdb table needs to
   * exist
   * brefore these statments can be initialized */
  return init_stmt(handle, &get_stmt, get_stmt_sql, sizeof(get_stmt_sql)) ||
         init_stmt(handle, &del_stmt, del_stmt_sql, sizeof(del_stmt_sql)) ||
         init_stmt(handle, &deltree_stmt, deltree_stmt_sql,
                   sizeof(deltree_stmt_sql)) ||
         init_stmt(handle, &deltree_all_stmt, deltree_all_stmt_sql,
                   sizeof(deltree_all_stmt_sql)) ||
         init_stmt(handle, &gettree_stmt, gettree_stmt_sql,
                   sizeof(gettree_stmt_sql)) ||
         init_stmt(handle, &gettree_all_stmt, gettree_all_stmt_sql,
                   sizeof(gettree_all_stmt_sql)) ||
         init_stmt(handle, &showkey_stmt, showkey_stmt_sql,
                   sizeof(showkey_stmt_sql)) ||
         init_stmt(handle, &put_stmt, put_stmt_sql, sizeof(put_stmt_sql));
}

static int db_create_astdb(struct kvdb *handle) {
  int res = 0;

  if (!create_astdb_stmt) {
    init_stmt(handle, &create_astdb_stmt, create_astdb_stmt_sql,
              sizeof(create_astdb_stmt_sql));
  }

  ast_mutex_lock(&handle->dblock);
  if (sqlite3_step(create_astdb_stmt) != SQLITE_DONE) {
    ast_log(LOG_WARNING, "Couldn't create astdb table: %s\n",
            sqlite3_errmsg(handle->db));
    res = -1;
  }
  sqlite3_reset(create_astdb_stmt);
  db_sync(handle);
  ast_mutex_unlock(&handle->dblock);

  return res;
}

static int db_open(struct kvdb *handle) {
  char *dbname;
  struct stat dont_care;

  dbname = handle->dbfile;
  ast_mutex_lock(&handle->dblock);
  if (sqlite3_open(dbname, &handle->db) != SQLITE_OK) {
    ast_log(LOG_WARNING, "Unable to open Asterisk database '%s': %s\n", dbname,
            sqlite3_errmsg(handle->db));
    sqlite3_close(handle->db);
    ast_mutex_unlock(&handle->dblock);
    return -1;
  }

  ast_mutex_unlock(&handle->dblock);

  return 0;
}

static int db_init(struct kvdb *handle) {
  if (handle->db) {
    return 0;
  }

  if (db_open(handle) || db_create_astdb(handle) || init_statements(handle)) {
    return -1;
  }

  return 0;
}

/* We purposely don't lock around the sqlite3 call because the transaction
 * calls will be called with the database lock held. For any other use, make
 * sure to take the dblock yourself. */
static int db_execute_sql(struct kvdb *handle, const char *sql,
                          int (*callback)(void *, int, char **, char **),
                          void *arg) {
  char *errmsg = NULL;
  int res = 0;

  if (sqlite3_exec(handle->db, sql, callback, arg, &errmsg) != SQLITE_OK) {
    ast_log(LOG_WARNING, "Error executing SQL (%s): %s\n", sql, errmsg);
    sqlite3_free(errmsg);
    res = -1;
  }

  return res;
}

static int ast_db_begin_transaction(struct kvdb *handle) {
  return db_execute_sql(handle, "BEGIN TRANSACTION", NULL, NULL);
}

static int ast_db_commit_transaction(struct kvdb *handle) {
  return db_execute_sql(handle, "COMMIT", NULL, NULL);
}

static int ast_db_rollback_transaction(struct kvdb *handle) {
  return db_execute_sql(handle, "ROLLBACK", NULL, NULL);
}

int ast_db_put(struct kvdb *handle, const char *family, const char *key,
               const char *value) {
  char fullkey[MAX_DB_FIELD];
  size_t fullkey_len;
  int res = 0;

  if (strlen(family) + strlen(key) + 2 > sizeof(fullkey) - 1) {
    ast_log(LOG_WARNING, "Family and key length must be less than %zu bytes\n",
            sizeof(fullkey) - 3);
    return -1;
  }

  fullkey_len = snprintf(fullkey, sizeof(fullkey), "/%s/%s", family, key);

  ast_mutex_lock(&handle->dblock);
  if (sqlite3_bind_text(put_stmt, 1, fullkey, fullkey_len, SQLITE_STATIC) !=
      SQLITE_OK) {
    ast_log(LOG_WARNING, "Couldn't bind key to stmt: %s\n",
            sqlite3_errmsg(handle->db));
    res = -1;
  } else if (sqlite3_bind_text(put_stmt, 2, value, -1, SQLITE_STATIC) !=
             SQLITE_OK) {
    ast_log(LOG_WARNING, "Couldn't bind value to stmt: %s\n",
            sqlite3_errmsg(handle->db));
    res = -1;
  } else if (sqlite3_step(put_stmt) != SQLITE_DONE) {
    ast_log(LOG_WARNING, "Couldn't execute statment: %s\n",
            sqlite3_errmsg(handle->db));
    res = -1;
  }

  sqlite3_reset(put_stmt);
  db_sync(handle);
  ast_mutex_unlock(&handle->dblock);

  return res;
}

/*!
 * \internal
 * \brief Get key value specified by family/key.
 *
 * Gets the value associated with the specified \a family and \a key, and
 * stores it, either into the fixed sized buffer specified by \a buffer
 * and \a bufferlen, or as a heap allocated string if \a bufferlen is -1.
 *
 * \note If \a bufferlen is -1, \a buffer points to heap allocated memory
 *       and must be freed by calling ast_free().
 *
 * \retval -1 An error occurred
 * \retval 0 Success
 */
static int db_get_common(struct kvdb *handle, const char *family,
                         const char *key, char **buffer, int bufferlen) {
  const unsigned char *result;
  char fullkey[MAX_DB_FIELD];
  size_t fullkey_len;
  int res = 0;

  if (strlen(family) + strlen(key) + 2 > sizeof(fullkey) - 1) {
    cutil_log(LOG_WARNING,
              "Family and key length must be less than %zu bytes\n",
              sizeof(fullkey) - 3);
    return -1;
  }

  fullkey_len = snprintf(fullkey, sizeof(fullkey), "/%s/%s", family, key);

  ast_mutex_lock(&handle->dblock);
  if (sqlite3_bind_text(get_stmt, 1, fullkey, fullkey_len, SQLITE_STATIC) !=
      SQLITE_OK) {
    cutil_log(LOG_WARNING, "Couldn't bind key to stmt: %s\n",
              sqlite3_errmsg(handle->db));
    res = -1;
  } else if (sqlite3_step(get_stmt) != SQLITE_ROW) {
    cutil_debug(1, "Unable to find key '%s' in family '%s'\n", key, family);
    res = -1;
  } else if (!(result = sqlite3_column_text(get_stmt, 0))) {
    cutil_log(LOG_WARNING, "Couldn't get value\n");
    res = -1;
  } else {
    const char *value = (const char *)result;

    if (bufferlen == -1) {
      *buffer = ast_strdup(value);
    } else {
      ast_copy_string(*buffer, value, bufferlen);
    }
  }
  sqlite3_reset(get_stmt);
  ast_mutex_unlock(&handle->dblock);

  return res;
}

int cutil_db_get(struct kvdb *handle, const char *family, const char *key,
                 char *value, int valuelen) {
  ast_assert(value != NULL);

  /* Make sure we initialize */
  value[0] = 0;

  return db_get_common(handle, family, key, &value, valuelen);
}

int cutil_db_get_allocated(struct kvdb *handle, const char *family,
                           const char *key, char **out) {
  *out = NULL;

  return db_get_common(handle, family, key, out, -1);
}

int cutil_db_del(struct kvdb *handle, const char *family, const char *key) {
  char fullkey[MAX_DB_FIELD];
  size_t fullkey_len;
  int res = 0;

  if (strlen(family) + strlen(key) + 2 > sizeof(fullkey) - 1) {
    ast_log(LOG_WARNING, "Family and key length must be less than %zu bytes\n",
            sizeof(fullkey) - 3);
    return -1;
  }

  fullkey_len = snprintf(fullkey, sizeof(fullkey), "/%s/%s", family, key);

  ast_mutex_lock(&handle->dblock);
  if (sqlite3_bind_text(del_stmt, 1, fullkey, fullkey_len, SQLITE_STATIC) !=
      SQLITE_OK) {
    ast_log(LOG_WARNING, "Couldn't bind key to stmt: %s\n",
            sqlite3_errmsg(handle->db));
    res = -1;
  } else if (sqlite3_step(del_stmt) != SQLITE_DONE) {
    ast_debug(1, "Unable to find key '%s' in family '%s'\n", key, family);
    res = -1;
  }
  sqlite3_reset(del_stmt);
  db_sync(handle);
  ast_mutex_unlock(&handle->dblock);

  return res;
}

int cutil_db_deltree(struct kvdb *handle, const char *family,
                     const char *keytree) {
  sqlite3_stmt *stmt = deltree_stmt;
  char prefix[MAX_DB_FIELD];
  int res = 0;

  if (!ast_strlen_zero(family)) {
    if (!ast_strlen_zero(keytree)) {
      /* Family and key tree */
      snprintf(prefix, sizeof(prefix), "/%s/%s", family, keytree);
    } else {
      /* Family only */
      snprintf(prefix, sizeof(prefix), "/%s", family);
    }
  } else {
    prefix[0] = '\0';
    stmt = deltree_all_stmt;
  }

  ast_mutex_lock(&handle->dblock);
  if (!ast_strlen_zero(prefix) &&
      (sqlite3_bind_text(stmt, 1, prefix, -1, SQLITE_STATIC) != SQLITE_OK)) {
    ast_log(LOG_WARNING, "Could bind %s to stmt: %s\n", prefix,
            sqlite3_errmsg(handle->db));
    res = -1;
  } else if (sqlite3_step(stmt) != SQLITE_DONE) {
    ast_log(LOG_WARNING, "Couldn't execute stmt: %s\n",
            sqlite3_errmsg(handle->db));
    res = -1;
  }
  res = sqlite3_changes(handle->db);
  sqlite3_reset(stmt);
  db_sync(handle);
  ast_mutex_unlock(&handle->dblock);

  return res;
}

struct cutil_db_entry *cutil_db_gettree(struct kvdb *handle, const char *family,
                                        const char *keytree) {
  char prefix[MAX_DB_FIELD];
  sqlite3_stmt *stmt = gettree_stmt;
  struct cutil_db_entry *cur, *last = NULL, *ret = NULL;

  if (!ast_strlen_zero(family)) {
    if (!ast_strlen_zero(keytree)) {
      /* Family and key tree */
      snprintf(prefix, sizeof(prefix), "/%s/%s", family, keytree);
    } else {
      /* Family only */
      snprintf(prefix, sizeof(prefix), "/%s", family);
    }
  } else {
    prefix[0] = '\0';
    stmt = gettree_all_stmt;
  }

  ast_mutex_lock(&handle->dblock);
  if (!ast_strlen_zero(prefix) &&
      (sqlite3_bind_text(stmt, 1, prefix, -1, SQLITE_STATIC) != SQLITE_OK)) {
    ast_log(LOG_WARNING, "Could bind %s to stmt: %s\n", prefix,
            sqlite3_errmsg(handle->db));
    sqlite3_reset(stmt);
    ast_mutex_unlock(&handle->dblock);
    return NULL;
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *key_s, *value_s;
    if (!(key_s = (const char *)sqlite3_column_text(stmt, 0))) {
      break;
    }
    if (!(value_s = (const char *)sqlite3_column_text(stmt, 1))) {
      break;
    }
    if (!(cur =
              ast_malloc(sizeof(*cur) + strlen(key_s) + strlen(value_s) + 2))) {
      break;
    }
    cur->next = NULL;
    cur->key = cur->data + strlen(value_s) + 1;
    strcpy(cur->data, value_s);
    strcpy(cur->key, key_s);
    if (last) {
      last->next = cur;
    } else {
      ret = cur;
    }
    last = cur;
  }
  sqlite3_reset(stmt);
  ast_mutex_unlock(&handle->dblock);

  return ret;
}

void cutil_db_freetree(struct cutil_db_entry *dbe) {
  struct cutil_db_entry *last;
  while (dbe) {
    last = dbe;
    dbe = dbe->next;
    ast_free(last);
  }
}

/*!
 * \internal
 * \brief Signal the astdb sync thread to do its thing.
 *
 * \note dblock is assumed to be held when calling this function.
 */
static void db_sync(struct kvdb *handle) {
  handle->dosync = 1;
  ast_cond_signal(&handle->dbcond);
}

/*!
 * \internal
 * \brief astdb sync thread
 *
 * This thread is in charge of syncing astdb to disk after a change.
 * By pushing it off to this thread to take care of, this I/O bound operation
 * will not block other threads from performing other critical processing.
 * If changes happen rapidly, this thread will also ensure that the sync
 * operations are rate limited.
 */
static void *db_sync_thread(void *data) {
  struct kvdb *handle = (struct kvdb *)data;
  ast_mutex_lock(&handle->dblock);
  ast_db_begin_transaction(handle);
  for (;;) {
    /* If dosync is set, db_sync() was called during sleep(1),
     * and the pending transaction should be committed.
     * Otherwise, block until db_sync() is called.
     */
    while (!handle->dosync) {
      ast_cond_wait(&handle->dbcond, &handle->dblock);
    }
    handle->dosync = 0;
    if (ast_db_commit_transaction(handle)) {
      ast_db_rollback_transaction(handle);
    }
    if (handle->doexit) {
      ast_mutex_unlock(&handle->dblock);
      break;
    }
    ast_db_begin_transaction(handle);
    ast_mutex_unlock(&handle->dblock);
    sleep(1);
    ast_mutex_lock(&handle->dblock);
  }

  return NULL;
}

/*!
 * \internal
 * \brief Clean up resources on main program shutdown
 */
void cutil_kvdb_free(struct kvdb *handle) {
  /* Set doexit to 1 to kill thread. db_sync must be called with
   * mutex held. */
  ast_mutex_lock(&handle->dblock);
  handle->doexit = 1;
  db_sync(handle);
  ast_mutex_unlock(&handle->dblock);

  pthread_join(handle->syncthread, NULL);
  ast_mutex_lock(&handle->dblock);
  clean_statements(handle);
  if (sqlite3_close(handle->db) == SQLITE_OK) {
    handle->db = NULL;
  }
  ast_mutex_unlock(&handle->dblock);

  ast_mutex_destroy(&handle->dblock);
}

struct kvdb *cutil_kvdb_new(char *file) {
  struct kvdb *kv_handle = cutil_calloc(1, sizeof(struct kvdb));
  size_t len = strlen(file);

  kv_handle->dbfile = cutil_calloc(len, sizeof(char));
  snprintf(kv_handle->dbfile, len, "%s.sqlite3", file);

  if (db_init(kv_handle)) {
    cutil_free(kv_handle);
    return NULL;
  }

  ast_cond_init(&kv_handle->dbcond, NULL);
  if (ast_pthread_create_background(&kv_handle->syncthread, NULL,
                                    db_sync_thread, (void *)kv_handle)) {
    cutil_free(kv_handle);
    return NULL;
  }

  return kv_handle;
}
