/*
* Copyright (C) 2016 - 2017, JYD, Inc.
*
* seanchann <xqzhou@bj-jyd.cn>
*
* See docs/ for more information about
* the  project.
*
* This program belongs to JYD, Inc. JYD, Inc reserves all rights
*/

#ifndef _CUTIL_DB_H
#define _CUTIL_DB_H

#include <sqlite3.h>
#include <pthread.h>

#include "libcutil/lock.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

struct kvdb {
  char *dbfile;

  cutil_mutex_t dblock;
  cutil_cond_t dbcond;
  sqlite3 *db;
  pthread_t syncthread;
  int doexit;
  int dosync;
};
struct kvdb *kvdb_new(char *file);
void kvdb_free(struct kvdb *handle);

struct cutil_db_entry {
  struct ast_db_entry *next;
  char *key;
  char data[0];
};

/*! \brief Get key value specified by family/key */
int cutil_db_get(struct kvdb *handle, const char *family, const char *key,
                 char *value, int valuelen);

/*!
 * \brief Get key value specified by family/key as a heap allocated string.
 *
 * \details
 * Given a \a family and \a key, sets \a out to a pointer to a heap
 * allocated string.  In the event of an error, \a out will be set to
 * NULL.  The string must be freed by calling ast_free().
 *
 * \retval -1 An error occurred
 * \retval 0 Success
 */
int cutil_db_get_allocated(struct kvdb *handle, const char *family,
                           const char *key, char **out);

/*! \brief Store value addressed by family/key */
int cutil_db_put(const char *family, const char *key, const char *value);

/*! \brief Delete entry in kvdb */
int cutil_db_del(struct kvdb *handle, const char *family, const char *key);

/*!
 * \brief Delete one or more entries in kvdb
 *
 * \details
 * If both parameters are NULL, the entire database will be purged.  If
 * only keytree is NULL, all entries within the family will be purged.
 * It is an error for keytree to have a value when family is NULL.
 *
 * \retval -1 An error occurred
 * \retval >= 0 Number of records deleted
 */
int cutil_db_deltree(struct kvdb *handle, const char *family,
                     const char *keytree);

/*!
 * \brief Get a list of values within in kvdb tree
 *
 * \details
 * If family is specified, only those keys will be returned.  If keytree
 * is specified, subkeys are expected to exist (separated from the key with
 * a slash).  If subkeys do not exist and keytree is specified, the tree will
 * consist of either a single entry or NULL will be returned.
 *
 * Resulting tree should be freed by passing the return value to
 * cutil_db_freetree()
 * when usage is concluded.
 */
struct cutil_db_entry *cutil_db_gettree(struct kvdb *handle, const char *family,
                                        const char *keytree);

/*! \brief Free structure created by cutil_db_gettree() */
void cutil_db_freetree(struct cutil_db_entry *entry);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _CUTIL_DB_H */
