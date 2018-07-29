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

#ifndef __CUTIL_VERSION_H
#define __CUTIL_VERSION_H

/*!
 * \brief Retrieve the libcutil version string.
 */
const char *cutil_get_version(void);

/*!
 * \brief Retrieve the numeric libcutil version
 *
 * Format ABBCC
 * AABB - Major version (1.4 would be 104)
 * CC - Minor version
 */
const char *cutil_get_version_num(void);

/*! Retreive the libcutil build options */
const char *cutil_get_build_opts(void);

#endif /* __CUTIL_VERSION_H */
