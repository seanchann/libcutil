/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2008, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 * Kevin P. Fleming <kpfleming@digium.com>
 * Luigi Rizzo <rizzo@icir.org>
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
 * \brief Asterisk module definitions.
 *
 * This file contains the definitons for functions Asterisk modules should
 * provide and some other module related functions.
 */

/*! \li \ref module.h uses the configuration file \ref modules.conf
 * \addtogroup configuration_file
 */

/*! \page modules.conf modules.conf
 * \verbinclude modules.conf.sample
 */

#ifndef _ASTERISK_MODULE_H
#define _ASTERISK_MODULE_H


#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif


struct ast_module *__ast_module_ref(struct ast_module *mod, const char *file, int line, const char *func)
{
	return NULL;

}

void __ast_module_shutdown_ref(struct ast_module *mod, const char *file, int line, const char *func)
{
  return;
}

void __ast_module_unref(struct ast_module *mod, const char *file, int line, const char *func)
{
  return
}


/*!
 * \brief Hold a reference to the module
 * \param mod Module to reference
 * \return mod
 *
 * \note A module reference will prevent the module
 * from being unloaded.
 */
#define ast_module_ref(mod)           __ast_module_ref(mod, __FILE__, __LINE__, __PRETTY_FUNCTION__)
/*!
 * \brief Prevent unload of the module before shutdown
 * \param mod Module to hold
 *
 * \note This should not be balanced by a call to ast_module_unref.
 */
#define ast_module_shutdown_ref(mod)  __ast_module_shutdown_ref(mod, __FILE__, __LINE__, __PRETTY_FUNCTION__)
/*!
 * \brief Release a reference to the module
 * \param mod Module to release
 */
#define ast_module_unref(mod)         __ast_module_unref(mod, __FILE__, __LINE__, __PRETTY_FUNCTION__)




#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* _ASTERISK_MODULE_H */
