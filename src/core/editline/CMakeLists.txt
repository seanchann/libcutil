# Copyright (c) 2006, 2013, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

INCLUDE_DIRECTORIES(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} )
INCLUDE(CheckIncludeFile)
include(CheckFunctionExists)
#CHECK_INCLUDE_FILES(term.h HAVE_TERM_H)
CHECK_INCLUDE_FILES(termcap.h HAVE_TERMCAP_H)

SET(CMAKE_REQUIRED_LIBRARIES ${CURSES_LIBRARY})
CHECK_CXX_SOURCE_COMPILES("
#include <term.h>
int main()
{
  tgoto(0,0,0);
  return 0;
}" HAVE_DECL_TGOTO)
IF(NOT HAVE_DECL_TGOTO)
  # On Solaris 11, term.h is broken, curses.h is also required.
  CHECK_CXX_SOURCE_COMPILES("
  #include <curses.h>
  #include <term.h>
  int main()
  {
    tgoto(0,0,0);
    return 0;
  }" HAVE_DECL_TGOTO2)
  IF(HAVE_DECL_TGOTO2)
    SET(HAVE_DECL_TGOTO 1 CACHE INTERNAL "" FORCE)
  ENDIF()
ENDIF()

SET(CMAKE_REQUIRED_LIBRARIES)



IF(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  #On Solaris, default awk is next to unusable while the xpg4 one is ok.
  IF(EXISTS /usr/xpg4/bin/awk)
    SET(AWK_EXECUTABLE /usr/xpg4/bin/awk)
  ENDIF()
ELSEIF(CMAKE_SYSTEM_NAME STREQUAL "OS400")
  #Workaround for cases, where /usr/bin/gawk is not executable
  IF(EXISTS /QOpenSys/usr/bin/awk)
    SET(AWK_EXECUTABLE /QOpenSys/usr/bin/awk)
  ENDIF()
ENDIF()

IF(NOT AWK_EXECUTABLE)
  FIND_PROGRAM(AWK_EXECUTABLE NAMES gawk awk DOC "path to the awk executable")
ENDIF()

MARK_AS_ADVANCED(AWK_EXECUTABLE)
SET(AWK ${AWK_EXECUTABLE})
CONFIGURE_FILE(makelist.sh ${CMAKE_CURRENT_BINARY_DIR}/makelist @ONLY)

include(CheckIncludeFile)

CHECK_INCLUDE_FILE(vis.h HAVE_VIS_H)
IF(HAVE_VIS_H)
  CHECK_FUNCTION_EXISTS(strvis HAVE_STRVIS)
  IF(NOT HAVE_STRVIS)
   SET(HAVE_VIS_H FALSE CACHE INTERNAL "" FORCE)
  ENDIF()
ENDIF()


CHECK_FUNCTION_EXISTS(strvis HAVE_STRVIS)
IF(NOT HAVE_STRVIS)
  SET(LIBEDIT_EXTRA_SOURCES ${LIBEDIT_EXTRA_SOURCES}  np/vis.c)
ENDIF()

CHECK_FUNCTION_EXISTS(strunvis HAVE_STRUNVIS)
IF(NOT HAVE_STRUNVIS)
  SET(LIBEDIT_EXTRA_SOURCES ${LIBEDIT_EXTRA_SOURCES} np/unvis.c)
ENDIF()

CHECK_FUNCTION_EXISTS(strlcpy HAVE_STRLCPY)
IF(NOT HAVE_STRLCPY)
  SET(LIBEDIT_EXTRA_SOURCES ${LIBEDIT_EXTRA_SOURCES} np/strlcpy.c)
ENDIF()

CHECK_FUNCTION_EXISTS(strlcat HAVE_STRLCAT)
IF(NOT HAVE_STRLCAT)
  SET(LIBEDIT_EXTRA_SOURCES ${LIBEDIT_EXTRA_SOURCES} np/strlcat.c)
ENDIF()

CHECK_FUNCTION_EXISTS(fgetln HAVE_FGETLN)
IF(NOT HAVE_FGETLN)
  SET(LIBEDIT_EXTRA_SOURCES ${LIBEDIT_EXTRA_SOURCES} np/fgetln.c)
ENDIF()

#CHECK_FUNCTION_EXISTS(fgetln HAVE_WCSDUP)
#IF(NOT HAVE_WCSDUP)
#  SET(LIBEDIT_EXTRA_SOURCES ${LIBEDIT_EXTRA_SOURCES} np/wcsdup.c)
#ENDIF()


#/bin/sh makelist -h common.c > common.h
#/bin/sh makelist -h emacs.c> emacs.h
#/bin/sh makelist -h vi.c > vi.h
#/bin/sh makelist -fh common.h emacs.h vi.h > fcns.h
#/bin/sh makelist -fc common.h emacs.h vi.h > fcns.c
#if uname -s | grep -i cygwin > /dev/null; then cat fcns.c | sed -e s/"sys\.h"/"config.h"/g > fcns.c.copy; mv --force fcns.c.copy fcns.c; fi
#/bin/sh makelist -bh common.c emacs.c vi.c > help.h
#/bin/sh makelist -bc common.c emacs.c vi.c > help.c
#if uname -s | grep -i cygwin > /dev/null; then cat help.c | sed -e s/"sys\.h"/"config.h"/g > help.c.copy; mv --force help.c.copy help.c; fi

# Generate headers
FOREACH(SRCBASENAME  vi emacs common)
  SET(SRC ${CMAKE_CURRENT_SOURCE_DIR}/${SRCBASENAME}.c)
  SET(HDR ${CMAKE_CURRENT_BINARY_DIR}/${SRCBASENAME}.h)

  ADD_CUSTOM_COMMAND(
    OUTPUT ${HDR}
    COMMAND sh ./makelist -h ${SRC} > ${HDR}
    DEPENDS ${SRC})

  SET(AHDR ${AHDR} ${HDR})
  SET(ASRC ${ASRC} ${SRC})
ENDFOREACH()

# Generate source files
ADD_CUSTOM_COMMAND(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/help.c
  COMMAND sh ./makelist -bc ${ASRC} > help.c
  DEPENDS ${ASRC}
)

ADD_CUSTOM_COMMAND(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/help.h
  COMMAND sh ./makelist -bh ${ASRC} > help.h
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${ASRC}
)

ADD_CUSTOM_COMMAND(
  OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/fcns.h
  COMMAND sh ./makelist -fh ${AHDR} > fcns.h
  VERBATIM
  DEPENDS ${AHDR}
)

ADD_CUSTOM_COMMAND(
  OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/fcns.c
  COMMAND sh ./makelist -fc ${AHDR} > fcns.c
  VERBATIM
  DEPENDS ${AHDR}
)


# SET(EDITLINE_SRC
#   common.c
#   emacs.c
#   vi.c
#   chared.c
#   el.c
#   hist.c
#   key.c
#   map.c
#   parse.c
#   prompt.c
#   read.c
#   refresh.c
#   search.c
#   sig.c
#   term.c
#   tty.c
#   ${CMAKE_CURRENT_BINARY_DIR}/fcns.c
#   ${CMAKE_CURRENT_BINARY_DIR}/help.c
# )

SET(EDITLINE_SRC
  common.c
)


ADD_CUSTOM_COMMAND(
  OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/editline.c
  COMMAND sh ./makelist -e ${EDITLINE_SRC} > editline.c
  VERBATIM
  DEPENDS ${AHDR}
)


CONFIGURE_FILE(config.h.cmakein ${CMAKE_CURRENT_BINARY_DIR}/config.h @ONLY)

INCLUDE_DIRECTORIES(
${CMAKE_SOURCE_DIR}/include
${CMAKE_CURRENT_BINARY_DIR}
${CURSES_INCLUDE_PATH}
)


SET(LIBEDIT_SOURCES
 ${CMAKE_CURRENT_BINARY_DIR}/editline.c
 #common.c
 history.c
 map.c
 prompt.c
 readline.c
 search.c
 tokenizer.c
 vi.c
 common.c
 emacs.c
 hist.c
 refresh.c
 sig.c
 tty.c
 key.c
 el.c
 chared.c
 parse.c
 emacs.c
 term.c
 read.c
 ${CMAKE_CURRENT_BINARY_DIR}/help.c
 ${CMAKE_CURRENT_BINARY_DIR}/help.h
 ${CMAKE_CURRENT_BINARY_DIR}/fcns.c
 ${CMAKE_CURRENT_BINARY_DIR}/fcns.h
 ${AHDR}
 ${LIBEDIT_EXTRA_SOURCES}
)
#history.o_a tokenizer.o_a readline.o_a
# SET(LIBEDIT_SOURCES
#  ${CMAKE_CURRENT_BINARY_DIR}/editline.c
#  history.c
#  readline.c
#  tokenizer.c
#  ${CMAKE_CURRENT_BINARY_DIR}/help.c
#  ${CMAKE_CURRENT_BINARY_DIR}/help.h
#  ${CMAKE_CURRENT_BINARY_DIR}/fcns.c
#  ${CMAKE_CURRENT_BINARY_DIR}/fcns.h
#  ${AHDR}
#  ${LIBEDIT_EXTRA_SOURCES}
# )

ADD_CONVENIENCE_LIBRARY(edit ${LIBEDIT_SOURCES})
target_compile_options(edit PUBLIC  "-fPIC"  "-Wno-error=unused-but-set-variable" "-D__RCSID(x)=" "-D__COPYRIGHT(x)=" "-D__RENAME(x)=" "-D_DIAGASSERT(x)=")
TARGET_LINK_LIBRARIES(edit ${CURSES_LIBRARY})
