cmake_minimum_required(VERSION 2.6)
project(libcutil)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/configure.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_tools.cmake)


option(BUILD_LIBCUTIL "build c utility library" ON)
option(ENABLE_HTTP "build http module" ON)
option(ENABLE_RESTFUL "build restful module" ON)
option(ENABLE_KVDB "support kvdb. dependence sqlite3" ON)
option(BUILD_TEST "build test binary" ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)
# Portions specific to cpprest binary versioning.
set (CUTIL_CORE_VERSION_MAJOR 1)
set (CUTIL_CORE_VERSION_MINOR 0)
set (CUTIL_CORE_VERSION_REVISION 0)
set (CUTIL_CORE_VERSION ${CUTIL_CORE_VERSION_MAJOR}.${CUTIL_CORE_VERSION_MINOR}.${CUTIL_CORE_VERSION_REVISION})
set (CUTIL_CORE_VERSION_NUM "10")
set (CUTIL_CORE_VERSION_EXTRA "master")


set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for binary")
#first build libcutilcore
set(CUTIL_CORE_LIBRARY cutil)
set(CUTIL_CORE_LIBRARY_STATIC ${CUTIL_CORE_LIBRARY}staticlib)
set(CUTIL_CORE_LIBRARY_SHARED ${CUTIL_CORE_LIBRARY}-shared)

message(STATUS "This is BINARY dir" ${libcutil_BINARY_DIR})
message(STATUS "This is SOURCE dir" ${libcutil_SOURCE_DIR})
message(STATUS "This is Cmake current source dir" ${CMAKE_CURRENT_SOURCE_DIR})
message(STATUS "build cutil version: ${CUTIL_CORE_VERSION}")

#call configure first
Configure()
#call build tools to generate build information file
BuildTools()

include(CheckCXXSourceCompiles)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/readline.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/libutils.cmake)
# build editline first
# Add system/bundled editline.
MYSQL_CHECK_EDITLINE()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/cutil.pc.cmakein ${CMAKE_CURRENT_BINARY_DIR}/cutil.pc @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.c.cmakein ${CMAKE_CURRENT_SOURCE_DIR}/src/version.c @ONLY)


# include_directories(${CMAKE_CURRENT_SOURCE_DIR}/asterisk)
# include_directories(${CMAKE_CURRENT_SOURCE_DIR}/core)
set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/syslog.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/term.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/lock.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/uuid.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/utils.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/md5.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/sha1.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/strings.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/stringfields.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/buildinfo.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/backtrace.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/obj2_container.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/obj2_hash.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/obj2_rbtree.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/obj2.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/netsock2.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/config.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/config_options.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/strcompat.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/io.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/crypt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/threadstorage.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/tcptls.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/optional_api.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/stdtime/localtime.c


  ${CMAKE_CURRENT_SOURCE_DIR}/src/core/cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core/core.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core/elhelper.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core/logger.c

  ${CMAKE_CURRENT_SOURCE_DIR}/src/version.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/libcutil.c
)

IF(ENABLE_KVDB)
  set(SOURCES
    ${SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utility/kvdb.c
  )
ENDIF(ENABLE_KVDB)

if(ENABLE_RESTFUL)
  set(ENABLE_HTTP ON)
endif()

IF(ENABLE_HTTP)
  set(SOURCES
    ${SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/http/uri.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/http/http.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/http/http_websocket.c
  )
ENDIF()

IF(ENABLE_RESTFUL)
  set(SOURCES
    ${SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/restful/restful.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/restful/restful_model.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/restful/restful_websockets.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/restful/restful_model_validators.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/restful/config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/restful/cli.c
  )
ENDIF()

message(STATUS "source list " ${SOURCES})

set(LIBCUTIL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${LIBCUTIL_INCLUDE_DIR})

# Platform (not compiler) specific settings
if(IOS)
  message(STATUS "This is on IOS platform, Not supported!")
elseif(ANDROID)
  message(STATUS "This is on android platform, Not supported!")
elseif(UNIX)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNINGS} -w -Wpointer-compare")
elseif(WIN32)
  message(STATUS "This is on win32 platform, Not supported!")
else()
  message(FATAL_ERROR "-- Unsupported Build Platform.")
endif()

add_library(${CUTIL_CORE_LIBRARY_STATIC} STATIC ${SOURCES})
add_library(${CUTIL_CORE_LIBRARY_SHARED} SHARED ${SOURCES})
find_package(Threads REQUIRED)
if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(${CUTIL_CORE_LIBRARY_STATIC} PUBLIC  "-pthread")
  target_compile_options(${CUTIL_CORE_LIBRARY_SHARED} PUBLIC  "-pthread")
endif()
target_compile_options(${CUTIL_CORE_LIBRARY_STATIC} PUBLIC  "-fPIC")
target_compile_options(${CUTIL_CORE_LIBRARY_SHARED} PUBLIC  "-fPIC")
if(CMAKE_THREAD_LIBS_INIT)
  SET(LINK_LIB ${LINK_LIB} ${CMAKE_THREAD_LIBS_INIT})
endif()

find_package(OpenSSL)
if(TARGET OpenSSL::SSL)
  set(LINK_LIB ${LINK_LIB} OpenSSL::SSL)
endif()
set(_CUTIL_FIND_SSL "if(NOT OpenSSL_FOUND)\n  find_package(OpenSSL)\nendif()")

IF(ENABLE_KVDB)
  #if not given -DLIBSQLITE3_PREFIX use default path
  If(DEFINED  LIBSQLITE3_PREFIX)
    message(STATUS "use given sqlite3 path" ${LIBSQLITE3_PREFIX})
    set(CMAKE_PREFIX_PATH ${LIBSQLITE3_PREFIX})
    find_library(SQLITE3_LIBRARY  NAMES sqlite3)
    set(SQLITE3_INCLUDE_DIR ${LIBSQLITE3_PREFIX}/include)
  else()
    find_path(SQLITE3_INCLUDE_DIR NAMES sqlite3.h)
    find_library(SQLITE3_LIBRARY  NAMES sqlite3)
  endif()

  message(STATUS "use sqlite3 path " ${SQLITE3_LIBRARY})
  include_directories(${SQLITE3_INCLUDE_DIR})
  SET(LINK_LIB ${LINK_LIB} ${SQLITE3_LIBRARY})
ENDIF(ENABLE_KVDB)

SET(LINK_LIB ${LINK_LIB} jansson)
SET(LINK_LIB ${LINK_LIB} ncurses)
SET(LINK_LIB ${LINK_LIB} uuid)

if(HAVE_CRYPT_R)
  SET(LINK_LIB ${LINK_LIB} crypt)
endif()

if(HAVE_CRYPT)
  SET(LINK_LIB ${LINK_LIB} crypt)
endif()


target_link_libraries(${CUTIL_CORE_LIBRARY_STATIC}
  ${LINK_LIB})
target_link_libraries(${CUTIL_CORE_LIBRARY_SHARED}
  ${LINK_LIB}
  "-fvisibility=hidden"
  "-Wl,--whole-archive,--exclude-libs,ALL"
  ${EDITLINE_LIBRARY}
  "-Wl,--no-whole-archive"
)

#merget libcutilcore.a and libedit.a begin
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/libutils.cmake)
merge_static_libs(${CUTIL_CORE_LIBRARY} ${EDITLINE_LIBRARY} ${CUTIL_CORE_LIBRARY_STATIC} )
#merget libcutilcore.a and libedit.a end



set_target_properties(${CUTIL_CORE_LIBRARY} PROPERTIES
SOVERSION ${CUTIL_CORE_VERSION_MAJOR}.${CUTIL_CORE_VERSION_MINOR}.${CUTIL_CORE_VERSION_REVISION})

set_target_properties(${CUTIL_CORE_LIBRARY_SHARED} PROPERTIES
SOVERSION ${CUTIL_CORE_VERSION_MAJOR}.${CUTIL_CORE_VERSION_MINOR}.${CUTIL_CORE_VERSION_REVISION}
OUTPUT_NAME ${CUTIL_CORE_LIBRARY})

install(
  TARGETS ${CUTIL_CORE_LIBRARY}
  LIBRARY DESTINATION ${INSTALL_LIB_DIR}
  ARCHIVE DESTINATION ${INSTALL_LIB_DIR}
)

install(
  TARGETS ${CUTIL_CORE_LIBRARY_SHARED}
  LIBRARY DESTINATION ${INSTALL_LIB_DIR}
  ARCHIVE DESTINATION ${INSTALL_LIB_DIR}
)


install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/cutil.pc
  DESTINATION "${INSTALL_PKGCONFIG_DIR}"
)

if(NOT SKIP_INSTALL_HEADERS AND NOT SKIP_INSTALL_ALL )
    install(DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION "${INSTALL_INC_DIR}"  FILES_MATCHING PATTERN "*.h")
endif()


if(BUILD_TEST)
  set(TEST_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/test/test_main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test/test_restful.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test/resources/resource_test.c
  ${CMAKE_CURRENT_SOURCE_DIR}/test/resources/resource_acl.c
  )

  # find_package(Curses REQUIRED)
  find_library(ncurses REQUIRED)

  include_directories(${LIBCUTIL_INCLUDE_DIR})  
  add_executable(cutiltest ${TEST_SOURCES})

  #find_library(${CUTILCORE_LIBRARY} NAMES  cutil)
  #target_link_libraries(test_logutil ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${CUTIL_CORE_LIBRARY}.a jansson ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libedit.a ${CURSES_LIBRARY})
  target_link_libraries(cutiltest ${CUTIL_CORE_LIBRARY_SHARED} jansson uuid ncurses)

  find_package(Threads REQUIRED)
  if(THREADS_HAVE_PTHREAD_ARG)
    target_compile_options(cutiltest PUBLIC  "-pthread")
  endif()
  if(CMAKE_THREAD_LIBS_INIT)
    target_link_libraries(cutiltest "${CMAKE_THREAD_LIBS_INIT}")
  endif()

  message(STATUS "on unix platform")

  install(
    TARGETS cutiltest
    RUNTIME  DESTINATION ${INSTALL_BIN_DIR}
    )
endif()

