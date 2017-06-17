# Portions specific to cpprest binary versioning.
set (CUTIL_CORE_VERSION_MAJOR 1)
set (CUTIL_CORE_VERSION_MINOR 0)
set (CUTIL_CORE_VERSION_REVISION 0)
set (CUTIL_CORE_VERSION ${CUTIL_CORE_VERSION_MAJOR}.${CUTIL_CORE_VERSION_MINOR}.${CUTIL_CORE_VERSION_REVISION})
set (CUTIL_CORE_VERSION_NUM "10")
set (CUTIL_CORE_VERSION_EXTRA "master")

message(STATUS "build cutil version: ${CUTIL_CORE_VERSION}")

include(CheckCXXSourceCompiles)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/readline.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/libutils.cmake)
# build editline first
# Add system/bundled editline.
MYSQL_CHECK_EDITLINE()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cutil.pc.cmakein ${CMAKE_CURRENT_BINARY_DIR}/cutil.pc @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.c.cmakein ${CMAKE_CURRENT_SOURCE_DIR}/version.c @ONLY)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/asterisk)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/core)
set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/syslog.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/term.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/lock.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/uuid.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/utils.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/md5.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/sha1.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/strings.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/stringfields.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/buildinfo.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/backtrace.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/astobj2_container.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/astobj2_hash.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/astobj2_rbtree.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/astobj2.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/netsock2.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/config.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/config_options.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/strcompat.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/io.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/crypt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/threadstorage.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/tcptls.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/optional_api.c
  ${CMAKE_CURRENT_SOURCE_DIR}/asterisk/stdtime/localtime.c


  ${CMAKE_CURRENT_SOURCE_DIR}/core/cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/core.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/elhelper.c
  ${CMAKE_CURRENT_SOURCE_DIR}/core/logger.c

  ${CMAKE_CURRENT_SOURCE_DIR}/version.c
  ${CMAKE_CURRENT_SOURCE_DIR}/libcutil.c
)

IF(ENABLE_HTTP)
  set(SOURCES
    ${SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/http/uri.c
    ${CMAKE_CURRENT_SOURCE_DIR}/http/http.c
    ${CMAKE_CURRENT_SOURCE_DIR}/http/http_websocket.c
  )
ENDIF()

IF(ENABLE_RESTFUL)
  set(SOURCES
    ${SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/restful/restful.c
    ${CMAKE_CURRENT_SOURCE_DIR}/restful/restful_model.c
    ${CMAKE_CURRENT_SOURCE_DIR}/restful/restful_websockets.c
    ${CMAKE_CURRENT_SOURCE_DIR}/restful/restful_model_validators.c
    ${CMAKE_CURRENT_SOURCE_DIR}/restful/config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/restful/cli.c
  )
ENDIF()


message(STATUS "source list " ${SOURCES})


if(UNIX)
  if(APPLE)
    message(STATUS "on ios platform")
  elseif(ANDROID)
    message(STATUS "on android platform")
  else()
  endif()
  #set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNINGS} -Werror -pedantic")
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNINGS} -w")
elseif(WIN32)
  message(STATUS "on win32 platform")
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

SET(LINK_LIB jansson)
SET(LINK_LIB ncurses)
SET(LINK_LIB uuid)

if(HAVE_CRYPT_R)
  SET(LINK_LIB crypt)
endif()

if(HAVE_CRYPT)
  SET(LINK_LIB crypt)
endif()

if(CMAKE_THREAD_LIBS_INIT)
  SET(LINK_LIB ${LINK_LIB} ${CMAKE_THREAD_LIBS_INIT})
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
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/libutils.cmake)
merge_static_libs(${CUTIL_CORE_LIBRARY} ${EDITLINE_LIBRARY} ${CUTIL_CORE_LIBRARY_STATIC} )
#merget libcutilcore.a and libedit.a end



if(WIN32)
  message(STATUS "build on win32 platform")
elseif(ANDROID)
  # Do not use SOVERSION on android. It is completely unsupported (and causes problems).
  # Perhaps revisit in the future? (NDK r9d, 8/7/14)
else()
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
endif()
