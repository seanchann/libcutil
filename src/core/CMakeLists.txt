include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../asterisk)
set(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/syslog.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/term.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/lock.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/uuid.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/utils.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/json.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/md5.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/sha1.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/strings.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/stringfields.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/buildinfo.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/backtrace.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/astobj2_container.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/astobj2_hash.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/astobj2_rbtree.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/astobj2.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/netsock2.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/config.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/strcompat.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../asterisk/stdtime/localtime.c
)


include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/editline)
set(SOURCES
  ${SOURCES}
  ${CMAKE_CURRENT_SOURCE_DIR}/astcore_dummy.c
  ${CMAKE_CURRENT_SOURCE_DIR}/cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/console.c
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon.c
  ${CMAKE_CURRENT_SOURCE_DIR}/el_api.c
)

message(STATUS "source list " ${SOURCES})

# Portions specific to cpprest binary versioning.
set (CUTIL_CORE_VERSION_MAJOR 1)
set (CUTIL_CORE_VERSION_MINOR 0)
set (CUTIL_CORE_VERSION_REVISION 0)
set (CUTIL_CORE_VERSION ${CUTIL_CORE_VERSION_MAJOR}.${CUTIL_CORE_VERSION_MINOR}.${CUTIL_CORE_VERSION_REVISION})

message(STATUS "build cutil version: ${CUTIL_CORE_VERSION}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cutilcore.pc.cmakein ${CMAKE_CURRENT_BINARY_DIR}/cutilcore.pc @ONLY)


if(UNIX)
  if(APPLE)
    message(STATUS "on ios platform")
  elseif(ANDROID)
    message(STATUS "on android platform")
  else()
  endif()

  find_package(Threads REQUIRED)
  #set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNINGS} -Werror -pedantic")
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNINGS} -w")
elseif(WIN32)
  message(STATUS "on win32 platform")
endif()




add_library(${CUTIL_CORE_LIBRARY} STATIC ${SOURCES})

if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(${CUTIL_CORE_LIBRARY} PUBLIC  "-pthread")
endif()

target_compile_options(${CUTIL_CORE_LIBRARY} PUBLIC  "-fPIC")

SET(LINK_LIB jansson)
if(CMAKE_THREAD_LIBS_INIT)
  #target_link_libraries(${AST_CORE_LIBRARY}
  #  ${CMAKE_THREAD_LIBS_INIT})
  SET(LINK_LIB ${LINK_LIB} ${CMAKE_THREAD_LIBS_INIT})
endif()


target_link_libraries(${CUTIL_CORE_LIBRARY}
  ${LINK_LIB})

if(WIN32)
  message(STATUS "build on win32 platform")
elseif(ANDROID)
  # Do not use SOVERSION on android. It is completely unsupported (and causes problems).
  # Perhaps revisit in the future? (NDK r9d, 8/7/14)
else()
  set_target_properties(${CUTIL_CORE_LIBRARY} PROPERTIES
  SOVERSION ${CUTIL_CORE_VERSION_MAJOR}.${CUTIL_CORE_VERSION_MINOR}.${CUTIL_CORE_VERSION_REVISION})

  install(
    TARGETS ${CUTIL_CORE_LIBRARY}
    LIBRARY DESTINATION ${INSTALL_LIB_DIR}
    ARCHIVE DESTINATION ${INSTALL_LIB_DIR}
    )

  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${CUTIL_CORE_LIBRARY}.pc
    DESTINATION "${INSTALL_PKGCONFIG_DIR}"
  )
endif()
