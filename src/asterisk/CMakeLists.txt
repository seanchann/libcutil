set(SOURCES
  syslog.c
  term.c
  lock.c
  uuid.c
  utils.c
)


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

message(STATUS "source list " ${SOURCES})

add_library(${AST_CORE_LIBRARY}  ${SOURCES})

if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(PUBLIC my_app "-pthread")
endif()

if(CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(${AST_CORE_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT})
endif()

# Portions specific to cpprest binary versioning.
set (AST_CORE_VERSION_MAJOR 1)
set (AST_CORE_VERSION_MINOR 0)
set (AST_CORE_VERSION_REVISION 0)



if(WIN32)
  message(STATUS "build on win32 platform")
elseif(ANDROID)
  # Do not use SOVERSION on android. It is completely unsupported (and causes problems).
  # Perhaps revisit in the future? (NDK r9d, 8/7/14)
else()
  set_target_properties(${AST_CORE_LIBRARY} PROPERTIES
  SOVERSION ${AST_CORE_VERSION_MAJOR}.${AST_CORE_VERSION_MINOR}.${AST_CORE_VERSION_REVISION})

  install(
    TARGETS ${AST_CORE_LIBRARY}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    )
endif()
