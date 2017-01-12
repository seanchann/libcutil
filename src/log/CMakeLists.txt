set(SOURCES
  logger.c
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

add_library(${LOGUTIL_LIBRARY}  ${SOURCES})
target_link_libraries(${LOGUTIL_LIBRARY}
  )

# Portions specific to cpprest binary versioning.
set (LOGUTIL_VERSION_MAJOR 1)
set (LOGUTIL_VERSION_MINOR 0)
set (LOGUTIL_VERSION_REVISION 0)



if(WIN32)
  message(STATUS "build on win32 platform")
elseif(ANDROID)
  # Do not use SOVERSION on android. It is completely unsupported (and causes problems).
  # Perhaps revisit in the future? (NDK r9d, 8/7/14)
else()
  set_target_properties(${LOGUTIL_LIBRARY} PROPERTIES
  SOVERSION ${LOGUTIL_VERSION_MAJOR}.${LOGUTIL_VERSION_MINOR}.${LOGUTIL_VERSION_REVISION})

  install(
    TARGETS ${LOGUTIL_LIBRARY}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    )
endif()
