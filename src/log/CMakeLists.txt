set(SOURCES
  logger.c
)
message(STATUS "source list " ${SOURCES})

# Portions specific to cpprest binary versioning.
set (LOGUTIL_VERSION_MAJOR 1)
set (LOGUTIL_VERSION_MINOR 0)
set (LOGUTIL_VERSION_REVISION 0)
set (LOGUTIL_VERSION ${LOGUTIL_VERSION_MAJOR}.${LOGUTIL_VERSION_MINOR}.${LOGUTIL_VERSION_REVISION})

set(LOGUTIL_PC_FILE ${CMAKE_CURRENT_BINARY_DIR}/logutil.pc)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/logutil.pc.cmakein ${LOGUTIL_PC_FILE}  @ONLY)


if(UNIX)
  if(APPLE)
    message(STATUS "on ios platform")
  elseif(ANDROID)
    message(STATUS "on android platform")
  else()
  endif()
  #set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNINGS} -Werror -pedantic")
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNINGS} -w")
  option(BUILD_SHARED_LIBS "Build shared Libraries." ON)

elseif(WIN32)
  message(STATUS "on win32 platform")
endif()



add_library(${LOGUTIL_LIBRARY}  ${SOURCES})
target_link_libraries(${LOGUTIL_LIBRARY}
  ${CUTIL_CORE_LIBRARY}
  )




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
    LIBRARY DESTINATION ${INSTALL_LIB_DIR}
    ARCHIVE DESTINATION ${INSTALL_LIB_DIR}
    )

  install(
    FILES ${LOGUTIL_PC_FILE}
    DESTINATION "${INSTALL_PKGCONFIG_DIR}"
  )

endif()
