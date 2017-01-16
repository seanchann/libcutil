set(SOURCES
  test_logutil.c
)

add_executable(test_logutil ${SOURCES})
target_link_libraries(test_logutil ${LOGUTIL_LIBRARY})

if(UNIX)
  message(STATUS "on unix platform")

  install(
    TARGETS test_logutil
    RUNTIME  DESTINATION ${INSTALL_BIN_DIR}
    )
endif()
