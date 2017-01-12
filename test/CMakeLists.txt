set(SOURCES
  test_logutil.c
)

add_executable(test_logutil ${SOURCES})
target_link_libraries(test_logutil ${LOGUTIL_LIBRARY})
