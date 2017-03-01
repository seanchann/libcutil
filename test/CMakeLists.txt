set(SOURCES
  test_logutil.c
)


FIND_CURSES()
add_executable(test_logutil ${SOURCES})
#target_link_libraries(test_logutil ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${CUTIL_CORE_LIBRARY}.a jansson ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libedit.a ${CURSES_LIBRARY})
target_link_libraries(test_logutil ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcutilcore.a jansson ${CURSES_LIBRARY})


find_package(Threads REQUIRED)
if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(test_logutil PUBLIC  "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(test_logutil "${CMAKE_THREAD_LIBS_INIT}")
endif()

if(UNIX)
  message(STATUS "on unix platform")

  install(
    TARGETS test_logutil
    RUNTIME  DESTINATION ${INSTALL_BIN_DIR}
    )
endif()
