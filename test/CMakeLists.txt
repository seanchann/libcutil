set(SOURCES
  test_logutil.c
)


# SET(CURSES_USE_NCURSES TRUE)
# find_package(Curses REQUIRED)
find_library(ncurses REQUIRED)

add_executable(test_logutil ${SOURCES})
message(STATUS "ncurses lib ${NCURSES_LIBRARY}")

find_library(CUTILCORE_LIBRARY NAMES  cutil)
#target_link_libraries(test_logutil ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${CUTIL_CORE_LIBRARY}.a jansson ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libedit.a ${CURSES_LIBRARY})
target_link_libraries(test_logutil  ${CUTILCORE_LIBRARY} jansson uuid ncurses)


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
