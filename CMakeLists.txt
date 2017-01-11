cmake_minimum_required(VERSION 2.6)
project(libcutil)

option(BUILD_LIBCUTIL "build c utility library" ON)
option(BUILD_LIBLOG "build log library" ON)

list (APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(LIBCUTIL_INSTALL_PREFIX ${libcutil_BINARY_DIR}/usr)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)

message(STATUS "This is BINARY dir" ${libcutil_BINARY_DIR})
message(STATUS "This is SOURCE dir" ${libcutil_SOURCE_DIR})
message(STATUS "This is Cmake current source dir" ${CMAKE_CURRENT_SOURCE_DIR})



if(BUILD_LIBCUTIL)
  # Platform (not compiler) specific settings
  if(IOS)
    message(STATUS "This is on IOS platform, Not supported!")
  elseif(ANDROID)
    message(STATUS "This is on android platform, Not supported!")
  elseif(UNIX)
    include_directories(${LIBCUTIL_INSTALL_PREFIX}/include)
    option(BUILD_SHARED_LIBS "Build shared Libraries." ON)

    if(BUILD_LIBLOG)
      set(LOG_LIBRARY logutil)
      include_directories(include/asterisk include/log)
      add_subdirectory(src/log)
    endif()
  elseif(WIN32)
    message(STATUS "This is on win32 platform, Not supported!")
  else()
    message(FATAL_ERROR "-- Unsupported Build Platform.")
  endif()
endif()
