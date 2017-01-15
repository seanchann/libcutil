cmake_minimum_required(VERSION 2.6)
project(libcutil)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/configure.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_tools.cmake)


option(BUILD_LIBCUTIL "build c utility library" ON)
option(BUILD_LOGUTIL "build log library" ON)

option(BUILD_TEST "build test binary" ON)


set(LIBCUTIL_INSTALL_PREFIX ${libcutil_BINARY_DIR}/usr)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)

message(STATUS "This is BINARY dir" ${libcutil_BINARY_DIR})
message(STATUS "This is SOURCE dir" ${libcutil_SOURCE_DIR})
message(STATUS "This is Cmake current source dir" ${CMAKE_CURRENT_SOURCE_DIR})

#call configure first
Configure()
#call build tools to generate file
BuildTools()


if(BUILD_LIBCUTIL)
  # Platform (not compiler) specific settings
  if(IOS)
    message(STATUS "This is on IOS platform, Not supported!")
  elseif(ANDROID)
    message(STATUS "This is on android platform, Not supported!")
  elseif(UNIX)

    find_package(Threads REQUIRED)

    #first build libcutilcore.a
    set(CUTIL_CORE_LIBRARY cutilcore)
    include_directories(include)
    add_subdirectory(src/core)


    if(BUILD_LOGUTIL)
      set(LOGUTIL_LIBRARY logutil)
      add_subdirectory(src/log)
    endif()

    if(BUILD_TEST)
      add_subdirectory(test)
    endif()
  elseif(WIN32)
    message(STATUS "This is on win32 platform, Not supported!")
  else()
    message(FATAL_ERROR "-- Unsupported Build Platform.")
  endif()
endif()
