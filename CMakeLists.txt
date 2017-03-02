cmake_minimum_required(VERSION 2.6)
project(libcutil)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/configure.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_tools.cmake)


option(BUILD_LIBCUTIL "build c utility library" ON)
option(BUILD_TEST "build test binary" ON)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/.libs)



message(STATUS "This is BINARY dir" ${libcutil_BINARY_DIR})
message(STATUS "This is SOURCE dir" ${libcutil_SOURCE_DIR})
message(STATUS "This is Cmake current source dir" ${CMAKE_CURRENT_SOURCE_DIR})


set(LIBCUTIL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
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
    set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Installation directory for libraries")
    set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
    set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
    set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for binary")

    #first build libcutilcore
    set(CUTIL_CORE_LIBRARY cutil)
    set(CUTIL_CORE_LIBRARY_STATIC ${CUTIL_CORE_LIBRARY}staticlib)
    set(CUTIL_CORE_LIBRARY_SHARED ${CUTIL_CORE_LIBRARY}-shared)
    include_directories(${LIBCUTIL_INCLUDE_DIR})
    add_subdirectory(src/core)

    if(BUILD_TEST)
      add_subdirectory(test)
    endif()


    if(NOT SKIP_INSTALL_HEADERS AND NOT SKIP_INSTALL_ALL )
        install(DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION "${INSTALL_INC_DIR}"  FILES_MATCHING PATTERN "*.h")
    endif()


  elseif(WIN32)
    message(STATUS "This is on win32 platform, Not supported!")
  else()
    message(FATAL_ERROR "-- Unsupported Build Platform.")
  endif()
endif()
