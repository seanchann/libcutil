## check libcutil dependence

macro(Configure)
  INCLUDE(CheckIncludeFiles)

  CHECK_INCLUDE_FILES ("sys/types.h" HAVE_SYS_TYPES_H)
  CHECK_INCLUDE_FILES ("sys/stat.h" HAVE_SYS_STAT_H)
  CHECK_INCLUDE_FILES ("stdlib.h;stddef.h" STDC_HEADERS)
  CHECK_INCLUDE_FILES ("stdlib.h" HAVE_STDLIB_H)
  CHECK_INCLUDE_FILES ("inttypes.h" HAVE_INTTYPES_H)
  CHECK_INCLUDE_FILES ("stdint.h" HAVE_STDINT_H)
  CHECK_INCLUDE_FILES ("unistd.h" HAVE_UNISTD_H)
  CHECK_INCLUDE_FILES ("memory.h" HAVE_MEMORY_H)
  CHECK_INCLUDE_FILES ("execinfo.h" HAVE_BKTR_HEADER)

  message(STATUS "header check " ${HAVE_BKTR_HEADER})


  INCLUDE(CheckFunctionExists)
  CHECK_FUNCTION_EXISTS(strtoq HAVE_STRTOQ)

  INCLUDE(CheckLibraryExists)
  CHECK_LIBRARY_EXISTS(c  atoi "" HAVE_GLIBC)

  IF(${HAVE_BKTR_HEADER})
    IF(${HAVE_GLIBC})
      CHECK_LIBRARY_EXISTS(c backtrace "" HAVE_BKTR)
    ELSE()
      CHECK_LIBRARY_EXISTS(execinfo backtrace "" HAVE_BKTR)
    ENDIF()
  ENDIF()


  CONFIGURE_FILE(${PROJECT_SOURCE_DIR}/include/autoconfig.h.in ${PROJECT_SOURCE_DIR}/include/autoconfig.h)
endmacro()
