## check libcutil dependence

macro(Configure)
  #check header file exist
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
  CHECK_INCLUDE_FILES ("locale.h" HAVE_LOCALE_T_IN_LOCALE_H)
  CHECK_INCLUDE_FILES ("xlocale.h" HAVE_LOCALE_T_IN_XLOCALE_H)
  CHECK_INCLUDE_FILES ("limits.h" HAVE_LIMITS_H)
  CHECK_INCLUDE_FILES ("stddef.h" HAVE_STDDEF_H)
  CHECK_INCLUDE_FILES ("alloca.h" HAVE_ALLOCA_H)
  CHECK_INCLUDE_FILES ("string.h" HAVE_STRING_H)
  CHECK_INCLUDE_FILES ("string.h" HAVE_STRING_H)
  CHECK_INCLUDE_FILES ("sys/thr.h" HAVE_SYS_THR_H)
  #newwork
  CHECK_INCLUDE_FILES ("arpa/inet.h" HAVE_ARPA_INET_H)
  CHECK_INCLUDE_FILES ("winsock.h" HAVE_WINSOCK_H)
  CHECK_INCLUDE_FILES ("winsock2.h" HAVE_WINSOCK2_H)


  INCLUDE(CheckSymbolExists)
  CHECK_SYMBOL_EXISTS (LLONG_MAX "limits.h" HAVE_LLONG_MAX)
  CHECK_SYMBOL_EXISTS (timersub "sys/time.h" HAVE_TIMERSUB)



  INCLUDE(CheckLibraryExists)
  CHECK_LIBRARY_EXISTS(c  atoi "" HAVE_GLIBC)


  # check functions define
  INCLUDE(CheckFunctionExists)
  CHECK_FUNCTION_EXISTS(strtoq HAVE_STRTOQ)
  CHECK_FUNCTION_EXISTS(inet_aton HAVE_INET_ATON)
  CHECK_FUNCTION_EXISTS(closefrom HAVE_CLOSEFROM)
  CHECK_FUNCTION_EXISTS(asprintf HAVE_ASPRINTF)
  CHECK_FUNCTION_EXISTS(ffsll HAVE_FFSLL)
  CHECK_FUNCTION_EXISTS(getloadavg HAVE_GETLOADAVG)
  CHECK_FUNCTION_EXISTS(mkdtemp HAVE_MKDTEMP)
  CHECK_FUNCTION_EXISTS(setenv HAVE_SETENV)
  CHECK_FUNCTION_EXISTS(strcasestr HAVE_STRCASESTR)
  CHECK_FUNCTION_EXISTS(strndup HAVE_STRNDUP)
  CHECK_FUNCTION_EXISTS(strnlen HAVE_STRNLEN)
  CHECK_FUNCTION_EXISTS(strsep HAVE_STRSEP)
  CHECK_FUNCTION_EXISTS(unsetenv HAVE_UNSETENV)
  CHECK_FUNCTION_EXISTS(vasprintf HAVE_VASPRINTF)
  CHECK_FUNCTION_EXISTS(gethostbyname HAVE_GETHOSTBYNAME)
  CHECK_FUNCTION_EXISTS(gethostname HAVE_GETHOSTNAME)
  CHECK_FUNCTION_EXISTS(fork HAVE_WORKING_FORK)
  CHECK_FUNCTION_EXISTS(vfork HAVE_WORKING_VFORK)



  INCLUDE(CheckCSourceCompiles)
  CHECK_C_SOURCE_COMPILES(
    "
    #include <ifaddrs.h>
    int main ()
    {
      struct ifaddrs *p;
      getifaddrs(&p);;
      return 0;
    }
    "

    HAVE_GETIFADDRS
  )



  CHECK_C_SOURCE_COMPILES(
    "
    #include <stdlib.h>
    #include <netdb.h>
    int
    main ()
    {
    struct hostent *he = gethostbyname_r((const char *)NULL, (struct hostent *)NULL, (char *)NULL, (int)0, (struct hostent **)NULL, (int *)NULL);
      ;
      return 0;
    }
    "

    HAVE_GETHOSTBYNAME_R_6
  )

  CHECK_C_SOURCE_COMPILES(
    "
    #include <stdlib.h>
    #include <netdb.h>
    int main ()
    {
    struct hostent *he = gethostbyname_r((const char *)NULL, (struct hostent *)NULL, (char *)NULL, (int)0, (int *)NULL);
      ;
      return 0;
    }
    "

    HAVE_GETHOSTBYNAME_R_5
  )

  CHECK_C_SOURCE_COMPILES(
    "
    #define _GNU_SOURCE 1
    #include <dlfcn.h>
    int
    main ()
    {
      dladdr((void *)0, (void *)0);
      return 0;
    }
    "

    HAVE_DLADDR
  )





  IF(${HAVE_BKTR_HEADER})
    IF(${HAVE_GLIBC})
      CHECK_LIBRARY_EXISTS(c backtrace "" HAVE_BKTR)
    ELSE()
      CHECK_LIBRARY_EXISTS(execinfo backtrace "" HAVE_BKTR)
    ENDIF()
  ENDIF()

  CHECK_LIBRARY_EXISTS(c htonll "arpa/inet.h" HAVE_HTONLL)
  CHECK_LIBRARY_EXISTS(c ntohll "arpa/inet.h" HAVE_NTOHLL)
  CHECK_LIBRARY_EXISTS(m roundl "" HAVE_CLOSEFROM)
  CHECK_LIBRARY_EXISTS(m roundl "" HAVE_ROUNDL)
  CHECK_LIBRARY_EXISTS(m round "" HAVE_ROUND)
  CHECK_LIBRARY_EXISTS(m roundf "" HAVE_ROUNDF)
  CHECK_LIBRARY_EXISTS(cap cap_set_proc "sys/capability.h" HAVE_CAP)




  IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    SET (AST_POLL_COMPAT 1)
  ELSE()
    CHECK_INCLUDE_FILES (sys/poll.h HAVE_POLL_H)
    IF(NOT ${HAVE_POLL_H})
      SET (AST_POLL_COMPAT 1)
    ENDIF()
  ENDIF()


  INCLUDE(CheckTypeSize)
  CHECK_TYPE_SIZE("char *" SIZEOF_CHAR_P)
  CHECK_TYPE_SIZE("int" SIZEOF_INT)
  CHECK_TYPE_SIZE("long" SIZEOF_LONG)
  CHECK_TYPE_SIZE("long long" SIZEOF_LONG_LONG)
  CHECK_TYPE_SIZE("char" SIZEOF_CHAR)
  SET(CMAKE_EXTRA_INCLUDE_FILES sys/select.h)
  CHECK_TYPE_SIZE("((fd_set*)0)->__fds_bits[0]" SIZEOF_FD_SET_FDS_BITS)
  IF(NOT ${SIZEOF_FD_SET_FDS_BITS})
    CHECK_TYPE_SIZE("((fd_set*)0)->fds_bits[0]" SIZEOF_FD_SET_FDS_BITS)
  ENDIF()
  SET(CMAKE_EXTRA_INCLUDE_FILES)

  IF(${SIZEOF_INT} EQUAL ${SIZEOF_FD_SET_FDS_BITS})
    SET (TYPEOF_FD_SET_FDS_BITS int)
  ELSEIF(${SIZEOF_LONG} EQUAL ${SIZEOF_FD_SET_FDS_BITS})
    SET (TYPEOF_FD_SET_FDS_BITS long)
  ELSEIF(${SIZEOF_LONG_LONG} EQUAL ${SIZEOF_FD_SET_FDS_BITS})
    SET (TYPEOF_FD_SET_FDS_BITS long long)
  ENDIF()


  #it is a libcutl
  SET(HAVE_LIBCUITL 1)

  CONFIGURE_FILE(${LIBCUTIL_INCLUDE_DIR}/autoconfig.h.in ${LIBCUTIL_INCLUDE_DIR}/autoconfig.h)


endmacro()
