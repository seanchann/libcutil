# MYSQL_ADD_CONVENIENCE_LIBRARY(name source1...sourceN)
# Create static library that can be linked to shared library.
# On systems that force position-independent code, adds -fPIC or
# equivalent flag to compile flags.
MACRO(ADD_CONVENIENCE_LIBRARY)
  SET(TARGET ${ARGV0})
  SET(SOURCES ${ARGN})
  LIST(REMOVE_AT SOURCES 0)
  ADD_LIBRARY(${TARGET} STATIC ${SOURCES})
  IF(NOT _SKIP_PIC)
    SET_TARGET_PROPERTIES(${TARGET} PROPERTIES  COMPILE_FLAGS
    "${CMAKE_SHARED_LIBRARY_C_FLAGS}")
  ENDIF()
ENDMACRO()
