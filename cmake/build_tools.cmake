macro(BuildTools)
  set(BUILD_HEADER_OUT_FILE "${LIBCUTIL_INCLUDE_DIR}/asterisk/build.h")
  add_custom_command(OUTPUT ${BUILD_HEADER_OUT_FILE}
   COMMAND /bin/sh "${CMAKE_CURRENT_SOURCE_DIR}/build_tools/make_build_h" > ${BUILD_HEADER_OUT_FILE})
  add_custom_target(buildHeader ALL DEPENDS ${BUILD_HEADER_OUT_FILE})
endmacro()
