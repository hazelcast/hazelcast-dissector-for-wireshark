# Hazelcast Dissector Plugin for Wireshark

project(hazelcast-wireshark-plugin C CXX)

cmake_minimum_required(VERSION 3.5)
set(CMAKE_BACKWARDS_COMPATIBILITY 3.5)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Wireshark 3.2)

if(Wireshark_FOUND)

  MESSAGE(STATUS "Wireshark libraries found in ${Wireshark_LIB_DIR}, performing a stand-alone plug-in build.")

  if(NOT CMAKE_INSTALL_LIBDIR )
    set(CMAKE_INSTALL_LIBDIR ~/.local/lib/wireshark/plugins/${Wireshark_VERSION_MAJOR}.${Wireshark_VERSION_MINOR}/epan)
  endif(NOT CMAKE_INSTALL_LIBDIR )
  MESSAGE(STATUS "Plug-in will be installed in: ${CMAKE_INSTALL_LIBDIR}")

  INCLUDE(UseMakePluginReg)

  set(GLIB2_MIN_VERSION 2.4.0)

  find_package(GLIB2)
  include_directories (${GLIB2_INCLUDE_DIRS})

  include_directories (${Wireshark_INCLUDE_DIR})

  IF(APPLE)
    LINK_DIRECTORIES(/usr/local/lib)
  ENDIF()

  set(LINK_MODE_LIB SHARED)
  set(LINK_MODE_MODULE MODULE)

  # Plugin name and version info (major minor micro)
  set(PLUGIN_VERSION "0.0.1.dev0")
  add_definitions(-DPLUGIN_VERSION=\"${PLUGIN_VERSION}\")

else(Wireshark_FOUND)

  MESSAGE(STATUS "Wireshark libraries not found, performing an in-tree Wireshark plug-in build.")

  include(WiresharkPlugin)

  # Plugin name and version info (major minor micro extra)
  set_module_info(hazelcast 0 0 1 0)

endif(Wireshark_FOUND)

set(DISSECTOR_SRC
	packet-hazelcast.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

set_source_files_properties(
	${CLEAN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

if(Wireshark_FOUND)

  add_library(hazelcast ${LINK_MODE_MODULE}
                  ${PLUGIN_FILES}
                  ${PLUGIN_RC_FILE}
  )

  set_target_properties(hazelcast PROPERTIES
          PREFIX ""
          LINK_FLAGS "${WS_LINK_FLAGS}"
          FOLDER "Plugins"
  )

  link_directories(${Wireshark_LIB_DIR})

  target_link_libraries(hazelcast wireshark)

  install(TARGETS hazelcast
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} NAMELINK_SKIP
          RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

else(Wireshark_FOUND)

  add_plugin_library(hazelcast epan)

  target_link_libraries(hazelcast epan)

  install_plugin(hazelcast epan)

  file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
  CHECKAPI(
  	NAME
  	  hazelcast
  	SWITCHES
  	  -g abort -g termoutput
  	SOURCES
  	  ${DISSECTOR_SRC}
  	  ${DISSECTOR_HEADERS}
  )

endif(Wireshark_FOUND)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
