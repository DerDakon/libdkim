project(libDKIM)

cmake_minimum_required(VERSION 2.8.10 FATAL_ERROR)

include(GNUInstallDirs)
include(WriteBasicConfigVersionFile)
set(PROJECT_VERSION 1.0.21)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_library(dkim
	dkim.cpp dns.cpp dkimbase.cpp dkimsign.cpp dkimverify.cpp
	dkim.h dns.h dkimbase.h dkimsign.h dkimverify.h
	libdkim.def libdkim.rc
)
target_link_libraries(dkim ${OPENSSL_LIBRARIES})
if (CMAKE_SYSTEM_NAME STREQUAL Linux)
	target_link_libraries(dkim resolv)
endif ()

add_executable(libdkimtest libdkimtest.cpp)
target_link_libraries(libdkimtest dkim)
set_target_properties(libdkimtest PROPERTIES VERSION ${PROJECT_VERSION})

set(INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_INCLUDEDIR}" CACHE PATH "Path suffix to install headers to")
set(LIB_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}" CACHE PATH "Path suffix to install libraries to")
set(BIN_INSTALL_DIR "${CMAKE_INSTALL_BINDIR}" CACHE PATH "Path suffix to install binaries to")
if (BUILD_SHARED_LIBS)
  set(libDKIM_LIB_PREFIX ${CMAKE_SHARED_LIBRARY_PREFIX})
  set(libDKIM_LIB_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
else ()
  set(libDKIM_LIB_PREFIX ${CMAKE_STATIC_LIBRARY_PREFIX})
  set(libDKIM_LIB_SUFFIX ${CMAKE_STATIC_LIBRARY_SUFFIX})
endif ()

install(TARGETS dkim DESTINATION ${LIB_INSTALL_DIR})
install(TARGETS libdkimtest DESTINATION ${BIN_INSTALL_DIR})
install(FILES dkim.h DESTINATION ${INCLUDE_INSTALL_DIR})

include(CMakePackageConfigHelpers)
configure_package_config_file(libDKIMConfig.cmake.in
   ${CMAKE_CURRENT_BINARY_DIR}/libDKIMConfig.cmake
   INSTALL_DESTINATION ${LIB_INSTALL_DIR}/libDKIM/cmake
   PATH_VARS INCLUDE_INSTALL_DIR LIB_INSTALL_DIR BIN_INSTALL_DIR
   NO_CHECK_REQUIRED_COMPONENTS_MACRO)
write_basic_package_version_file(
   ${CMAKE_CURRENT_BINARY_DIR}/libDKIMConfigVersion.cmake
   COMPATIBILITY SameMajorVersion )
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libDKIMConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/libDKIMConfigVersion.cmake
        DESTINATION ${LIB_INSTALL_DIR}/libDKIM/cmake )
