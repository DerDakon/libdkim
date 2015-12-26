project(libDKIM)

cmake_minimum_required(VERSION 2.8.10 FATAL_ERROR)

include(GNUInstallDirs)

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

install(TARGETS dkim DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS libdkimtest DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES dkim.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
