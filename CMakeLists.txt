cmake_minimum_required(VERSION 3.24)
project(dnsquery)

# curl
set(BUILD_SHARED_LIBS OFF) # sad
set(BUILD_STATIC_LIBS ON) # sad
set(CURL_USE_LIBPSL OFF)
set(BUILD_CURL_EXE OFF)
set(BUILD_TESTING OFF)
set(BUILD_EXAMPLES OFF)
set(BUILD_LIBCURL_DOCS OFF)
set(BUILD_MISC_DOCS OFF)
set(ENABLE_CURL_MANUAL OFF)
# set(CURL_STATIC_CRT ON) # mhh
set(CURL_USE_SCHANNEL ON)
add_subdirectory(external/curl)

# libdnsquery
add_library(libdnsquery STATIC source/dnsquery.cpp)
target_include_directories(libdnsquery PUBLIC include)
target_link_libraries(libdnsquery PRIVATE libcurl)
set_target_properties(libdnsquery PROPERTIES CXX_STANDARD 17)

# dnsquery_demo
add_executable(dnsquery_demo demo/main.cpp)
target_link_libraries(dnsquery_demo PRIVATE libdnsquery)
set_target_properties(dnsquery_demo PROPERTIES CXX_STANDARD 17)
