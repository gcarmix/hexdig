cmake_minimum_required(VERSION 3.10)
project(hexdig)


set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE SRC_FILES
    src/*.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)
pkg_check_modules(LIBZIP REQUIRED libzip)
find_package(ZLIB REQUIRED)
find_package(LibLZMA REQUIRED)
find_package(cJSON REQUIRED)
include_directories(${LIBARCHIVE_INCLUDE_DIRS} ${LIBZIP_INCLUDE_DIRS})
link_directories(${LIBARCHIVE_LIBRARY_DIRS} ${LIBZIP_LIBRARY_DIRS})
add_definitions(${LIBARCHIVE_CFLAGS_OTHER})
add_compile_options("-g3")
include_directories(
    src
    src/parsers
    src/extractors
    src/utils
    src/common
)

add_executable(hexdig ${SRC_FILES})

target_link_libraries(hexdig ${LIBARCHIVE_LIBRARIES} ${LIBZIP_LIBRARIES} ZLIB::ZLIB LibLZMA::LibLZMA cjson)

install (TARGETS hexdig
    RUNTIME DESTINATION bin
)