cmake_minimum_required(VERSION 3.10)
project(hexdig)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB_RECURSE SRC_FILES
    src/*.cpp
)

find_package(PkgConfig REQUIRED)

find_package(ZLIB REQUIRED)
find_package(cJSON REQUIRED)


add_compile_options("-g3")
include_directories(
    src
    src/parsers
    src/extractors
    src/utils
    src/common
)

add_executable(hexdig ${SRC_FILES})

target_link_libraries(hexdig  ZLIB::ZLIB cjson)

install (TARGETS hexdig
    RUNTIME DESTINATION bin
)