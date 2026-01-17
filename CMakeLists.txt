cmake_minimum_required(VERSION 3.10)
project(hexdig)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)



file(GLOB_RECURSE SRC_FILES
    src/*.cpp
    src/*.c
)

if (UNIX)
    find_package(ZLIB REQUIRED)
elseif (WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    set(BUILD_SHARED_LIBS OFF)
    set(ZLIB_INCLUDE_DIR "c:/devlibs/zlib/include")
    set(ZLIB_LIBRARY "c:/devlibs/zlib/lib/libz.a")
    add_library(ZLIB::ZLIB STATIC IMPORTED)
    set_target_properties(ZLIB::ZLIB PROPERTIES IMPORTED_LOCATION "${ZLIB_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${ZLIB_INCLUDE_DIR}" )
endif()
add_compile_options("-g3")
include_directories(
    src
    src/parsers
    src/extractors
    src/utils
    src/common
)

add_executable(hexdig ${SRC_FILES})
target_link_libraries(hexdig  ZLIB::ZLIB)
target_link_options(hexdig PRIVATE -s)
install (TARGETS hexdig
    RUNTIME DESTINATION bin
)
