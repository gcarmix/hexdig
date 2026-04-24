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
    find_package(LibLZMA REQUIRED)
    find_path(LZO_INCLUDE_DIR lzo/lzo1x.h)
    find_library(LZO_LIBRARY NAMES lzo2)
elseif (MINGW)
    # MSYS2/MinGW64: install deps with pacman:
    #   pacman -S mingw-w64-x86_64-zlib mingw-w64-x86_64-xz mingw-w64-x86_64-lzo2
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    set(BUILD_SHARED_LIBS OFF)
    find_package(ZLIB REQUIRED)
    find_package(LibLZMA REQUIRED)
    find_path(LZO_INCLUDE_DIR lzo/lzo1x.h)
    find_library(LZO_LIBRARY NAMES lzo2)
elseif (WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    set(BUILD_SHARED_LIBS OFF)
    set(ZLIB_INCLUDE_DIR "c:/devlibs/zlib/include")
    set(ZLIB_LIBRARY "c:/devlibs/zlib/lib/libz.a")
    add_library(ZLIB::ZLIB STATIC IMPORTED)
    set_target_properties(ZLIB::ZLIB PROPERTIES IMPORTED_LOCATION "${ZLIB_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${ZLIB_INCLUDE_DIR}")
    set(LIBLZMA_INCLUDE_DIR "c:/devlibs/liblzma/include")
    set(LIBLZMA_LIBRARY "c:/devlibs/liblzma/lib/liblzma.a")
    add_library(LibLZMA::LibLZMA STATIC IMPORTED)
    set_target_properties(LibLZMA::LibLZMA PROPERTIES IMPORTED_LOCATION "${LIBLZMA_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${LIBLZMA_INCLUDE_DIR}")
    find_path(LZO_INCLUDE_DIR lzo/lzo1x.h PATHS "c:/devlibs/lzo/include")
    find_library(LZO_LIBRARY NAMES lzo2 PATHS "c:/devlibs/lzo/lib")
endif()
add_compile_options("-O3")
include_directories(
    src
    src/parsers
    src/extractors
    src/utils
    src/common
)

add_executable(hexdig ${SRC_FILES})
target_link_libraries(hexdig  ZLIB::ZLIB LibLZMA::LibLZMA ${LZO_LIBRARY})
target_link_options(hexdig PRIVATE -s)
install (TARGETS hexdig
    RUNTIME DESTINATION bin
)

enable_testing()

if (UNIX)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    file(GLOB PY_TEST_FILES "${CMAKE_SOURCE_DIR}/tests/test_*.py")
    foreach(PY_TEST_FILE ${PY_TEST_FILES})
        get_filename_component(PY_TEST_NAME ${PY_TEST_FILE} NAME_WE)
        add_test(
            NAME ${PY_TEST_NAME}
            COMMAND ${Python3_EXECUTABLE} ${PY_TEST_FILE}
                    $<TARGET_FILE:hexdig>
                    ${CMAKE_BINARY_DIR}/tests/${PY_TEST_NAME}
        )
    endforeach()
endif()
