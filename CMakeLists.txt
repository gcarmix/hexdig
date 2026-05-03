cmake_minimum_required(VERSION 3.12)
project(hexdig VERSION 1.0.1)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)



file(GLOB_RECURSE ALL_SRC_FILES
    src/*.cpp
    src/*.c
)

# The library target excludes main.cpp so it has no entry point and can be
# consumed by other projects (e.g. HexWalk).
set(LIB_SRC_FILES ${ALL_SRC_FILES})
list(FILTER LIB_SRC_FILES EXCLUDE REGEX ".*/main\\.cpp$")

if (UNIX)
    find_package(ZLIB REQUIRED)
    find_package(LibLZMA REQUIRED)
    find_path(LZO_INCLUDE_DIR lzo/lzo1x.h)
    find_library(LZO_LIBRARY NAMES lzo2)
elseif (MINGW)
    # MSYS2/MinGW64: install deps with pacman:
    #   pacman -S mingw-w64-x86_64-zlib mingw-w64-x86_64-xz mingw-w64-x86_64-lzo2
    set(BUILD_SHARED_LIBS OFF)

    # Prefer .a over .dll.a so find_package / find_library return static
    # archives — the default order on MinGW returns .dll.a first.
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a .lib)

    # Bypass find_package(ZLIB): Qt's WrapZLIB has already created the
    # ZLIB::ZLIB imported target pointing at the dynamic import library by
    # the time we get here, and re-finding cannot replace that target. Link
    # the static archive directly via its file path.
    unset(LIBLZMA_LIBRARY CACHE)
    unset(LIBLZMA_LIBRARY_RELEASE CACHE)
    unset(LIBLZMA_LIBRARY_DEBUG CACHE)
    unset(LZO_LIBRARY CACHE)

    find_library(ZLIB_STATIC_LIB NAMES libz.a z REQUIRED)
    find_path(ZLIB_INCLUDE_DIR zlib.h REQUIRED)
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

# OBJECT library — parsers/extractors auto-register via static initialisers in
# anonymous namespaces (REGISTER_PARSER / REGISTER_EXTRACTOR). A conventional
# STATIC archive would let the linker drop those TUs for lack of external refs;
# an OBJECT library feeds every object directly to the consumer's link step.
add_library(hexdig_lib OBJECT ${LIB_SRC_FILES})
target_compile_options(hexdig_lib PRIVATE -O3)
target_include_directories(hexdig_lib PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/parsers"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/extractors"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/utils"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
)

# On MinGW link the static zlib archive directly (see ZLIB_STATIC_LIB above);
# elsewhere keep the conventional ZLIB::ZLIB target.
if(MINGW AND ZLIB_STATIC_LIB)
    target_include_directories(hexdig_lib PUBLIC "${ZLIB_INCLUDE_DIR}")
    target_link_libraries(hexdig_lib PUBLIC "${ZLIB_STATIC_LIB}" LibLZMA::LibLZMA ${LZO_LIBRARY})
else()
    target_link_libraries(hexdig_lib PUBLIC ZLIB::ZLIB LibLZMA::LibLZMA ${LZO_LIBRARY})
endif()

# Standalone executable (unchanged external behaviour).
add_executable(hexdig src/main.cpp)
target_compile_options(hexdig PRIVATE -O3)
target_compile_definitions(hexdig PRIVATE PROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(hexdig PRIVATE hexdig_lib)
target_link_options(hexdig PRIVATE $<$<CONFIG:Release>:-s>)

# Windows: produce a fully self-contained executable. Combined with the
# CMAKE_FIND_LIBRARY_SUFFIXES override above (so zlib/lzma/lzo come in as
# static archives), this leaves only Win32 system DLLs as runtime deps.
if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(hexdig PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
    )
endif()

install(TARGETS hexdig
    RUNTIME DESTINATION bin
)

# Tests only when hexdig is the top-level project — keeps HexWalk's ctest set clean.
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    enable_testing()
    if (UNIX)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        file(GLOB PY_TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.py")
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
endif()