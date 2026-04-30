# Building HexDig on Windows

> **Just want to use HexDig on Windows?** Download `hexdig.exe` from the
> [latest release](https://github.com/gcarmix/hexdig/releases/latest).
> The binary is statically linked and runs without any extra setup.

HexDig builds on Windows with **MinGW-w64**, either from MSYS2
(recommended) or with a standalone MinGW toolchain. **MSVC is not
currently supported** — the build relies on `-static` and a few
GCC-specific linker flags.

## MSYS2 / MinGW64 (recommended)

Install [MSYS2](https://www.msys2.org/), open the **MSYS2 MinGW 64-bit**
shell, then install the toolchain and dependencies:

```bash
pacman -S --needed git \
        mingw-w64-x86_64-toolchain \
        mingw-w64-x86_64-cmake \
        mingw-w64-x86_64-pkgconf \
        mingw-w64-x86_64-zlib \
        mingw-w64-x86_64-xz \
        mingw-w64-x86_64-lzo2
```

Then build (still inside the MinGW64 shell):

```bash
git clone https://github.com/gcarmix/hexdig.git
cd hexdig
cmake -B build -G "MinGW Makefiles"
cmake --build build -j
```

The resulting `build/hexdig.exe` is statically linked, so it can be
copied and run on Windows machines without MSYS2 installed.

## Standalone MinGW

If you want to build outside MSYS2 with a plain MinGW-w64 toolchain,
the `CMakeLists.txt` looks for the dependencies under `C:\devlibs\`:

```text
C:\devlibs\zlib\include\         zlib.h
C:\devlibs\zlib\lib\             libz.a
C:\devlibs\liblzma\include\      lzma.h
C:\devlibs\liblzma\lib\          liblzma.a
C:\devlibs\lzo\include\          lzo\lzo1x.h
C:\devlibs\lzo\lib\              liblzo2.a
```

Once those are in place, build with:

```bat
cmake -B build -G "MinGW Makefiles"
cmake --build build -j
```
