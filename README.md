# HexDig



🔍 **HexDig** is a fast, extensible tool for scanning, inspecting, and extracting embedded data from binary files and firmware images.



Inspired by tools like **binwalk**, HexDig focuses on modern workflows, clear output, and hackable internals—making it ideal for reverse engineers, firmware analysts, and security researchers.



---



## ✨ Features



- 🧠 Scan binary files for embedded file signatures

- 🧩 Identify compressed data, file systems, and common firmware formats

- 📦 Extract discovered data automatically or selectively

- 🧪 Analyze raw binaries and hex-level structures

- ⚡ Fast scanning with minimal dependencies

- 🔌 Plugin-friendly architecture (WIP)



---



## 🚀 Installation



### Quick install (Linux)

The `install.sh` script detects your distribution, installs the build
dependencies, then builds and installs HexDig with CMake. Supported
families: Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE, Alpine.

```bash

git clone https://github.com/gcarmix/hexdig.git

cd hexdig

./install.sh

```

Useful flags:

- `-y`, `--yes` — non-interactive (don't prompt before installing packages)
- `--no-install` — only build the binary, don't run `cmake --install`
- `--prefix=/path` — set a custom `CMAKE_INSTALL_PREFIX`
- `-h`, `--help` — show usage



### From source



```bash

git clone https://github.com/gcarmix/hexdig.git

cd hexdig

cmake -B build

cmake --build build -j

sudo cmake --install build

```

Build dependencies: a C++17 compiler, CMake (>= 3.12), `pkg-config`, and
the development headers for `zlib`, `liblzma` (xz) and `lzo2`. On
Debian/Ubuntu:

```bash

sudo apt install build-essential cmake pkg-config \
                 zlib1g-dev liblzma-dev liblzo2-dev

```



### Debian / Ubuntu package

To produce a `.deb`, install the packaging tools and run:

```bash

sudo apt install dpkg-dev debhelper devscripts cmake fakeroot lintian \
                 zlib1g-dev liblzma-dev liblzo2-dev pkg-config

./build-deb.sh --lintian

```



### Windows (MSYS2 / MinGW64) — recommended

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



### Windows (standalone MinGW)

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



> MSVC is not currently supported — the build relies on `-static` and
> a few GCC-specific linker flags. Use MinGW (via MSYS2 or standalone).



> Installation instructions may change as HexDig evolves.  

> Packaging support (pip, cargo, apt, etc.) is planned.



---



## 🛠 Usage



### Basic scan

```bash

hexdig firmware.bin

```



### Scan with extraction

```bash

hexdig -e firmware.bin

```


### Show detailed output

```bash

hexdig -v firmware.bin

```



---



## 📄 Example Output



```text

* ../inputs/openwrt-18.06.3-mediatek-mt7623-7623n-bananapi-bpi-r2-initramfs-kernel.bin
└── [0x0000] UIMAGE (length=4259578)
    Source: ../inputs/openwrt-18.06.3-mediatek-mt7623-7623n-bananapi-bpi-r2-initramfs-kernel.bin  
    Info: UImage: ARM OpenWrt Linux-4.14.128, timestamp=2019-06-21
          12:17:25 UTC, OS=Linux, CPU=ARM, Type=Kernel,
          Compression=None
    ├── [0x3c38] XZ (length=4220724)
    │   Source: extractions/openwrt-18.06.3-mediatek-mt7623-7623n-bananapi-bpi-r2-initramfs-kernel.bin.extracted/0/ARM OpenWrt Linux-4.14.128.bin
    │   Info: XZ compressed stream, total size: 4220724 bytes
    └── [0x40a3ac] DTB (length=23434)
        Source: extractions/openwrt-18.06.3-mediatek-mt7623-7623n-bananapi-bpi-r2-initramfs-kernel.bin.extracted/0/ARM OpenWrt Linux-4.14.128.bin
        Info: Device Tree Blob

```



---



## 🔧 Configuration



HexDig supports configuration via:

- Command-line flags

- Environment variables (planned)

- Config file support (planned)



Run `hexdig --help` for all available options.



---



## 🧩 Supported Parsers


- AES
- Android Sparse
- ARJ
- BMP
- BZIP2
- CAB
- CPIO
- CRAMFS
- CRC
- DEB
- DTB
- ELF
- FAT
- GIF
- GZIP
- JPG
- Linux
- LZMA
- MBR
- PDF
- PE
- PNG
- RAR
- ROMFS
- 7Z
- SquashFS
- TAR
- UImage
- UBI
- XZ
- ZIP


> More formats are continuously being added.



---



## 🧪 Development Status



⚠️ **HexDig is under active development.**  

APIs, output formats, and features may change.



Contributions, feedback, and testing are very welcome.



---



## 🤝 Contributing



Contributions are encouraged!



1\. Fork the repository

2\. Create a feature branch

3\. Commit your changes

4\. Open a pull request



Please include:

- Clear commit messages

- Tests when applicable

- Documentation updates for new features



---



## 📜 License



HexDig is released under the **GPL-3.0 License**.  

See the [LICENSE](LICENSE) file for details.



---



## 🙏 Acknowledgements



- Inspired by **binwalk**

- Thanks to the firmware reverse-engineering and open-source security communities



---



## 📫 Contact



Have ideas, bugs, or feature requests?  

Open an issue or start a discussion on GitHub.



Happy digging 🧑‍💻
