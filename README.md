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



### Pre-built releases (easiest)

Pre-built binaries for the latest version are attached to the
[GitHub releases page](https://github.com/gcarmix/hexdig/releases/latest):

- 🐧 **Debian / Ubuntu** — `hexdig_<version>_amd64.deb`

  ```bash

  sudo dpkg -i hexdig_*_amd64.deb

  sudo apt-get install -f   # only if needed

  ```

- 🪟 **Windows** — decompress `hexdig_<version>_win_x64_portable.zip`, and start using it by running `hexdig.exe`a standalone static binary.
7Zip executable and DLL are provided for extraction functionalities



### Quick install (Linux, build from source)

For other Linux distributions, the `install.sh` script detects your
distribution, installs the build dependencies, then builds and installs
HexDig with CMake. Supported families: Debian/Ubuntu, Fedora/RHEL, Arch,
openSUSE, Alpine.

```bash

git clone https://github.com/gcarmix/hexdig.git

cd hexdig

./install.sh

```

Useful flags:

- `-y`, `--yes` — non-interactive (don't prompt before installing packages)
- `--no-install` — only build the binary, don't run `cmake --install`
- `--prefix=/path` — set a custom `CMAKE_INSTALL_PREFIX`
- `--uninstall` — remove a previously installed copy
- `-h`, `--help` — show usage



### Build from source manually

Build dependencies: a C++17 compiler, CMake (>= 3.12), `pkg-config`, and
the development headers for `zlib`, `liblzma` (xz) and `lzo2`.

```bash

git clone https://github.com/gcarmix/hexdig.git

cd hexdig

cmake -B build

cmake --build build -j

sudo cmake --install build

```



### Other build paths

- 🪟 **Windows from source (MinGW)** — see [docs/building-windows.md](docs/building-windows.md)
- 📦 **Build a `.deb` yourself** — see [docs/packaging-deb.md](docs/packaging-deb.md)



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
- MachO
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
