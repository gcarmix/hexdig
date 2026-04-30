# Building a Debian / Ubuntu .deb package

> **Just want to install HexDig on Debian/Ubuntu?** Download the
> `.deb` from the [latest release](https://github.com/gcarmix/hexdig/releases/latest)
> and run:
>
> ```bash
> sudo dpkg -i hexdig_*_amd64.deb
> sudo apt-get install -f    # only if dependencies need resolving
> ```

This document is for building the `.deb` yourself from source.

## Build dependencies

```bash
sudo apt install dpkg-dev debhelper devscripts cmake fakeroot lintian \
                 zlib1g-dev liblzma-dev liblzo2-dev pkg-config
```

## Build

```bash
./build-deb.sh --lintian
```

The script stages a clean source copy, builds the orig tarball, runs
`dpkg-buildpackage`, and prints the path to the resulting `.deb`,
`.changes`, and `.tar.xz` artefacts.

### Flags

- `--source` — also build the source package (`.dsc` + `.tar.xz`)
- `--lintian` — run lintian on the resulting `.changes` file

## Debian Policy notes

The `debian/` directory follows Debian Policy and is suitable for an
upload to the Debian archive after sponsorship:

- `3.0 (quilt)` source format
- DEP-5 machine-readable copyright (GPL-3)
- `dh` sequencer with `--buildsystem=cmake`
- Manpage installed at `/usr/share/man/man1/hexdig.1.gz`
- `Standards-Version: 4.7.0`

For a real Debian upload, file an ITP bug on `wnpp` and add
`(Closes: #NNNNNN)` to the first entry of `debian/changelog`.

## Known lintian notes

- `groff-message: troff: Segmentation fault` is suppressed via
  `debian/hexdig.lintian-overrides` — it is a known interaction
  between the `/usr/bin/man` AppArmor profile on Ubuntu and lintian's
  sandbox ([Debian #1056196](https://bugs.debian.org/1056196)),
  not an issue with the manpage itself.
- `initial-upload-closes-no-bugs` will appear until the first upload
  closes its ITP bug.
