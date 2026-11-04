macOS releases include debug symbols
====================================

Each macOS release now has a debug symbol archive,
`qbit-<version>-x86_64-apple-darwin-debug.tar.gz` and
`qbit-<version>-arm64-apple-darwin-debug.tar.gz`, alongside the Linux and
Windows debug archives. It holds a `.dSYM` bundle for every binary in `bin/`
and `libexec/`. The bundles let `atos`, `lldb` and other macOS tools resolve
the addresses in a crash report to function names, source files and line
numbers. One example is
`atos -o qbit-qt.dSYM/Contents/Resources/DWARF/qbit-qt -arch arm64 -l <load address> <address>`.

A bundle matches a binary when `dwarfdump --uuid` prints the same UUID for
both. Each bundle matches its binary in the release tarball, in the signed
tarball and zip when those are published, and the `qbit-qt` binary inside
`qbit-qt.app`. The release binaries and the other macOS archives are
unchanged.

Releases up to v1.0.0 have no macOS debug archive.
