# qbit Releases

This directory contains public release and verification guidance for qbit source
and binary artifacts.

For the normal public release process, see [release-process.md](release-process.md).

The release process includes the fail-closed qbit P2MR v1 mainnet gate. The
[evidence JSON](examples/p2mr-v1-conformance-evidence.json) is a field example
only: its zero hashes and `example.invalid` references deliberately cannot
validate. The checked-in [integration support
matrix](../integration/p2mr-v1-support-matrix.md) is likewise a draft until a
final external snapshot is completed for an exact signed release tag target.

For release binaries:

- download artifacts from the matching qbit GitHub Release
- verify `SHA256SUMS.asc` against `SHA256SUMS`
- verify downloaded files against `SHA256SUMS`

For public release and builder key metadata, see
[/contrib/keys/README.md](/contrib/keys/README.md).

Release execution runbooks, launch signoff, and key-custody procedures are
internal operational materials and are not part of the public documentation
surface.
