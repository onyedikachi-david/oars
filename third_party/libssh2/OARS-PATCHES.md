# Oars security backports

Base release: libssh2 1.11.1. The version string identifies the upstream base;
these fixes are included in Oars' statically linked build.

- CVE-2026-55200: reject an oversized full-packet cipher length before size
  arithmetic and allocation. Backport of upstream
  [`97acf3d`](https://github.com/libssh2/libssh2/commit/97acf3dfda80c91c3a8c9f2372546301d4a1a7a8).
- CVE-2026-55199: stop parsing EXT_INFO when a claimed name/value pair is
  truncated. Backport of upstream
  [`1762685`](https://github.com/libssh2/libssh2/commit/17626857d20b3c9a1addfa45979dadcee1cd84a4).
- CVE-2025-15661: check the declared READLINK/REALPATH result length against
  the received packet before copying. Adapted from upstream
  [`2dae302`](https://github.com/libssh2/libssh2/commit/2dae3024897e1898d389835151f4e9606227721d).
  The local backport retains 1.11.1's status/request-ID parsing and adds the
  missing response-data bound after its existing 13-byte header check.
