/*
 * Oars vendored-build configuration for libssh2.
 *
 * libssh2 ships without a usable config header for manual builds
 * (autotools/CMake generate libssh2_config.h from the .in template).
 * This is our generated equivalent: a minimal POSIX + mbedTLS
 * configuration that builds with zig cc on macOS and Linux.
 */
#ifndef OARS_LIBSSH2_CONFIG_H
#define OARS_LIBSSH2_CONFIG_H

/* Crypto backend: mbedTLS (vendored, third_party/mbedtls). */
#define LIBSSH2_MBEDTLS 1

/* C89/C99 standard headers. */
#define STDC_HEADERS 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_ERRNO_H 1
#define HAVE_FCNTL_H 1
#define HAVE_DLFCN_H 1
#define HAVE_ALLOCA_H 1
#define HAVE_ALLOCA 1
#define HAVE_UNISTD_H 1

/* POSIX networking. */
#define HAVE_SYS_SOCKET_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_SYS_UIO_H 1

/* Functions libssh2 uses for timers, sleeping and non-blocking sockets. */
#define HAVE_GETTIMEOFDAY 1
#define HAVE_POLL 1
#define HAVE_SELECT 1
#define HAVE_SNPRINTF 1
#define HAVE_STRTOLL 1
#define HAVE_O_NONBLOCK 1

/* explicit_bzero/memset_s are feature-test-gated on macOS and Zig's
   clang does not enable the macro that exposes them; libssh2 falls
   back to its own memory-clearing loop, which is what we want here. */
/* #undef HAVE_EXPLICIT_BZERO */
/* #undef HAVE_EXPLICIT_MEMSET */
/* #undef HAVE_MEMSET_S */

/* zlib compression is intentionally not compiled in. */
/* #undef LIBSSH2_HAVE_ZLIB */

#define VERSION "1.11.1"

#endif /* OARS_LIBSSH2_CONFIG_H */
