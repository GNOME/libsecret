SUBDIRS = . tests

noinst_LTLIBRARIES = \
	libegg.la

EXTRA_DIST = egg-testing.h

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/build \
	-DWITH_VALGRIND

if WITH_GCRYPT
ENCRYPTION_SRCS = egg-dh.c egg-dh.h
ENCRYPTION_SRCS += egg-hkdf.c egg-hkdf.h
ENCRYPTION_SRCS += egg-libgcrypt.c egg-libgcrypt.h
else
ENCRYPTION_SRCS =
endif

libegg_la_SOURCES = \
	egg-hex.c egg-hex.h \
	egg-secure-memory.c egg-secure-memory.h \
	egg-testing.c egg-testing.h \
	$(ENCRYPTION_SRCS) \
	$(BUILT_SOURCES)

check-memory:
	make -C tests check-memory