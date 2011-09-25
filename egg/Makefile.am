
noinst_LTLIBRARIES = \
	libegg.la

INCLUDES = \
	-I$(top_srcdir)

if WITH_GCRYPT
ENCRYPTION_SRCS = egg-dh.c egg-dh.h
ENCRYPTION_SRCS += egg-hkdf.c egg-hkdf.h
ENCRYPTION_SRCS += egg-libgcrypt.c egg-libgcrypt.h
else
ENCRYPTION_SRCS =
endif

libegg_la_SOURCES = \
	egg-secure-memory.c egg-secure-memory.h \
	$(ENCRYPTION_SRCS) \
	$(BUILT_SOURCES)