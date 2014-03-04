noinst_LTLIBRARIES += \
	libegg.la

EXTRA_DIST += egg/egg-testing.h

if WITH_GCRYPT
ENCRYPTION_SRCS = egg/egg-dh.c egg/egg-dh.h
ENCRYPTION_SRCS += egg/egg-hkdf.c egg/egg-hkdf.h
ENCRYPTION_SRCS += egg/egg-libgcrypt.c egg/egg-libgcrypt.h
else
ENCRYPTION_SRCS =
endif

libegg_la_SOURCES = \
	egg/egg-hex.c egg/egg-hex.h \
	egg/egg-secure-memory.c egg/egg-secure-memory.h \
	egg/egg-testing.c egg/egg-testing.h \
	$(ENCRYPTION_SRCS)

egg_LIBS =  \
	libegg.la \
	$(LIBGCRYPT_LIBS) \
	$(GLIB_LIBS)

egg_TESTS = \
	test-hex \
	test-secmem

test_hex_SOURCES = egg/test-hex.c
test_hex_LDADD = $(egg_LIBS)

test_secmem_SOURCES = egg/test-secmem.c
test_secmem_LDADD = $(egg_LIBS)

if WITH_GCRYPT
egg_TESTS += test-hkdf test-dh

test_hkdf_SOURCES = egg/test-hkdf.c
test_hkdf_LDADD = $(egg_LIBS)

test_dh_SOURCES = egg/test-dh.c
test_dh_LDADD = $(egg_LIBS)
endif

check_PROGRAMS += $(egg_TESTS)
TESTS += $(egg_TESTS)
