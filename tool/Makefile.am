bin_PROGRAMS += tool/secret-tool

tool_secret_tool_SOURCES = \
	tool/secret-tool.c

tool_secret_tool_LDADD = \
	libsecret-@SECRET_MAJOR@.la

if WITH_GCRYPT
TESTS += tool/test-secret-tool.sh
endif

check_SCRIPTS += tool/test-secret-tool.sh
