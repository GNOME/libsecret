include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/libsecret \
	-DSECRET_COMPILATION \
	$(NULL)

bin_PROGRAMS = secret-tool

secret_tool_SOURCES = \
	secret-tool.c

secret_tool_LDADD = \
	$(top_builddir)/libsecret/libsecret-0.la
