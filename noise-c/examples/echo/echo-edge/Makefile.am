
AUTOMAKE_OPTIONS = subdir-objects

noinst_PROGRAMS = echo-edge

echo_edge_SOURCES = echo-edge.c ../echo-server/echo-common.c

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir)/../echo-server
AM_CFLAGS = @WARNING_FLAGS@

LDADD = ../../../src/protocol/libnoiseprotocol.a
