INCLUDES = -I $(top_srcdir) -I $(top_srcdir)/warmrestart

bin_PROGRAMS = neighsyncd

if DEBUG
DBGFLAGS = -ggdb -DDEBUG
else
DBGFLAGS = -g
endif

neighsyncd_SOURCES = neighsyncd.cpp neighsync.cpp $(top_srcdir)/warmrestart/warmRestartAssist.cpp

neighsyncd_CFLAGS = $(DBGFLAGS) $(AM_CFLAGS) $(CFLAGS_COMMON)
neighsyncd_CPPFLAGS = $(DBGFLAGS) $(AM_CFLAGS) $(CFLAGS_COMMON)
neighsyncd_LDADD = -lnl-3 -lnl-route-3 -lswsscommon

