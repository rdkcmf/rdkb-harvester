AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CPPFLAGS = -Wall -g -Werror
AM_CXXFLAGS = -std=c++11

ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = harvester_gtest.bin
harvester_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest -I${top_srcdir}/gtest/include -I${top_srcdir}/source -I${top_srcdir}/source/include
harvester_gtest_bin_SOURCES =  harvesterTest.cpp\
                               gtest_main.cpp
harvester_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -lpthread
