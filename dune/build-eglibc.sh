#!/bin/sh

# TODO: Check that svn, patch, and make are installed on the system

# Comment/Uncomment the following svn line for first time installation.
# fix the error mentioned in the link before install 
# https://stackoverflow.com/questions/46534957/configure-error-these-critical-programs-are-missing-or-too-old-gcc-make-w

svn co svn://svn.eglibc.org/branches/eglibc-2_14 eglibc-2.14

# Following line is added to set CFLAGS
export CFLAGS="-U_FORTIFY_SOURCE -O2 -fno-stack-protector"
cd eglibc-2.14/libc
cat ../../eglibc-2.14.diff | patch -p2 -d ./
mkdir ../eglibc-build
cd ../eglibc-build
../libc/configure --disable-sanity-checks
make

