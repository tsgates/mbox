#!/bin/sh -x
#
# pre: test -d doc
# post: test -f doc/process_events.rst
# post: test -f doc/ptrace_signal.rst
#

ls -al doc
pwd
cd ..
pwd
cd /tmp
pwd
ls
pwd
cd -
pwd
cd doc
pwd
ls -al .