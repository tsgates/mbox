#!/bin/bash -x
#
# pre: test ! -d nosuchadir
# post: test -d $SPWD/nosuchadir
#

mkdir nosuchadir
ls nosuchadir