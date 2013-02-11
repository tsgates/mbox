#!/bin/bash -x
#
# pre: test ! -d nosuchadir
# post: test ! -d $SPWD/nosuchadir
# post: test ! -d $HPWD/nosuchadir
#

mkdir nosuchadir
ls nosuchadir
rmdir nosuchadir