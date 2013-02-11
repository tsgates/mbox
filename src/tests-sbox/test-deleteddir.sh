#!/bin/bash -x
#
# pre: test ! -d nosuchadir
# post: test ! -d $SPWD/nosuchadir
# post: test ! -d $HPWD/nosuchadir
# post: grep -q "No such file" $SPWD/err-rmdir
#

# create a new dir
mkdir nosuchadir

# create a new file in the dir
echo 123 > nosuchadir/newfile
ls nosuchadir

# delete them all
rm nosuchadir/newfile
rmdir nosuchadir
rmdir nosuchadir &> err-rmdir

exit 0