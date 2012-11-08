#!/bin/sh

# creating new file
echo 1234 > ./crash/newfile
# checking
ls crash
# unlinking the existing file
rm ./crash/abort.c
# unlinking the new file
rm ./crash/newfile
# double checking
ls crash