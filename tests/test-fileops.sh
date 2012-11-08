#!/bin/sh

# listing
/bin/ls -al ./crash
# overwriting
echo 1234 > ./crash/abort.c
# creating a new file
echo 5678 > ./crash/test
# reading the overwritten file
/bin/cat ./crash/abort.c
# checking
/bin/ls -al ./crash
# unlinking
/bin/rm ./crash/test