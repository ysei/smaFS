#!/bin/bash

src=$1
mp=/home/dsk/mntpnt


if [ $# -lt 2 ]
then
    echo "Usage: $0 <source> <mount point>"
    exit -1
fi

echo "Mounting $1 at $2"
./smaFS -omodules=subdir,subdir=$1 $2 -o default_permissions,allow_other

exit $?
