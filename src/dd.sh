#!/bin/bash

### run after demo-stage.sh ###

f1=random_dump
f2=urandom_dump

mp=/home/dsk/mntpnt

dd if=/dev/zero of=$f1 bs=1M count=64 
dd if=/dev/urandom of=$f2 bs=1M count=8 

echo

echo "original checksum for $f1 =" `md5sum $f1`
echo "original checksum for $f2 =" `md5sum $f2`

cp $f1 $mp
cp $f2 $mp

echo 

echo "checksum on smaFS for $f1 =" `md5sum $mp/$f1`
echo "checksum on smaFS for $f2 =" `md5sum $mp/$f2`
