src=/tmp/test

mntpnt=/home/dsk/mntpnt

sudo umount -l -f $mntpnt 2> /dev/null

rm -rf $src

mkdir -p $src 2> /dev/null

mount.sh $src $mntpnt

if [ $? -ne 0 ]
then
    echo  "problems found ... bailing out!"
    exit $?
fi    

cd $mntpnt;
echo "1" > test.txt; echo "2" > test.txt; echo "3" > test.txt; echo "4" > test.txt; echo "5" > test.txt; echo "6" > test.txt; echo "7" > test.txt; echo "8" > test.txt; 


echo "Demo Staged!"
