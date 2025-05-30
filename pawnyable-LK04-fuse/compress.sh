#!/bin/sh
gcc exp1.c -o exp1 -D_FILE_OFFSET_BITS=64 -lfuse -static $1
mv ./exp1 ./rootfs
cd rootfs
find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs_updated.cpio
