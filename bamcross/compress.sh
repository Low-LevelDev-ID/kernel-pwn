#!/bin/sh
gcc -o exp-file exp-file.c -static $1
mv ./exp-file ./rootfs
cd rootfs
find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs.cpio
