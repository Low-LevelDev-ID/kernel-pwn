#!/bin/sh

mkdir rootfs
cd rootfs
cp ../rootfs.cpio.gz .
gunzip ./rootfs.cpio.gz
cpio -idv < ./rootfs.cpio.gz
