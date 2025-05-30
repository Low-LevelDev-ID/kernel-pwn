#!/bin/sh

mkdir rootfs
cd rootfs
cp ../rootfs.cpio .
gunzip ./rootfs.cpio
cpio -idv < ./rootfs.cpio
rm rootfs.cpio
