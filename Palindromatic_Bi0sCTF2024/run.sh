#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -cpu kvm64,+smep,+smap \
    -kernel bzImage \
    -drive file=initramfs.cpio.gz,format=raw \
    -drive file=exploit,format=raw \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "root=/dev/sda rw init=/init console=ttyS0 kaslr kpti=1 loglevel=3 oops=panic panic=-1"
