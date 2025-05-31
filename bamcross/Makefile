# Nama file modul
obj-m := bamcache.o

# Path kernel yang sudah dibuild
KERNEL_DIR := ~/bam/kernel/linux-5.16.14

# Path header yang sudah diinstall
HEADER_DIR := /home/bam/header-5.16.14

# Aturan untuk kompilasi modul
all:
	make -C $(KERNEL_DIR) M=$(PWD) INSTALL_HDR_PATH=$(HEADER_DIR) modules

# Aturan untuk membersihkan hasil build
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
