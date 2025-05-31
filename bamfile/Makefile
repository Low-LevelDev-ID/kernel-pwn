# Nama file modul
obj-m := bamfile.o

# Path kernel yang sudah dibuild
KERNEL_DIR := ~/bam/kernel/linux-6.6.31

ccflags-y += -Wno-unused-result

# Path header yang sudah diinstall
HEADER_DIR := /home/bam/header-6.6.31

# Aturan untuk kompilasi modul
all:
	make -C $(KERNEL_DIR) M=$(PWD) INSTALL_HDR_PATH=$(HEADER_DIR) modules

# Aturan untuk membersihkan hasil build
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
