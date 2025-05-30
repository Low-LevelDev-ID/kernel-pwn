#define _GNU_SOURCE
#define FUSE_USE_VERSION 29
#include<fuse.h>
#include<errno.h>
#include<assert.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/ioctl.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<sys/mman.h>
#include<fcntl.h>
#include<pthread.h>
#include<sched.h>
#include<signal.h>

static const char *context = "hello, world!\n";
static int getattr_callback(const char *path,  struct stat *statbuf)
{
    puts("[+] getattr_calback");
    memset(statbuf,0,sizeof(struct stat)); 

    /* Memeriksa apakah jalur dari titik mount adalah "/file" */
    if(strcmp(path,"/file")==0){
        statbuf->st_mode = S_IFREG | 0777; //izin
        statbuf->st_nlink = 1; //jumlah hardlink
        statbuf->st_size = strlen(context); //ukuran berkas
        return 0;
    }   

    return -ENOENT;
}

static int open_callback(const char *path, struct fuse_file_info *file_info)
{
    puts("[+] open callback");
    return 0;
}

static int read_callback(const char *path,char *buf, size_t size,
            off_t offset, struct fuse_file_info *file_info)
{
    puts("[+] read callback");
    if(strcmp(path,"/file")==0){
        size_t len = strlen(context);
        if(offset >= len){
            return 0;
        }
        /* Mengembalikan data */
        if((size > len) || (offset + size > len)){
            memcpy(buf,context + offset,len - offset);
            return len - offset;
        }else{
            memcpy(buf,context + offset, size);
            return size;
        }
    }

    return -ENOENT;
}            

static struct fuse_operations fops = {
    .getattr = getattr_callback,
    .open = open_callback,
    .read = read_callback,
};

int main(int argc, char *argv[])
{
    return fuse_main(argc,argv,&fops,NULL);
}