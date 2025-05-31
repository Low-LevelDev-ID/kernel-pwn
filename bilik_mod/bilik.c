#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/numa.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "bilik"
#define CLASS_NAME "bilik"

MODULE_DESCRIPTION("bilik challenge");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("bam0x7");

static DEFINE_MUTEX(bilik_lock);

#define MAX_IDX 100

#define ALLOC_SIZE 1024
#define MAX_BUFF 1024

#define BILIK_ADD 0xb45001
#define BILIK_DEL 0xb45002
#define BILIK_DUP 0xb45003


int count_ = 1;
int idx = 0;

char *buff = NULL;
char __user u_buff[MAX_BUFF];
char *copy_buff = NULL;

static long bilik_ioctl(struct file *__file, unsigned int cmd, unsigned long arg);
static long bilik_add(char __user u_buff[MAX_BUFF]);
static long bilik_del(void);
static long bilik_dup(void);

static struct file_operations bilik_fops = {

    .owner = THIS_MODULE,
    .unlocked_ioctl = bilik_ioctl
    };

static long bilik_ioctl(struct file *__file, unsigned int cmd, unsigned long arg)
{
    int ret;

    if(copy_from_user(u_buff, (void *)arg, sizeof(arg))) {
        printk(KERN_INFO "copy_from_user failed\n");
        return -EINVAL;
    }

    mutex_lock(&bilik_lock);
    
    switch(cmd)
    {
        case BILIK_ADD:
            ret = bilik_add(u_buff);
            break;
        case BILIK_DEL:
            ret = bilik_del();
            break;
        case BILIK_DUP:
            ret = bilik_dup();    
            break;
        default:
            ret = -1;     
    }
    mutex_unlock(&bilik_lock);
    return ret;
}

static long bilik_add(char __user u_buff[MAX_BUFF])
{

    if(count_ >= MAX_IDX){
        printk(KERN_INFO "bilik: INDEX FAILED");
        return -1;
    }

    buff = kzalloc(ALLOC_SIZE, GFP_KERNEL_ACCOUNT);
    count_++;

    if(!buff){
        printk(KERN_INFO "bilik: ALLOCATION FAILED");
        return -1;
    }
    memcpy(buff,u_buff,MAX_BUFF);
    //buff[MAX_BUFF] = '\0';

    printk(KERN_INFO "bilik: allocated!!");
    return 0;
}

static long bilik_del(void)
{
    if(!count_){
        printk(KERN_INFO "bilik: already free!!");
        return -1;
    }

    printk(KERN_INFO "bilik: iam free:)");
    kfree(buff);
    count_--;
    return 0;
}

static long bilik_dup()
{
    if(buff == NULL){
        printk(KERN_INFO "bilik: buff already free:(");
        return -1;
    }
    copy_buff = buff;
    printk(KERN_INFO "bilik: duplicate the buff");
    return 0;
}

static struct miscdevice bilik_dev;

static int init_bilik(void)
{
    bilik_dev.minor = MISC_DYNAMIC_MINOR;
    bilik_dev.name = DEVICE_NAME;
    bilik_dev.fops = &bilik_fops;
    bilik_dev.mode = 0666;

    mutex_init(&bilik_lock);

    if(misc_register(&bilik_dev)){
        printk(KERN_INFO "bilik: registering failed");
        return -1;
    }

    printk(KERN_INFO "Ready to pwn, good luck:)");

    return 0;
}

static void bilik_cleanup(void)
{
    misc_deregister(&bilik_dev);
    mutex_destroy(&bilik_lock);

    printk(KERN_INFO "goodbye:)\n");
}

module_init(init_bilik);
module_exit(bilik_cleanup);