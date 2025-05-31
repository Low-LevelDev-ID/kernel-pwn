#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "bamcache"
#define CLASS_NAME  "bamcache"

#define OVERFLOW_SZ 0x8

#define CHUNK_SIZE 0x1000
#define MAX 0x1000

#define ALLOC 0xcafe01
#define DELETE 0xcafe02
#define EDIT 0xcafe03

MODULE_DESCRIPTION("a bamcache module, a secluded slab, a marooned memory");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("bam0x7");

typedef struct
{
    int64_t idx;
    uint64_t size;
    char *buf;    
} user_req_t;

typedef struct
{
    char buf[CHUNK_SIZE];
} bamcache_t;

struct bamcache_data
{
    char buf[CHUNK_SIZE];
};
char temp[CHUNK_SIZE];

static DEFINE_MUTEX(bamcache_lock);

bamcache_t **bamcache_arr;

static int bamcache_open(struct inode *inode, struct file *file) {
    return 0;
}

static int bamcache_release(struct inode *inode, struct file *file) {
    return 0;
}
static long bamcache_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static long bamcache_add(int64_t idx);
static long bamcache_delete(int64_t idx);
static long bamcache_edit(int64_t idx, uint64_t size, char *buf);
static long bamcache_read(struct file *file, char __user *buf, size_t count,
                           loff_t *f_pos);
static long bamcache_write(struct file *file, const char __user *buf, size_t count,
                           loff_t *f_pos);                        

static struct miscdevice bamcache_dev;

static struct file_operations bamcache_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = bamcache_ioctl,
    .open = bamcache_open,
    .release = bamcache_release,
    .read = bamcache_read,
    .write = bamcache_write,
};

int64_t bamcache_ctr;

static long bamcache_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    user_req_t req;
    long ret = 0;

    if (cmd != ALLOC && copy_from_user(&req, (void *)arg, sizeof(req)))
    {
        return -1;
    }
    mutex_lock(&bamcache_lock);
    switch (cmd)
    {
        case ALLOC:
            ret = bamcache_add(req.idx);
            break;
        case DELETE:
            ret = bamcache_delete(req.idx);
            break;
        case EDIT:
            ret = bamcache_edit(req.idx, req.size, req.buf);
            break;
        default:
            ret = -1;
    }
    mutex_unlock(&bamcache_lock);
    return ret;
}

static long bamcache_add(int64_t idx)
{
    if (bamcache_ctr >= MAX)
    {
        printk(KERN_INFO "[bamcache]: Cache full, cannot allocate more\n");
        return -1;
    }

    idx = bamcache_ctr;  
    if (bamcache_arr[idx]) 
    {
        printk(KERN_INFO "[bamcache]: Index %lld already allocated\n", idx);
        return -1;
    }

    bamcache_arr[idx] = kzalloc(CHUNK_SIZE, GFP_KERNEL_ACCOUNT);
    if (!bamcache_arr[idx])
    {
        printk(KERN_INFO "[bamcache]: Allocation failed at index %lld\n", idx);
        return -1;
    }

    printk(KERN_INFO "[bamcache]: Successfully allocated index %lld\n", idx);
    bamcache_ctr++; 

    return idx;
}

static long bamcache_delete(int64_t idx)
{
    if (idx < 0 || idx >= MAX || !bamcache_arr[idx])
    {
        printk(KERN_INFO "[bamcache]: Delete failed: invalid index %lld\n", idx);
        return -1;
    }

    kfree(bamcache_arr[idx]);
    printk(KERN_INFO "[bamcache]: Deleted index %lld\n", idx);

    return 0;
}


static long bamcache_edit(int64_t idx, uint64_t size, char *buf)
{
    if (idx < 0 || idx >= MAX || !bamcache_arr[idx])
    {
        printk(KERN_INFO "[bamcache]: Edit failed: invalid index %lld\n", idx);
        return -1;
    }

    if (size > CHUNK_SIZE)
    {
        printk(KERN_INFO "[bamcache]: Edit failed: size %llu too large\n", size);
        return -1;
    }

    if (copy_from_user(temp, buf, size))
    {
        printk(KERN_INFO "[bamcache]: Edit failed: copy_from_user() error\n");
        return -1;
    }

    memcpy(bamcache_arr[idx]->buf, temp, size);
    bamcache_arr[idx]->buf[CHUNK_SIZE] = '\x00';
    printk(KERN_INFO "[bamcache]: Edited index %lld, size %llu\n", idx, size);

    return size;
}

static long bamcache_read(struct file *file, char __user *buf, size_t count,
                           loff_t *f_pos) {

    if(count > CHUNK_SIZE){
        printk(KERN_INFO "invalid buffer size\n");
        return -EINVAL;
    }        

    if (copy_to_user(buf, temp, count)) {
        printk(KERN_INFO "copy_to_user failed\n");
        return -EINVAL;
    }

    return count;       
    
}

static long bamcache_write(struct file *file, const char __user *buf, size_t count,
                           loff_t *f_pos) {

    if(count > CHUNK_SIZE){
        printk(KERN_INFO "invalid buffer size\n");
        return -EINVAL;
    }        
   
    if (copy_from_user(temp, buf, count)) {
        printk(KERN_INFO "copy_to_user failed\n");
        return -EINVAL;
    }

    return count;       
    
}


static int init_bamcache_driver(void)
{
    bamcache_dev.minor = MISC_DYNAMIC_MINOR;
    bamcache_dev.name = DEVICE_NAME;
    bamcache_dev.fops = &bamcache_fops;
    bamcache_dev.mode = 0666;

    mutex_init(&bamcache_lock);
    if (misc_register(&bamcache_dev))
    {
        return -1;
    }
    bamcache_arr = kzalloc(MAX * sizeof(bamcache_t *), GFP_KERNEL);
    if (!bamcache_arr)
    {
        return -1;
    }

    bamcache_ctr = 1;

    printk(KERN_INFO "All alone in a bamcache... \n");
    printk(KERN_INFO "[bamcache]: There's no way a pwner can escape!\n");
    return 0;
}

static void cleanup_bamcache_driver(void)
{
    int i;
    misc_deregister(&bamcache_dev);
    mutex_destroy(&bamcache_lock);
    for (i = 0; i < MAX; i++)
    {
        if (bamcache_arr[i])
        {
            kfree(bamcache_arr[i]);
        }
    }
    kfree(bamcache_arr);
    printk(KERN_INFO "[bamcache]: Guess you remain in bamcache\n");
}

module_init(init_bamcache_driver);
module_exit(cleanup_bamcache_driver);
