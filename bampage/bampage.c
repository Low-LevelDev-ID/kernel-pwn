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

#define ALLOC_SIZE 4096
#define IDX_NUM 256

#define BAM_ALLOC 0xbad1
#define BAM_EDIT  0xbad2
#define BAM_DELETE 0xbad3

struct bam_item {
    char *buf;
    size_t size;
};

static struct bam_item bam_list[IDX_NUM];
static DEFINE_MUTEX(bam_lock);

static int bam_open(struct inode *inode, struct file *file) {
    return 0;
}

static int bam_release(struct inode *inode, struct file *file) {
    return 0;
}

static long bam_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    
    struct{
        int idx;
        size_t sz;
        char __user *buf;
    }usr_cmd;

    char *bam_buf;
    size_t size;
    int retval = -EINVAL;

    if (copy_from_user(&usr_cmd, (void __user *)arg, sizeof(usr_cmd)))
        return -EFAULT;

    mutex_lock(&bam_lock);

    switch (cmd) {
    case BAM_ALLOC:
        if (usr_cmd.idx < 0 || usr_cmd.idx >= IDX_NUM || bam_list[usr_cmd.idx].buf) {
            printk(KERN_ALERT "[bam:] Invalid index or already allocated.\n");
            break;
        }

        bam_list[usr_cmd.idx].buf = (void*)__get_free_page(GFP_KERNEL);
        if (!bam_list[usr_cmd.idx].buf) {
            printk(KERN_ALERT "[bam:] Allocation failed.\n");
            break;
        }

        bam_list[usr_cmd.idx].size = 0;
        retval = 0;
        break;

    case BAM_EDIT:
        if (usr_cmd.idx < 0 || usr_cmd.idx >= IDX_NUM || !bam_list[usr_cmd.idx].buf) {
            printk(KERN_ALERT "[bam:] Invalid index to edit.\n");
            break;
        }

        if (usr_cmd.sz > ALLOC_SIZE || (usr_cmd.sz + bam_list[usr_cmd.idx].size) >= ALLOC_SIZE) {
            size = ALLOC_SIZE - bam_list[usr_cmd.idx].size;
        } else {
            size = usr_cmd.sz;
        }

        bam_buf = bam_list[usr_cmd.idx].buf;
        bam_buf += bam_list[usr_cmd.idx].size;

        if (copy_from_user(bam_buf, usr_cmd.buf, size)) {
            printk(KERN_ALERT "[bam:] Copy from user failed.\n");
            break;
        }

        retval = 0;
        break;

    case BAM_DELETE:
        if (usr_cmd.idx < 0 || usr_cmd.idx >= IDX_NUM || !bam_list[usr_cmd.idx].buf) {
            printk(KERN_ALERT "[bam:] Invalid index to delete.\n");
            break;
        }

        free_page((unsigned long)bam_list[usr_cmd.idx].buf);

        retval = 0;
        break;

    default:
        printk(KERN_ALERT "[bam:] Unknown command.\n");
        break;
    }

    mutex_unlock(&bam_lock);
    return retval;

}

static const struct file_operations bam_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = bam_ioctl,
    .open = bam_open,
    .release = bam_release,
};

#define DEVICE_NAME "bampage"
#define CLASS_NAME DEVICE_NAME

static struct miscdevice bam_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &bam_fops,
    .mode = 0666,
};

static int __init bam_module_init(void) {

    if(misc_register(&bam_device)){
        printk(KERN_INFO "bam: registering failed");
        return -1;
    }    

    mutex_init(&bam_lock);

    memset(bam_list, 0, sizeof(bam_list));
    printk(KERN_INFO "[bam:] Module loaded successfully.\n");
    return 0;
}

static void __exit bam_module_exit(void) {

    misc_deregister(&bam_device);
    mutex_destroy(&bam_lock);
    printk(KERN_INFO "[bam:] Module unloaded successfully.\n");
}

module_init(bam_module_init);
module_exit(bam_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bamCTF");
MODULE_DESCRIPTION("Kernel module for CTF challenges.");
