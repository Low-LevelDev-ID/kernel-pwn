#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/anon_inodes.h>

static DEFINE_MUTEX(bam_lock);

ssize_t bam_file_read(struct file *filp, char __user *buf, size_t sz, loff_t *off) {
	char msg[] = "🤓";
	(void)copy_to_user(buf, msg, sizeof(msg));
	return sizeof(msg);
}

const struct file_operations bam_file_fops = {
	.owner = THIS_MODULE,
	.read = bam_file_read
};

unsigned enabled = 1;

static long bam_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	long ret = -EINVAL;
	struct file *myfile;
	int fd;

	if (!enabled) {
		goto out;
	}
	enabled = 0;

    myfile = anon_inode_getfile("[bamfile]", &bam_file_fops, NULL, 0);

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        ret = fd;
        goto err;
    }

    fd_install(fd, myfile);

	if (copy_to_user((unsigned int __user *)arg, &fd, sizeof(fd))) {
		ret = -EINVAL;
		goto err;
	}

	ret = 0;
    return ret;

err:
    fput(myfile);
out:
	return ret;
}

static int bam_open(struct inode *inode, struct file *file) {
	return 0;
}

static int bam_release(struct inode *inode, struct file *file) {
	return 0;
}

static struct file_operations bam_fops = {
	.owner = THIS_MODULE,
	.open = bam_open,
	.release = bam_release,
	.unlocked_ioctl = bam_ioctl
};

#define DEVICE_NAME "bamfile"
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

