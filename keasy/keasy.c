#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>

#include "keasy.h"

static struct chrdev_info cinfo = {};

ssize_t keasy_file_read(struct file *filp, char __user *buf, size_t sz, loff_t *off) {
	char msg[] = "🤓";
	(void)copy_to_user(buf, msg, sizeof(msg));
	return sizeof(msg);
}

const struct file_operations keasy_file_fops = {
	.owner = THIS_MODULE,
	.read = keasy_file_read
};

unsigned enabled = 1;

static long keasy_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	long ret = -EINVAL;
	struct file *myfile;
	int fd;

	if (!enabled) {
		goto out;
	}
	enabled = 0;

    myfile = anon_inode_getfile("[easy]", &keasy_file_fops, NULL, 0);

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

static int keasy_open(struct inode *inode, struct file *file) {
	return 0;
}

static int keasy_release(struct inode *inode, struct file *file) {
	return 0;
}

static struct file_operations keasy_fops = {
	.owner = THIS_MODULE,
	.open = keasy_open,
	.release = keasy_release,
	.unlocked_ioctl = keasy_ioctl
};

static int __init keasy_init(void) {
	dev_t dev;

	if (alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME))
		return -EBUSY;

	cinfo.major = MAJOR(dev);

	cdev_init(&cinfo.cdev, &keasy_fops);
	cinfo.cdev.owner = THIS_MODULE;

	if (cdev_add(&cinfo.cdev, dev, 1))
		goto ERR_CDEV_ADD;

	cinfo.class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(cinfo.class))
		goto ERR_CLASS_CREATE;

	device_create(cinfo.class, NULL, MKDEV(cinfo.major, 0), NULL, DEVICE_NAME);
	return 0;

ERR_CLASS_CREATE:
	cdev_del(&cinfo.cdev);
ERR_CDEV_ADD:
	unregister_chrdev_region(dev, 1);
	return -EBUSY;
}

static void __exit keasy_exit(void) {
	device_destroy(cinfo.class, MKDEV(cinfo.major, 0));
	class_destroy(cinfo.class);

	cdev_del(&cinfo.cdev);
	unregister_chrdev_region(MKDEV(cinfo.major, 0), 1);
}

module_init(keasy_init);
module_exit(keasy_exit);

MODULE_AUTHOR("bros");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Easiest kernel chall of ur life");
