#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("Fleckvieh - Vulnerable Kernel Driver for Pawnyable");

#define DEVICE_NAME "fleckvieh"
#define CMD_ADD 0xf1ec0001
#define CMD_DEL 0xf1ec0002
#define CMD_GET 0xf1ec0003
#define CMD_SET 0xf1ec0004

typedef struct {
  int id;
  size_t size;
  char *data;
} request_t;

typedef struct {
  int id;
  size_t size;
  char *data;
  struct list_head list;
} blob_list;

static int module_open(struct inode *inode, struct file *filp) {
  /* Allocate list head */
  filp->private_data = (void*)kmalloc(sizeof(struct list_head), GFP_KERNEL);
  if (unlikely(!filp->private_data))
    return -ENOMEM;

  INIT_LIST_HEAD((struct list_head*)filp->private_data);
  return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  struct list_head *top;
  blob_list *itr, *tmp;

  /* Remove everything */
  top = (struct list_head*)filp->private_data;
  tmp = NULL;
  list_for_each_entry_safe(itr, tmp, top, list) {
    list_del(&itr->list);
    kfree(itr->data);
    kfree(itr);
  }

  kfree(top);
  return 0;
}

blob_list *blob_find_by_id(struct list_head *top, int id) {
  blob_list *itr;

  /* Find blob by id */
  list_for_each_entry(itr, top, list) {
    if (unlikely(itr->id == id)) return itr;
  }

  return NULL;
}

long blob_add(struct list_head *top, request_t *req) {
  blob_list *new;

  /* Check size */
  if (req->size > 0x1000)
    return -EINVAL;

  /* Allocate a new blob structure */
  new = (blob_list*)kmalloc(sizeof(blob_list), GFP_KERNEL);
  if (unlikely(!new)) return -ENOMEM;

  /* Allocate data buffer */
  new->data = (char*)kmalloc(req->size, GFP_KERNEL);
  if (unlikely(!new->data)) {
    kfree(new);
    return -ENOMEM;
  }

  /* Copy data from user buffer */
  if (unlikely(copy_from_user(new->data, req->data, req->size))) {
    kfree(new->data);
    kfree(new);
    return -EINVAL;
  }

  new->size = req->size;
  INIT_LIST_HEAD(&new->list);

  /* Generate a random positive integer */
  do {
    get_random_bytes(&new->id, sizeof(new->id));
  } while (unlikely(new->id < 0));

  /* Insert to list */
  list_add(&new->list, top);

  return new->id;
}

long blob_del(struct list_head *top, request_t *req) {
  blob_list *victim;
  if (!(victim = blob_find_by_id(top, req->id)))
    return -EINVAL;

  /* Delete the item */
  list_del(&victim->list);
  kfree(victim->data);
  kfree(victim);

  return req->id;
}

long blob_get(struct list_head *top, request_t *req) {
  blob_list *victim;
  if (!(victim = blob_find_by_id(top, req->id)))
    return -EINVAL;

  /* Check size */
  if (req->size > victim->size)
    return -EINVAL;

  /* Copy data to user */
  if (unlikely(copy_to_user(req->data, victim->data, req->size)))
    return -EINVAL;

  return req->id;
}

long blob_set(struct list_head *top, request_t *req) {
  blob_list *victim;
  if (!(victim = blob_find_by_id(top, req->id)))
    return -EINVAL;

  /* Check size */
  if (req->size > victim->size)
    return -EINVAL;

  /* Copy data from user */
  if (unlikely(copy_from_user(victim->data, req->data, req->size)))
    return -EINVAL;

  return req->id;
}

static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  struct list_head *top;
  request_t req;
  if (unlikely(copy_from_user(&req, (void*)arg, sizeof(req))))
    return -EINVAL;

  top = (struct list_head*)filp->private_data;

  switch (cmd) {
    case CMD_ADD: return blob_add(top, &req);
    case CMD_DEL: return blob_del(top, &req);
    case CMD_GET: return blob_get(top, &req);
    case CMD_SET: return blob_set(top, &req);
    default: return -EINVAL;
  }
}

static struct file_operations module_fops = {
  .owner   = THIS_MODULE,
  .open    = module_open,
  .release = module_close,
  .unlocked_ioctl = module_ioctl
};

static dev_t dev_id;
static struct cdev c_dev;

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME))
    return -EBUSY;

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);
