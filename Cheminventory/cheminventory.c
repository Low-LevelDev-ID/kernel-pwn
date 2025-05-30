#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>

#define IOC_MAGIC '\xca'

#define DO_CREATE  _IOWR(IOC_MAGIC, 0, struct req)
#define DO_REPLACE _IOWR(IOC_MAGIC, 1, struct req)
#define DO_READ    _IOWR(IOC_MAGIC, 2, struct req) 
#define DO_DELETE  _IOWR(IOC_MAGIC, 3, struct req) 

struct mutex chem_mutex;

uint64_t chemical_count = 0; 

struct list_head chemical_head;

struct chemical { 
    char name[0xc8];
    uint64_t quantity;
    uint64_t cas;
    uint64_t idx;
    struct list_head list;
    uint64_t note_size; 
    uint64_t note_addr;
};

struct req {
    uint64_t quantity; 
    uint64_t cas;
    uint64_t idx;
    uint64_t note_size;
    uint64_t note_addr;
    uint64_t name_addr;
};

static int open_module(struct inode *inode, struct file *filp);
static long ioctl_module(struct file *filp, unsigned int cmd, unsigned long arg);

static struct file_operations fops = {
	open : open_module,
	unlocked_ioctl : ioctl_module
};

static struct miscdevice cheminventory = {
    .minor      = 53,
    .name       = "cheminventory",
    .fops       = &fops,
    .mode	= 0666,
};

static int open_module (struct inode *inode, struct file *filp) {
	return 0;
}

static long ioctl_module (struct file *filp, unsigned int cmd, unsigned long arg) {
    struct req user_data;
    struct chemical  * chem  = 0;
    struct chemical  * entry = 0;
    struct list_head * ptr   = 0;
    void * note;
    char buf[1000]; 
    int ret = 0;
    
    mutex_lock(&chem_mutex);
    
    memset(&user_data, 0, sizeof(user_data));
    memset(buf, 0, sizeof(buf)); 
    
    if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
        mutex_unlock(&chem_mutex);
		return -1;
    } 
    pr_info("Copy from user done\n"); 
    
    switch(cmd) {
        case DO_CREATE: {           
            if (user_data.note_size > 100 || user_data.note_size == 0) {
                pr_info("A chemical explosion occurred. Oh no!\n");
                mutex_unlock(&chem_mutex);
                return -1;
            }
            
            chem = kmalloc(sizeof(struct chemical), GFP_KERNEL); 
            
            // Quantity
            chem->quantity = user_data.quantity;
            
            // CAS
            chem->cas = user_data.cas;
            
            // idx
            chem->idx = chemical_count; 
            chemical_count = chemical_count +1;
            
            // list_head
            list_add_tail(&chem->list, &chemical_head);
            
            // note_addr 
            chem->note_size = user_data.note_size; 
            note = kmalloc(user_data.note_size, GFP_KERNEL_ACCOUNT);
            memset(note, 0, user_data.note_size);
            chem->note_addr = (uint64_t) note;
            ret = copy_from_user(buf, (void __user *) user_data.note_addr, user_data.note_size-1);
            memcpy((void *) note, buf, user_data.note_size-1); 
            
            // name_addr 
            memset(buf, 0, sizeof(buf));
            ret = copy_from_user(buf, (void __user *) user_data.name_addr, 0xc8-1);
            memcpy((void *) chem->name, buf, 0xc8-1); 
            mutex_unlock(&chem_mutex);
            return 0;
            }
        case DO_REPLACE: {
            if (user_data.note_size == 0) {
                pr_info("A chemical explosion occurred. Oh no!\n");
                mutex_unlock(&chem_mutex);
                return -1;
            }
            
            list_for_each(ptr, &chemical_head) {
                entry = list_entry(ptr, struct chemical, list);
                if (entry->idx == user_data.idx) {
                    kfree((void *) entry->note_addr);
                
                    list_del(&entry->list); 
                    kfree(entry);
                    pr_info("Replacing chemical at index %lld\n", user_data.idx);
                    
                    chem = kzalloc(sizeof(struct chemical), GFP_KERNEL); 
                    chem->quantity = user_data.quantity;
                    chem->cas = user_data.cas;
                    chem->idx = user_data.idx; 
                    list_add_tail(&chem->list, &chemical_head); 
                    
                    // New note
                    note = kmalloc(user_data.note_size, GFP_KERNEL_ACCOUNT); 
                    if (note == NULL) {
                        kfree(chem); 
                        pr_info("A chemical explosion occurred. Oh no!\n");
                        mutex_unlock(&chem_mutex);
                        return -1;
                    }
                    if (user_data.note_size > 100) { 
                        chem->note_size = 100;
                    } else {
                        chem->note_size = user_data.note_size; 
                    }
                    memset(note, 0, chem->note_size);
                    chem->note_addr = (uint64_t) note;
                    ret = copy_from_user(buf, (void __user *) user_data.note_addr, user_data.note_size-1);
                    memcpy((void *) note, buf, user_data.note_size-1); 
                    
                    // name_addr 
                    memset(buf, 0, sizeof(buf));
                    ret = copy_from_user(buf, (void __user *) user_data.name_addr, 0xc8-1);
                    memcpy((void *) chem->name, buf, 0xc8-1); 
                    mutex_unlock(&chem_mutex);
                    return 0;
                }
            }
            mutex_unlock(&chem_mutex);
            return 0;
            }
        case DO_READ: {
            list_for_each(ptr, &chemical_head) {
                entry = list_entry(ptr, struct chemical, list);
                if (entry->idx == user_data.idx) {
                    
                    if (entry->note_size <= 100) {
                        ret = copy_to_user((void __user *)user_data.note_addr, (void *) entry->note_addr, entry->note_size);
                    }
                    
                    ret = copy_to_user((void __user *)user_data.name_addr, &entry->name, 0xc8-1);
                    
                    mutex_unlock(&chem_mutex);
                    return 0;
                }
            }
            mutex_unlock(&chem_mutex);
            return 0;
            }
        case DO_DELETE: {
            list_for_each(ptr, &chemical_head) {
                entry = list_entry(ptr, struct chemical, list);
                if (entry->idx == user_data.idx) {
                    list_del(&entry->list); 
                    kfree((void *) entry->note_addr);
                    entry->note_addr = 0; 
                    kfree(entry);
                    pr_info("Deleted chemical at index %lld\n", user_data.idx);
                    mutex_unlock(&chem_mutex);
                    return 0;
                }
            }
            mutex_unlock(&chem_mutex);
            return 0;
            }
        default: 
            mutex_unlock(&chem_mutex);
            return -1;
    }
}

static int cheminventory_init(void) {
    INIT_LIST_HEAD(&chemical_head);
    mutex_init(&chem_mutex);
	return misc_register(&cheminventory);
}

static void cheminventory_exit(void) {
	 misc_deregister(&cheminventory);
}

module_init(cheminventory_init);
module_exit(cheminventory_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Cheminventory V1.0 :3");
