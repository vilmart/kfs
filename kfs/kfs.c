#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <asm/uaccess.h>	/* Access to user mode */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gabriel Krisman Bertazi");

#define KFS_MAGIC 30
#define MAX_PID 256

static ssize_t kfs_read_file(struct file *filp, char *buf,
		size_t count, loff_t *offset) {

/*
   if (copy_to_user(buf, '0', 1))
		return -EFAULT;
	*offset += count;
        */

	return count;
}

/*
 * Write a file.
 */
static ssize_t kfs_write_file(struct file *filp, const char *buf,
		size_t count, loff_t *offset) {

	return count;
}

static int kfs_open(struct inode *inode, struct file *filp) {
	return 0;
}

static struct file_operations kfs_ops = {
        .open = kfs_open,
        .read = kfs_read_file,
        .write = kfs_write_file
};

static int kfs_refresh_proc_list(struct tree_descr **files) {

        struct task_struct *proc;
        static struct tree_descr proc_list[MAX_PID];
        int i = 1;

        /* Initiate tree descriptor.  */
        proc_list[0].name = NULL;
        proc_list[0].ops =  NULL;
        proc_list[0].mode = 0;

        for_each_process(proc) {
                struct pid *pid = task_pid(proc);

                if(proc_list[i].name == NULL)
                        proc_list[i].name =
                                kmalloc(sizeof(char)* 4, GFP_KERNEL);

                sprintf(proc_list[i].name, "%d", pid->numbers[0].nr);
                proc_list[i].ops = &kfs_ops;
                proc_list[i].mode = S_IWUSR|S_IRUGO;

                i++;
        }

        /* Finish file tree descriptor.  */
        proc_list[i].name = "";
        proc_list[i].ops = NULL;
        proc_list[i].mode = 0;

        *files = proc_list;
        return 0;
}

static int kfs_fill_super(struct super_block *sb, void *data, int silent) {

        struct tree_descr *files;
        int err;

        err = kfs_refresh_proc_list(&files);

        if (err != 0) {
          printk("KFS: could not obtain process list");
          return err;
        }

        return simple_fill_super(sb, KFS_MAGIC, files);
}

static struct dentry *kfs_get_super(struct file_system_type *fst, int flags,
                                    const char *devname, void *data) {

        return mount_bdev(fst, flags, devname, data, kfs_fill_super);
}

static struct file_system_type kfs_type = {
	.owner = THIS_MODULE,
	.name = "kfs",
	.mount = kfs_get_super,
        .kill_sb = kill_litter_super,
};

static int __init kfs_init(void) {

	return register_filesystem(&kfs_type);
}

static void __exit kfs_exit(void) {

        unregister_filesystem(&kfs_type);
}

module_init(kfs_init);
module_exit(kfs_exit);
