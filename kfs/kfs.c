/* KFS - Signal Process interface virtual filesystem..

 Copyright (C) 2013 Gabriel Krisman Bertazi <krisman.gabriel@gmail.com>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <asm/uaccess.h>	/* Access to user mode */
#include <linux/syscalls.h>

#define KFS_MAGIC 30
#define MAX_PID 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gabriel Krisman Bertazi");

int proc_map[MAX_PID];

static ssize_t kfs_read_file(struct file *filp, char *buf,
		size_t count, loff_t *offset) {

   /*
   if (copy_to_user(buf, '0', 1))
		return -EFAULT;
	*offset += count;
        */

        return count;
}

static ssize_t kfs_write_file(struct file *filp, const char *buf,
		size_t count, loff_t *offset) {

        unsigned signum;
        int err;

        err = sscanf(buf, "%d", &signum);

        if(err != 1) {
                return -EINVAL;
        }

        err = valid_signal(signum);

        if(err == 0) {
               /* Invalid Signal.  */
                return -EINVAL;
        }

        printk(KERN_DEBUG "KFS: pid %d received signum: %d\n",
               *((int *) filp->private_data), signum);

        /* Dispatch signal.  */
        sys_kill(*(int *) filp->private_data, signum);

        return count;
}

static int kfs_open(struct inode *inode, struct file *filp) {

        filp->private_data = &(proc_map[inode->i_ino]);
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
        int inode = 2;

        /* Initiate tree descriptor.  */
        proc_list[0].name = NULL;
        proc_list[0].ops = NULL;
        proc_list[0].mode = 0;

        /* Root descriptor.  */
        proc_list[1].name = NULL;
        proc_list[1].ops = NULL;
        proc_list[1].mode = 0;

        for_each_process(proc) {
                struct pid *pid = task_pid(proc);
                unsigned pid_num = pid->numbers[0].nr;

                if(proc_list[inode].name == NULL) {
                        proc_list[inode].name =
                                kmalloc(sizeof(char)* 4, GFP_KERNEL);

                        if(proc_list[inode].name == NULL)
                                return -ENOMEM;
                }

                sprintf(proc_list[inode].name, "%d", pid_num);
                proc_list[inode].ops = &kfs_ops;
                proc_list[inode].mode = S_IWUSR|S_IRUGO;

                /* Create relation between i-node number and PID.  */
                proc_map[inode] = pid_num;
                inode++;
        }

        /* Finish file tree descriptor.  */
        proc_list[inode].name = "";
        proc_list[inode].ops = NULL;
        proc_list[inode].mode = 0;

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

