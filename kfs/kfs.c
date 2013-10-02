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
#include <linux/pagemap.h> 	/* PAGE_CACHE_SIZE */
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <asm/uaccess.h>	/* Access to user mode */
#include <linux/syscalls.h>

#define KFS_MAGIC 30
#define MAX_PID 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gabriel Krisman Bertazi");


#define SIGHUP_STR "SIGHUP"
#define SIGINT_STR "SIGINT"
#define SIGQUIT_STR "SIGQUIT"
#define SIGILL_STR "SIGILL"
#define SIGTRAP_STR "SIGTRAP"
#define SIGIOT_STR "SIGIOT"
#define SIGBUS_STR "SIGBUS"
#define SIGFPE_STR "SIGFPE"
#define SIGKILL_STR "SIGKILL"
#define SIGUSR1_STR "SIGUSR1"
#define SIGSEGV_STR "SIGSEGV"
#define SIGUSR2_STR "SIGUSR2"
#define SIGPIPE_STR "SIGPIPE"
#define SIGALRM_STR "SIGALRM"
#define SIGTERM_STR "SIGTERM"
#define SIGSTKFLT_STR "SIGSTKFLT"
#define SIGCHLD_STR "SIGCHLD"
#define SIGCONT_STR "SIGCONT"
#define SIGSTOP_STR "SIGSTOP"
#define SIGTSTP_STR "SIGTSTP"
#define SIGTTIN_STR "SIGTTIN"
#define SIGTTOU_STR "SIGTTOU"
#define SIGURG_STR "SIGURG"
#define SIGXCPU_STR "SIGXCPU"
#define SIGXFSZ_STR "SIGXFSZ"
#define SIGVTALRM_STR "SIGVTALRM"
#define SIGPROF_STR "SIGPROF"
#define SIGWINCH_STR "SIGWINCH"
#define SIGIO_STR "SIGIO"
#define SIGPOLL_STR "SIGPOLL"
#define SIGPWR_STR "SIGPWR"
#define SIGSYS_STR "SIGSYS"


struct kfs_process {
        unsigned signum;
        unsigned pidnum;
};

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

        struct kfs_process *k_proc;
        int err;

        k_proc = (struct kfs_process *) filp->private_data;

        if(!k_proc) {
                return -EINVAL;
        }

        err = valid_signal(k_proc->signum);

        if(err == 0) {
               /* Invalid Signal.  */
                return -EINVAL;
        }

        printk(KERN_DEBUG "KFS: pid %d received signum: %d\n",
               k_proc->pidnum, k_proc->signum);

        /* Dispatch signal.  */
        sys_kill(k_proc->pidnum, k_proc->signum);

        return count;
}

static int kfs_open(struct inode *inode, struct file *filp) {

        filp->private_data = inode->i_private;
        return 0;
}

static struct file_operations kfs_ops = {
        .open = kfs_open,
        .read = kfs_read_file,
        .write = kfs_write_file
};

static struct inode *kfs_make_inode(struct super_block *sb, int mode) {

        struct inode *ret = new_inode(sb);
        static int inode_number = 1;

        if(ret) {
                ret->i_mode = mode;
                ret->i_uid = 0;
                ret->i_gid = 0;
                ret->i_blocks = 0;
                ret->i_atime = ret->i_mtime = ret->i_ctime = CURRENT_TIME;
                ret->i_ino = inode_number++;
                /* We must always set the inode number up
                   here. Otherwise, we might get a *very* strange
                   behavior like some files doesn't get created while
                   others do.  */
        }
        return  ret;
}

/*
 * Create a file mapping a name to a counter.
 */
static struct dentry *kfs_create_file (struct super_block *sb,
                                       struct dentry *dir, unsigned pidnum,
                                       unsigned signum, const char *name) {
        struct dentry *dentry;
        struct inode *inode;
        struct qstr qname;
        struct kfs_process *k_proc;

        /*
         * Make a hashed version of the name to go with the dentry.
         */
        qname.name = name;
        qname.len = strlen(name);
        qname.hash = full_name_hash(name, qname.len);
        /*
         * Now we can create our dentry and the inode to go with it.
         */
        dentry = d_alloc(dir, &qname);
        if (! dentry)
                goto out;
        inode = kfs_make_inode(sb, S_IFREG | 0644);
        if (! inode)
                goto out_dput;
        inode->i_fop = &kfs_ops;

        /* Create new kfs_process structure  */
        k_proc = kmalloc(sizeof(struct kfs_process), GFP_KERNEL);
        if (!k_proc)
                goto out_dput;

        k_proc->signum = signum;
        k_proc->pidnum = pidnum;

        inode->i_private = k_proc;

        /*
         * Put it all into the dentry cache and we're done.
         */
        d_add(dentry, inode);
        return dentry;
        /*
         * Then again, maybe it didn't work.
         */
out_dput:
        dput(dentry);
out:
        return 0;
}

/*
 * Create a directory which can be used to hold files.  This code is
 * almost identical to the "create file" logic, except that we create
 * the inode with a different mode, and use the libfs "simple" operations.
 */
static struct dentry *kfs_create_dir (struct super_block *sb,
                                      struct dentry *parent,
                                      const char *name) {
        struct dentry *dentry;
        struct inode *inode;
        struct qstr qname;

        qname.name = name;
        qname.len = strlen (name);
        qname.hash = full_name_hash(name, qname.len);
        dentry = d_alloc(parent, &qname);
        if (! dentry)
                goto out;

        inode = kfs_make_inode(sb, S_IFDIR | 0644);
        if (! inode)
                goto out_dput;
        inode->i_op = &simple_dir_inode_operations;
        inode->i_fop = &simple_dir_operations;

        d_add(dentry, inode);
        return dentry;

out_dput:
        dput(dentry);
out:
        return 0;
}

static int kfs_populate(struct super_block *sb, struct dentry *parent) {
        struct task_struct *proc;
        struct dentry *proc_dir;

        for_each_process(proc) {
                struct pid *pid = task_pid(proc);
                unsigned pid_num = pid->numbers[0].nr;
                char  *pid_str;

                pid_str = kmalloc(sizeof(char)* 8, GFP_KERNEL);

                if(pid_str == NULL)
                        return -ENOMEM;

                sprintf(pid_str, "%d", pid_num);
                printk("KERN_DEBUG, creating directory %s\n", pid_str);

                proc_dir = kfs_create_dir(sb, parent, pid_str);

                if(!proc_dir) {
                        printk("kfs: Unable to build directory. \n"
                                "pid :%d\n"
                               "pid_str:%s\n", pid_num, pid_str);
                }

                kfs_create_file(sb, proc_dir, pid_num, 1, SIGHUP_STR);
                kfs_create_file(sb, proc_dir, pid_num, 2, SIGINT_STR);
                kfs_create_file(sb, proc_dir, pid_num, 3, SIGQUIT_STR);
                kfs_create_file(sb, proc_dir, pid_num, 4, SIGILL_STR);
                kfs_create_file(sb, proc_dir, pid_num, 5, SIGTRAP_STR);
                kfs_create_file(sb, proc_dir, pid_num, 6, SIGIOT_STR);
                kfs_create_file(sb, proc_dir, pid_num, 7, SIGBUS_STR);
                kfs_create_file(sb, proc_dir, pid_num, 8, SIGFPE_STR);
                kfs_create_file(sb, proc_dir, pid_num, 9, SIGKILL_STR);
                kfs_create_file(sb, proc_dir, pid_num, 10, SIGUSR1_STR);
                kfs_create_file(sb, proc_dir, pid_num, 11, SIGSEGV_STR);
                kfs_create_file(sb, proc_dir, pid_num, 12, SIGUSR2_STR);
                kfs_create_file(sb, proc_dir, pid_num, 13, SIGPIPE_STR);
                kfs_create_file(sb, proc_dir, pid_num, 14, SIGALRM_STR);
                kfs_create_file(sb, proc_dir, pid_num, 15, SIGTERM_STR);
                kfs_create_file(sb, proc_dir, pid_num, 16, SIGSTKFLT_STR);
                kfs_create_file(sb, proc_dir, pid_num, 17, SIGCHLD_STR);
                kfs_create_file(sb, proc_dir, pid_num, 18, SIGCONT_STR);
                kfs_create_file(sb, proc_dir, pid_num, 19, SIGSTOP_STR);
                kfs_create_file(sb, proc_dir, pid_num, 20, SIGTSTP_STR);
                kfs_create_file(sb, proc_dir, pid_num, 21, SIGTTIN_STR);
                kfs_create_file(sb, proc_dir, pid_num, 22, SIGTTOU_STR);
                kfs_create_file(sb, proc_dir, pid_num, 23, SIGURG_STR);
                kfs_create_file(sb, proc_dir, pid_num, 24, SIGXCPU_STR);
                kfs_create_file(sb, proc_dir, pid_num, 25, SIGXFSZ_STR);
                kfs_create_file(sb, proc_dir, pid_num, 26, SIGVTALRM_STR);
                kfs_create_file(sb, proc_dir, pid_num, 27, SIGPROF_STR);
                kfs_create_file(sb, proc_dir, pid_num, 28, SIGWINCH_STR);
                kfs_create_file(sb, proc_dir, pid_num, 29, SIGIO_STR);
                kfs_create_file(sb, proc_dir, pid_num, 30, SIGPOLL_STR);
                kfs_create_file(sb, proc_dir, pid_num, 31, SIGPWR_STR);
                kfs_create_file(sb, proc_dir, pid_num, 32, SIGSYS_STR);
        }

        return 0;
}

/*
 * Our superblock operations, both of which are generic kernel ops
 * that we don't have to write ourselves.
 */
static struct super_operations kfs_s_ops = {
      	.statfs		= simple_statfs,
      	.drop_inode	= generic_delete_inode,
};

static int kfs_fill_super(struct super_block *sb, void *data, int silent) {

        struct inode *root;
        struct dentry *root_dentry;
        int err;

        /* Build superblock.  */
        sb->s_blocksize = PAGE_CACHE_SIZE;
        sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
        sb->s_magic = KFS_MAGIC;
        sb->s_op = &kfs_s_ops;

        /* Create root inode.  */
        root = kfs_make_inode(sb, S_IFDIR | 0755);

        if(!root)
                return -ENOMEM;

       /* Use dafault operations for root inode.  */
        root->i_op = &simple_dir_inode_operations;
        root->i_fop = &simple_dir_operations;

        /* Create dentry.  */
        root_dentry = d_make_root(root);
        if(!root_dentry) {
                iput(root);
                return -ENOMEM;
        }
        sb->s_root = root_dentry;

        /* Build file structure.  */
        err = kfs_populate(sb, root_dentry);

        if(err != 0) {
          printk("KFS: could not build  process tree");
          return err;
        }

        return 0;
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

