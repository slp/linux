// SPDX-License-Identifier: GPL-2.0
/*
 * cmdline_secret module
 *
 * Based on efi_secrets.c
 *
 * Copyright (C) 2022 Red Hat Inc.
 * Author: Sergio Lopez <slp@redhat.com>
 */

#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/security.h>
#include <asm/cacheflush.h>

#define MAX_CMDLINE_SIZE 2048

struct cmdline_secret {
	struct dentry *secrets_dir;
	struct dentry *fs_dir;
	u64 secret_cmdline_len;
};

static struct cmdline_secret the_cmdline_secret;

static inline struct cmdline_secret *cmdline_secret_get(void)
{
	return &the_cmdline_secret;
}

static int cmdline_secret_bin_file_show(struct seq_file *file, void *data)
{
	struct cmdline_secret *s = cmdline_secret_get();

	seq_write(file, secret_cmdline, s->secret_cmdline_len);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(cmdline_secret_bin_file);

static int cmdline_secret_unlink(struct inode *dir, struct dentry *dentry)
{
	struct cmdline_secret *s = cmdline_secret_get();

	memzero_explicit(secret_cmdline, s->secret_cmdline_len);
#ifdef CONFIG_X86
	clflush_cache_range(secret_cmdline, s->secret_cmdline_len);
#endif

	/*
	 * securityfs_remove tries to lock the directory's inode, but we reach
	 * the unlink callback when it's already locked
	 */
	inode_unlock(dir);
	securityfs_remove(dentry);
	inode_lock(dir);

	return 0;
}

static const struct inode_operations efi_secret_dir_inode_operations = {
	.lookup = simple_lookup,
	.unlink = cmdline_secret_unlink,
};

static int __init cmdline_secret_init(void)
{
	struct cmdline_secret *s = cmdline_secret_get();
	struct dentry *dent;
	int ret;

	s->secrets_dir = NULL;
	s->fs_dir = NULL;

	dent = securityfs_create_dir("secrets", NULL);
	if (IS_ERR(dent)) {
		printk
		    ("Error creating secrets securityfs directory entry err=%ld\n",
		     PTR_ERR(dent));
		return PTR_ERR(dent);
	}
	s->secrets_dir = dent;

	dent = securityfs_create_dir("coco", s->secrets_dir);
	if (IS_ERR(dent)) {
		printk
		    ("Error creating coco securityfs directory entry err=%ld\n",
		     PTR_ERR(dent));
		ret = PTR_ERR(dent);
		goto cleanup_dir;
	}
	d_inode(dent)->i_op = &efi_secret_dir_inode_operations;
	s->fs_dir = dent;

	dent = securityfs_create_file("cmdline", 0440, s->fs_dir, NULL,
				      &cmdline_secret_bin_file_fops);
	if (IS_ERR(dent)) {
		printk("Error creating efi_secret securityfs entry\n");
		ret = PTR_ERR(dent);
		goto cleanup_all;
	}

	s->secret_cmdline_len = strnlen(secret_cmdline, MAX_CMDLINE_SIZE);

	return 0;

cleanup_all:
	securityfs_remove(s->fs_dir);
	s->fs_dir = NULL;
cleanup_dir:
	securityfs_remove(s->secrets_dir);
	s->secrets_dir = NULL;

	return ret;
}

static void __exit cmdline_secret_exit(void)
{
	struct cmdline_secret *s = cmdline_secret_get();

	securityfs_remove(s->fs_dir);
	s->fs_dir = NULL;

	securityfs_remove(s->secrets_dir);
	s->secrets_dir = NULL;
}

MODULE_DESCRIPTION("Confidential computing CMDLINE secret area access");
MODULE_AUTHOR("Red Hat");
MODULE_LICENSE("GPL");
module_init(cmdline_secret_init);
module_exit(cmdline_secret_exit);
