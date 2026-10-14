/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _FS_FUSE_DEFER_H
#define _FS_FUSE_DEFER_H

struct fuse_conn;
struct fuse_args;
struct super_block;

int fuse_defer_init(struct fuse_conn *fc);
void fuse_defer_destroy(struct fuse_conn *fc);
ssize_t fuse_defer_request(struct fuse_conn *fc, struct fuse_args *args);
int fuse_defer_background(struct fuse_conn *fc, struct fuse_args *args, gfp_t gfp);
int fuse_defer_sync(struct super_block *sb);

#endif
