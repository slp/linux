// SPDX-License-Identifier: GPL-2.0-only
/* Exclusive-owner guest cache. Journal pressure may replay ordered mutations;
 * explicit checkpoints additionally make the replayed changes durable.
 */
#include "dev.h"
#include "fuse_i.h"
#include "defer.h"

#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/xattr.h>

#define DC_HASH_BITS 8
#define DC_TIMEOUT (365ULL * 24 * 60 * 60)
#define DC_READ_SIZE (32 * 1024)
#define DC_EXIT_CODE_IOCTL 0x7602
#define DC_WRITEBACK_BATCH 32

static unsigned long deferred_cache_mb = 256;
module_param(deferred_cache_mb, ulong, 0444);
MODULE_PARM_DESC(deferred_cache_mb, "Per-mount deferred journal budget in MiB");

struct dc_node {
	struct list_head list;
	struct hlist_node host_hash;
	u64 id, host, host_size, parent;
	u64 read_fh, open_count;
	u64 dirty_seq;
	struct fuse_attr attr;
	bool attr_valid, dir_loaded, xattrs_loaded, dirty;
	bool server_owned, volatile_name, read_open;
	u64 cookie;
	struct list_head children, xattrs;
	char *symlink;
};

struct dc_entry {
	struct hlist_node hash;
	struct list_head list;
	struct dc_node *parent, *node;
	u64 cookie, ino;
	u32 type;
	bool present;
	char name[];
};

struct dc_xattr {
	struct list_head list;
	char *name;
	void *value;
	size_t size;
	bool present, fetched;
};

struct dc_op {
	struct list_head list;
	struct fuse_args args;
	struct dc_node *node, *result, *other;
	u64 seq;
	size_t bytes;
	char data[];
};

struct fuse_defer {
	struct mutex lock;
	struct mutex replay_lock, admission_lock;
	struct workqueue_struct *writeback_wq;
	struct work_struct writeback_work;
	wait_queue_head_t space_wait;
	struct fuse_conn *fc;
	struct list_head nodes, journal;
	DECLARE_HASHTABLE(names, DC_HASH_BITS);
	DECLARE_HASHTABLE(hosts, DC_HASH_BITS);
	struct xarray ids;
	u64 next_id;
	u64 next_seq;
	size_t used, limit;
	size_t journal_bytes, blocked_bytes;
	int alloc_error;
	int writeback_error;
	atomic_t pending;
	atomic_t write_error;
	bool initialized, stopping;
	ssize_t (*send)(struct fuse_chan *chan, struct fuse_args *args);
};

struct dc_allocation {
	size_t size;
	u8 data[] __aligned(8);
};

static void *dc_alloc(struct fuse_defer *dc, size_t size)
{
	struct dc_allocation *p;
	size_t total = size + sizeof(*p);

	p = kvzalloc(total, GFP_NOFS);
	if (!p) {
		dc->alloc_error = -ENOMEM;
		return NULL;
	}
	p->size = total;
	dc->used += total;
	return p->data;
}

static void dc_free(struct fuse_defer *dc, void *ptr)
{
	struct dc_allocation *p;

	if (!ptr)
		return;
	p = container_of(ptr, struct dc_allocation, data);
	dc->used -= p->size;
	kvfree(p);
}

static char *dc_string(struct fuse_defer *dc, const char *s)
{
	size_t len = strlen(s) + 1;
	char *p = dc_alloc(dc, len);

	if (p)
		memcpy(p, s, len);
	return p;
}

static struct dc_node *dc_node(struct fuse_defer *dc, u64 id)
{
	return xa_load(&dc->ids, id);
}

static struct dc_node *dc_new_node(struct fuse_defer *dc, u64 host)
{
	struct dc_node *n;
	int err;

	if (host) {
		hash_for_each_possible(dc->hosts, n, host_hash, host)
			if (n->host == host)
				return n;
	}
	n = dc_alloc(dc, sizeof(*n));
	if (!n)
		return NULL;
	n->id = dc->next_id++;
	n->host = host;
	n->cookie = 2;
	INIT_LIST_HEAD(&n->children);
	INIT_LIST_HEAD(&n->xattrs);
	err = xa_err(xa_store(&dc->ids, n->id, n, GFP_NOFS));
	if (err) {
		dc_free(dc, n);
		dc->alloc_error = err;
		return NULL;
	}
	list_add_tail(&n->list, &dc->nodes);
	if (host)
		hash_add(dc->hosts, &n->host_hash, host);
	return n;
}

static u32 dc_name_hash(struct dc_node *dir, const char *name, size_t len)
{
	return full_name_hash(dir, name, len);
}

static struct dc_entry *dc_entry(struct fuse_defer *dc, struct dc_node *dir,
				 const char *name, size_t len)
{
	struct dc_entry *e;
	u32 key = dc_name_hash(dir, name, len);

	hash_for_each_possible(dc->names, e, hash, key)
		if (e->parent == dir && strlen(e->name) == len &&
		    !memcmp(e->name, name, len))
			return e;
	e = dc_alloc(dc, sizeof(*e) + len + 1);
	if (!e)
		return NULL;
	e->parent = dir;
	e->cookie = ++dir->cookie;
	memcpy(e->name, name, len);
	e->name[len] = '\0';
	hash_add(dc->names, &e->hash, key);
	list_add_tail(&e->list, &dir->children);
	return e;
}

static ssize_t dc_send(struct fuse_defer *dc, struct fuse_args *a)
{
	unsigned int nofs = memalloc_nofs_save();
	ssize_t ret;

	/* A replayed mutation must not be ambiguously interrupted after execution. */
	a->force = true;
	ret = dc->send(dc->fc->chan, a);
	memalloc_nofs_restore(nofs);
	return ret;
}

static ssize_t dc_replay_send(struct fuse_defer *dc, struct fuse_args *a)
{
	ssize_t ret;

	/* The replay lock preserves journal order while reads use the cache lock. */
	lockdep_assert_held(&dc->replay_lock);
	lockdep_assert_held(&dc->lock);
	mutex_unlock(&dc->lock);
	ret = dc_send(dc, a);
	mutex_lock(&dc->lock);
	return ret;
}

static void dc_args(struct fuse_args *dst, const struct fuse_args *src,
		    struct dc_node *n, u32 opcode)
{
	memset(dst, 0, sizeof(*dst));
	dst->opcode = opcode;
	dst->nodeid = n->host;
	dst->uid = src->uid;
	dst->gid = src->gid;
	dst->pid = src->pid;
}

static void dc_entry_out(struct dc_node *n, struct fuse_entry_out *out)
{
	memset(out, 0, sizeof(*out));
	out->entry_valid = DC_TIMEOUT;
	out->attr_valid = DC_TIMEOUT;
	if (n) {
		out->nodeid = n->id;
		out->generation = 1;
		out->attr = n->attr;
		if (n->volatile_name) {
			out->entry_valid = 0;
			out->attr_valid = 0;
		}
	}
}

static void dc_attr_out(struct dc_node *n, struct fuse_attr_out *out)
{
	memset(out, 0, sizeof(*out));
	out->attr_valid = DC_TIMEOUT;
	out->attr = n->attr;
}

static int dc_getattr(struct fuse_defer *dc, struct dc_node *n,
		      const struct fuse_args *src)
{
	struct fuse_getattr_in in = {};
	struct fuse_attr_out out = {};

	FUSE_ARGS(a);
	int err;

	if (n->attr_valid)
		return 0;
	dc_args(&a, src, n, FUSE_GETATTR);
	a.in_numargs = 1;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
	err = dc_send(dc, &a);
	if (!err) {
		n->attr = out.attr;
		n->host_size = out.attr.size;
		n->attr_valid = true;
	}
	return err;
}

static int dc_lookup(struct fuse_defer *dc, struct dc_node *dir,
		     const char *name, size_t len, const struct fuse_args *src,
		     struct dc_entry **entry)
{
	struct fuse_entry_out out = {};
	struct dc_entry *e = dc_entry(dc, dir, name, len);
	struct dc_node *n;

	FUSE_ARGS(a);
	int err;

	if (!e)
		return dc->alloc_error;
	*entry = e;
	if (e->node && !e->node->volatile_name)
		return 0;
	/* A negative entry has type UINT_MAX, unlike an unqueried directory name. */
	if (e->type == UINT_MAX)
		return 0;
	if (!dir->host)
		return 0;
	dc_args(&a, src, dir, FUSE_LOOKUP);
	a.in_numargs = 3;
	fuse_set_zero_arg0(&a);
	a.in_args[1] = (struct fuse_in_arg){ len, e->name };
	a.in_args[2] = (struct fuse_in_arg){ 1, "" };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
	err = dc_send(dc, &a);
	if (err == -ENOENT || (!err && !out.nodeid)) {
		e->node = NULL;
		e->present = false;
		e->type = UINT_MAX;
		return 0;
	}
	if (err)
		return err;
	n = dc_new_node(dc, out.nodeid);
	if (!n)
		return dc->alloc_error;
	if (!n->attr_valid) {
		n->attr = out.attr;
		n->server_owned = out.attr.flags & FUSE_ATTR_SERVER_OWNED;
		n->volatile_name = n->server_owned && !out.entry_valid && !out.entry_valid_nsec;
		n->attr.flags &= ~FUSE_ATTR_SERVER_OWNED;
		n->host_size = out.attr.size;
		n->attr_valid = true;
		n->parent = dir->id;
	}
	e->node = n;
	e->present = true;
	e->ino = n->attr.ino;
	e->type = (n->attr.mode & S_IFMT) >> 12;
	return 0;
}

static int dc_open_host(struct fuse_defer *dc, struct dc_node *n,
			const struct fuse_args *src, u32 flags, u64 *fh, bool replay)
{
	struct fuse_open_in in = { .flags = flags };
	struct fuse_open_out out = {};

	FUSE_ARGS(a);
	int err;

	dc_args(&a, src, n, S_ISDIR(n->attr.mode) ? FUSE_OPENDIR : FUSE_OPEN);
	a.in_numargs = 1;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
	err = replay ? dc_replay_send(dc, &a) : dc_send(dc, &a);
	*fh = out.fh;
	return err;
}

static void dc_close_host(struct fuse_defer *dc, struct dc_node *n,
			  const struct fuse_args *src, u64 fh, u32 flags, bool replay)
{
	struct fuse_release_in in = { .fh = fh, .flags = flags };

	FUSE_ARGS(a);

	dc_args(&a, src, n, S_ISDIR(n->attr.mode) ? FUSE_RELEASEDIR : FUSE_RELEASE);
	a.in_numargs = 1;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
	if (replay)
		dc_replay_send(dc, &a);
	else
		dc_send(dc, &a);
}

static void dc_close_read(struct fuse_defer *dc, struct dc_node *n,
			  const struct fuse_args *src)
{
	if (!n->read_open)
		return;
	dc_close_host(dc, n, src, n->read_fh, O_RDONLY, false);
	n->read_open = false;
}

static void dc_copy_pages(struct fuse_args *args, void *buffer, size_t size,
			  bool output)
{
	struct fuse_args_pages *ap = container_of(args, struct fuse_args_pages, args);
	size_t done = 0;
	unsigned int i;

	for (i = 0; i < ap->num_folios; i++) {
		size_t len = min_t(size_t, ap->descs[i].length, size - done);

		if (output) {
			memcpy_to_folio(ap->folios[i], ap->descs[i].offset,
					buffer + done, len);
			if (args->page_zeroing && len < ap->descs[i].length)
				folio_zero_range(ap->folios[i], ap->descs[i].offset + len,
						 ap->descs[i].length - len);
		} else {
			memcpy_from_folio(buffer + done, ap->folios[i],
					  ap->descs[i].offset, len);
		}
		done += len;
	}
}

static struct dc_op *dc_save(struct fuse_defer *dc, struct fuse_args *a,
			     struct dc_node *n)
{
	struct dc_op *op;
	char *p;
	size_t size = sizeof(*op);
	unsigned int i;

	for (i = 0; i < a->in_numargs; i++)
		size += a->in_args[i].size;
	op = dc_alloc(dc, size);
	if (!op)
		return NULL;
	op->args = *a;
	op->args.in_pages = false;
	op->args.out_pages = false;
	op->args.end = NULL;
	op->args.out_argvar = false;
	op->node = n;
	op->bytes = sizeof(struct dc_allocation) + size;
	p = op->data;
	for (i = 0; i < a->in_numargs; i++) {
		if (!a->in_args[i].size)
			continue;
		if (a->in_pages && i == a->in_numargs - 1)
			dc_copy_pages(a, p, a->in_args[i].size, false);
		else
			memcpy(p, a->in_args[i].value, a->in_args[i].size);
		op->args.in_args[i].value = p;
		p += a->in_args[i].size;
	}
	return op;
}

static size_t dc_high_watermark(struct fuse_defer *dc)
{
	return max_t(size_t, 1, dc->limit - dc->limit / 4);
}

static void dc_queue_writeback(struct fuse_defer *dc)
{
	if (!dc->stopping && !dc->writeback_error && !list_empty(&dc->journal))
		queue_work(dc->writeback_wq, &dc->writeback_work);
}

static void dc_dirty(struct dc_node *n, u64 seq)
{
	if (n) {
		n->dirty = true;
		n->dirty_seq = seq;
	}
}

static void dc_append(struct fuse_defer *dc, struct dc_op *op)
{
	op->seq = ++dc->next_seq;
	list_add_tail(&op->list, &dc->journal);
	dc->journal_bytes += op->bytes;
	dc_dirty(op->node, op->seq);
	dc_dirty(op->result, op->seq);
	dc_dirty(op->other, op->seq);
	if (dc->journal_bytes >= dc_high_watermark(dc))
		dc_queue_writeback(dc);
}

static void dc_touch(struct dc_node *n)
{
	struct timespec64 now;

	ktime_get_real_ts64(&now);
	n->attr.ctime = now.tv_sec;
	n->attr.ctimensec = now.tv_nsec;
	n->attr.mtime = now.tv_sec;
	n->attr.mtimensec = now.tv_nsec;
}

static void dc_ctime(struct dc_node *n)
{
	struct timespec64 now;

	ktime_get_real_ts64(&now);
	n->attr.ctime = now.tv_sec;
	n->attr.ctimensec = now.tv_nsec;
}

static void dc_setattr(struct dc_node *n, const struct fuse_setattr_in *in)
{
	struct fuse_attr *a = &n->attr;
	struct timespec64 now;

	ktime_get_real_ts64(&now);
	if (in->valid & FATTR_SIZE) {
		a->size = in->size;
		a->blocks = DIV_ROUND_UP_ULL(a->size, 512);
	}
	if (in->valid & FATTR_MODE)
		a->mode = (a->mode & S_IFMT) | (in->mode & ~S_IFMT);
	if (in->valid & FATTR_UID)
		a->uid = in->uid;
	if (in->valid & FATTR_GID)
		a->gid = in->gid;
	if (in->valid & (FATTR_ATIME | FATTR_ATIME_NOW)) {
		a->atime = in->valid & FATTR_ATIME_NOW ? now.tv_sec : in->atime;
		a->atimensec = in->valid & FATTR_ATIME_NOW ? now.tv_nsec : in->atimensec;
	}
	if (in->valid & (FATTR_MTIME | FATTR_MTIME_NOW)) {
		a->mtime = in->valid & FATTR_MTIME_NOW ? now.tv_sec : in->mtime;
		a->mtimensec = in->valid & FATTR_MTIME_NOW ? now.tv_nsec : in->mtimensec;
	}
	a->ctime = in->valid & FATTR_CTIME ? in->ctime : now.tv_sec;
	a->ctimensec = in->valid & FATTR_CTIME ? in->ctimensec : now.tv_nsec;
}

static int dc_load_dir(struct fuse_defer *dc, struct dc_node *n,
		       const struct fuse_args *src)
{
	struct fuse_read_in in = { .size = DC_READ_SIZE };
	char *buffer;
	u64 fh;
	int err;

	if (n->dir_loaded)
		return 0;
	if (!n->host) {
		n->dir_loaded = true;
		return 0;
	}
	buffer = kvmalloc(DC_READ_SIZE, GFP_NOFS);
	if (!buffer)
		return -ENOMEM;
	err = dc_open_host(dc, n, src, O_RDONLY, &fh, false);
	if (err)
		goto free;
	in.fh = fh;
	for (;;) {
		FUSE_ARGS(a);
		ssize_t bytes;
		size_t off = 0;

		dc_args(&a, src, n, FUSE_READDIR);
		a.in_numargs = 1;
		a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
		a.out_numargs = 1;
		a.out_args[0] = (struct fuse_arg){ DC_READ_SIZE, buffer };
		a.out_argvar = true;
		bytes = dc_send(dc, &a);
		if (bytes <= 0) {
			err = bytes;
			break;
		}
		while (off < bytes) {
			struct fuse_dirent *de = (void *)(buffer + off);
			struct dc_entry *e;
			char name[NAME_MAX + 1];
			size_t len;

			if (bytes - off < FUSE_NAME_OFFSET || !de->namelen ||
			    de->namelen > NAME_MAX) {
				err = -EIO;
				goto close;
			}
			len = FUSE_DIRENT_SIZE(de);
			if (len > bytes - off || de->off == in.offset) {
				err = -EIO;
				goto close;
			}
			memcpy(name, de->name, de->namelen);
			name[de->namelen] = 0;
			in.offset = de->off;
			off += len;
			if (!strcmp(name, ".") || !strcmp(name, ".."))
				continue;
			e = dc_entry(dc, n, name, de->namelen);
			if (!e) {
				err = dc->alloc_error;
				goto close;
			}
			if (!e->node && e->type != UINT_MAX) {
				e->present = true;
				e->ino = de->ino;
				e->type = de->type;
			}
		}
	}
	if (!err)
		n->dir_loaded = true;
close:
	dc_close_host(dc, n, src, fh, O_RDONLY, false);
free:
	kvfree(buffer);
	return err;
}

static ssize_t dc_output(struct fuse_args *a, void *buffer, size_t size)
{
	struct fuse_arg *out = &a->out_args[a->out_numargs - 1];

	if (a->out_pages)
		dc_copy_pages(a, buffer, size, true);
	else
		memcpy(out->value, buffer, size);
	out->size = size;
	return a->out_argvar ? size : 0;
}

static size_t dc_dirent(char *buffer, size_t space, u64 ino, u64 cookie,
		       u32 type, const char *name)
{
	struct fuse_dirent *de = (void *)buffer;
	size_t size = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + strlen(name));

	if (size > space)
		return 0;
	memset(de, 0, size);
	de->ino = ino;
	de->off = cookie;
	de->type = type;
	de->namelen = strlen(name);
	memcpy(de->name, name, de->namelen);
	return size;
}

static ssize_t dc_readdir(struct fuse_defer *dc, struct dc_node *n,
			  struct fuse_args *a)
{
	const struct fuse_read_in *in = a->in_args[0].value;
	struct dc_entry *e;
	char *buffer;
	size_t size = 0, len;
	ssize_t err;

	err = dc_load_dir(dc, n, a);
	if (err)
		return err;
	buffer = kvzalloc(in->size, GFP_NOFS);
	if (!buffer)
		return -ENOMEM;
	if (in->offset < 1)
		size += dc_dirent(buffer, in->size, n->attr.ino, 1, DT_DIR, ".");
	if (in->offset < 2 && size < in->size) {
		struct dc_node *parent = dc_node(dc, n->parent);

		size += dc_dirent(buffer + size, in->size - size,
				  parent ? parent->attr.ino : n->attr.ino, 2, DT_DIR, "..");
	}
	list_for_each_entry(e, &n->children, list) {
		if (!e->present || e->cookie <= in->offset)
			continue;
		len = dc_dirent(buffer + size, in->size - size,
				e->node ? e->node->attr.ino : e->ino,
				e->cookie, e->type, e->name);
		if (!len)
			break;
		size += len;
	}
	err = dc_output(a, buffer, size);
	kvfree(buffer);
	return err;
}

static struct dc_xattr *dc_find_xattr(struct dc_node *n, const char *name)
{
	struct dc_xattr *x;

	list_for_each_entry(x, &n->xattrs, list)
		if (!strcmp(x->name, name))
			return x;
	return NULL;
}

static void dc_free_xattr(struct fuse_defer *dc, struct dc_xattr *x)
{
	list_del(&x->list);
	dc_free(dc, x->name);
	dc_free(dc, x->value);
	dc_free(dc, x);
}

static struct dc_xattr *dc_new_xattr(struct fuse_defer *dc, const char *name,
				    size_t size)
{
	struct dc_xattr *x = dc_alloc(dc, sizeof(*x));

	if (!x)
		return NULL;
	x->name = dc_string(dc, name);
	x->value = dc_alloc(dc, size);
	if (!x->name || !x->value) {
		dc_free(dc, x->name);
		dc_free(dc, x->value);
		dc_free(dc, x);
		return NULL;
	}
	x->size = size;
	x->present = true;
	x->fetched = true;
	return x;
}

static ssize_t dc_host_xattr(struct fuse_defer *dc, struct dc_node *n,
			     const struct fuse_args *src, const char *name,
			     void *buffer, u32 size)
{
	struct fuse_getxattr_in in = { .size = size };
	struct fuse_getxattr_out out = {};

	FUSE_ARGS(a);
	ssize_t err;

	dc_args(&a, src, n, name ? FUSE_GETXATTR : FUSE_LISTXATTR);
	a.in_numargs = name ? 2 : 1;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
	if (name)
		a.in_args[1] = (struct fuse_in_arg){ strlen(name) + 1, name };
	a.out_numargs = 1;
	a.out_argvar = size != 0;
	a.out_args[0] = size ? (struct fuse_arg){ size, buffer } :
				(struct fuse_arg){ sizeof(out), &out };
	err = dc_send(dc, &a);
	return !err && !size ? out.size : err;
}

static int dc_load_xattrs(struct fuse_defer *dc, struct dc_node *n,
			  const struct fuse_args *src)
{
	char *names, *p, *end;
	ssize_t size, len;
	int err = 0;

	if (n->xattrs_loaded)
		return 0;
	if (!n->host) {
		n->xattrs_loaded = true;
		return 0;
	}
	size = dc_host_xattr(dc, n, src, NULL, NULL, 0);
	if (size == -ENOSYS || size == -EOPNOTSUPP)
		size = 0;
	if (size < 0)
		return size;
	if (size > XATTR_LIST_MAX)
		return -E2BIG;
	if (!size) {
		n->xattrs_loaded = true;
		return 0;
	}
	names = kvmalloc(size, GFP_NOFS);
	if (!names)
		return -ENOMEM;
	len = dc_host_xattr(dc, n, src, NULL, names, size);
	if (len < 0) {
		err = len;
		goto out;
	}
	end = names + len;
	for (p = names; p < end; p += strlen(p) + 1) {
		struct dc_xattr *x;

		if (!memchr(p, 0, end - p) || !*p) {
			err = -EIO;
			goto out;
		}
		if (dc_find_xattr(n, p))
			continue;
		x = dc_new_xattr(dc, p, 0);
		if (!x) {
			err = dc->alloc_error;
			goto out;
		}
		x->fetched = false;
		list_add_tail(&x->list, &n->xattrs);
	}
	n->xattrs_loaded = true;
out:
	kvfree(names);
	return err;
}

static int dc_load_xattr(struct fuse_defer *dc, struct dc_node *n,
			 const struct fuse_args *src, const char *name,
			 struct dc_xattr **result)
{
	struct dc_xattr *old = dc_find_xattr(n, name), *x;
	ssize_t size = 0;
	bool absent = (!old && n->xattrs_loaded) || !n->host;

	if (old && old->fetched) {
		*result = old;
		return 0;
	}
	if (!absent) {
		size = dc_host_xattr(dc, n, src, name, NULL, 0);
		absent = size == -ENODATA || size == -ENOSYS || size == -EOPNOTSUPP;
		if (absent)
			size = 0;
		if (size < 0)
			return size;
		if (size > XATTR_SIZE_MAX)
			return -E2BIG;
	}
	x = dc_new_xattr(dc, name, size);
	if (!x)
		return dc->alloc_error;
	x->present = !absent;
	if (size) {
		size = dc_host_xattr(dc, n, src, name, x->value, size);
		if (size < 0) {
			INIT_LIST_HEAD(&x->list);
			dc_free_xattr(dc, x);
			return size;
		}
		x->size = size;
	}
	if (old)
		dc_free_xattr(dc, old);
	list_add_tail(&x->list, &n->xattrs);
	*result = x;
	return 0;
}

static ssize_t dc_xattr(struct fuse_defer *dc, struct dc_node *n,
			struct fuse_args *a)
{
	struct dc_xattr *x = NULL, *next = NULL;
	struct dc_op *op;
	const char *name = a->opcode == FUSE_LISTXATTR ? NULL : a->in_args[1].value;
	int err;
	size_t size = 0;
	char *buffer, *p;

	if (name)
		err = dc_load_xattr(dc, n, a, name, &x);
	else
		err = dc_load_xattrs(dc, n, a);
	if (err)
		return err;
	if (a->opcode == FUSE_SETXATTR) {
		const struct fuse_setxattr_in *in = a->in_args[0].value;

		if (x->present && (in->flags & XATTR_CREATE))
			return -EEXIST;
		if (!x->present && (in->flags & XATTR_REPLACE))
			return -ENODATA;
		next = dc_new_xattr(dc, name, in->size);
		if (!next)
			return dc->alloc_error;
		memcpy(next->value, a->in_args[2].value, in->size);
	} else if (a->opcode == FUSE_GETXATTR || a->opcode == FUSE_REMOVEXATTR) {
		if (!x->present)
			return -ENODATA;
		if (a->opcode == FUSE_REMOVEXATTR) {
			next = dc_new_xattr(dc, name, 0);
			if (!next)
				return dc->alloc_error;
			next->present = false;
		}
	}
	if (a->opcode == FUSE_SETXATTR || a->opcode == FUSE_REMOVEXATTR) {
		op = dc_save(dc, a, n);
		if (!op) {
			if (next) {
				INIT_LIST_HEAD(&next->list);
				dc_free_xattr(dc, next);
			}
			return dc->alloc_error;
		}
		if (x)
			dc_free_xattr(dc, x);
		if (next)
			list_add_tail(&next->list, &n->xattrs);
		dc_append(dc, op);
		dc_ctime(n);
		return 0;
	}
	if (name)
		size = x->size;
	else
		list_for_each_entry(x, &n->xattrs, list)
			if (x->present)
				size += strlen(x->name) + 1;
	if (!((const struct fuse_getxattr_in *)a->in_args[0].value)->size) {
		struct fuse_getxattr_out *out = a->out_args[0].value;

		*out = (struct fuse_getxattr_out){ .size = size };
		return 0;
	}
	if (size > a->out_args[0].size)
		return -ERANGE;
	if (name)
		return dc_output(a, x->value, size);
	buffer = kvmalloc(max_t(size_t, size, 1), GFP_NOFS);
	if (!buffer)
		return -ENOMEM;
	p = buffer;
	list_for_each_entry(x, &n->xattrs, list) {
		size_t len = strlen(x->name) + 1;

		if (!x->present)
			continue;
		memcpy(p, x->name, len);
		p += len;
	}
	err = dc_output(a, buffer, size);
	kvfree(buffer);
	return err;
}

static ssize_t dc_read(struct fuse_defer *dc, struct dc_node *n,
		       struct fuse_args *a)
{
	struct fuse_read_in in = *(const struct fuse_read_in *)a->in_args[0].value;
	struct dc_op *op;
	char *buffer;
	size_t size;
	ssize_t err = 0;

	if (in.offset >= n->attr.size)
		return dc_output(a, NULL, 0);
	size = min_t(u64, in.size, n->attr.size - in.offset);
	buffer = kvzalloc(size, GFP_NOFS);
	if (!buffer)
		return -ENOMEM;
	if (n->host && in.offset < n->host_size) {
		FUSE_ARGS(raw);
		u64 fh;

		if (n->read_open) {
			fh = n->read_fh;
		} else {
			err = dc_open_host(dc, n, a, O_RDONLY, &fh, false);
			if (err)
				goto out;
			if (n->open_count) {
				n->read_fh = fh;
				n->read_open = true;
			}
		}
		in.fh = fh;
		in.size = min_t(u64, size, n->host_size - in.offset);
		dc_args(&raw, a, n, FUSE_READ);
		raw.in_numargs = 1;
		raw.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
		raw.out_numargs = 1;
		raw.out_args[0] = (struct fuse_arg){ in.size, buffer };
		raw.out_argvar = true;
		err = dc_send(dc, &raw);
		if (!n->read_open)
			dc_close_host(dc, n, a, fh, O_RDONLY, false);
		if (err < 0)
			goto out;
	}
	list_for_each_entry(op, &dc->journal, list) {
		if (op->node != n)
			continue;
		if (op->args.opcode == FUSE_WRITE) {
			const struct fuse_write_in *wr = op->args.in_args[0].value;
			u64 start = max(in.offset, wr->offset);
			u64 end = min(in.offset + size, wr->offset + wr->size);

			if (end > start)
				memcpy(buffer + start - in.offset,
				       op->args.in_args[1].value + start - wr->offset,
				       end - start);
		} else if (op->args.opcode == FUSE_SETATTR) {
			const struct fuse_setattr_in *at = op->args.in_args[0].value;
			u64 start = max(in.offset, at->size);

			if ((at->valid & FATTR_SIZE) && start < in.offset + size)
				memset(buffer + start - in.offset, 0, in.offset + size - start);
		}
	}
	err = dc_output(a, buffer, size);
out:
	kvfree(buffer);
	return err;
}

static int dc_create(struct fuse_defer *dc, struct dc_node *dir,
		     struct fuse_args *a)
{
	struct dc_entry *e;
	struct dc_node *n;
	struct dc_op *op;
	const char *name = a->in_args[1].value;
	u32 mode, rdev = 0;
	int err;

	if (a->opcode == FUSE_SYMLINK) {
		mode = S_IFLNK | 0777;
	} else {
		switch (a->opcode) {
		case FUSE_CREATE:
			mode = ((const struct fuse_create_in *)a->in_args[0].value)->mode;
			break;
		case FUSE_MKDIR:
			mode = ((const struct fuse_mkdir_in *)a->in_args[0].value)->mode;
			mode = (mode & ~S_IFMT) | S_IFDIR;
			break;
		default:
			mode = ((const struct fuse_mknod_in *)a->in_args[0].value)->mode;
			rdev = ((const struct fuse_mknod_in *)a->in_args[0].value)->rdev;
		}
	}
	err = dc_lookup(dc, dir, name, strlen(name), a, &e);
	if (err)
		return err;
	if (e->present)
		return -EEXIST;
	op = dc_save(dc, a, dir);
	if (!op)
		return dc->alloc_error;
	n = dc_new_node(dc, 0);
	if (!n) {
		dc_free(dc, op);
		return dc->alloc_error;
	}
	if (a->opcode == FUSE_SYMLINK) {
		n->symlink = dc_string(dc, a->in_args[2].value);
		if (!n->symlink) {
			dc_free(dc, op);
			return dc->alloc_error;
		}
		n->attr.size = strlen(n->symlink);
	}
	n->attr.mode = mode;
	n->attr.uid = a->uid;
	n->attr.gid = a->gid;
	if (dir->attr.mode & S_ISGID) {
		n->attr.gid = dir->attr.gid;
		if (S_ISDIR(mode))
			n->attr.mode |= S_ISGID;
	}
	n->attr.ino = BIT_ULL(63) | n->id;
	n->attr.nlink = S_ISDIR(mode) ? 2 : 1;
	n->attr.rdev = rdev;
	n->attr.blksize = PAGE_SIZE;
	n->attr_valid = true;
	n->dir_loaded = S_ISDIR(mode);
	n->xattrs_loaded = true;
	n->parent = dir->id;
	dc_touch(n);
	n->attr.atime = n->attr.mtime;
	n->attr.atimensec = n->attr.mtimensec;
	e->node = n;
	e->present = true;
	e->type = (mode & S_IFMT) >> 12;
	if (S_ISDIR(mode))
		dir->attr.nlink++;
	dc_touch(dir);
	op->result = n;
	dc_append(dc, op);
	dc_entry_out(n, a->out_args[0].value);
	if (a->opcode == FUSE_CREATE) {
		struct fuse_open_out *out = a->out_args[1].value;

		n->open_count++;
		*out = (struct fuse_open_out){ .fh = n->id, .open_flags = FOPEN_KEEP_CACHE };
	}
	return 0;
}

static int dc_unlink(struct fuse_defer *dc, struct dc_node *dir,
		     struct fuse_args *a)
{
	struct dc_entry *e, *child;
	struct dc_op *op;
	struct dc_node *n;
	const char *name = a->in_args[1].value;
	int err = dc_lookup(dc, dir, name, strlen(name), a, &e);

	if (err)
		return err;
	if (!e->present)
		return -ENOENT;
	n = e->node;
	if (n->server_owned)
		return -EPERM;
	if (a->opcode == FUSE_RMDIR) {
		if (!S_ISDIR(n->attr.mode))
			return -ENOTDIR;
		err = dc_load_dir(dc, n, a);
		if (err)
			return err;
		list_for_each_entry(child, &n->children, list)
			if (child->present)
				return -ENOTEMPTY;
	} else if (S_ISDIR(n->attr.mode)) {
		return -EISDIR;
	}
	op = dc_save(dc, a, dir);
	if (!op)
		return dc->alloc_error;
	op->result = n;
	e->present = false;
	e->type = UINT_MAX;
	if (S_ISDIR(n->attr.mode)) {
		n->attr.nlink = 0;
		if (dir->attr.nlink)
			dir->attr.nlink--;
	} else if (n->attr.nlink) {
		n->attr.nlink--;
	}
	dc_touch(dir);
	dc_ctime(n);
	dc_append(dc, op);
	return 0;
}

static int dc_rename(struct fuse_defer *dc, struct dc_node *dir,
		     struct fuse_args *a)
{
	const struct fuse_rename2_in *in = a->in_args[0].value;
	struct dc_node *newdir = dc_node(dc, in->newdir);
	struct dc_entry *old, *new, *child;
	struct dc_op *op;
	u32 flags = a->opcode == FUSE_RENAME2 ? in->flags : 0;
	int err;

	if (!newdir || flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE))
		return -EOPNOTSUPP;
	if (newdir->server_owned)
		return -EPERM;
	err = dc_lookup(dc, dir, a->in_args[1].value,
			strlen(a->in_args[1].value), a, &old);
	if (err)
		return err;
	if (!old->present)
		return -ENOENT;
	err = dc_lookup(dc, newdir, a->in_args[2].value,
			strlen(a->in_args[2].value), a, &new);
	if (err)
		return err;
	if (old->node->server_owned || (new->present && new->node->server_owned))
		return -EPERM;
	if (old == new || (new->present && old->node == new->node))
		return 0;
	if (new->present && (flags & RENAME_NOREPLACE))
		return -EEXIST;
	if ((flags & RENAME_EXCHANGE) && !new->present)
		return -ENOENT;
	if (!(flags & RENAME_EXCHANGE) && new->present) {
		if (S_ISDIR(old->node->attr.mode) != S_ISDIR(new->node->attr.mode))
			return S_ISDIR(old->node->attr.mode) ? -ENOTDIR : -EISDIR;
		if (S_ISDIR(new->node->attr.mode)) {
			err = dc_load_dir(dc, new->node, a);
			if (err)
				return err;
			list_for_each_entry(child, &new->node->children, list)
				if (child->present)
					return -ENOTEMPTY;
		}
	}
	op = dc_save(dc, a, dir);
	if (!op)
		return dc->alloc_error;
	op->other = newdir;
	op->result = old->node;
	if (flags & RENAME_EXCHANGE) {
		if (dir != newdir) {
			int delta = S_ISDIR(new->node->attr.mode) - S_ISDIR(old->node->attr.mode);

			dir->attr.nlink += delta;
			newdir->attr.nlink -= delta;
		}
		swap(old->node, new->node);
		swap(old->type, new->type);
		old->node->parent = dir->id;
		dc_dirty(old->node, dc->next_seq + 1);
		dc_ctime(old->node);
	} else {
		if (new->present) {
			if (S_ISDIR(new->node->attr.mode)) {
				new->node->attr.nlink = 0;
				newdir->attr.nlink--;
			} else if (new->node->attr.nlink) {
				new->node->attr.nlink--;
			}
			dc_dirty(new->node, dc->next_seq + 1);
			dc_ctime(new->node);
		}
		if (dir != newdir && S_ISDIR(old->node->attr.mode)) {
			dir->attr.nlink--;
			newdir->attr.nlink++;
		}
		new->node = old->node;
		new->type = old->type;
		new->present = true;
		old->present = false;
		old->type = UINT_MAX;
	}
	new->node->parent = newdir->id;
	dc_touch(dir);
	dc_touch(newdir);
	dc_ctime(new->node);
	dc_append(dc, op);
	return 0;
}

static int dc_link(struct fuse_defer *dc, struct dc_node *dir, struct fuse_args *a)
{
	const struct fuse_link_in *in = a->in_args[0].value;
	struct dc_node *n = dc_node(dc, in->oldnodeid);
	struct dc_entry *e;
	struct dc_op *op;
	int err;

	if (!n)
		return -ESTALE;
	if (n->server_owned)
		return -EPERM;
	err = dc_lookup(dc, dir, a->in_args[1].value,
			strlen(a->in_args[1].value), a, &e);
	if (err)
		return err;
	if (e->present)
		return -EEXIST;
	op = dc_save(dc, a, dir);
	if (!op)
		return dc->alloc_error;
	op->result = n;
	e->node = n;
	e->present = true;
	e->type = (n->attr.mode & S_IFMT) >> 12;
	n->attr.nlink++;
	dc_ctime(n);
	dc_touch(dir);
	dc_append(dc, op);
	dc_entry_out(n, a->out_args[0].value);
	return 0;
}

static int dc_replay_write(struct fuse_defer *dc, struct dc_op *op)
{
	struct fuse_write_in in = *(const struct fuse_write_in *)op->args.in_args[0].value;
	struct fuse_write_out out;
	u32 done = 0, size = in.size;
	u64 offset = in.offset, fh;
	int err;

	err = dc_open_host(dc, op->node, &op->args, O_WRONLY, &fh, true);
	if (err)
		return err;
	while (done < size) {
		struct fuse_args a = op->args;

		in.fh = fh;
		in.offset = offset + done;
		in.size = size - done;
		a.nodeid = op->node->host;
		a.in_args[0].value = &in;
		a.in_args[1].value = op->args.in_args[1].value + done;
		a.in_args[1].size = in.size;
		a.out_numargs = 1;
		a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
		memset(&out, 0, sizeof(out));
		err = dc_replay_send(dc, &a);
		if (err)
			break;
		if (!out.size || out.size > in.size) {
			err = -EIO;
			break;
		}
		done += out.size;
		op->node->host_size = max(op->node->host_size, offset + done);
	}
	dc_close_host(dc, op->node, &op->args, fh, O_WRONLY, true);
	return err;
}

static int dc_replay(struct fuse_defer *dc, struct dc_op *op)
{
	struct fuse_args a = op->args;
	struct fuse_entry_out entry = {};
	struct fuse_open_out open = {};
	struct fuse_attr_out attr = {};
	u32 opcode = a.opcode;
	int err;

	if (opcode == FUSE_WRITE)
		return dc_replay_write(dc, op);
	a.nodeid = op->node->host;
	a.out_numargs = 0;
	switch (opcode) {
	case FUSE_CREATE:
		a.out_args[1] = (struct fuse_arg){ sizeof(open), &open };
		a.out_numargs = 1;
		fallthrough;
	case FUSE_MKDIR:
	case FUSE_MKNOD:
	case FUSE_SYMLINK:
	case FUSE_LINK:
		a.out_numargs++;
		a.out_args[0] = (struct fuse_arg){ sizeof(entry), &entry };
		if (opcode == FUSE_LINK)
			((struct fuse_link_in *)a.in_args[0].value)->oldnodeid = op->result->host;
		break;
	case FUSE_SETATTR:
		((struct fuse_setattr_in *)a.in_args[0].value)->valid &= ~FATTR_FH;
		a.out_numargs = 1;
		a.out_args[0] = (struct fuse_arg){ sizeof(attr), &attr };
		break;
	case FUSE_RENAME:
	case FUSE_RENAME2:
		((struct fuse_rename_in *)a.in_args[0].value)->newdir = op->other->host;
		break;
	}
	err = dc_replay_send(dc, &a);
	if (err)
		return err;
	if (op->result && !op->result->host && entry.nodeid) {
		op->result->host = entry.nodeid;
		op->result->host_size = entry.attr.size;
		hash_add(dc->hosts, &op->result->host_hash, entry.nodeid);
	}
	if (opcode == FUSE_CREATE)
		dc_close_host(dc, op->result, &a, open.fh,
			      ((const struct fuse_create_in *)a.in_args[0].value)->flags, true);
	if (opcode == FUSE_SETATTR) {
		const struct fuse_setattr_in *in = a.in_args[0].value;

		if (in->valid & FATTR_SIZE)
			op->node->host_size = in->size;
	}
	return 0;
}

static bool dc_has_room(struct fuse_defer *dc, size_t bytes)
{
	/* Admit a single oversized request, never an unbounded oversized backlog. */
	return !dc->journal_bytes ||
		(bytes <= dc->limit && dc->journal_bytes <= dc->limit - bytes);
}

static int dc_replay_one(struct fuse_defer *dc)
{
	struct dc_op *op = list_first_entry(&dc->journal, struct dc_op, list);
	int err = dc_replay(dc, op);

	if (err) {
		dc->writeback_error = err;
	} else {
		list_del(&op->list);
		dc->journal_bytes -= op->bytes;
		dc_free(dc, op);
	}
	wake_up_all(&dc->space_wait);
	return err;
}

static bool dc_needs_writeback(struct fuse_defer *dc)
{
	return dc->journal_bytes > dc->limit / 2 ||
		(dc->blocked_bytes && !dc_has_room(dc, dc->blocked_bytes));
}

static void dc_writeback_work(struct work_struct *work)
{
	struct fuse_defer *dc = container_of(work, struct fuse_defer, writeback_work);
	unsigned int count = 0;
	bool again;
	int err = 0;

	mutex_lock(&dc->replay_lock);
	mutex_lock(&dc->lock);
	while (!dc->stopping && !dc->writeback_error &&
	       !list_empty(&dc->journal) && dc_needs_writeback(dc)) {
		err = dc_replay_one(dc);
		if (err || ++count == DC_WRITEBACK_BATCH)
			break;
	}
	again = !dc->stopping && !dc->writeback_error &&
		!list_empty(&dc->journal) && dc_needs_writeback(dc);
	if (again)
		dc_queue_writeback(dc);
	mutex_unlock(&dc->lock);
	mutex_unlock(&dc->replay_lock);
	if (err)
		pr_warn_ratelimited("virtio-fs: deferred writeback failed: %d\n", err);
}

static int dc_commit(struct fuse_defer *dc, const struct fuse_args *src)
{
	struct dc_node *n;
	struct dc_op *op;
	u64 boundary = dc->next_seq;
	int pass, err;

	dc->writeback_error = 0;
	while (!list_empty(&dc->journal)) {
		op = list_first_entry(&dc->journal, struct dc_op, list);
		if (op->seq > boundary)
			break;
		err = dc_replay_one(dc);
		if (err)
			return err;
	}
	/* Flush file contents before directory metadata at the durability boundary. */
	for (pass = 0; pass < 2; pass++) {
		list_for_each_entry_reverse(n, &dc->nodes, list) {
			struct fuse_fsync_in in = {};

			FUSE_ARGS(a);
			u64 fh;

			if (!n->dirty || !n->host || !n->attr.nlink)
				continue;
			if (S_ISDIR(n->attr.mode) != (pass == 1))
				continue;
			if (!S_ISDIR(n->attr.mode) && !S_ISREG(n->attr.mode)) {
				if (n->dirty_seq <= boundary)
					n->dirty = false;
				continue;
			}
			err = dc_open_host(dc, n, src, O_RDONLY, &fh, true);
			if (err)
				return err;
			in.fh = fh;
			dc_args(&a, src, n, pass ? FUSE_FSYNCDIR : FUSE_FSYNC);
			a.in_numargs = 1;
			a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
			err = dc_replay_send(dc, &a);
			dc_close_host(dc, n, src, fh, O_RDONLY, true);
			if (err)
				return err;
			if (n->dirty_seq <= boundary)
				n->dirty = false;
		}
	}
	return atomic_read(&dc->write_error);
}

static ssize_t dc_server_request(struct fuse_defer *dc, struct dc_node *n,
				struct fuse_args *a)
{
	void (*end)(struct fuse_args *, int) = a->end;
	u64 nodeid = a->nodeid;
	bool force = a->force;
	ssize_t ret;

	switch (a->opcode) {
	case FUSE_OPEN: {
		const struct fuse_open_in *in = a->in_args[0].value;

		if ((in->flags & O_ACCMODE) != O_RDONLY || (in->flags & O_TRUNC))
			return -EACCES;
		fallthrough;
	}
	case FUSE_GETATTR:
	case FUSE_OPENDIR:
	case FUSE_READ:
	case FUSE_READLINK:
	case FUSE_READDIR:
	case FUSE_GETXATTR:
	case FUSE_LISTXATTR:
	case FUSE_FLUSH:
	case FUSE_RELEASE:
	case FUSE_RELEASEDIR:
		/*
		 * Keep the original request's embedded page descriptors, but leave
		 * completion to the outer worker. Only the guest RELEASE may retire
		 * a one-shot inode, not an internal read's temporary close.
		 */
		a->nodeid = n->host;
		a->end = NULL;
		ret = dc_send(dc, a);
		a->nodeid = nodeid;
		a->end = end;
		a->force = force;
		return ret;
	case FUSE_CREATE:
	case FUSE_MKNOD:
	case FUSE_MKDIR:
	case FUSE_SYMLINK:
	case FUSE_UNLINK:
	case FUSE_RMDIR:
	case FUSE_RENAME:
	case FUSE_RENAME2:
	case FUSE_LINK:
	case FUSE_SETATTR:
	case FUSE_WRITE:
	case FUSE_SETXATTR:
	case FUSE_REMOVEXATTR:
	case FUSE_FALLOCATE:
		return -EPERM;
	case FUSE_STATX:
	case FUSE_TMPFILE:
	case FUSE_GETLK:
	case FUSE_SETLK:
	case FUSE_SETLKW:
		return -ENOSYS;
	default:
		return -EOPNOTSUPP;
	}
}

static ssize_t dc_request(struct fuse_defer *dc, struct fuse_args *a)
{
	struct dc_node *n = dc_node(dc, a->nodeid ?: FUSE_ROOT_ID);
	struct dc_op *op;
	int err;

	if (a->opcode == FUSE_FSYNC || a->opcode == FUSE_FSYNCDIR ||
	    a->opcode == FUSE_SYNCFS || a->opcode == FUSE_DESTROY) {
		err = dc_commit(dc, a);
		if (err || a->opcode != FUSE_DESTROY)
			return err;
		list_for_each_entry(n, &dc->nodes, list)
			dc_close_read(dc, n, a);
		return dc_send(dc, a);
	}
	if (n && n->server_owned && a->opcode != FUSE_LOOKUP &&
	    a->opcode != FUSE_IOCTL && a->opcode != FUSE_STATFS)
		return dc_server_request(dc, n, a);
	if (a->opcode == FUSE_RELEASE) {
		if (n && n->open_count && !--n->open_count)
			dc_close_read(dc, n, a);
		return 0;
	}
	if (a->opcode == FUSE_FLUSH || a->opcode == FUSE_RELEASEDIR)
		return 0;
	if (!n)
		return -ESTALE;
	err = dc_getattr(dc, n, a);
	if (err)
		return err;
	switch (a->opcode) {
	case FUSE_GETATTR:
		dc_attr_out(n, a->out_args[0].value);
		return 0;
	case FUSE_LOOKUP: {
		struct dc_entry *e;
		const char *name = a->in_args[1].value;
		size_t len = a->in_args[1].size;

		/* LOOKUP passes a counted name and a separate terminating NUL. */
		if ((len == 1 && name[0] == '.') ||
		    (len == 2 && name[0] == '.' && name[1] == '.')) {
			struct dc_node *target = len == 1 ? n : dc_node(dc, n->parent);

			if (!target)
				return -ESTALE;
			dc_entry_out(target, a->out_args[0].value);
			return 0;
		}
		err = dc_lookup(dc, n, name, len, a, &e);
		if (!err)
			dc_entry_out(e->present ? e->node : NULL, a->out_args[0].value);
		return err;
	}
	case FUSE_OPEN:
	case FUSE_OPENDIR: {
		struct fuse_open_out *out = a->out_args[0].value;
		const struct fuse_open_in *in = a->in_args[0].value;

		if (a->opcode == FUSE_OPEN && (in->flags & O_TRUNC)) {
			struct fuse_setattr_in truncate = { .valid = FATTR_SIZE };

			FUSE_ARGS(setattr);

			setattr = *a;
			setattr.opcode = FUSE_SETATTR;
			setattr.in_args[0] = (struct fuse_in_arg){ sizeof(truncate), &truncate };
			op = dc_save(dc, &setattr, n);
			if (!op)
				return dc->alloc_error;
			dc_setattr(n, &truncate);
			dc_append(dc, op);
		}

		if (a->opcode == FUSE_OPEN)
			n->open_count++;
		*out = (struct fuse_open_out){ .fh = n->id,
			.open_flags = FOPEN_KEEP_CACHE | (a->opcode == FUSE_OPENDIR ? FOPEN_CACHE_DIR : 0) };
		return 0;
	}
	case FUSE_CREATE:
	case FUSE_MKNOD:
	case FUSE_MKDIR:
	case FUSE_SYMLINK:
		return dc_create(dc, n, a);
	case FUSE_UNLINK:
	case FUSE_RMDIR:
		return dc_unlink(dc, n, a);
	case FUSE_RENAME:
	case FUSE_RENAME2:
		return dc_rename(dc, n, a);
	case FUSE_LINK:
		return dc_link(dc, n, a);
	case FUSE_SETATTR:
		op = dc_save(dc, a, n);
		if (!op)
			return dc->alloc_error;
		dc_setattr(n, a->in_args[0].value);
		dc_append(dc, op);
		dc_attr_out(n, a->out_args[0].value);
		return 0;
	case FUSE_WRITE: {
		const struct fuse_write_in *in = a->in_args[0].value;
		struct fuse_write_out *out = a->out_args[0].value;

		op = dc_save(dc, a, n);
		if (!op)
			return dc->alloc_error;
		dc_append(dc, op);
		n->attr.size = max(n->attr.size, in->offset + in->size);
		n->attr.blocks = DIV_ROUND_UP_ULL(n->attr.size, 512);
		dc_touch(n);
		*out = (struct fuse_write_out){ .size = in->size };
		return 0;
	}
	case FUSE_READ:
		return dc_read(dc, n, a);
	case FUSE_READDIR:
		return dc_readdir(dc, n, a);
	case FUSE_READLINK:
		if (!n->symlink) {
			FUSE_ARGS(raw);
			char *buffer = kvmalloc(PATH_MAX, GFP_NOFS);
			ssize_t len;

			if (!buffer)
				return -ENOMEM;
			dc_args(&raw, a, n, FUSE_READLINK);
			raw.out_numargs = 1;
			raw.out_args[0] = (struct fuse_arg){ PATH_MAX - 1, buffer };
			raw.out_argvar = true;
			len = dc_send(dc, &raw);
			if (len < 0) {
				kvfree(buffer);
				return len;
			}
			buffer[len] = 0;
			n->symlink = dc_string(dc, buffer);
			kvfree(buffer);
			if (!n->symlink)
				return dc->alloc_error;
		}
		return dc_output(a, n->symlink, min_t(size_t, strlen(n->symlink), a->out_args[0].size));
	case FUSE_GETXATTR:
	case FUSE_LISTXATTR:
	case FUSE_SETXATTR:
	case FUSE_REMOVEXATTR:
		return dc_xattr(dc, n, a);
	case FUSE_STATFS: {
		struct fuse_args raw = *a;

		raw.nodeid = FUSE_ROOT_ID;
		return dc_send(dc, &raw);
	}
	case FUSE_IOCTL: {
		struct fuse_ioctl_in in = *(const struct fuse_ioctl_in *)a->in_args[0].value;
		struct fuse_args raw = *a;

		/* libkrun's init reports its exit code through a non-filesystem ioctl. */
		if (in.cmd != DC_EXIT_CODE_IOCTL || in.in_size || in.out_size || !n->host)
			return -EOPNOTSUPP;
		in.fh = 0;
		raw.nodeid = n->host;
		raw.in_args[0].value = &in;
		return dc_send(dc, &raw);
	}
	case FUSE_STATX:
	case FUSE_TMPFILE:
	case FUSE_GETLK:
	case FUSE_SETLK:
	case FUSE_SETLKW:
		return -ENOSYS;
	default:
		/* Unknown operations must never bypass deferred mutation semantics. */
		return -EOPNOTSUPP;
	}
}

static bool dc_is_checkpoint(u32 opcode)
{
	return opcode == FUSE_FSYNC || opcode == FUSE_FSYNCDIR ||
		opcode == FUSE_SYNCFS || opcode == FUSE_DESTROY;
}

static size_t dc_request_bytes(struct fuse_args *a)
{
	size_t bytes = sizeof(struct dc_allocation) + sizeof(struct dc_op);
	unsigned int i;

	switch (a->opcode) {
	case FUSE_OPEN:
		if (!(((const struct fuse_open_in *)a->in_args[0].value)->flags & O_TRUNC))
			return 0;
		return bytes + sizeof(struct fuse_setattr_in);
	case FUSE_CREATE:
	case FUSE_MKNOD:
	case FUSE_MKDIR:
	case FUSE_SYMLINK:
	case FUSE_UNLINK:
	case FUSE_RMDIR:
	case FUSE_RENAME:
	case FUSE_RENAME2:
	case FUSE_LINK:
	case FUSE_SETATTR:
	case FUSE_WRITE:
	case FUSE_SETXATTR:
	case FUSE_REMOVEXATTR:
		for (i = 0; i < a->in_numargs; i++)
			bytes += a->in_args[i].size;
		return bytes;
	default:
		return 0;
	}
}

static int dc_wait_for_space(struct fuse_defer *dc, size_t bytes)
{
	int err = 0;

	while (!dc_has_room(dc, bytes)) {
		size_t before = dc->journal_bytes;

		if (dc->writeback_error || dc->stopping) {
			err = dc->writeback_error ?: -ENOTCONN;
			break;
		}
		/* Admission is serialized so a large request cannot starve. */
		dc->blocked_bytes = bytes;
		dc_queue_writeback(dc);
		mutex_unlock(&dc->lock);
		wait_event(dc->space_wait,
			   READ_ONCE(dc->journal_bytes) != before ||
			   READ_ONCE(dc->writeback_error) || READ_ONCE(dc->stopping));
		mutex_lock(&dc->lock);
	}
	dc->blocked_bytes = 0;
	return err;
}

ssize_t fuse_defer_request(struct fuse_conn *fc, struct fuse_args *args)
{
	struct fuse_defer *dc = fc->defer;
	size_t bytes = dc_request_bytes(args);
	bool checkpoint = dc_is_checkpoint(args->opcode);
	ssize_t result;

	if (checkpoint)
		mutex_lock(&dc->replay_lock);
	if (bytes)
		mutex_lock(&dc->admission_lock);
	mutex_lock(&dc->lock);
	result = 0;
	if (!dc->initialized) {
		result = fuse_chan_wait_initialized(fc->chan);
		if (!result && fc->conn_error)
			result = -ECONNREFUSED;
		if (!result)
			dc->initialized = true;
	}
	if (!result && bytes)
		result = dc_wait_for_space(dc, bytes);
	if (!result)
		result = dc_request(dc, args);
	if (result < 0 && args->opcode == FUSE_WRITE)
		atomic_cmpxchg(&dc->write_error, 0, result);
	mutex_unlock(&dc->lock);
	if (bytes)
		mutex_unlock(&dc->admission_lock);
	if (checkpoint)
		mutex_unlock(&dc->replay_lock);
	return result;
}

struct dc_work {
	struct work_struct work;
	struct fuse_conn *fc;
	struct fuse_args *args;
};

static void dc_work(struct work_struct *work)
{
	struct dc_work *w = container_of(work, struct dc_work, work);
	struct fuse_conn *fc = w->fc;
	struct fuse_args *args = w->args;
	ssize_t result = fuse_defer_request(fc, args);

	args->end(args, result < 0 ? result : 0);
	atomic_dec(&fc->defer->pending);
	kfree(w);
	fuse_conn_put(fc);
}

int fuse_defer_background(struct fuse_conn *fc, struct fuse_args *args, gfp_t gfp)
{
	struct dc_work *w;

	/* Dirty-page throttling, not a request-count cutoff, bounds writeback. */
	atomic_inc(&fc->defer->pending);
	w = kmalloc_obj(*w, gfp);
	if (!w) {
		atomic_dec(&fc->defer->pending);
		if (args->opcode == FUSE_WRITE)
			atomic_cmpxchg(&fc->defer->write_error, 0, -ENOMEM);
		return -ENOMEM;
	}
	w->fc = fuse_conn_get(fc);
	w->args = args;
	INIT_WORK(&w->work, dc_work);
	queue_work(system_unbound_wq, &w->work);
	return 0;
}

int fuse_defer_sync(struct super_block *sb)
{
	int err;

	/* No inode lock may be held: every inode participates in this checkpoint. */
	down_read(&sb->s_umount);
	err = sync_filesystem(sb);
	up_read(&sb->s_umount);
	return err;
}

int fuse_defer_init(struct fuse_conn *fc)
{
	struct fuse_defer *dc;
	struct dc_node *root;

	dc = kzalloc_obj(*dc);
	if (!dc)
		return -ENOMEM;
	mutex_init(&dc->lock);
	mutex_init(&dc->replay_lock);
	mutex_init(&dc->admission_lock);
	init_waitqueue_head(&dc->space_wait);
	INIT_WORK(&dc->writeback_work, dc_writeback_work);
	dc->writeback_wq = alloc_workqueue("fuse-defer-writeback",
					 WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!dc->writeback_wq) {
		kfree(dc);
		return -ENOMEM;
	}
	dc->fc = fc;
	dc->send = fuse_chan_send;
	atomic_set(&dc->pending, 0);
	atomic_set(&dc->write_error, 0);
	dc->limit = min_t(unsigned long, deferred_cache_mb, ULONG_MAX >> 20) << 20;
	dc->next_id = FUSE_ROOT_ID;
	INIT_LIST_HEAD(&dc->nodes);
	INIT_LIST_HEAD(&dc->journal);
	hash_init(dc->names);
	hash_init(dc->hosts);
	xa_init(&dc->ids);
	root = dc_new_node(dc, FUSE_ROOT_ID);
	if (!root) {
		int err = dc->alloc_error;

		xa_destroy(&dc->ids);
		destroy_workqueue(dc->writeback_wq);
		kfree(dc);
		return err;
	}
	root->parent = FUSE_ROOT_ID;
	fc->defer = dc;
	return 0;
}
EXPORT_SYMBOL_GPL(fuse_defer_init);

void fuse_defer_destroy(struct fuse_conn *fc)
{
	struct fuse_defer *dc = fc->defer;
	struct dc_node *n, *next;
	struct dc_op *op, *next_op;

	if (!dc)
		return;
	mutex_lock(&dc->lock);
	dc->stopping = true;
	wake_up_all(&dc->space_wait);
	mutex_unlock(&dc->lock);
	cancel_work_sync(&dc->writeback_work);
	destroy_workqueue(dc->writeback_wq);
	list_for_each_entry_safe(op, next_op, &dc->journal, list)
		dc_free(dc, op);
	list_for_each_entry_safe(n, next, &dc->nodes, list) {
		struct dc_entry *e, *next_e;
		struct dc_xattr *x, *next_x;

		list_for_each_entry_safe(e, next_e, &n->children, list)
			dc_free(dc, e);
		list_for_each_entry_safe(x, next_x, &n->xattrs, list)
			dc_free_xattr(dc, x);
		dc_free(dc, n->symlink);
		dc_free(dc, n);
	}
	xa_destroy(&dc->ids);
	kfree(dc);
	fc->defer = NULL;
}

#if IS_ENABLED(CONFIG_FUSE_DEFER_KUNIT_TEST)
#include "defer_test.c"
#endif
