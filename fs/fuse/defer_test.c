// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>

struct dc_test_state {
	struct fuse_conn fc;
	u32 calls[64];
	u32 fail;
	u64 next_host;
	char disk[128];
	size_t disk_size;
	char symlink_name[32];
	char symlink_target[128];
};

static struct fuse_attr dc_test_attr(u64 id)
{
	return (struct fuse_attr){
		.ino = id, .mode = id == 1 ? S_IFDIR | 0755 : S_IFREG | 0644,
		.nlink = id == 1 ? 2 : 1, .blksize = PAGE_SIZE, .size = id == 100 ? 4 : 0,
	};
}

static ssize_t dc_test_send(struct fuse_chan *chan, struct fuse_args *a)
{
	struct dc_test_state *s = (void *)chan;

	if (a->opcode >= ARRAY_SIZE(s->calls))
		return -ENOSYS;
	s->calls[a->opcode]++;
	if (s->fail == a->opcode)
		return -EIO;
	switch (a->opcode) {
	case FUSE_GETATTR: {
		struct fuse_attr_out *out = a->out_args[0].value;

		*out = (struct fuse_attr_out){ .attr = dc_test_attr(a->nodeid) };
		return 0;
	}
	case FUSE_LOOKUP: {
		struct fuse_entry_out *out = a->out_args[0].value;

		if (a->in_numargs != 3 || a->in_args[0].size || a->in_args[0].value ||
		    a->in_args[2].size != 1 || memcmp(a->in_args[2].value, "", 1))
			return -EINVAL;
		if (a->in_args[1].size != 4 || memcmp(a->in_args[1].value, "base", 4))
			return -ENOENT;
		*out = (struct fuse_entry_out){ .nodeid = 100, .attr = dc_test_attr(100) };
		return 0;
	}
	case FUSE_SYMLINK:
		if (a->in_numargs != 3 || a->in_args[0].size || a->in_args[0].value)
			return -EINVAL;
		strscpy(s->symlink_name, a->in_args[1].value, sizeof(s->symlink_name));
		strscpy(s->symlink_target, a->in_args[2].value, sizeof(s->symlink_target));
		fallthrough;
	case FUSE_CREATE:
	case FUSE_MKNOD:
	case FUSE_MKDIR: {
		struct fuse_entry_out *out = a->out_args[0].value;
		u64 host = ++s->next_host;

		*out = (struct fuse_entry_out){ .nodeid = host, .attr = dc_test_attr(host) };
		if (a->opcode == FUSE_CREATE)
			*(struct fuse_open_out *)a->out_args[1].value =
				(struct fuse_open_out){ .fh = host };
		return 0;
	}
	case FUSE_OPEN:
	case FUSE_OPENDIR:
		*(struct fuse_open_out *)a->out_args[0].value =
			(struct fuse_open_out){ .fh = a->nodeid };
		return 0;
	case FUSE_READ: {
		const struct fuse_read_in *in = a->in_args[0].value;
		size_t size = in->offset >= s->disk_size ? 0 :
			min_t(size_t, in->size, s->disk_size - in->offset);

		return dc_output(a, s->disk + min_t(u64, in->offset, sizeof(s->disk)), size);
	}
	case FUSE_WRITE: {
		const struct fuse_write_in *in = a->in_args[0].value;
		struct fuse_write_out *out = a->out_args[0].value;

		if (in->offset + in->size > sizeof(s->disk))
			return -ENOSPC;
		memcpy(s->disk + in->offset, a->in_args[1].value, in->size);
		s->disk_size = max_t(size_t, s->disk_size, in->offset + in->size);
		*out = (struct fuse_write_out){ .size = in->size };
		return 0;
	}
	case FUSE_SETATTR: {
		const struct fuse_setattr_in *in = a->in_args[0].value;

		if ((in->valid & FATTR_SIZE) && in->size <= sizeof(s->disk)) {
			if (in->size > s->disk_size)
				memset(s->disk + s->disk_size, 0, in->size - s->disk_size);
			s->disk_size = in->size;
		}
		*(struct fuse_attr_out *)a->out_args[0].value =
			(struct fuse_attr_out){ .attr = dc_test_attr(a->nodeid) };
		return 0;
	}
	case FUSE_GETXATTR: {
		const struct fuse_getxattr_in *in = a->in_args[0].value;

		if (strcmp(a->in_args[1].value, "user.present"))
			return -ENODATA;
		if (!in->size) {
			*(struct fuse_getxattr_out *)a->out_args[0].value =
				(struct fuse_getxattr_out){ .size = 4 };
			return 0;
		}
		return dc_output(a, "seed", 4);
	}
	case FUSE_LISTXATTR: {
		const struct fuse_getxattr_in *in = a->in_args[0].value;

		if (!in->size) {
			*(struct fuse_getxattr_out *)a->out_args[0].value =
				(struct fuse_getxattr_out){ .size = sizeof("user.present") };
			return 0;
		}
		return dc_output(a, "user.present", sizeof("user.present"));
	}
	case FUSE_READDIR:
		return dc_output(a, NULL, 0);
	default:
		return 0;
	}
}

static int dc_test_init(struct kunit *test)
{
	struct dc_test_state *s = kunit_kzalloc(test, sizeof(*s), GFP_KERNEL);
	int err;

	if (!s)
		return -ENOMEM;
	test->priv = s;
	s->next_host = 100;
	memcpy(s->disk, "seed", 4);
	s->disk_size = 4;
	err = fuse_defer_init(&s->fc);
	if (err)
		return err;
	s->fc.chan = (void *)s;
	s->fc.defer->send = dc_test_send;
	s->fc.defer->initialized = true;
	return 0;
}

static void dc_test_exit(struct kunit *test)
{
	struct dc_test_state *s = test->priv;

	fuse_defer_destroy(&s->fc);
}

static u64 dc_test_lookup_name(struct kunit *test, const struct qstr *name)
{
	struct dc_test_state *s = test->priv;
	struct fuse_entry_out out = {};

	FUSE_ARGS(a);

	a.opcode = FUSE_LOOKUP;
	a.nodeid = 1;
	a.in_numargs = 3;
	fuse_set_zero_arg0(&a);
	a.in_args[1] = (struct fuse_in_arg){ name->len, name->name };
	a.in_args[2] = (struct fuse_in_arg){ 1, "" };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
	KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &a), 0);
	return out.nodeid;
}

static u64 dc_test_lookup(struct kunit *test, const char *name)
{
	const struct qstr qstr = QSTR_INIT(name, strlen(name));

	return dc_test_lookup_name(test, &qstr);
}

static u64 dc_test_create(struct kunit *test, const char *name)
{
	struct dc_test_state *s = test->priv;
	struct fuse_create_in in = { .flags = O_RDWR, .mode = S_IFREG | 0644 };
	struct fuse_entry_out out;
	struct fuse_open_out open;

	FUSE_ARGS(a);

	a.opcode = FUSE_CREATE;
	a.nodeid = 1;
	a.in_numargs = 2;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
	a.in_args[1] = (struct fuse_in_arg){ strlen(name) + 1, name };
	a.out_numargs = 2;
	a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
	a.out_args[1] = (struct fuse_arg){ sizeof(open), &open };
	KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &a), 0);
	return out.nodeid;
}

static int dc_test_write(struct kunit *test, u64 id, u64 offset, const char *data)
{
	struct dc_test_state *s = test->priv;
	struct fuse_write_in in = { .fh = id, .offset = offset, .size = strlen(data) };
	struct fuse_write_out out;

	FUSE_ARGS(a);

	a.opcode = FUSE_WRITE;
	a.nodeid = id;
	a.in_numargs = 2;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
	a.in_args[1] = (struct fuse_in_arg){ in.size, data };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
	return fuse_defer_request(&s->fc, &a);
}

static ssize_t dc_test_read(struct kunit *test, u64 id, char *data, size_t size)
{
	struct dc_test_state *s = test->priv;
	struct fuse_read_in in = { .fh = id, .size = size };

	FUSE_ARGS(a);

	a.opcode = FUSE_READ;
	a.nodeid = id;
	a.in_numargs = 1;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ size, data };
	a.out_argvar = true;
	return fuse_defer_request(&s->fc, &a);
}

static int dc_test_commit(struct kunit *test, u32 opcode)
{
	struct dc_test_state *s = test->priv;

	FUSE_ARGS(a);

	a.opcode = opcode;
	a.nodeid = 1;
	return fuse_defer_request(&s->fc, &a);
}

static void dc_cached_attributes(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	u64 id = dc_test_lookup(test, "base");
	struct fuse_attr_out out;

	FUSE_ARGS(a);
	int i;

	a.opcode = FUSE_GETATTR;
	a.nodeid = id;
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
	for (i = 0; i < 10; i++) {
		KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &a), 0);
		KUNIT_EXPECT_EQ(test, out.attr.size, 4);
		KUNIT_EXPECT_EQ(test, dc_test_lookup(test, "base"), id);
		KUNIT_EXPECT_EQ(test, dc_test_lookup(test, "absent"), 0);
	}
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_GETATTR], 1);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_LOOKUP], 2);
}

static void dc_lookup_uses_counted_names(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	const struct qstr names[] = {
		QSTR_INIT("base/suffix", 4),
		QSTR_INIT("absent/suffix", 6),
		QSTR_INIT("./suffix", 1),
		QSTR_INIT("../suffix", 2),
	};
	u64 id = dc_test_lookup_name(test, &names[0]);

	KUNIT_ASSERT_NE(test, id, 0);
	KUNIT_EXPECT_EQ(test, dc_test_lookup(test, "base"), id);
	KUNIT_EXPECT_EQ(test, dc_test_lookup_name(test, &names[1]), 0);
	KUNIT_EXPECT_EQ(test, dc_test_lookup(test, "absent"), 0);
	KUNIT_EXPECT_EQ(test, dc_test_lookup_name(test, &names[2]), FUSE_ROOT_ID);
	KUNIT_EXPECT_EQ(test, dc_test_lookup_name(test, &names[3]), FUSE_ROOT_ID);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_LOOKUP], 2);
}

static void dc_symlink_uses_zero_header_layout(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	struct fuse_entry_out out = {};
	char name[] = "link", target[] = "base/target";
	char buffer[32];

	FUSE_ARGS(a);
	FUSE_ARGS(read);

	a.opcode = FUSE_SYMLINK;
	a.nodeid = FUSE_ROOT_ID;
	a.in_numargs = 3;
	fuse_set_zero_arg0(&a);
	a.in_args[1] = (struct fuse_in_arg){ sizeof(name), name };
	a.in_args[2] = (struct fuse_in_arg){ sizeof(target), target };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
	KUNIT_ASSERT_EQ(test, fuse_defer_request(&s->fc, &a), 0);
	KUNIT_ASSERT_NE(test, out.nodeid, 0);
	KUNIT_EXPECT_EQ(test, out.attr.mode, S_IFLNK | 0777);
	KUNIT_EXPECT_EQ(test, out.attr.size, strlen("base/target"));
	memset(name, 'x', sizeof(name) - 1);
	memset(target, 'x', sizeof(target) - 1);
	KUNIT_EXPECT_EQ(test, dc_test_lookup(test, "link"), out.nodeid);
	read.opcode = FUSE_READLINK;
	read.nodeid = out.nodeid;
	read.out_numargs = 1;
	read.out_args[0] = (struct fuse_arg){ sizeof(buffer), buffer };
	read.out_argvar = true;
	KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &read), strlen("base/target"));
	KUNIT_EXPECT_MEMEQ(test, buffer, "base/target", strlen("base/target"));
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_SYMLINK], 0);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_READLINK], 0);
	KUNIT_ASSERT_EQ(test, dc_test_commit(test, FUSE_FSYNCDIR), 0);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_SYMLINK], 1);
	KUNIT_EXPECT_STREQ(test, s->symlink_name, "link");
	KUNIT_EXPECT_STREQ(test, s->symlink_target, "base/target");
	KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &read), strlen("base/target"));
	KUNIT_EXPECT_MEMEQ(test, buffer, "base/target", strlen("base/target"));
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_READLINK], 0);
}

static void dc_cached_xattrs(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	u64 id = dc_test_lookup(test, "base");
	struct fuse_getxattr_in in = { .size = 32 };
	char buffer[32];

	FUSE_ARGS(a);
	int i;

	a.opcode = FUSE_GETXATTR;
	a.nodeid = id;
	a.in_numargs = 2;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
	a.out_numargs = 1;
	a.out_argvar = true;
	for (i = 0; i < 10; i++) {
		a.in_args[1] = (struct fuse_in_arg){ sizeof("user.present"), "user.present" };
		a.out_args[0] = (struct fuse_arg){ sizeof(buffer), buffer };
		KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &a), 4);
		KUNIT_EXPECT_MEMEQ(test, buffer, "seed", 4);
		a.in_args[1] = (struct fuse_in_arg){ sizeof("security.absent"), "security.absent" };
		KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &a), -ENODATA);
	}
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_GETXATTR], 3);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_LISTXATTR], 0);
}

static void dc_deferred_mutations(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	u64 id = dc_test_create(test, "new");
	char buffer[8] = {};
	u32 opcode;

	KUNIT_ASSERT_NE(test, id, 0);
	KUNIT_EXPECT_EQ(test, dc_test_write(test, id, 0, "local"), 0);
	KUNIT_EXPECT_EQ(test, dc_test_read(test, id, buffer, sizeof(buffer)), 5);
	KUNIT_EXPECT_MEMEQ(test, buffer, "local", 5);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_CREATE], 0);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_WRITE], 0);
	for (opcode = FUSE_FSYNC; opcode <= FUSE_SYNCFS; opcode++) {
		if (opcode != FUSE_FSYNC && opcode != FUSE_FSYNCDIR && opcode != FUSE_SYNCFS)
			continue;
		KUNIT_EXPECT_EQ(test, dc_test_commit(test, opcode), 0);
		KUNIT_EXPECT_TRUE(test, list_empty(&s->fc.defer->journal));
	}
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_CREATE], 1);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_WRITE], 1);
	KUNIT_EXPECT_MEMEQ(test, s->disk, "local", 5);
	KUNIT_EXPECT_GT(test, s->calls[FUSE_FSYNC], 0);
	KUNIT_EXPECT_GT(test, s->calls[FUSE_FSYNCDIR], 0);
}

static void dc_failed_replay_is_retryable(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	u64 id = dc_test_create(test, "new");
	char buffer[8];

	KUNIT_EXPECT_EQ(test, dc_test_write(test, id, 0, "local"), 0);
	s->fail = FUSE_WRITE;
	KUNIT_EXPECT_EQ(test, dc_test_commit(test, FUSE_FSYNC), -EIO);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_CREATE], 1);
	KUNIT_EXPECT_FALSE(test, list_empty(&s->fc.defer->journal));
	KUNIT_EXPECT_EQ(test, dc_test_read(test, id, buffer, sizeof(buffer)), 5);
	KUNIT_EXPECT_MEMEQ(test, buffer, "local", 5);
	s->fail = 0;
	KUNIT_EXPECT_EQ(test, dc_test_commit(test, FUSE_SYNCFS), 0);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_CREATE], 1);
}

static void dc_cache_limit_never_flushes(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	u64 id = dc_test_create(test, "new");

	s->fc.defer->limit = s->fc.defer->used;
	KUNIT_EXPECT_EQ(test, dc_test_write(test, id, 0, "no room"), -ENOSPC);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_CREATE], 0);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_WRITE], 0);
	KUNIT_EXPECT_EQ(test, dc_test_commit(test, FUSE_SYNCFS), -ENOSPC);
}

static void dc_xattr_mutations_stay_cached(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	u64 id = dc_test_lookup(test, "base");
	struct fuse_setxattr_in set = { .size = 5 };
	struct fuse_getxattr_in get = { .size = 32 };
	char buffer[32];

	FUSE_ARGS(a);

	a.opcode = FUSE_SETXATTR;
	a.nodeid = id;
	a.in_numargs = 3;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(set), &set };
	a.in_args[1] = (struct fuse_in_arg){ sizeof("user.present"), "user.present" };
	a.in_args[2] = (struct fuse_in_arg){ 5, "local" };
	KUNIT_ASSERT_EQ(test, fuse_defer_request(&s->fc, &a), 0);
	a.opcode = FUSE_GETXATTR;
	a.in_numargs = 2;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(get), &get };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(buffer), buffer };
	a.out_argvar = true;
	KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &a), 5);
	KUNIT_EXPECT_MEMEQ(test, buffer, "local", 5);
	a.opcode = FUSE_REMOVEXATTR;
	a.in_args[0] = (struct fuse_in_arg){};
	a.in_numargs = 2;
	a.out_numargs = 0;
	a.out_argvar = false;
	KUNIT_ASSERT_EQ(test, fuse_defer_request(&s->fc, &a), 0);
	a.opcode = FUSE_GETXATTR;
	a.in_numargs = 2;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(get), &get };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(buffer), buffer };
	a.out_argvar = true;
	KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &a), -ENODATA);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_GETXATTR], 2);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_SETXATTR], 0);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_REMOVEXATTR], 0);
	KUNIT_EXPECT_EQ(test, dc_test_commit(test, FUSE_SYNCFS), 0);
	KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &a), -ENODATA);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_GETXATTR], 2);
}

static void dc_truncate_and_extend_preserve_zeroes(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	u64 id = dc_test_lookup(test, "base");
	struct fuse_setattr_in in = { .valid = FATTR_SIZE, .size = 2 };
	struct fuse_attr_out out;
	char buffer[8] = {};

	FUSE_ARGS(a);

	KUNIT_ASSERT_EQ(test, dc_test_write(test, id, 0, "data"), 0);
	a.opcode = FUSE_SETATTR;
	a.nodeid = id;
	a.in_numargs = 1;
	a.in_args[0] = (struct fuse_in_arg){ sizeof(in), &in };
	a.out_numargs = 1;
	a.out_args[0] = (struct fuse_arg){ sizeof(out), &out };
	KUNIT_ASSERT_EQ(test, fuse_defer_request(&s->fc, &a), 0);
	in.size = 6;
	KUNIT_ASSERT_EQ(test, fuse_defer_request(&s->fc, &a), 0);
	KUNIT_EXPECT_EQ(test, out.attr.size, 6);
	KUNIT_EXPECT_EQ(test, dc_test_read(test, id, buffer, sizeof(buffer)), 6);
	KUNIT_EXPECT_MEMEQ(test, buffer, "da\0\0\0\0", 6);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_SETATTR], 0);
	KUNIT_EXPECT_EQ(test, dc_test_commit(test, FUSE_SYNCFS), 0);
	KUNIT_EXPECT_MEMEQ(test, s->disk, "da\0\0\0\0", 6);
}

static void dc_failed_fsync_keeps_durability_state(struct kunit *test)
{
	struct dc_test_state *s = test->priv;
	u64 id = dc_test_create(test, "new");

	KUNIT_ASSERT_EQ(test, dc_test_write(test, id, 0, "local"), 0);
	s->fail = FUSE_FSYNC;
	KUNIT_EXPECT_EQ(test, dc_test_commit(test, FUSE_SYNCFS), -EIO);
	KUNIT_EXPECT_TRUE(test, list_empty(&s->fc.defer->journal));
	KUNIT_EXPECT_TRUE(test, dc_node(s->fc.defer, id)->dirty);
	s->fail = 0;
	KUNIT_EXPECT_EQ(test, dc_test_commit(test, FUSE_SYNCFS), 0);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_CREATE], 1);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_WRITE], 1);
	KUNIT_EXPECT_FALSE(test, dc_node(s->fc.defer, id)->dirty);
}

static void dc_unrecognized_mutation_never_reaches_host(struct kunit *test)
{
	struct dc_test_state *s = test->priv;

	FUSE_ARGS(a);

	a.opcode = FUSE_FALLOCATE;
	a.nodeid = 1;
	KUNIT_EXPECT_EQ(test, fuse_defer_request(&s->fc, &a), -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, s->calls[FUSE_FALLOCATE], 0);
}

static struct kunit_case dc_tests[] = {
	KUNIT_CASE(dc_cached_attributes),
	KUNIT_CASE(dc_lookup_uses_counted_names),
	KUNIT_CASE(dc_symlink_uses_zero_header_layout),
	KUNIT_CASE(dc_cached_xattrs),
	KUNIT_CASE(dc_deferred_mutations),
	KUNIT_CASE(dc_failed_replay_is_retryable),
	KUNIT_CASE(dc_cache_limit_never_flushes),
	KUNIT_CASE(dc_xattr_mutations_stay_cached),
	KUNIT_CASE(dc_truncate_and_extend_preserve_zeroes),
	KUNIT_CASE(dc_failed_fsync_keeps_durability_state),
	KUNIT_CASE(dc_unrecognized_mutation_never_reaches_host),
	{}
};

static struct kunit_suite dc_suite = {
	.name = "fuse-deferred-writeback",
	.init = dc_test_init,
	.exit = dc_test_exit,
	.test_cases = dc_tests,
};

kunit_test_suite(dc_suite);
