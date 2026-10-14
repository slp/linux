.. SPDX-License-Identifier: GPL-2.0

.. _virtiofs_index:

===================================================
virtiofs: virtio-fs host<->guest shared file system
===================================================

- Copyright (C) 2019 Red Hat, Inc.

Introduction
============
The virtiofs file system for Linux implements a driver for the paravirtualized
VIRTIO "virtio-fs" device for guest<->host file system sharing.  It allows a
guest to mount a directory that has been exported on the host.

Guests often require access to files residing on the host or remote systems.
Use cases include making files available to new guests during installation,
booting from a root file system located on the host, persistent storage for
stateless or ephemeral guests, and sharing a directory between guests.

Although it is possible to use existing network file systems for some of these
tasks, they require configuration steps that are hard to automate and they
expose the storage network to the guest.  The virtio-fs device was designed to
solve these problems by providing file system access without networking.

Furthermore the virtio-fs device takes advantage of the co-location of the
guest and host to increase performance and provide semantics that are not
possible with network file systems.

Usage
=====
Mount file system with tag ``myfs`` on ``/mnt``:

.. code-block:: sh

  guest# mount -t virtiofs myfs /mnt

Please see https://virtio-fs.gitlab.io/ for details on how to configure QEMU
and the virtiofsd daemon.

Mount options
-------------

virtiofs supports general VFS mount options, for example, remount,
ro, rw, context, etc. It also supports FUSE mount options.

atime behavior
^^^^^^^^^^^^^^

The atime-related mount options, for example, noatime, strictatime,
are ignored. The atime behavior for virtiofs is the same as the
underlying filesystem of the directory that has been exported
on the host.

Internals
=========
Since the virtio-fs device uses the FUSE protocol for file system requests, the
virtiofs file system for Linux is integrated closely with the FUSE file system
client.  The guest acts as the FUSE client while the host acts as the FUSE
server.  The /dev/fuse interface between the kernel and userspace is replaced
with the virtio-fs device interface.

FUSE requests are placed into a virtqueue and processed by the host.  The
response portion of the buffer is filled in by the host and the guest handles
the request completion.

Mapping /dev/fuse to virtqueues requires solving differences in semantics
between /dev/fuse and virtqueues.  Each time the /dev/fuse device is read, the
FUSE client may choose which request to transfer, making it possible to
prioritize certain requests over others.  Virtqueues have queue semantics and
it is not possible to change the order of requests that have been enqueued.
This is especially important if the virtqueue becomes full since it is then
impossible to add high priority requests.  In order to address this difference,
the virtio-fs device uses a "hiprio" virtqueue specifically for requests that
have priority over normal requests.

Synchronous request queues
--------------------------

The experimental ``VIRTIO_FS_F_SYNC`` feature (bit 1) adds synchronous request
queues without changing the hiprio and normal request queues.  When this feature
is negotiated, the device configuration includes a ``le32 num_sync_queues`` field
immediately after ``num_request_queues``.  The device must advertise at least one
synchronous queue.

Queue 0 remains the hiprio queue and queues 1 through ``num_request_queues``
remain normal request queues.  Synchronous queue ``i`` has index
``1 + num_request_queues + i`` and is associated with guest CPU ``i``.  The driver
uses at most ``nr_cpu_ids`` synchronous queues.  Non-background requests use the
current CPU's synchronous queue when it exists; other requests use the normal
request queue mapping.  FORGET requests always use the hiprio queue.

The device must complete requests on a synchronous queue and publish the used
buffers before returning from a queue notification.  This allows the host to
execute the request in the notifying vCPU thread and the guest to process the
completion immediately.  The driver always notifies synchronous queues,
regardless of event suppression.  The queue identifies synchronous requests;
the FUSE request header retains its original layout and padding.

Deferred guest writeback (experimental)
---------------------------------------

``VIRTIO_FS_F_DEFERRED_WRITEBACK`` (experimental bit 2) permits a guest to keep
filesystem mutations entirely in guest memory until an explicit checkpoint.
It is independent of ``VIRTIO_FS_F_SYNC``. Both the device and the driver must
negotiate it; devices must not offer it by default. The libkrun filesystem API
offers it through ``FsDevice::set_deferred_writeback(true)`` or the equivalent
``krun_fs_device_set_deferred_writeback()`` C function.

The guest must exclusively own the exported directory. Concurrent host writers,
other guests, cache invalidations, and cross-domain file descriptor export are
not supported. Cached attributes and positive and negative name and xattr
lookups are authoritative until unmount. Local mutations update these cached
results without revalidating them on the host. Cached directory contents and
symlink targets are also retained. Cold reads can still require host requests.

File data uses the guest page cache. Background writeback and close move dirty
data into the guest journal, not to the host. The journal also records create,
mkdir, mknod, symlink, link, unlink, rmdir, rename, setattr, setxattr and
removexattr operations. Files created locally have stable guest inode IDs, which
are mapped to host node IDs when their creation is replayed. Unknown operations
are rejected rather than forwarded, so they cannot silently bypass the journal.
In particular, this initial implementation does not support tmpfile, fallocate,
copy-file-range, filesystem ioctls, or direct host mappings. Applications must
use ordinary read/write and named-file creation paths instead.
The libkrun init exit-status ioctl remains available because it does not mutate
the filesystem; normal shutdown subsequently issues ``sync()``.

``fsync()`` and directory ``fsync()`` checkpoint the whole mount, including the
page cache of other files. ``sync()``, ``syncfs()`` and clean unmount also
checkpoint. The journal is replayed in order, followed by host fsyncs of affected
files and directories. A completed journal operation is not replayed again if a
later operation fails. Dirty durability state is retained after host fsync
failure so a subsequent checkpoint can retry. A checkpoint is not an atomic
transaction: host-visible changes may be partially applied on error or crash.

The ``fuse.deferred_cache_mb`` parameter sets the per-mount cache and journal
budget, in MiB (default 256). Namespace/inode and xattr records are pinned for
the mount lifetime in this initial implementation; successful commits free the
journal, but not these records. Cache exhaustion returns ``ENOSPC`` and memory
allocation failures return ``ENOMEM``; neither triggers an implicit commit.
If buffered data could not be retained, subsequent checkpoints continue to
report the write error rather than claim that the data was made durable.

Uncommitted changes are lost on guest crash or forced teardown. Clean-unmount
commit failures are logged, but teardown cannot preserve an in-memory journal.
DAX, read-only exports, NullFs exports and context-dependent permission
semantics are incompatible with this mode. There is no change to normal FUSE
or virtio-fs behavior when the feature is not negotiated.

``CONFIG_FUSE_DEFER_KUNIT_TEST`` builds request-level cache and replay tests.
``fs/fuse/defer.config`` provides a Kconfig fragment for these tests. They verify
that repeated getattr and getxattr requests, including absent xattrs, do not
reach the backend, and cover deferred writes, commit retries and cache limits.

Without ``VIRTIO_FS_F_SYNC``, the driver does not read ``num_sync_queues`` or
initialize synchronous queues, and retains the original queue routing and
completion handling.
