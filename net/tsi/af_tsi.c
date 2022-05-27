#include <linux/types.h>
#include <linux/poll.h>
#include <net/sock.h>
#include <net/af_vsock.h>

#define S_IDLE			0
#define S_CONNECTING_INET	1
#define S_CONNECTED_VSOCK	2
#define S_CONNECTED_INET        3

#define TSI_CID 2
#define TSI_DEFAULT_PORT  620

#define TSI_PROXY_CREATE  1024
#define TSI_CONNECT       1025
#define TSI_GETNAME       1026
#define TSI_SENDTO_ADDR   1027
#define TSI_SENDTO_DATA   1028
#define TSI_LISTEN        1029
#define TSI_ACCEPT        1030
#define TSI_PROXY_RELEASE 1031

struct tsi_proxy_create {
	u32 svm_port;
	u16 type;
} __attribute__((packed));

struct tsi_connect_req {
	u32 svm_port;
	u32 addr;
	u16 port;
} __attribute__((packed));

struct tsi_connect_rsp {
	int result;
};

struct tsi_sendto_addr {
	u32 svm_port;
	u32 addr;
	u16 port;
} __attribute__((packed));

struct tsi_listen_req {
	u32 svm_port;
	u32 addr;
	u16 port;
	u32 vm_port;
	int backlog;
} __attribute__((packed));

struct tsi_listen_rsp {
	int result;
};

struct tsi_accept_req {
	u32 svm_port;
	int flags;
} __attribute__((packed));

struct tsi_accept_rsp {
	int result;
} __attribute__((packed));

struct tsi_getname_req {
	u32 svm_port;
	u32 svm_peer_port;
	u32 peer;
} __attribute__((packed));

struct tsi_getname_rsp {
	u32 addr;
	u16 port;
} __attribute__((packed));

struct tsi_sock {
	/* sk must be the first member. */
	struct sock sk;
	struct socket *isocket;
	struct socket *vsocket;
	struct socket *csocket;
	unsigned int status;
	u32 svm_port;
	u32 svm_peer_port;
	struct sockaddr_in *bound_addr;
	struct sockaddr_in *sendto_addr;
};

struct tsi_proxy_release {
	u32 svm_port;
	u32 svm_peer_port;
} __attribute__((packed));

/* Protocol family. */
static struct proto tsi_proto = {
	.name = "AF_TSI",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct tsi_sock),
};

#define tsi_sk(__sk)    ((struct tsi_sock *)__sk)
#define sk_tsi(__tsk)   (&(__tsk)->sk)

static int tsi_create_control_socket(struct socket **csocket)
{
	struct sockaddr_vm vm_addr;
	int err;

	err = __sock_create(current->nsproxy->net_ns, PF_VSOCK,
			    SOCK_DGRAM, 0, csocket, 1);
	if (err) {
		pr_debug("%s: error creating control socket\n", __func__);
		goto release;
	}

	memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
	vm_addr.svm_family = AF_VSOCK;
	vm_addr.svm_port = VMADDR_PORT_ANY;
	vm_addr.svm_cid = VMADDR_CID_ANY;

	err = kernel_bind(*csocket, (struct sockaddr *)&vm_addr,
			  sizeof(struct sockaddr_vm));
	if (err) {
		pr_debug("%s: error binding port\n", __func__);
		goto release;
	}

	return 0;

release:
	(*csocket)->ops->release(*csocket);
	return err;
}

static int tsi_control_sendrecv_msg(struct socket *csocket, int port,
				    void *data, int data_len, bool recv)
{
	struct sockaddr_vm vm_addr;
	struct msghdr msg = {.msg_flags = 0 };
	struct kvec iov = {
		.iov_base = data,
		.iov_len = data_len,
	};

	memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
	vm_addr.svm_family = AF_VSOCK;
	vm_addr.svm_cid = TSI_CID;
	vm_addr.svm_port = port;

	msg.msg_name = &vm_addr;
	msg.msg_namelen = sizeof(struct sockaddr_vm);

	if (recv)
		return kernel_recvmsg(csocket, &msg, &iov, 1, iov.iov_len, 0);
	else
		return kernel_sendmsg(csocket, &msg, &iov, 1, iov.iov_len);
}

static int tsi_control_sendmsg(struct socket *csocket, int port,
			       void *data, int data_len)
{
	return tsi_control_sendrecv_msg(csocket, port, data, data_len, 0);
}

static int tsi_control_recvmsg(struct socket *csocket, int port,
			       void *data, int data_len)
{
	return tsi_control_sendrecv_msg(csocket, port, data, data_len, 1);
}

static int tsi_release(struct socket *sock)
{
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	struct sock *sk;
	int err;

	pr_debug("%s: socket=%p\n", __func__, sock);
	if (!sock) {
		pr_debug("%s: no sock\n", __func__);
	}

	if (!sock->sk) {
		pr_debug("%s: no sock->sk\n", __func__);
		return 0;
	} else {
		pr_debug("%s: sock->sk\n", __func__);
	}

	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;
	sk = sock->sk;

	pr_debug("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);

	if (!vsocket) {
		pr_debug("%s: no vsocket\n", __func__);
	} else {
		struct tsi_proxy_release tpr;

		tpr.svm_port = tsk->svm_port;
		tpr.svm_peer_port = tsk->svm_peer_port;

		err = tsi_control_sendmsg(tsk->csocket,
					  TSI_PROXY_RELEASE,
					  (void *)&tpr,
					  sizeof(struct tsi_proxy_release));
		if (err < 0) {
			pr_debug("%s: error sending proxy release\n", __func__);
			return err;
		}

		err = vsocket->ops->release(vsocket);
		if (err != 0) {
			pr_debug("%s: error releasing vsock socket\n",
				 __func__);
		}
	}

	if (!isocket) {
		pr_debug("%s: no isocket\n", __func__);
	} else {
		err = isocket->ops->release(isocket);
		if (err != 0) {
			pr_debug("%s: error releasing inner socket\n",
				 __func__);
		}
	}

	sock_orphan(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;
	skb_queue_purge(&sk->sk_receive_queue);
	release_sock(sk);
	sock_put(sk);
	sock->sk = NULL;
	sock->state = SS_FREE;

	return 0;
}

static int tsi_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	struct sockaddr_vm addr_vsock;
	int err;

	pr_debug("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);

	if (!isocket) {
		pr_debug("%s: not socket\n", __func__);
		return -EINVAL;
	}

	if (!isocket->ops) {
		pr_debug("%s: not ops\n", __func__);
		return -EINVAL;
	}

	if (!isocket->ops) {
		pr_debug("%s: no bind\n", __func__);
		return -EINVAL;
	}

	memset(&addr_vsock, 0, sizeof(addr_vsock));
	addr_vsock.svm_family = AF_VSOCK;
	addr_vsock.svm_cid = VMADDR_CID_ANY;
	addr_vsock.svm_port = VMADDR_PORT_ANY;

	err = vsocket->ops->bind(vsocket, (struct sockaddr *)&addr_vsock,
				 sizeof(addr_vsock));
	if (err) {
		pr_debug("%s: error setting up vsock listener: %d\n", __func__,
			 err);
	} else if (addr_len == sizeof(struct sockaddr_in)) {
		if (!tsk->bound_addr) {
			tsk->bound_addr =
			    kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
		}
		memcpy(tsk->bound_addr, addr, sizeof(struct sockaddr_in));
	}

	return isocket->ops->bind(isocket, addr, addr_len);
}

static int tsi_create_proxy(struct tsi_sock *tsk, int type)
{
	struct socket *vsocket = tsk->vsocket;
	struct sockaddr_vm vm_addr;
	struct tsi_proxy_create tpc;
	int err;

	memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
	vm_addr.svm_family = AF_VSOCK;
	vm_addr.svm_port = VMADDR_PORT_ANY;
	vm_addr.svm_cid = VMADDR_CID_ANY;

	err = kernel_bind(vsocket, (struct sockaddr *)&vm_addr,
			  sizeof(struct sockaddr_vm));
	if (err) {
		pr_debug("%s: error binding port: %d\n", __func__, err);
	}

	err = vsocket->ops->getname(vsocket, (struct sockaddr *)&vm_addr, 0);
	if (err < 0) {
		pr_debug("%s: error in getname: %d\n", __func__, err);
		return err;
	}

	tpc.svm_port = tsk->svm_port = vm_addr.svm_port;
	tpc.type = type;

	pr_debug("%s: type=%d\n", __func__, tpc.type);

	err = tsi_control_sendmsg(tsk->csocket,
				  TSI_PROXY_CREATE,
				  (void *)&tpc,
				  sizeof(struct tsi_proxy_create));
	if (err < 0) {
		pr_debug("%s: error sending proxy request\n", __func__);
		return err;
	}

	tsk->status = S_CONNECTED_VSOCK;

	return 0;
}

static int tsi_connect(struct socket *sock, struct sockaddr *addr,
		       int addr_len, int flags)
{
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, addr);
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	int err = 0;

	pr_debug("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);

	if (sin->sin_family != AF_INET) {
		pr_debug("%s: rejecting unknown family\n", __func__);
		return -EINVAL;
	}

	if (isocket) {
		err = isocket->ops->connect(isocket, addr, addr_len, flags);
		if (err == 0 || err == -EALREADY) {
			tsk->status = S_CONNECTED_INET;
			pr_debug("%s: switching to CONNECTED_INET\n", __func__);
			return err;
		} else if (err == -EINPROGRESS) {
			tsk->status = S_CONNECTING_INET;
			pr_debug("%s: switching to CONNECTING_INET\n",
				 __func__);
			return err;
		}
	}

	if (vsocket) {
		struct sockaddr_vm vm_addr;
		struct tsi_connect_req tc_req;
		struct tsi_connect_rsp tc_rsp;

		if (!tsk->svm_port) {
			if (tsi_create_proxy(tsk, vsocket->type) != 0) {
				return EINVAL;
			}
		}

		tc_req.svm_port = tsk->svm_port;
		tc_req.addr = sin->sin_addr.s_addr;
		tc_req.port = sin->sin_port;

		pr_debug("%s: sending connection request id=%u\n", __func__,
			 tc_req.svm_port);

		err = tsi_control_sendmsg(tsk->csocket,
					  TSI_CONNECT,
					  (void *)&tc_req,
					  sizeof(struct tsi_connect_req));
		if (err < 0) {
			pr_debug("%s: error sending connection request\n",
				 __func__);
			return err;
		}

		err = tsi_control_recvmsg(tsk->csocket,
					  TSI_CONNECT,
					  (void *)&tc_rsp,
					  sizeof(struct tsi_connect_rsp));
		if (err < 0) {
			pr_debug
			    ("%s: error receiving connection request answer\n",
			     __func__);
			return err;
		}

		pr_debug("%s: response result: %d\n", __func__, tc_rsp.result);

		if (tc_rsp.result != 0) {
			return -EINVAL;
		}

		memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
		vm_addr.svm_family = AF_VSOCK;
		vm_addr.svm_cid = TSI_CID;
		if (vsocket->type == SOCK_DGRAM)
			vm_addr.svm_port = tc_req.svm_port;
		else
			vm_addr.svm_port = TSI_DEFAULT_PORT;

		err = kernel_connect(vsocket, (struct sockaddr *)&vm_addr,
				     sizeof(struct sockaddr_vm), 0);
		if (err < 0) {
			pr_debug("%s: error connecting vsock endpoint: %d\n",
				 __func__, err);
			return err;
		}

		tsk->status = S_CONNECTED_VSOCK;
	}

	return err;
}

static int tsi_accept_vsock(struct tsi_sock *tsk, struct socket **newsock,
			    int flags, bool kern)
{
	struct socket *socket = tsk->vsocket;
	struct socket *nsock;
	struct tsi_accept_rsp ta_rsp;
	int err;

	nsock = sock_alloc();
	if (!nsock)
		return -ENOMEM;

	nsock->type = socket->type;
	nsock->ops = socket->ops;

	err = tsi_control_recvmsg(tsk->csocket,
				  TSI_ACCEPT,
				  (void *)&ta_rsp,
				  sizeof(struct tsi_accept_rsp));
	if (err < 0) {
		pr_debug("%s: error receiving accept answer\n", __func__);
		goto out;
	}

	pr_debug("%s: response result: %d\n", __func__, ta_rsp.result);

	err = socket->ops->accept(socket, nsock, flags, kern);

out:
	if (err < 0) {
		pr_debug("%s: vsock accept failed: %d\n", __func__, err);
		sock_release(nsock);
	} else {
		pr_debug("%s: connection accepted\n", __func__);
		*newsock = nsock;
	}

	return err;
}

static int tsi_accept(struct socket *sock, struct socket *newsock, int flags,
		      bool kern)
{
	struct sockaddr_vm vm_addr;
	struct socket *csocket;
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct tsi_sock *newtsk;
	struct socket *nsock;
	struct sock *sk;
	int err;

	pr_debug("%s: socket=%p newsock=%p\n", __func__, sock, newsock);

	sk = sk_alloc(current->nsproxy->net_ns, AF_TSI, GFP_KERNEL,
		      &tsi_proto, 0);
	if (!sk)
		return -ENOMEM;

	sock_init_data(newsock, sk);
	newtsk = tsi_sk(newsock->sk);

	err = tsi_accept_vsock(tsk, &nsock, flags, kern);
	if (err >= 0) {
		err =
		    nsock->ops->getname(nsock, (struct sockaddr *)&vm_addr, 0);
		if (err < 0) {
			pr_debug("%s: error in getname: %d\n", __func__, err);
			goto release;
		}
		newtsk->svm_port = vm_addr.svm_port;
		err =
		    nsock->ops->getname(nsock, (struct sockaddr *)&vm_addr, 1);
		if (err < 0) {
			pr_debug("%s: error in peer getname: %d\n", __func__,
				 err);
			goto release;
		}
		newtsk->svm_peer_port = vm_addr.svm_port;

		newtsk->status = S_CONNECTED_VSOCK;
		pr_debug("%s: switching to CONNECTED_VSOCK\n", __func__);
		newtsk->vsocket = nsock;

		err = tsi_create_control_socket(&csocket);
		if (err)
			goto release;

		newtsk->csocket = csocket;

		newsock->state = SS_CONNECTED;
	}

	return err;
release:
	nsock->ops->release(nsock);
	return err;
}

static int vsock_proxy_getname(struct tsi_sock *tsk,
			       struct sockaddr *addr, int peer)
{
	struct tsi_getname_req gn_req;
	struct tsi_getname_rsp gn_rsp;
	int addr_len;
	int err;
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, addr);

	gn_req.svm_port = tsk->svm_port;
	gn_req.svm_peer_port = tsk->svm_peer_port;
	gn_req.peer = peer;

	err = tsi_control_sendmsg(tsk->csocket,
				  TSI_GETNAME,
				  (void *)&gn_req,
				  sizeof(struct tsi_getname_req));
	if (err < 0) {
		pr_debug("%s: error sending getname request\n", __func__);
		return err;
	}

	err = tsi_control_recvmsg(tsk->csocket,
				  TSI_GETNAME,
				  (void *)&gn_rsp,
				  sizeof(struct tsi_getname_rsp));
	if (err < 0) {
		pr_debug("%s: error receiving getname answer\n", __func__);
		return err;
	}

	sin->sin_family = AF_INET;
	sin->sin_port = gn_rsp.port;
	sin->sin_addr.s_addr = gn_rsp.addr;
	addr_len = sizeof(struct sockaddr_in);

	memcpy(addr, sin, addr_len);

	return addr_len;
}

static int tsi_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, addr);

	pr_debug("%s: s=%p is=%p st=%d svm_port=%u peer=%d\n", __func__, sock,
		 isocket, tsk->status, tsk->svm_port, peer);

	switch (tsk->status) {
	case S_CONNECTED_INET:
		return isocket->ops->getname(isocket, addr, peer);
	case S_CONNECTED_VSOCK:
		if (peer) {
			return vsock_proxy_getname(tsk, addr, peer);
		} else if (!isocket) {
			sin->sin_family = AF_INET;
			sin->sin_port = htons(1234);
			sin->sin_addr.s_addr = htonl(2130706433);
			memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
			return sizeof(*sin);
		}
	}

	return isocket->ops->getname(isocket, addr, peer);
}

static __poll_t tsi_poll(struct file *file, struct socket *sock,
			 poll_table * wait)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	__poll_t events = 0;

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		 vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		sock->sk->sk_err = isocket->sk->sk_err;
		events = isocket->ops->poll(file, isocket, wait);
		if (events) {
			tsk->status = S_CONNECTED_INET;
		}
		break;
	case S_CONNECTED_VSOCK:
		sock->sk->sk_err = vsocket->sk->sk_err;
		events = vsocket->ops->poll(file, vsocket, wait);
		if (events) {
			tsk->status = S_CONNECTED_VSOCK;
		}
		break;
	default:
		if (isocket)
			events |= isocket->ops->poll(file, isocket, wait);

		if (events)
			tsk->status = S_CONNECTED_INET;
		else {
			if (vsocket)
				events |=
				    vsocket->ops->poll(file, vsocket, wait);
			if (events)
				tsk->status = S_CONNECTED_VSOCK;
		}
	}

	return events;
}

static int tsi_listen(struct socket *sock, int backlog)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *vsocket = tsk->vsocket;
	struct sockaddr_vm vm_addr;
	struct sockaddr_in *sin;
	struct tsi_listen_req lreq;
	struct tsi_listen_rsp lrsp;
	int err;

	pr_debug("%s: vsocket=%p\n", __func__, vsocket);

	err = vsocket->ops->listen(vsocket, backlog);
	if (err != 0) {
		pr_debug("%s: vsock listen error: %d\n", __func__, err);
		return err;
	}

	err = vsocket->ops->getname(vsocket, (struct sockaddr *)&vm_addr, 0);
	if (err < 0) {
		pr_debug("%s: error in getname: %d\n", __func__, err);
		return err;
	}

	if (!tsk->bound_addr) {
		pr_debug("%s: !bound_addr", __func__);
		return -EINVAL;
	}
	sin = tsk->bound_addr;

	if (!tsk->svm_port) {
		if (tsi_create_proxy(tsk, SOCK_STREAM) != 0) {
			return EINVAL;
		}
	}

	lreq.svm_port = tsk->svm_port;
	lreq.addr = sin->sin_addr.s_addr;
	lreq.port = sin->sin_port;
	lreq.vm_port = vm_addr.svm_port;
	lreq.backlog = backlog;

	pr_debug("%s: requesting to listen on port=%d\n", __func__, lreq.port);

	err = tsi_control_sendmsg(tsk->csocket,
				  TSI_LISTEN,
				  (void *)&lreq, sizeof(struct tsi_listen_req));
	if (err < 0) {
		pr_debug("%s: error sending listen request: %d\n", __func__,
			 err);
		return err;
	}

	err = tsi_control_recvmsg(tsk->csocket,
				  TSI_LISTEN,
				  (void *)&lrsp, sizeof(struct tsi_listen_rsp));
	if (err < 0) {
		pr_debug("%s: error receiving listen request answer\n",
			 __func__);
		return err;
	} else {
		tsk->svm_peer_port = TSI_DEFAULT_PORT;
	}

	pr_debug("%s: listen result=%d", __func__, lrsp.result);

	return lrsp.result;
}

static int tsi_shutdown(struct socket *sock, int mode)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		 vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->shutdown(isocket, mode);
	case S_CONNECTED_VSOCK:
		return vsocket->ops->shutdown(vsocket, mode);
	}

	return -ENOTCONN;
}

static int tsi_stream_setsockopt(struct socket *sock,
				 int level,
				 int optname,
				 sockptr_t optval, unsigned int optlen)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;

	pr_debug("%s: s=%p is=%p st=%d\n", __func__, sock,
		 isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->setsockopt(isocket, level, optname, optval,
						optlen);
	case S_CONNECTED_VSOCK:
		// TODO implement remote setsockopt
		return 0;
	}

	return -EINVAL;
}

static int tsi_dgram_setsockopt(struct socket *sock,
				int level,
				int optname,
				sockptr_t optval, unsigned int optlen)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;

	pr_debug("%s: s=%p is=%p st=%d\n", __func__, sock,
		 isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->setsockopt(isocket, level, optname, optval,
						optlen);
	case S_CONNECTED_VSOCK:
	case S_IDLE:
		// TODO implement remote setsockopt
		return 0;
	}

	return -EINVAL;
}

static int tsi_stream_getsockopt(struct socket *sock,
				 int level, int optname,
				 char *optval, int __user * optlen)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		 vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->getsockopt(isocket, level, optname, optval,
						optlen);
	case S_CONNECTED_VSOCK:
		// TODO implement remote setsockopt
		return vsocket->ops->getsockopt(vsocket, level, optname, optval,
						optlen);
	}

	return -EINVAL;
}

static int tsi_stream_sendmsg(struct socket *sock, struct msghdr *msg,
			      size_t len)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	int err;

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		 vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_IDLE:
		return -EINVAL;
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->sendmsg(isocket, msg, len);
	case S_CONNECTED_VSOCK:
		err = vsocket->ops->sendmsg(vsocket, msg, len);
		pr_debug("%s: s=%p vs=%p is=%p st=%d exit\n", __func__, sock,
			 vsocket, isocket, tsk->status);
		return err;
	}

	return -ENOTCONN;
}

static int tsi_dgram_sendmsg(struct socket *sock, struct msghdr *msg,
			     size_t len)
{
	struct tsi_sendto_addr sa_req;
	struct sockaddr_in *sin;
	struct sockaddr_vm *svm;
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	int err;

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		 vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_IDLE:
		err = isocket->ops->sendmsg(isocket, msg, len);
		if (err == 0)
			return err;
		fallthrough;
	case S_CONNECTED_VSOCK:
		if (msg->msg_name) {
			pr_debug("%s: fixing msg_name for vsock proxy\n",
				 __func__);
			if (!tsk->sendto_addr) {
				tsk->sendto_addr =
				    kmalloc(sizeof(struct sockaddr_in),
					    GFP_KERNEL);
			}
			memcpy(tsk->sendto_addr, msg->msg_name,
			       sizeof(struct sockaddr_in));

			if (tsk->svm_port == 0) {
				if (tsi_create_proxy(tsk, SOCK_DGRAM) != 0)
					return -EINVAL;
			}

			sin = (struct sockaddr_in *)msg->msg_name;
			sa_req.svm_port = tsk->svm_port;
			sa_req.addr = sin->sin_addr.s_addr;
			sa_req.port = sin->sin_port;

			err = tsi_control_sendmsg(tsk->csocket,
						  TSI_SENDTO_ADDR,
						  (void *)&sa_req,
						  sizeof(struct
							 tsi_sendto_addr));
			if (err < 0) {
				pr_debug
				    ("%s: error sending connection request: %d\n",
				     __func__, err);
				return err;
			}

			svm = (struct sockaddr_vm *)msg->msg_name;
			svm->svm_family = AF_VSOCK;
			svm->svm_port = TSI_SENDTO_DATA;
			svm->svm_cid = TSI_CID;
			svm->svm_flags = 0;
		}

		err = vsocket->ops->sendmsg(vsocket, msg, len);
		if (err == 0) {
			tsk->status = S_CONNECTED_VSOCK;
		}
		return err;
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->sendmsg(isocket, msg, len);
	}

	return -ENOTCONN;
}

static int tsi_stream_recvmsg(struct socket *sock, struct msghdr *msg,
			      size_t len, int flags)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		 vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->recvmsg(isocket, msg, len, flags);
	case S_CONNECTED_VSOCK:
		return vsocket->ops->recvmsg(vsocket, msg, len, flags);
	}

	return -ENOTCONN;
}

static int tsi_dgram_recvmsg(struct socket *sock, struct msghdr *msg,
			     size_t len, int flags)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	int err;

	pr_debug("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		 vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->recvmsg(isocket, msg, len, flags);
	case S_CONNECTED_VSOCK:
		err = vsocket->ops->recvmsg(vsocket, msg, len, flags);
		if (err > 0 && msg && msg->msg_name && tsk->sendto_addr) {
			pr_debug
			    ("%s: msg_name=%p sin_sendto=%p, msg_len=%d sin_len=%ld\n",
			     __func__, msg->msg_name, tsk->sendto_addr,
			     msg->msg_namelen, sizeof(struct sockaddr_in));
			memcpy(msg->msg_name, tsk->sendto_addr,
			       sizeof(struct sockaddr_in));
		}
		return err;
	}

	return -ENOTCONN;
}

static const struct proto_ops tsi_stream_ops = {
	.family = PF_VSOCK,
	.owner = THIS_MODULE,
	.release = tsi_release,
	.bind = tsi_bind,
	.connect = tsi_connect,
	.socketpair = sock_no_socketpair,
	.accept = tsi_accept,
	.getname = tsi_getname,
	.poll = tsi_poll,
	.ioctl = sock_no_ioctl,
	.listen = tsi_listen,
	.shutdown = tsi_shutdown,
	.setsockopt = tsi_stream_setsockopt,
	.getsockopt = tsi_stream_getsockopt,
	.sendmsg = tsi_stream_sendmsg,
	.recvmsg = tsi_stream_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static const struct proto_ops tsi_dgram_ops = {
	.family = PF_VSOCK,
	.owner = THIS_MODULE,
	.release = tsi_release,
	.bind = tsi_bind,
	.connect = tsi_connect,
	.socketpair = sock_no_socketpair,
	.accept = tsi_accept,
	.getname = tsi_getname,
	.poll = tsi_poll,
	.ioctl = sock_no_ioctl,
	.listen = tsi_listen,
	.shutdown = tsi_shutdown,
	.setsockopt = tsi_dgram_setsockopt,
	.getsockopt = tsi_stream_getsockopt,
	.sendmsg = tsi_dgram_sendmsg,
	.recvmsg = tsi_dgram_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static int tsi_create(struct net *net, struct socket *sock,
		      int protocol, int kern)
{
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	struct socket *csocket;
	struct sock *sk;
	int err;

	pr_debug("%s: socket=%p\n", __func__, sock);

	if (!sock)
		return -EINVAL;

	switch (sock->type) {
	case SOCK_STREAM:
		sock->ops = &tsi_stream_ops;
		break;
	case SOCK_DGRAM:
		sock->ops = &tsi_dgram_ops;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	sk = sk_alloc(net, AF_TSI, GFP_KERNEL, &tsi_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	tsk = tsi_sk(sk);

	isocket = NULL;
	err = __sock_create(current->nsproxy->net_ns, PF_INET,
			    sock->type, protocol, &isocket, 1);
	if (err) {
		pr_err("%s (%d): problem creating inet socket\n",
		       __func__, task_pid_nr(current));
		goto release_isocket;
	}

	vsocket = NULL;
	err = __sock_create(current->nsproxy->net_ns, PF_VSOCK,
			    sock->type, PF_VSOCK, &vsocket, 1);
	if (err) {
		pr_err("%s (%d): problem creating vsock socket\n",
		       __func__, task_pid_nr(current));
		goto release_vsocket;
	}

	err = tsi_create_control_socket(&csocket);
	if (err) {
		pr_err("%s (%d): problem creating control socket\n",
		       __func__, task_pid_nr(current));
		goto release_vsocket;
	}

	pr_debug("isocket: %p\n", isocket);
	pr_debug("vsocket: %p\n", vsocket);
	tsk->isocket = isocket;
	tsk->vsocket = vsocket;
	tsk->csocket = csocket;
	sock->state = SS_UNCONNECTED;
	tsk->svm_port = 0;
	tsk->svm_peer_port = TSI_DEFAULT_PORT;
	tsk->sendto_addr = NULL;
	tsk->bound_addr = NULL;

	return 0;

release_vsocket:
	vsocket->ops->release(vsocket);
release_isocket:
	isocket->ops->release(isocket);
	return err;
}

static const struct net_proto_family tsi_family_ops = {
	.family = AF_TSI,
	.create = tsi_create,
	.owner = THIS_MODULE,
};

static int __init tsi_init(void)
{
	int err = 0;

	tsi_proto.owner = THIS_MODULE;

	err = proto_register(&tsi_proto, 1);
	if (err) {
		pr_err("Could not register tsi protocol\n");
		goto err_do_nothing;
	}
	err = sock_register(&tsi_family_ops);
	if (err) {
		pr_err("could not register af_tsi (%d) address family: %d\n",
		       AF_TSI, err);
		goto err_unregister_proto;
	}

	return 0;

err_unregister_proto:
	proto_unregister(&tsi_proto);
err_do_nothing:
	return err;
}

static void __exit tsi_exit(void)
{
	sock_unregister(AF_TSI);
	proto_unregister(&tsi_proto);
}

module_init(tsi_init);
module_exit(tsi_exit);

MODULE_AUTHOR("Red Hat, Inc.");
MODULE_DESCRIPTION("Transparent Socket Impersonation Sockets");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
