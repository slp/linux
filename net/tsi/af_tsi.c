#include <linux/types.h>
#include <linux/poll.h>
#include <net/sock.h>
#include <net/af_vsock.h>

#define DEBUG 1

#ifdef DEBUG
#define DPRINTK(...) printk(__VA_ARGS__)
#else
#define DPRINTK(...) do {} while (0)
#endif

#define S_IDLE			0
#define S_LISTEN_HYBRID		1
#define S_CONNECTING_VSOCK	2
#define S_CONNECTING_INET	3
#define S_CONNECTED_VSOCK	4
#define S_CONNECTED_INET	5

#define TSI_CID 2
#define TSI_DEFAULT_PORT  620

#define TSI_PROXY_CREATE  1024
#define TSI_CONNECT       1025
#define TSI_GETNAME       1026
#define TSI_SENDTO_ADDR   1027
#define TSI_SENDTO_DATA   1028
#define TSI_LISTEN        1029
#define TSI_ACCEPT        1030

struct socket *control_socket = NULL;

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
	unsigned int status;
    u32 svm_port;
    u32 svm_peer_port;
    struct sockaddr_in *bound_addr;
    struct sockaddr_in *sendto_addr;
};

/* Protocol family. */
static struct proto tsi_proto = {
	.name = "AF_TSI",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct tsi_sock),
};

#define tsi_sk(__sk)    ((struct tsi_sock *)__sk)
#define sk_tsi(__tsk)   (&(__tsk)->sk)

static int tsi_release(struct socket *sock)
{
	struct tsi_sock *tsk;
	struct socket *isocket;
	struct socket *vsocket;
	struct sock *sk;
	int err;

	DPRINTK("%s: socket=%p\n", __func__, sock);
	if (!sock) {
		DPRINTK("%s: no sock\n", __func__);
	}

	if (!sock->sk) {
		DPRINTK("%s: no sock->sk\n", __func__);
		return 0;
	} else {
		DPRINTK("%s: sock->sk\n", __func__);
	}

	tsk = tsi_sk(sock->sk);
	isocket = tsk->isocket;
	vsocket = tsk->vsocket;
	sk = sock->sk;

	DPRINTK("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);

	if (!vsocket) {
		DPRINTK("%s: no vsocket\n", __func__);
	} else {
		err = vsocket->ops->release(vsocket);
		if (err != 0) {
			DPRINTK("%s: error releasing vsock socket\n", __func__);
		}
	}

	if (!isocket) {
		DPRINTK("%s: no isocket\n", __func__);
	} else {
		err = isocket->ops->release(isocket);
		if (err != 0) {
			DPRINTK("%s: error releasing inner socket\n", __func__);
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

	DPRINTK("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);

	if (!isocket) {
		DPRINTK("%s: not socket\n", __func__);
		return -EINVAL;
	}

	if (!isocket->ops) {
		DPRINTK("%s: not ops\n", __func__);
		return -EINVAL;
	}

	if (!isocket->ops) {
		DPRINTK("%s: no bind\n", __func__);
		return -EINVAL;
	}

	memset(&addr_vsock, 0, sizeof(addr_vsock));
	addr_vsock.svm_family = AF_VSOCK;
	addr_vsock.svm_cid = VMADDR_CID_ANY;
	addr_vsock.svm_port = VMADDR_PORT_ANY;

	err = vsocket->ops->bind(vsocket, (struct sockaddr *)&addr_vsock, sizeof(addr_vsock));
	if (err) {
		DPRINTK("%s: error setting up vsock listener: %d\n", __func__, err);
	} else if (addr_len == sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sin = (struct sockaddr_in *) addr;
        DPRINTK("%s: port=%d\n", __func__, sin->sin_port);
        if (!tsk->bound_addr) {
            tsk->bound_addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
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
    struct msghdr msg = { .msg_flags = 0 };
    struct kvec iov = {
        .iov_base = (u8 *) &tpc,
        .iov_len = sizeof(struct tsi_proxy_create),
    };
    int err;

    memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
    vm_addr.svm_family = AF_VSOCK;
    vm_addr.svm_port = VMADDR_PORT_ANY;
    vm_addr.svm_cid = VMADDR_CID_ANY;

    err = kernel_bind(vsocket, (struct sockaddr *) &vm_addr, sizeof(struct sockaddr_vm));
    if (err) {
        DPRINTK("%s: error binding port: %d\n", __func__, err);
        //return err;
    }

    err = vsocket->ops->getname(vsocket, (struct sockaddr *) &vm_addr, 0);
    if (err < 0) {
        DPRINTK("%s: error in getname: %d\n", __func__, err);
			return err;
    }

    tpc.svm_port = tsk->svm_port = vm_addr.svm_port;
    tpc.type = type;

    vm_addr.svm_port = TSI_PROXY_CREATE;
    vm_addr.svm_cid = TSI_CID;

    msg.msg_name = &vm_addr;
    msg.msg_namelen = sizeof(struct sockaddr_vm);

    DPRINTK("%s: type=%d\n", __func__, tpc.type);

    err = kernel_sendmsg(control_socket, &msg, &iov, 1, iov.iov_len);
    if (err < 0) {
        DPRINTK("%s: error sending proxy request\n", __func__);
        return err;
    }

    tsk->status = S_CONNECTED_VSOCK;

    return 0;
}

static int tsi_stream_connect(struct socket *sock, struct sockaddr *addr,
			      int addr_len, int flags)
{
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, addr);
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	int err = 0;

	DPRINTK("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);

	if (isocket) {
		err = isocket->ops->connect(isocket, addr, addr_len, flags);
		if (err == 0 || err == -EALREADY) {
			tsk->status = S_CONNECTED_INET;
			DPRINTK("%s: switching to CONNECTED_INET\n", __func__);
			return err;
		} else if (err == -EINPROGRESS) {
			tsk->status = S_CONNECTING_INET;
			DPRINTK("%s: switching to CONNECTING_INET\n", __func__);
			return err;
		}
	}

	if (vsocket) {
		struct sockaddr_vm vm_addr;
		struct msghdr msg = { .msg_flags = 0 };
		struct tsi_connect_req tc_req;
		struct tsi_connect_rsp tc_rsp;
		struct kvec iov = {
			.iov_base = (u8 *) &tc_req,
			.iov_len = sizeof(struct tsi_connect_req),
		};

        if (!tsk->svm_port) {
            if (tsi_create_proxy(tsk, SOCK_STREAM) != 0) {
                return EINVAL;
            }
        }

		tc_req.svm_port = tsk->svm_port;
		tc_req.addr = sin->sin_addr.s_addr;
		tc_req.port = sin->sin_port;

		memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
		vm_addr.svm_family = AF_VSOCK;
		vm_addr.svm_port = TSI_CONNECT;
		vm_addr.svm_cid = TSI_CID;

		msg.msg_name = &vm_addr;
		msg.msg_namelen = sizeof(struct sockaddr_vm);

		err = kernel_sendmsg(control_socket, &msg, &iov, 1, iov.iov_len);
		if (err < 0) {
			DPRINTK("%s: error sending connection request\n", __func__);
			return err;
		}

		iov.iov_base = (u8 *) &tc_rsp;
		iov.iov_len = sizeof(struct tsi_connect_rsp);

		err = kernel_recvmsg(control_socket, &msg, &iov, 1, iov.iov_len, 0);
		if (err < 0) {
			DPRINTK("%s: error receiving connection request answer\n", __func__);
			return err;
		}

		DPRINTK("%s: response result: %d\n", __func__, tc_rsp.result);

        /*
		while (pc_rsp.result == -EINPROGRESS) {
			DPRINTK("%s: EINPROGRESS, waiting...\n", __func__);

			err = kernel_recvmsg(control_socket, &msg, &iov, 1, iov.iov_len, 0);
			if (err < 0) {
				DPRINTK("%s: error receiving connection request answer\n", __func__);
				return err;
			}

			DPRINTK("%s: new response result: %d\n", __func__, crsp.result);
		}
        */

		if (tc_rsp.result != 0) {
			return -EINVAL;
		}

		vm_addr.svm_port = TSI_DEFAULT_PORT;
		vm_addr.svm_cid = TSI_CID;

		err = kernel_connect(vsocket, (struct sockaddr *) &vm_addr, sizeof(struct sockaddr_vm), 0);
		if (err < 0) {
			DPRINTK("%s: error connecting vsock endpoint: %d\n", __func__, err);
			return err;
		}

        err = vsocket->ops->getname(vsocket, (struct sockaddr *) &vm_addr, 1);
        if (err < 0) {
            DPRINTK("%s: error in peer getname: %d\n", __func__, err);
			return err;
        }

        tsk->svm_peer_port = vm_addr.svm_port;
		tsk->status = S_CONNECTED_VSOCK;

        return 0;
		/*
		err = vsock_tsi_connect(vsocket, addr, addr_len, flags);
		if (err == 0 || err == -EALREADY) {
			tsk->status = S_CONNECTED_VSOCK;
			DPRINTK("%s: switching to CONNECTED_VSOCK\n", __func__);
		} else if (err == -EINPROGRESS) {
			tsk->status = S_CONNECTING_VSOCK;
			DPRINTK("%s: switching to CONNECTING_VSOCK\n", __func__);
		}
		*/
	}

	return err;
}

static int tsi_dgram_connect(struct socket *sock, struct sockaddr *addr,
			      int addr_len, int flags)
{
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, addr);
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	int err = 0;

	DPRINTK("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);

    if (sin->sin_family != AF_INET) {
        DPRINTK("%s: rejecting unknown family\n", __func__);
        return -EINVAL;
    }

	if (isocket) {
		err = isocket->ops->connect(isocket, addr, addr_len, flags);
		if (err == 0 || err == -EALREADY) {
			tsk->status = S_CONNECTED_INET;
			DPRINTK("%s: switching to CONNECTED_INET\n", __func__);
			return err;
		} else if (err == -EINPROGRESS) {
			tsk->status = S_CONNECTING_INET;
			DPRINTK("%s: switching to CONNECTING_INET\n", __func__);
			return err;
		}
	}

	if (vsocket) {
		struct sockaddr_vm vm_addr;
		struct msghdr msg = { .msg_flags = 0 };
		struct tsi_connect_req tc_req;
		struct tsi_connect_rsp tc_rsp;
		struct kvec iov = {
			.iov_base = (u8 *) &tc_req,
			.iov_len = sizeof(struct tsi_connect_req),
		};

        if (!tsk->svm_port) {
            if (tsi_create_proxy(tsk, SOCK_DGRAM) != 0) {
                return EINVAL;
            }
        }

		tc_req.svm_port = tsk->svm_port;
		tc_req.addr = sin->sin_addr.s_addr;
		tc_req.port = sin->sin_port;

        DPRINTK("%s: sending connection request id=%u\n", __func__, tc_req.svm_port);

		memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
		vm_addr.svm_family = AF_VSOCK;
		vm_addr.svm_port = TSI_CONNECT;
		vm_addr.svm_cid = TSI_CID;

		msg.msg_name = &vm_addr;
		msg.msg_namelen = sizeof(struct sockaddr_vm);

		err = kernel_sendmsg(control_socket, &msg, &iov, 1, iov.iov_len);
		if (err < 0) {
			DPRINTK("%s: error sending connection request\n", __func__);
			return err;
		}

		iov.iov_base = (u8 *) &tc_rsp;
		iov.iov_len = sizeof(struct tsi_connect_rsp);

		err = kernel_recvmsg(control_socket, &msg, &iov, 1, iov.iov_len, 0);
		if (err < 0) {
			DPRINTK("%s: error receiving connection request answer\n", __func__);
			return err;
		}

		DPRINTK("%s: response result: %d\n", __func__, tc_rsp.result);

		if (tc_rsp.result != 0) {
			return -EINVAL;
		}

		vm_addr.svm_port = tc_req.svm_port;
		vm_addr.svm_cid = TSI_CID;

		err = kernel_connect(vsocket, (struct sockaddr *) &vm_addr, sizeof(struct sockaddr_vm), 0);
		if (err < 0) {
			DPRINTK("%s: error connecting vsock endpoint: %d\n", __func__, err);
			return err;
		}

		tsk->status = S_CONNECTED_VSOCK;

		/*
		err = vsock_tsi_connect(vsocket, addr, addr_len, flags);
		if (err == 0 || err == -EALREADY) {
			tsk->status = S_CONNECTED_VSOCK;
			DPRINTK("%s: switching to CONNECTED_VSOCK\n", __func__);
		} else if (err == -EINPROGRESS) {
			tsk->status = S_CONNECTING_VSOCK;
			DPRINTK("%s: switching to CONNECTING_VSOCK\n", __func__);
		}
		*/
	}

	return err;
}


static int tsi_accept_inet(struct socket *socket, struct socket **newsock,
			     int flags, bool kern)
{
	struct socket *nsock;
	int err;

	nsock = sock_alloc();
	if (!nsock)
		return -ENOMEM;

	nsock->type = socket->type;
	nsock->ops = socket->ops;

	err = socket->ops->accept(socket, nsock, flags, kern);
	if (err < 0) {
		sock_release(nsock);
	} else {
		*newsock = nsock;
	}

	return err;
}

static int tsi_accept_vsock(struct tsi_sock *tsk, struct socket **newsock,
                            int flags, bool kern)
{
    struct socket *socket = tsk->vsocket;
    struct socket *nsock;
	struct sockaddr_vm vm_addr;
	struct msghdr msg = { .msg_flags = 0 };
	struct tsi_accept_req ta_req;
	struct tsi_accept_rsp ta_rsp;
	struct kvec iov = {
		.iov_base = (u8 *)&ta_req,
		.iov_len = sizeof(struct tsi_accept_req),
	};
	int err;

	nsock = sock_alloc();
	if (!nsock)
		return -ENOMEM;

	nsock->type = socket->type;
	nsock->ops = socket->ops;

    ta_req.svm_port = tsk->svm_port;
    ta_req.flags = flags;

    memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
    vm_addr.svm_family = AF_VSOCK;
    vm_addr.svm_port = TSI_ACCEPT;
    vm_addr.svm_cid = TSI_CID;

    msg.msg_name = &vm_addr;
    msg.msg_namelen = sizeof(struct sockaddr_vm);

    err = kernel_sendmsg(control_socket, &msg, &iov, 1, iov.iov_len);
    if (err < 0) {
        DPRINTK("%s: error sending accept request\n", __func__);
        goto out;
    }

    iov.iov_base = (u8 *) &ta_rsp;
    iov.iov_len = sizeof(struct tsi_accept_rsp);

    err = kernel_recvmsg(control_socket, &msg, &iov, 1, iov.iov_len, 0);
    if (err < 0) {
        DPRINTK("%s: error receiving accept answer\n", __func__);
        goto out;
    }

    DPRINTK("%s: response result: %d\n", __func__, ta_rsp.result);

	err = socket->ops->accept(socket, nsock, flags, kern);

 out:
	if (err < 0) {
        DPRINTK("%s: vsock accept failed: %d\n", __func__, err);
		sock_release(nsock);
	} else {
        DPRINTK("%s: connection accepted\n", __func__);
		*newsock = nsock;
	}

	return err;
}

static int tsi_accept(struct socket *sock, struct socket *newsock, int flags,
		      bool kern)
{
    struct sockaddr_vm vm_addr;
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct tsi_sock *newtsk;
	struct socket *nsock;
	struct sock *sk;
	int err;

	DPRINTK("%s: socket=%p newsock=%p\n", __func__, sock, newsock);

	sk = sk_alloc(current->nsproxy->net_ns, AF_TSI, GFP_KERNEL,
		      &tsi_proto, 0);
	if (!sk)
		return -ENOMEM;

	sock_init_data(newsock, sk);
	newtsk = tsi_sk(newsock->sk);

	// TODO - Deal with !O_NONBLOCK properly
    /*
	err = tsi_accept_inet(tsk->isocket, &nsock, flags | O_NONBLOCK, kern);
	if (err >= 0) {
		newtsk->status = S_CONNECTED_INET;
		DPRINTK("%s: switching to CONNECTED_INET\n", __func__);
		newtsk->isocket = nsock;
        } else if (err == -EAGAIN) {*/
    err = tsi_accept_vsock(tsk, &nsock, flags, kern);
    if (err >= 0) {
        err = nsock->ops->getname(nsock, (struct sockaddr *) &vm_addr, 0);
        if (err < 0) {
            DPRINTK("%s: error in getname: %d\n", __func__, err);
			return err;
        }
        newtsk->svm_port = vm_addr.svm_port;
        err = nsock->ops->getname(nsock, (struct sockaddr *) &vm_addr, 1);
        if (err < 0) {
            DPRINTK("%s: error in peer getname: %d\n", __func__, err);
			return err;
        }
        newtsk->svm_peer_port = vm_addr.svm_port;

        newtsk->status = S_CONNECTED_VSOCK;
        DPRINTK("%s: switching to CONNECTED_VSOCK\n", __func__);
        newtsk->vsocket = nsock;
    }
        //}

	if (err >= 0)
		newsock->state = SS_CONNECTED;

	return err;
}

static int vsock_proxy_getname(struct tsi_sock *tsk,
			       struct sockaddr *addr, int peer)
{
    struct socket *vsocket = tsk->vsocket;
	struct sockaddr_vm vm_addr;
	struct msghdr msg = { .msg_flags = 0 };
	struct tsi_getname_req gn_req;
	struct tsi_getname_rsp gn_rsp;
	struct kvec iov = {
		.iov_base = (u8 *)&gn_req,
		.iov_len = sizeof(struct tsi_getname_req),
	};
	int err;
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, addr);

	memset(&vm_addr, 0, sizeof(struct sockaddr_vm));

	err = vsocket->ops->getname(vsocket, (struct sockaddr *) &vm_addr, 0);
	if (err < 0) {
		DPRINTK("%s: error in getname: %d\n", __func__, err);
		return err;
	}

	gn_req.svm_port = tsk->svm_port;
    gn_req.svm_peer_port = tsk->svm_peer_port;
	gn_req.peer = peer;

	vm_addr.svm_port = TSI_GETNAME;
	vm_addr.svm_cid = TSI_CID;

	msg.msg_name = &vm_addr;
	msg.msg_namelen = sizeof(struct sockaddr_vm);

	err = kernel_sendmsg(control_socket, &msg, &iov, 1, iov.iov_len);
	if (err < 0) {
		DPRINTK("%s: error sending getname request\n", __func__);
		return err;
	}

	iov.iov_base = (u8 *)&gn_rsp;
	iov.iov_len = sizeof(struct tsi_getname_rsp);

	err = kernel_recvmsg(control_socket, &msg, &iov, 1, iov.iov_len, 0);
	if (err < 0) {
		DPRINTK("%s: error receiving getname answer\n", __func__);
		return err;
	}

	sin->sin_family = AF_INET;
	sin->sin_port = gn_rsp.port;
	sin->sin_addr.s_addr = gn_rsp.addr;

	return 0;
}

static int tsi_getname(struct socket *sock,
		       struct sockaddr *addr, int peer)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, addr);

	DPRINTK("%s: s=%p vs=%p is=%p st=%d svm_port=%u peer=%d\n", __func__, sock,
            vsocket, isocket, tsk->status, tsk->svm_port, peer);

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
			 poll_table *wait)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	__poll_t events = 0;

	DPRINTK("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
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
	case S_CONNECTING_VSOCK:
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
				events |= vsocket->ops->poll(file, vsocket, wait);
			if (events)
				tsk->status = S_CONNECTED_VSOCK;
		}
	}

	return events;
}

static int tsi_listen(struct socket *sock, int backlog)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
    struct sockaddr_in *sin;
    struct tsi_listen_req lreq;
    struct tsi_listen_rsp lrsp;
    struct sockaddr_vm vm_addr;
    struct msghdr lreq_msg = { .msg_flags = 0 };
    struct kvec iov = {
        .iov_base = (u8 *) &lreq,
        .iov_len = sizeof(struct tsi_listen_req),
    };
    int err;

	DPRINTK("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);

    err = vsocket->ops->listen(vsocket, backlog);
    if (err != 0) {
        DPRINTK("%s: vsock listen error: %d\n", __func__, err);
        return err;
    }

    err = vsocket->ops->getname(vsocket, (struct sockaddr *) &vm_addr, 0);
    if (err < 0) {
        DPRINTK("%s: error in getname: %d\n", __func__, err);
        return err;
    }

    if (!tsk->bound_addr) {
        DPRINTK("%s: !bound_addr", __func__);
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

    DPRINTK("%s: requesting to listen on port=%d\n", __func__, lreq.port);

    vm_addr.svm_family = AF_VSOCK;
    vm_addr.svm_port = TSI_LISTEN;
    vm_addr.svm_cid = TSI_CID;
    vm_addr.svm_flags = 0;

    lreq_msg.msg_name = &vm_addr;
    lreq_msg.msg_namelen = sizeof(struct sockaddr_vm);

    err = kernel_sendmsg(control_socket, &lreq_msg, &iov, 1, iov.iov_len);
    if (err < 0) {
        DPRINTK("%s: error sending listen request: %d\n", __func__, err);
        return err;
    }

    iov.iov_base = (u8 *) &lrsp;
    iov.iov_len = sizeof(struct tsi_listen_rsp);

    err = kernel_recvmsg(control_socket, &lreq_msg, &iov, 1, iov.iov_len, 0);
    if (err < 0) {
        DPRINTK("%s: error receiving listen request answer\n", __func__);
        return err;
    }

    return lrsp.result;
}

static int tsi_shutdown(struct socket *sock, int mode)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;

	DPRINTK("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->shutdown(isocket, mode);
	case S_CONNECTED_VSOCK:
	case S_CONNECTING_VSOCK:
		return vsocket->ops->shutdown(vsocket, mode);
	}

	return -ENOTCONN;
}

static int tsi_stream_setsockopt(struct socket *sock,
				 int level,
				 int optname,
				 sockptr_t optval,
				 unsigned int optlen)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;

	DPRINTK("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->setsockopt(isocket, level, optname, optval, optlen);
	case S_CONNECTED_VSOCK:
	case S_CONNECTING_VSOCK:
		return 0;
		//return vsocket->ops->setsockopt(vsocket, level, optname, optval, optlen);
	}

	return -EINVAL;
}

static int tsi_dgram_setsockopt(struct socket *sock,
				 int level,
				 int optname,
				 sockptr_t optval,
				 unsigned int optlen)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;

	DPRINTK("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->setsockopt(isocket, level, optname, optval, optlen);
	case S_CONNECTED_VSOCK:
	case S_CONNECTING_VSOCK:
    case S_IDLE:
        DPRINTK("%s: TODO implement setsockopt", __func__);
		return 0;
		//return vsocket->ops->setsockopt(vsocket, level, optname, optval, optlen);
	}

	return -EINVAL;
}

static int tsi_stream_getsockopt(struct socket *sock,
				 int level, int optname,
				 char *optval,
				 int __user *optlen)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;

	DPRINTK("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->getsockopt(isocket, level, optname, optval, optlen);
	case S_CONNECTED_VSOCK:
	case S_CONNECTING_VSOCK:
		return vsocket->ops->getsockopt(vsocket, level, optname, optval, optlen);
	}

	return -EINVAL;
}

/*
static int vsock_proxy_sendmsg(struct socket *vsocket, struct msghdr *msg,
			       size_t len)
{
	struct sockaddr_vm vm_addr;
	int err;

	memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
	vm_addr.svm_family = AF_VSOCK;
	vm_addr.svm_port = STREAM_DATA;
	vm_addr.svm_cid = TSI_CID;

	msg->msg_name = &vm_addr;
	msg->msg_namelen = sizeof(struct sockaddr_vm);

	return sock_sendmsg(vsocket, msg);

}
*/

static int tsi_stream_sendmsg(struct socket *sock, struct msghdr *msg,
			      size_t len)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;

	int err;

	DPRINTK("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_IDLE:
		return -EINVAL;
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->sendmsg(isocket, msg, len);
	case S_CONNECTED_VSOCK:
	case S_CONNECTING_VSOCK:
		err = vsocket->ops->sendmsg(vsocket, msg, len);
        DPRINTK("%s: s=%p vs=%p is=%p st=%d exit\n", __func__, sock,
                vsocket, isocket, tsk->status);
        return err;
	}

	return -ENOTCONN;
}

static int tsi_dgram_sendmsg(struct socket *sock, struct msghdr *msg,
			      size_t len)
{
    struct sockaddr_in *sin;
    struct sockaddr_vm *svm;
    struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	int err;

	DPRINTK("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_IDLE:
		err = -EINVAL;
        err = isocket->ops->sendmsg(isocket, msg, len);
        if (err != 0) {
            if (msg->msg_name) {
                struct tsi_sendto_addr sa_req;
                struct sockaddr_vm sa_req_svm;
                struct msghdr sa_req_msg = { .msg_flags = 0 };
                struct kvec iov = {
                    .iov_base = (u8 *) &sa_req,
                    .iov_len = sizeof(struct tsi_sendto_addr),
                };

                DPRINTK("%s: fixing msg->msg_name\n", __func__);

                sin = (struct sockaddr_in *) msg->msg_name;

                if (tsk->svm_port == 0) {
                    if (tsi_create_proxy(tsk, SOCK_DGRAM) != 0)
                        return -EINVAL;
                }

                sa_req.svm_port = tsk->svm_port;
                sa_req.addr = sin->sin_addr.s_addr;
                sa_req.port = sin->sin_port;

                sa_req_svm.svm_family = AF_VSOCK;
                sa_req_svm.svm_port = TSI_SENDTO_ADDR;
                sa_req_svm.svm_cid = TSI_CID;
                sa_req_svm.svm_flags = 0;

                sa_req_msg.msg_name = &sa_req_svm;
                sa_req_msg.msg_namelen = sizeof(struct sockaddr_vm);

                err = kernel_sendmsg(control_socket, &sa_req_msg, &iov, 1, iov.iov_len);
                if (err < 0) {
                    DPRINTK("%s: error sending connection request: %d\n", __func__, err);
                    return err;
                }
            }

            if (!tsk->sendto_addr) {
                tsk->sendto_addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
            }
            memcpy(tsk->sendto_addr, msg->msg_name, sizeof(struct sockaddr_in));

            svm = (struct sockaddr_vm *) msg->msg_name;
            svm->svm_family = AF_VSOCK;
            svm->svm_port = TSI_SENDTO_DATA;
            svm->svm_cid = TSI_CID;
            svm->svm_flags = 0;

            err = vsocket->ops->sendmsg(vsocket, msg, len);
            if (err == 0) {
                tsk->status = S_CONNECTED_VSOCK;
            }
        }
		return err;
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->sendmsg(isocket, msg, len);
	case S_CONNECTED_VSOCK:
	case S_CONNECTING_VSOCK:
        if (msg->msg_name) {
            if (!tsk->sendto_addr) {
                tsk->sendto_addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
            }

            memcpy(tsk->sendto_addr, msg->msg_name, sizeof(struct sockaddr_in));
            svm = (struct sockaddr_vm *) msg->msg_name;
            svm->svm_family = AF_VSOCK;
            svm->svm_port = TSI_SENDTO_DATA;
            svm->svm_cid = TSI_CID;
            svm->svm_flags = 0;
        }

		return vsocket->ops->sendmsg(vsocket, msg, len);
	}

	return -ENOTCONN;
}

static int tsi_stream_recvmsg(struct socket *sock, struct msghdr *msg,
			      size_t len, int flags)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;

	DPRINTK("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->recvmsg(isocket, msg, len, flags);
	case S_CONNECTED_VSOCK:
	case S_CONNECTING_VSOCK:
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

	DPRINTK("%s: s=%p vs=%p is=%p st=%d\n", __func__, sock,
		vsocket, isocket, tsk->status);

	switch (tsk->status) {
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->recvmsg(isocket, msg, len, flags);
	case S_CONNECTED_VSOCK:
	case S_CONNECTING_VSOCK:
		err = vsocket->ops->recvmsg(vsocket, msg, len, flags);
        if (err > 0 && msg && msg->msg_name && tsk->sendto_addr) {
            printk("%s: msg_name=%p sin_sendto=%p, msg_len=%d sin_len=%ld\n", __func__, msg->msg_name, tsk->sendto_addr, msg->msg_namelen, sizeof(struct sockaddr_in));
            memcpy(msg->msg_name, tsk->sendto_addr, sizeof(struct sockaddr_in));
            //memset(msg->msg_name, 0, sizeof(struct sockaddr_in));
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
	.connect = tsi_stream_connect,
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
	.connect = tsi_dgram_connect,
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
	struct sock *sk;
	int err;

	DPRINTK("%s: socket=%p\n", __func__, sock);

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
		return err;
	}

	vsocket = NULL;
	err = __sock_create(current->nsproxy->net_ns, PF_VSOCK,
			    sock->type, PF_VSOCK, &vsocket, 1);
	if (err) {
		pr_err("%s (%d): problem creating vsock socket\n",
		       __func__, task_pid_nr(current));
		return err;
	}

	DPRINTK("isocket: %p\n", isocket);
	DPRINTK("vsocket: %p\n", vsocket);
	tsk->isocket = isocket;
	tsk->vsocket = vsocket;
	sock->state = SS_UNCONNECTED;
    tsk->svm_port = 0;
    tsk->svm_peer_port = 0;
    tsk->sendto_addr = NULL;
    tsk->bound_addr = NULL;

	return 0;
}

static const struct net_proto_family tsi_family_ops = {
	.family = AF_TSI,
	.create = tsi_create,
	.owner = THIS_MODULE,
};

static int __init tsi_init(void)
{
	struct sockaddr_vm vm_addr;
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

	err = __sock_create(current->nsproxy->net_ns, PF_VSOCK,
			    SOCK_DGRAM, 0, &control_socket, 1);
	if (err) {
		DPRINTK("%s: error creating control socket\n", __func__);
		goto err_unregister_proto;
	}

	memset(&vm_addr, 0, sizeof(struct sockaddr_vm));
	vm_addr.svm_family = AF_VSOCK;
	vm_addr.svm_port = VMADDR_PORT_ANY;
	vm_addr.svm_cid = VMADDR_CID_ANY;

	err = kernel_bind(control_socket, (struct sockaddr *) &vm_addr, sizeof(struct sockaddr_vm));
	if (err) {
		DPRINTK("%s: error binding port\n", __func__);
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
