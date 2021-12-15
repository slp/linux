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

struct tsi_sock {
	/* sk must be the first member. */
	struct sock sk;
	struct socket *isocket;
	struct socket *vsocket;
	unsigned int status;
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
	}

	return isocket->ops->bind(isocket, addr, addr_len);
}

struct connreq {
	struct sockaddr_in addr;
	size_t addr_len;
};

static int tsi_stream_connect(struct socket *sock, struct sockaddr *addr,
			      int addr_len, int flags)
{
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
		struct sockaddr_vm remote_addr;
		struct msghdr msg = { .msg_flags = 0 };
		struct connreq creq;
		struct kvec iov = {
			.iov_base = (u8 *)&creq,
			.iov_len = sizeof(struct connreq),
		};

		memset(&remote_addr, 0, sizeof(struct sockaddr_vm));
		remote_addr.svm_family = AF_VSOCK;
		remote_addr.svm_port = 1024;
		remote_addr.svm_cid = 2;

		err = kernel_connect(vsocket,
				     (struct sockaddr *) &remote_addr,
				     sizeof(struct sockaddr_vm), 0);
		if (err != 0) {
			printk("%s: error creating tsi->vsock connection\n", __func__);
			return err;
		}

		memcpy(&creq.addr, addr, addr_len);

		err = kernel_sendmsg(vsocket, &msg, &iov, 1, iov.iov_len);
		if (err < 0) {
			printk("%s: error sending connection request\n", __func__);
			return err;
		}

		err = kernel_recvmsg(vsocket, &msg, &iov, 1, iov.iov_len, 0);
		if (err < 0) {
			printk("%s: error receiving connection request answer\n", __func__);
			return err;
		}

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

static int tsi_accept_socket(struct socket *socket, struct socket **newsock,
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

static int tsi_accept(struct socket *sock, struct socket *newsock, int flags,
		      bool kern)
{
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
	err = tsi_accept_socket(tsk->isocket, &nsock, flags | O_NONBLOCK, kern);
	if (err >= 0) {
		newtsk->status = S_CONNECTED_INET;
		DPRINTK("%s: switching to CONNECTED_INET\n", __func__);
		newtsk->isocket = nsock;
	} else if (err == -EAGAIN) {
		err = tsi_accept_socket(tsk->vsocket, &nsock, flags, kern);
		if (err >= 0) {
			newtsk->status = S_CONNECTED_VSOCK;
			DPRINTK("%s: switching to CONNECTED_VSOCK\n", __func__);
			newtsk->vsocket = nsock;
		}
	}

	if (err >= 0)
		newsock->state = SS_CONNECTED;

	return err;
}

static int tsi_getname(struct socket *sock,
		       struct sockaddr *addr, int peer)
{
	struct tsi_sock *tsk = tsi_sk(sock->sk);
	struct socket *isocket = tsk->isocket;
	struct socket *vsocket = tsk->vsocket;
	int err = 0;
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, addr);

	DPRINTK("%s: s=%p vs=%p is=%p st=%d peer=%d\n", __func__, sock,
            vsocket, isocket, tsk->status, peer);

	switch (tsk->status) {
	case S_CONNECTED_INET:
		return isocket->ops->getname(isocket, addr, peer);
	case S_CONNECTED_VSOCK:
		if (peer) {
			return vsocket->ops->getname(vsocket, addr, peer);
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
	int err;

	DPRINTK("%s: vsocket=%p isocket=%p\n", __func__, vsocket, isocket);
	/*
	err = vsocket->ops->listen(vsocket, backlog);
	if (err) {
		DPRINTK("%s: error setting up vsock listener: %d\n", __func__, err);
	} else {
		err = vsock_tsi_listen(vsocket, isocket);
		if (err) {
			DPRINTK("%s: error setting up TSI vsock listener: %d\n", __func__, err);
		}
	}
	*/
	return isocket->ops->listen(isocket, backlog);
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
		err = -EINVAL;
		if (sock->type == SOCK_DGRAM) {
			err = isocket->ops->sendmsg(isocket, msg, len);
			if (err != 0) {
				err = vsocket->ops->sendmsg(vsocket, msg, len);
				if (err != 0) {
					tsk->status = S_CONNECTED_VSOCK;
				}
			}
		}
		return err;
	case S_CONNECTED_INET:
	case S_CONNECTING_INET:
		return isocket->ops->sendmsg(isocket, msg, len);
	case S_CONNECTED_VSOCK:
	case S_CONNECTING_VSOCK:
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
	case SOCK_DGRAM:
		sock->ops = &tsi_stream_ops;
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
			    sock->type, 0, &vsocket, 1);
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

	return 0;
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
