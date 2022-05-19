/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Transparent Socket Impersonation Driver
 *
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Authors:
 *  Sergio Lopez <slp@redhat.com>
 */

#ifndef _AF_TSI_H_
#define _AF_TSI_H_

#define S_HYBRID           0
#define S_INET             1
#define S_VSOCK            2

#define TSI_DEFAULT_PORT   620

#define TSI_PROXY_CREATE   1024
#define TSI_CONNECT        1025
#define TSI_GETNAME        1026
#define TSI_SENDTO_ADDR    1027
#define TSI_SENDTO_DATA    1028
#define TSI_LISTEN         1029
#define TSI_ACCEPT         1030
#define TSI_PROXY_RELEASE  1031

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

#endif
