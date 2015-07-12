/*
   Unix SMB/CIFS implementation.

   Web Services for Device and LLMNR Samba service

   https://msdn.microsoft.com/library/windows/desktop/aa826001(v=vs.85).aspx
   https://msdn.microsoft.com/library/windows/hardware/jj123472.aspx
   https://tools.ietf.org/html/rfc4795

   Copyright (C) Tobias Waldvogel 2013
   Copyright (C) Jose M. Prieto 2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <talloc.h>
#include <tevent.h>

#include "wsdd.h"
#include "llmnr.h"
#include "wsd.h"
#include "includes.h"
#include "param/param.h"
#include "smbd/process_model.h"
#include "smbd/service_task.h"
#include "lib/socket/netif.h"
#include "lib/socket/socket.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/util_tdb.h"
#include "libcli/util/ntstatus.h"
#include "lib/util/data_blob.h"
#include "lib/tsocket/tsocket.h"
#include "librpc/ndr/libndr.h"
#include "lib/messaging/irpc.h"

/* set new debug class */
#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_WSDD

enum wsdd_http_version {
	HTTP_VER_NULL,
	HTTP_VER_1_0,
	HTTP_VER_1_1
};

enum wsdd_http_method {
	HTTP_METHOD_NULL,
	HTTP_METHOD_GET,
	HTTP_METHOD_POST
};

enum wsdd_content_type {
	WSD_CONTENT_TYPE_NULL,
	WSD_CONTENT_TYPE_SOAP,
	WSD_CONTENT_TYPE_XML
};

struct wsdd_mcast_socket;
struct wsdd_http_ctx;

struct wsdd_call {
	bool http;
	union {
		struct wsdd_mcast_socket *mcast;
		struct wsdd_http_ctx *http;
	} ctx;
	struct tsocket_address *src;
	DATA_BLOB in;
	DATA_BLOB out;
};

struct wsdd_http_ctx {
	struct wsdd_server *wsdd;
	struct stream_connection *conn;
	struct wsdd_call *call;
	struct {
		enum wsdd_http_method method;
		char *uri;
		enum wsdd_content_type content_type;
		size_t content_length;
		bool endof_headers;
		DATA_BLOB read_buffer;
	} req;
	struct {
		size_t bytes_hdr_sent;
		size_t bytes_body_sent;
		uint16_t status;
		DATA_BLOB headers;
		DATA_BLOB error_reason;
		DATA_BLOB error_details;
	} resp;
};

struct wsdd_mcast_ops {
	tevent_req_fn recvfrom_cb;
	tevent_req_fn sendto_cb;
	NTSTATUS (*process_cb)(struct wsdd_server *, struct wsdd_call *);
	int (*destroy_cb)(struct wsdd_mcast_socket *);
};

struct wsdd_mcast_socket {
	struct wsdd_server *wsdd;
	const char *name;
	const char *maddr;
	bool is_ipv6;
	int fd;
	struct tsocket_address *saddr;
	struct wsdd_mcast_ops *ops;
	struct tdgram_context *dgram_ctx;
	struct tevent_queue *send_queue;
};

/*
 * convert DATA_BLOB to string
 */
static char *wsdd_datablob_printable_string(TALLOC_CTX *mem_ctx, DATA_BLOB *b)
{
	int i;
	char *str;

	if (!b || b->length == 0) {
		return talloc_strdup(mem_ctx, "");
	}

	str = talloc_zero_array(mem_ctx, char, b->length*1);
	if (str == NULL) {
		return NULL;
	}

	for (i = 0; i<b->length; i++) {
		if (b->data[i] == 0x0A || b->data[i] == 0x0D) {
			str[i] = b->data[i];
		} else if (b->data[i] < 32 || b->data[i] > 127) {
			/* non-printable char */
			str[i] = '.';
		} else {
			str[i] = b->data[i];
		}
	}

	return str;
}

/*
 * send message synchrnously via UDP socket
 */
static int wsdd_mcast_sendmsg_sync(struct wsdd_mcast_socket *socket,
					DATA_BLOB msg)
{
	struct wsdd_server *wsdd = socket->wsdd;
	struct sockaddr_storage wsd_mcast;
	struct sockaddr_in *wsd_mcast4;
	uint16_t port;
	const char *ip, *ifname;
	int i, nifaces, rc;
	char cmsg_buf[1024];
	struct iovec iovec[1];
	struct msghdr hmsg;
	struct cmsghdr *cmsg;
	struct in_pktinfo *pktinfo;
	char *pkt_str, *pkt_hex;
	bool iface_ipv6;
#ifdef HAVE_IPV6
	struct sockaddr_in6 *wsd_mcast6;
	struct in6_pktinfo *pktinfo6;
#endif

	/* get socket port */
	port = tsocket_address_inet_port(socket->saddr);
	if (port == 0) {
		DEBUG(1, ("error in tsocket_address_inet_port (%s)\n",
			  strerror(errno)));
		return -1;
	}

	/* prepare wsd multicast socket address */
	memset((char *)&wsd_mcast, 0, sizeof(wsd_mcast));
#ifdef HAVE_IPV6
	if (socket->is_ipv6) {
		wsd_mcast6 = (struct sockaddr_in6 *)&wsd_mcast;
		wsd_mcast6->sin6_family = AF_INET6;
		wsd_mcast6->sin6_port = htons(port);
		rc = inet_pton(AF_INET6, socket->maddr, &wsd_mcast6->sin6_addr);
	} else
#endif
	{
		wsd_mcast4 = (struct sockaddr_in *)&wsd_mcast;
		wsd_mcast4->sin_family = AF_INET;
		wsd_mcast4->sin_port = htons(port);
		rc = inet_pton(AF_INET, socket->maddr, &wsd_mcast4->sin_addr);
	}
	if (rc <= 0) {
		DEBUG(1, ("failed to convert address %s\n", socket->maddr));
		return -1;
	}

	if (CHECK_DEBUGLVL(15)) {
		pkt_str = wsdd_datablob_printable_string(socket, &msg);
		pkt_hex = data_blob_hex_string_upper(socket, &msg);
		DEBUG(15, ("output packet to be sent out synchronously to "
			   "%s:%u (bytes: %lu)\n", socket->maddr, port,
			   msg.length));
		DEBUGADD(16, ("%s\n", pkt_str));
		DEBUGADD(16, ("%s\n", pkt_hex));
		TALLOC_FREE(pkt_str);
		TALLOC_FREE(pkt_hex);
	}

	/* prepare message I/O vector */
	iovec[0].iov_base = msg.data;
	iovec[0].iov_len = msg.length;

	/* prepare ancilliary data for send */
	hmsg.msg_name = (struct sockaddr_storage *)&wsd_mcast;
	hmsg.msg_namelen = sizeof(wsd_mcast);
	hmsg.msg_iov = iovec;
	hmsg.msg_iovlen = 1;
	hmsg.msg_flags = 0;
	memset(cmsg_buf, 0, sizeof(cmsg_buf));
	hmsg.msg_control = cmsg_buf;
#ifdef HAVE_IPV6
	if (socket->is_ipv6) {
		hmsg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	} else
#endif
	{
		hmsg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
	}

	cmsg = CMSG_FIRSTHDR(&hmsg);
#ifdef HAVE_IPV6
	if (socket->is_ipv6) {
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		pktinfo6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	} else
#endif
	{
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
	}

	/* for each interfaces passed in, send message to multicast group */
	nifaces = iface_list_count(wsdd->ifaces);
	for(i=0; i<nifaces; i++) {
		iface_ipv6 = !iface_list_n_is_v4(wsdd->ifaces, i);
		if ((socket->is_ipv6 && !iface_ipv6) ||
		    (!socket->is_ipv6 && iface_ipv6))
		{
			if (CHECK_DEBUGLVL(10)) {
				ip = iface_list_n_ip(wsdd->ifaces, i);
				DEBUG(10, ("discard interface %s\n", ip));
			}
			continue;
		}

		ip = iface_list_n_ip(wsdd->ifaces, i);
#ifdef HAVE_IPV6
		if (iface_ipv6) {
			ifname = iface_list_n_name(wsdd->ifaces, i);
			pktinfo6->ipi6_ifindex = if_nametoindex(ifname);
			if (pktinfo6->ipi6_ifindex  == 0) {
				DEBUG(1, ("failed to get index for %s\n",
					  ifname));
				DEBUGADD(1, ("discard interface %s\n", ip));
				continue;
			}

		} else
#endif
		{
			rc = inet_pton(AF_INET, ip, &pktinfo->ipi_spec_dst);
			if (rc == -1) {
				DEBUG(1, ("failed to convert address %s\n", ip));
				DEBUGADD(1, ("discard interface %s\n", ip));
				continue;
			}
		}

		/* send message to WSD multicast */
		rc = sendmsg(socket->fd, &hmsg, 0);
		if (rc == -1) {
			DEBUG(1, ("failed to send out the packet to %s (%d: %s)\n",
				  socket->maddr, errno, strerror(errno)));
			DEBUGADD(1, ("discard interface %s\n", ip));
			continue;
		}

		DEBUG(10, ("synchronous packet successfully sent from %s "
			   "to multicast group %s\n", ip, socket->maddr));
	}

	return 0;
}

/*
 * set up multicast membership
 */
static int wsdd_set_mcast_membership(struct wsdd_mcast_socket *socket, bool set)
{
	struct wsdd_server *wsdd = socket->wsdd;
	struct ip_mreq mreq;
#ifdef HAVE_IPV6
	struct ipv6_mreq mreq6;
#endif
	const char *ip, *ifname = NULL;
	int i, nifaces, rc;
	int action;
	bool iface_ipv6;

	/* set multicast address and action */
	if (socket->is_ipv6) {
#ifdef HAVE_IPV6
		action = set?IPV6_JOIN_GROUP:IPV6_LEAVE_GROUP;
		rc = inet_pton(AF_INET6, socket->maddr, &mreq6.ipv6mr_multiaddr);
#else
		errno = EAFNOSUPPORT;
		rc = -1;
#endif
	} else {
		action = set?IP_ADD_MEMBERSHIP:IP_DROP_MEMBERSHIP;
		rc = inet_pton(AF_INET, socket->maddr, &mreq.imr_multiaddr);
	}
	if (rc <= 0) {
		DEBUG(1, ("failed to convert address %s\n", socket->maddr));
		return -1;
	}

	/* for each interfaces passed in, set multicast membership */
	nifaces = iface_list_count(wsdd->ifaces);
	for(i=0; i<nifaces; i++) {
		iface_ipv6 = !iface_list_n_is_v4(wsdd->ifaces, i);
		if ((socket->is_ipv6 && !iface_ipv6) ||
		    (!socket->is_ipv6 && iface_ipv6))
		{
			if (CHECK_DEBUGLVL(10)) {
				ip = iface_list_n_ip(wsdd->ifaces, i);
				DEBUG(10, ("discard interface %s\n", ip));
			}
			continue;
		}

		ip = iface_list_n_ip(wsdd->ifaces, i);
#ifdef HAVE_IPV6
		if (iface_ipv6) {
			ifname = iface_list_n_name(wsdd->ifaces, i);
			mreq6.ipv6mr_interface = if_nametoindex(ifname);
			if (mreq6.ipv6mr_interface == 0) {
				DEBUG(1, ("failed to get index for %s\n",
					  ifname));
				DEBUGADD(1, ("discard interface %s\n", ip));
				continue;
			}

			rc = setsockopt(socket->fd, IPPROTO_IPV6, action, &mreq6,
					sizeof(mreq6));
		} else
#endif
		{
			rc = inet_pton(AF_INET, ip, &mreq.imr_interface);
			if (rc == -1) {
				DEBUG(1, ("failed to convert address %s\n", ip));
				DEBUGADD(1, ("discard interface %s\n", ip));
				continue;
			}

			rc = setsockopt(socket->fd, IPPROTO_IP, action, &mreq,
					sizeof(mreq));
		}
		if (rc == -1) {
			DEBUG(1, ("failed to set mcast membership opt for "
				  "%s\n", ip));
			DEBUGADD(1, ("discard interface %s\n", ip));
			continue;
		}

		DEBUG(10, ("interface %s successfully %s multicast %s\n", ip,
			   set?"added to":"removed from", socket->maddr));
	}

	return 0;
}

/*
 * create UDP socket using system calls
 */
static int wsdd_create_udp_socket(struct tsocket_address *saddr, bool is_ipv6)
{
	int rc, fd, err;
	struct sockaddr_storage sa;
	size_t sa_len;
	const int enable = 1;
	const int disable = 0;

#ifndef HAVE_IPV6
	if (is_ipv6) {
		errno = EAFNOSUPPORT;
		return -1;
	}
#endif
	/* file descriptor for udp socket */
#ifdef HAVE_IPV6
	if (is_ipv6) {
		fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	} else
#endif
	{
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	if (fd == -1) {
		DEBUG(1, ("error creating the socket (%d: %s)\n", errno,
			  strerror(errno)));
		return -1;
	}

	/* set socket options */
#ifdef HAVE_IPV6
	if (is_ipv6) {
		sa_len = sizeof(struct sockaddr_in6);

		rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &enable,
				sizeof(enable));
		if (rc == -1) {
			DEBUG(1, ("error setting opt IPV6_V6ONLY (%d: %s)\n",
				  errno, strerror(errno)));
			goto failed_create_udp_socket;
		}

		/*
		 * setting sticky socket option IPV6_PKTINFO on IPv6 seems to be
		 * buggy on Linux kernel. It returns EINVAL. As workaround
		 * outgoing interface selection is based on input given in
		 * section 6.7 of RFC 3542.
		 * see kernel bug:
		 *	https://bugzilla.kernel.org/show_bug.cgi?id=18132
		 * see also RFC 3542, sections 4.2, 6, 6.2, 6.7
		 *	https://tools.ietf.org/html/rfc3542
		 */
#if 0
		rc = setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &enable,
				sizeof(enable));
		if (rc == -1) {
			DEBUG(1, ("error setting opt IPV6_PKTINFO "
				  "(%d: %s)\n", errno, strerror(errno)));
			goto failed_create_udp_socket;
		}
#endif

		rc = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &disable,
				sizeof(disable));
		if (rc == -1) {
			DEBUG(1, ("error setting opt IPV6_MULTICAST_LOOP "
				  "(%d: %s)\n", errno, strerror(errno)));
			goto failed_create_udp_socket;
		}
	} else
#endif
	{
		sa_len = sizeof(struct sockaddr_in);

		rc = setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &enable,
				sizeof(enable));
		if (rc == -1) {
			DEBUG(1, ("error setting opt IP_PKTINFO (%d: %s)\n",
				  errno, strerror(errno)));
			goto failed_create_udp_socket;
		}

		rc = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &disable,
				sizeof(disable));
		if (rc == -1) {
			DEBUG(1, ("error setting opt IP_MULTICAST_LOOP "
				  "(%d: %s)\n", errno, strerror(errno)));
			goto failed_create_udp_socket;
		}
	}

	/* convert tsocket_address to sockaddr */
	rc = tsocket_address_bsd_sockaddr(saddr, (struct sockaddr *)&sa, sa_len);
	if (rc == -1) {
		DEBUG(1, ("error converting tsocket address (%d: %s)\n",
			  errno, strerror(errno)));
		goto failed_create_udp_socket;
	}

	/* bind socket */
	rc = bind(fd, (struct sockaddr *)&sa, sa_len);
	if (rc == -1) {
		DEBUG(1, ("error binding the socket (%d, %s)\n", errno,
			  strerror(errno)));
		goto failed_create_udp_socket;
	}

	return fd;

failed_create_udp_socket:
	err = errno;
	shutdown(fd, SHUT_RDWR);
	close(fd);
	errno = err;
	return -1;
}

/*
 * set up an multicast socket
 */
static NTSTATUS wsdd_create_mcast_socket(struct wsdd_server *wsdd,
				const char *name, bool is_ipv6,
				const char *maddr, uint16_t port,
				struct wsdd_mcast_ops *ops,
				struct wsdd_mcast_socket **socket)
{
	NTSTATUS status;
	struct wsdd_mcast_socket *mcast_socket;
	struct tevent_req *mcast_req;
	int ret;

	/* allocate memory for multicast socket context */
	mcast_socket = talloc_zero(wsdd, struct wsdd_mcast_socket);
	NT_STATUS_HAVE_NO_MEMORY(mcast_socket);

	mcast_socket->wsdd = wsdd;
	mcast_socket->name = talloc_strdup(mcast_socket, name);
	mcast_socket->maddr = talloc_strdup(mcast_socket, maddr);
	mcast_socket->is_ipv6 = is_ipv6;
	mcast_socket->ops = ops;
	
	/* set up destructor for remove multicast membership */
	talloc_set_destructor(mcast_socket, ops->destroy_cb);

	/* create socket address */
	if (is_ipv6) {
		ret = tsocket_address_inet_from_strings(mcast_socket, "ipv6",
							NULL, port,
							&mcast_socket->saddr);
	} else {
		ret = tsocket_address_inet_from_strings(mcast_socket, "ipv4",
							NULL, port,
							&mcast_socket->saddr);
	}
	if (ret == -1) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG (1, ("failed to create socket address for port %u\n",
			   (unsigned)port));
		return status;
	}

	/* create udp socket */
	mcast_socket->fd = wsdd_create_udp_socket(mcast_socket->saddr, is_ipv6);
	if (mcast_socket->fd == -1) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG (1, ("failed to create UDP socket for port %u\n",
			   (unsigned)port));
		return status;
	}
	
	/* add multicast membership */
	ret = wsdd_set_mcast_membership(mcast_socket, true);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(1, ("failed to add multicast membership for %s\n",
			  maddr));
		shutdown(mcast_socket->fd, SHUT_RDWR);
		close(mcast_socket->fd);
		mcast_socket->fd = -1;
		return status;
	}

	/* create tsocket datagram context */
	ret = tdgram_bsd_existing_socket(mcast_socket, mcast_socket->fd,
					 &mcast_socket->dgram_ctx);
	if (ret == -1) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG (1, ("failed to bind to multicast %s:%u\n", maddr,
			   (unsigned)port));
		shutdown(mcast_socket->fd, SHUT_RDWR);
		close(mcast_socket->fd);
		mcast_socket->fd = -1;
		return status;
	}

	/* create send queue */
	mcast_socket->send_queue = tevent_queue_create(mcast_socket, name);
	NT_STATUS_HAVE_NO_MEMORY(mcast_socket->send_queue);

	/* set recvfrom callback */
	mcast_req = tdgram_recvfrom_send(mcast_socket, wsdd->task->event_ctx,
					 mcast_socket->dgram_ctx);
	NT_STATUS_HAVE_NO_MEMORY(mcast_req);
	tevent_req_set_callback(mcast_req, ops->recvfrom_cb, mcast_socket);

	/* return multicast socket if required */
	if (socket && *socket) {
		*socket = mcast_socket;
	}

	DEBUG(10, ("multicast socket (%s) sucessfully created\n", maddr));

	return NT_STATUS_OK;
}

/*
 * wsd multicast generic sendto callback
 */
static void wsdd_mcast_sendto_done(struct tevent_req *req)
{
	struct wsdd_call *call =
		tevent_req_callback_data(req, struct wsdd_call);
	struct wsdd_mcast_socket *socket = call->ctx.mcast;
	NTSTATUS status;
	int rc, sys_errno;
	char *addr_str, *pkt_str, *pkt_hex;

	/* get system error if any */
	rc = tdgram_sendto_queue_recv(req, &sys_errno);
	if (rc == -1) {
		/* display error on sendto */
		status = map_nt_error_from_unix_common(sys_errno);
		addr_str = tsocket_address_string(call->src, call);
		DEBUG(0, ("error while replying to %s from %s (%s)\n", addr_str,
			  socket->maddr, nt_errstr(status)));
		TALLOC_FREE(addr_str);
	}

	if (CHECK_DEBUGLVL(15)) {
		pkt_str = wsdd_datablob_printable_string(socket, &call->out);
		pkt_hex = data_blob_hex_string_upper(socket, &call->out);
		addr_str = tsocket_address_string(call->src, call);
		DEBUG(15, ("multicast (%s) reply successfully sent to %s "
			   "(bytes: %lu)\n", socket->maddr, addr_str,
			   call->out.length));
		DEBUGADD(16, ("%s\n", pkt_str));
		DEBUGADD(16, ("%s\n", pkt_hex));
		TALLOC_FREE(addr_str);
		TALLOC_FREE(pkt_str);
		TALLOC_FREE(pkt_hex);
	}

	/* destroy call memory chunk and children, we are done */
	TALLOC_FREE(call);

	return;
}

/*
 * wsd multicast generic recvfrom loop
 */
static void wsdd_mcast_recvfrom_loop(struct tevent_req *req)
{
	struct wsdd_mcast_socket *socket =
			tevent_req_callback_data(req, struct wsdd_mcast_socket);
	struct wsdd_server *wsdd = socket->wsdd;
	struct task_server *task = wsdd->task;
	struct wsdd_call *call;
	struct tevent_req *sendreq, *mcast_req;
	int sys_errno;
	NTSTATUS status;
	char *addr_str, *pkt_str, *pkt_hex;

	call = talloc_zero(socket, struct wsdd_call);
	if (call == NULL) {
		DEBUG(0, ("failed to allocate memory for multicast call\n"));
		goto done;
	}

	call->http = false;
	call->ctx.mcast = socket;
	call->in.length = tdgram_recvfrom_recv(req, &sys_errno, call,
					       &call->in.data, &call->src);
	TALLOC_FREE(req);
	if (call->in.length == -1) {
		status = map_nt_error_from_unix_common(sys_errno);
		addr_str = tsocket_address_string(socket->saddr, call);
		DEBUG (0, ("error recvfrom handler for multicast to %s (%s)\n",
			   addr_str, nt_errstr(status)));
		TALLOC_FREE(call);
		goto done;
	}

	if (CHECK_DEBUGLVL(15)) {
		addr_str = tsocket_address_string(call->src, call);
		pkt_str = wsdd_datablob_printable_string(call, &call->in);
		pkt_hex = data_blob_hex_string_upper(call, &call->in);
		DEBUG(15, ("multicast (%s) request successfully read from %s "
			   "(bytes: %lu)\n", socket->maddr, addr_str,
			   (long)call->in.length));
		DEBUGADD(16, ("%s\n", pkt_str));
		DEBUGADD(16, ("%s\n", pkt_hex));
		TALLOC_FREE(addr_str);
		TALLOC_FREE(pkt_str);
		TALLOC_FREE(pkt_hex);
	}

	/* process multicast request */
	status = socket->ops->process_cb(wsdd, call);
	if (!NT_STATUS_IS_OK(status)) {
		addr_str = tsocket_address_string(call->src, call);
		DEBUG(0, ("failed to process multicast request in group %s "
			  "from %s (%s)\n", socket->maddr, addr_str,
			  nt_errstr(status)));
		TALLOC_FREE(call);
		goto done;
	} else if (call->out.length == 0) {
		/* nothing to send back */
		DEBUG(10, ("nothing to send out while processing multicast "
			   "request in group %s\n", socket->maddr));
		goto done;
	}

	sendreq = tdgram_sendto_queue_send(call, task->event_ctx,
					   socket->dgram_ctx,
					   socket->send_queue,
					   call->out.data, call->out.length,
					   call->src);
	if (sendreq == NULL) {
		DEBUG(0, ("failed to set callback for multicast sendto "
			  "handler\n"));
		TALLOC_FREE(call);
		goto done;
	}

	tevent_req_set_callback(sendreq, socket->ops->sendto_cb, call);

	if (CHECK_DEBUGLVL(10)) {
		addr_str = tsocket_address_string(call->src, call);
		DEBUG(10, ("multicast (%s) request from %s successfully "
			   "processed (bytes: %lu)\n", socket->maddr, addr_str,
			   call->in.length));
		TALLOC_FREE(addr_str);
	}

done:
	/* set recvfrom callback again */
	mcast_req = tdgram_recvfrom_send(socket, task->event_ctx,
					 socket->dgram_ctx);
	if (mcast_req == NULL) {
		task_server_terminate(task,
			              "cannot set callback for multicast "
				      "recvfrom handler",
				      true);
		return;
	}

	tevent_req_set_callback(mcast_req, socket->ops->recvfrom_cb, socket);

	return;
}

/*
 * resolve best local IP address from caller
 */
static const char* wsdd_resolve_from_source(TALLOC_CTX *mem_ctx,
				struct wsdd_server *wsdd,
				struct tsocket_address *src)
{
	char *remote;
	const char *resolv_ip;

	/* resolve the best local IP address out of remote caller */
	remote = tsocket_address_inet_addr_string(src, wsdd);
	if (remote == NULL) {
		DEBUG(1, ("cannot translate remote socket address into "
			  "an IP address\n"));
		return NULL;
	}

	resolv_ip = iface_list_best_ip(wsdd->ifaces, remote);
	DEBUG(5, ("best local interface for %s is %s\n", remote, resolv_ip));

	TALLOC_FREE(remote);
	return resolv_ip;
}

/*
 * WSD request handler
 */
static NTSTATUS wsdd_wsd_handle_request(struct wsdd_server *wsdd,
				struct wsdd_call *call)
{
	const char *resolv_ip;
	struct wsd_req_info *req_info;
	char *addr_str;

	/* parse incoming WSD request */
	req_info = wsd_req_parse(call, call->in);
	if (req_info == NULL) {
		DEBUG(1, ("failed to parse incoming WSD request\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* resolve the best local IP address out of remote caller */
	resolv_ip = wsdd_resolve_from_source(call, wsdd, call->src);
	if (resolv_ip == NULL) {
		DEBUG(1, ("cannot find a local interface from caller\n"));
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	if (!req_info->action) {
		if (call->http) {
			/* if HTTP, response with something */
			call->out = wsd_action_get(call, wsdd, req_info);
			return NT_STATUS_OK;
		}
		
		DEBUG(1, ("failed to determine Action from WSD request\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!req_info->msgid) {
		DEBUG(1, ("failed to determine MessageID from WSD request\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (CHECK_DEBUGLVL(5)) {
		addr_str = tsocket_address_string(call->src, call);
		DEBUG(5, ("WSD request from %s\n", addr_str));
		DEBUGADD(5, ("  HTTP: %s\n", call->http?"Yes":"No"));
		DEBUGADD(5, ("  Action: %s\n", req_info->action));
		DEBUGADD(5, ("  MessageID: %s\n", req_info->msgid));
		TALLOC_FREE(addr_str);
	}

	/* handle request depending on action */
	switch(wsd_action_id(req_info)) {
	case WSD_ACTION_HELLO:
	case WSD_ACTION_BYE:
		/* nothing to do */
		call->out = data_blob_null;
		return NT_STATUS_OK;

	case WSD_ACTION_PROBE:
		call->out = wsd_action_probe(call, wsdd, req_info,
					     resolv_ip, WSD_PORT);
		DEBUG(5, ("WSD Probe request processed\n"));
		return NT_STATUS_OK;

	case WSD_ACTION_RESOLVE:
		call->out = wsd_action_resolve(call, wsdd, req_info,
					       resolv_ip, WSD_PORT);
		DEBUG(5, ("WSD Resolve request processed\n"));
		return NT_STATUS_OK;

	case WSD_ACTION_GET:
		call->out = wsd_action_get(call, wsdd, req_info);
		DEBUG(5, ("WSD Get request processed\n"));
		return NT_STATUS_OK;
	}

	return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
}


/* 
 * llmnr multicast udp request processing 
 */
static NTSTATUS wsdd_llmnr_call_process(struct wsdd_server *wsdd,
				struct wsdd_call *call)
{
	const char *resolv_ip;
	char *addr_str;

	/* resolve the best local IP address out of remote caller */
	resolv_ip = wsdd_resolve_from_source(call, wsdd, call->src);
	if (resolv_ip == NULL) {
		DEBUG(1, ("cannot find a local interface from caller\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* process LLMNR call */
	call->out = llmnr_call_process(call, call->in, wsdd->devinfo->name,
				       resolv_ip);

	if (CHECK_DEBUGLVL(5)) {
		addr_str = tsocket_address_string(call->src, call);
		DEBUG(5, ("LLNR UDP request from %s processed\n", addr_str));
		TALLOC_FREE(addr_str);
	}

	return NT_STATUS_OK;
}

/*
 * llmnr multicast socket destructor
 */
static int wsdd_llmnr_destructor(struct wsdd_mcast_socket *mcast_socket)
{
	int rc;
	NTSTATUS status;

	/* remove multicast membership */
	rc = wsdd_set_mcast_membership(mcast_socket, false);
	if (rc == -1) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(0, ("failed to drop multicast membership for %s (%s)\n",
			  mcast_socket->maddr, nt_errstr(status)));
	}

	DEBUG(5, ("LLMNR UDP socket destructor processed (rc: %d)\n", rc));

	return rc;
}

/* 
 * wsd multicast udp request processing 
 */
static NTSTATUS wsdd_wsd_call_process(struct wsdd_server *wsdd,
				struct wsdd_call *call)
{
	NTSTATUS status;
	char *addr_str;

	status = wsdd_wsd_handle_request(wsdd, call);

	if (CHECK_DEBUGLVL(5)) {
		addr_str = tsocket_address_string(call->src, call);
		DEBUG(5, ("WSD UDP request from %s processed\n", addr_str));
		TALLOC_FREE(addr_str);
	}

	return status;
}

/*
 * wsd multicast socket destructor
 */
static int wsdd_wsd_destructor(struct wsdd_mcast_socket *mcast_socket)
{
	int rc;
	struct wsdd_server *wsdd = mcast_socket->wsdd;
	DATA_BLOB bye;
	NTSTATUS status;

	/* send bye message asynchronously */
	bye = wsd_action_bye(mcast_socket, wsdd);
	rc = wsdd_mcast_sendmsg_sync(mcast_socket, bye);
	if (rc < 0) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(0, ("failed to send bye message (%s)\n",
			  nt_errstr(status)));
	}
	data_blob_clear_free(&bye);

	/* remove multicast membership */
	rc = wsdd_set_mcast_membership(mcast_socket, false);
	if (rc == -1) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(0, ("failed to drop multicast membership for %s (%s)\n",
			  mcast_socket->maddr, nt_errstr(status)));
	}

	DEBUG(5, ("WSD UDP socket destructor processed (rc: %d)\n", rc));

	return rc;
}

/*
 * wsd http timeout handler
 */
static void wsdd_http_timeout(struct tevent_context *ev,
				struct tevent_timer *te, struct timeval tv,
				void *private_data)
{
	struct wsdd_http_ctx *ctx = talloc_get_type(private_data,
						    struct wsdd_http_ctx);
	struct wsdd_call *call = ctx->call;
	struct stream_connection *conn = ctx->conn;
	char *addr_str;

	if (CHECK_DEBUGLVL(5)) {
		addr_str = tsocket_address_string(call->src, call);
		DEBUG(5, ("HTTP session timeout processing call from %s\n",
			   addr_str));
		TALLOC_FREE(addr_str);
	}

	/* terminate connection */
	ctx->conn = NULL;
	stream_terminate_connection(conn, "wsd_http_timeout: timed out");

	return;
}

/*
 * wsd http accept connection handler
 */
static void wsdd_http_accept(struct stream_connection *conn)
{
	struct wsdd_server *wsdd = talloc_get_type(conn->private_data,
						   struct wsdd_server);
	struct wsdd_http_ctx *ctx;
	struct wsdd_call *call;
	char *addr_str;

	/* initialized WSD HTTP context */
	ctx = talloc_zero(conn, struct wsdd_http_ctx);
	if (ctx == NULL) {
		DEBUG(1, ("failed to initialized WSD HTTP context\n"));
		stream_terminate_connection(conn,
					    "WSD HTTP context: out of memory");
		return;
	}

	call = talloc_zero(ctx, struct wsdd_call);
	if (call == NULL) {
		DEBUG(1, ("failed to initialized WSD call context\n"));
		stream_terminate_connection(conn,
					    "WSD HTTP context: out of memory");
		return;
	}

	/* update private data area in stream connection */
	call->http = true;
	call->ctx.http = ctx;
	call->src = conn->remote_address;
	ctx->wsdd = wsdd;
	ctx->conn = conn;
	ctx->call = call;
	ctx->req.method = HTTP_METHOD_NULL;
	ctx->req.content_type = WSD_CONTENT_TYPE_NULL;
	conn->private_data = ctx;

	/* set timeout event */
	tevent_add_timer(conn->event.ctx, ctx,
			 timeval_current_ofs(WSD_HTTP_TIMEOUT, 0),
			 wsdd_http_timeout, ctx);

	if (CHECK_DEBUGLVL(5)) {
		addr_str = tsocket_address_string(call->src, call);
		DEBUG(5, ("HTTP request accepted from %s\n", addr_str));
		TALLOC_FREE(addr_str);
	}

	return;
}

/*
 * Parse WSD HTTP URI
 * Returns true if URI is in the form of /<endpoint uuid>[/]
 */
static bool wsdd_http_parse_uri(const char *endpoint, const char *uri)
{
	size_t uri_len;

	if (!uri || uri[0] != '/') {
		return false;
	}

	uri_len = strlen(uri);
	if (uri_len > 0 && uri[uri_len-1] == '/') {
		/* discard last char if '/' */
		uri_len--;
	}

	return (uri_len > 0 && strlen(endpoint) <= uri_len &&
		strncmp(endpoint, &uri[1], uri_len-1) == 0);
}

/*
 * WSD HTTP header parser
 */
static NTSTATUS wsdd_http_parse_header(struct wsdd_http_ctx *ctx,
				const char *hdr)
{
	char *reason, **l_str;
	DATA_BLOB b;
	struct wsdd_server *wsdd = ctx->wsdd;

	if (ctx->req.method == HTTP_METHOD_NULL) {
		/* HTTP start line not yet processed */
		l_str = str_list_make(ctx, hdr, " \t");
		if (str_list_length((const char * const *)l_str) < 3) {
			reason = talloc_strdup(ctx, "");
			b = data_blob_string_const_null(reason);
			ctx->resp.status = 400;
			ctx->resp.error_reason = b;
			ctx->resp.error_details = b;
			if (l_str) {
				TALLOC_FREE(l_str);
			}
			return NT_STATUS_UNSUCCESSFUL;
		}

		/* HTTP method */
		if (strncasecmp(l_str[0], "POST", 4) == 0) {
			ctx->req.method = HTTP_METHOD_POST;
		} else {
			/* error: HTTP method not allowed */
			reason = talloc_strdup(ctx,
					       "HTTP method not supported");
			b = data_blob_string_const_null(reason);
			ctx->resp.status = 405;
			ctx->resp.error_reason = b;
			ctx->resp.error_details = b;
			TALLOC_FREE(l_str);
			return NT_STATUS_UNSUCCESSFUL;
		}

		/* URI */
		if (wsdd_http_parse_uri(wsdd->endpoint, l_str[1])) {
			ctx->req.uri = talloc_strdup(ctx, l_str[1]);
		} else {
			/* error: resource not found */
			reason = talloc_strdup(ctx, "Resource not found");
			b = data_blob_string_const_null(reason);
			ctx->resp.status = 404;
			ctx->resp.error_reason = b;
			ctx->resp.error_details = b;
			TALLOC_FREE(l_str);
			return NT_STATUS_UNSUCCESSFUL;
		}

		TALLOC_FREE(l_str);
	} else if (hdr[0] == 0) {
		/* end of headers (CRLF) */
		ctx->req.endof_headers = true;
	} else if (strncasecmp(hdr, "Content-Type:", 13) == 0) {
		/* Content-Type */
		if (strlen(hdr) > 13) {
			if (strstr("text/xml", &hdr[14])) {
				ctx->req.content_type = WSD_CONTENT_TYPE_XML;
			} else if (strstr("application/soap+xml", &hdr[14])) {
				ctx->req.content_type = WSD_CONTENT_TYPE_SOAP;
			}
		}

		if (ctx->req.content_type == WSD_CONTENT_TYPE_NULL) {
			/* error: only SOAP messages allowed */
			reason = talloc_strdup(ctx, "Invalid content type");
			b = data_blob_string_const_null(reason);
			ctx->resp.status = 400;
			ctx->resp.error_reason = b;
			ctx->resp.error_details = b;
			return NT_STATUS_UNSUCCESSFUL;
		}
	} else if (strncasecmp(hdr, "Content-Length:", 15) == 0) {
		/* Content-Length */
		if (strlen(hdr) > 15) {
			ctx->req.content_length = strtoul(&hdr[16], NULL, 10);
			if (errno == EINVAL || errno == ERANGE) {
				reason = talloc_strdup(ctx, "request content "
						       "length not determined");
				b = data_blob_string_const_null(reason);
				ctx->resp.status = 400;
				ctx->resp.error_reason = b;
				ctx->resp.error_details = b;
				return map_nt_error_from_unix_common(errno);
			}
		}
	}

	return NT_STATUS_OK;
}

/*
 * WSD HTTP response header 
 */
static NTSTATUS wsdd_http_resp_header(struct wsdd_http_ctx *ctx,
				uint16_t status, uint32_t length)
{
	const char resp_hdr_fmt[] =
		"HTTP/1.1 %s\r\n" 
		"Server: Samba WSD Server\r\n"
		"Date: %s\r\n"
		"Connection: close\r\n"
		"Content-Type: application/soap+xml\r\n"
		"Content-Length: %u\r\n"
		"\r\n";

	char status_str[64], time_str[32];
	char *s;
	time_t t;

	/*
	 * HTTP status codes
	 * RFC 2616: https://tools.ietf.org/html/rfc2616
	 */
	switch(status) {
	case 200:
		strncpy(status_str, "200 OK", sizeof(status_str));
		break;

	case 400:
		strncpy(status_str, "400 Bad Request", sizeof(status_str));
		break;

	case 405:
		strncpy(status_str, "405 Method Not Allowed",
			sizeof(status_str));
		break;

	case 500:
		strncpy(status_str, "500 Internal Server Error",
			sizeof(status_str));
		break;

	default:
		strncpy(status_str, "404 Not Found", sizeof(status_str));
	}

	time(&t);
	strftime(time_str, sizeof(time_str), "%a, %d %b %Y %H:%M:%S GMT",
		 gmtime(&t));

	s = talloc_asprintf(ctx, resp_hdr_fmt, status_str, time_str, length);
	NT_STATUS_HAVE_NO_MEMORY(s);
	ctx->resp.headers = data_blob_string_const(s);

	return NT_STATUS_OK;
}

/*
 * wsd http receive handler
 *
 * HTTP/1.1 Message Syntax and Routing
 * https://tools.ietf.org/html/rfc7230
 */
static void wsdd_http_recv(struct stream_connection *conn, uint16_t flags)
{
	struct wsdd_http_ctx *ctx =
		talloc_get_type(conn->private_data, struct wsdd_http_ctx);
	struct wsdd_server *wsdd = ctx->wsdd;
	struct wsdd_call *call = ctx->call;
	NTSTATUS status;
	uint8_t buf[8*1024], *eol_p;
	DATA_BLOB b;
	size_t nread;
	char *addr_str, *pkt_str, *pkt_hex;

	/* read available data from socket */
	status = socket_recv(conn->socket, buf, sizeof(buf), &nread);
	if (NT_STATUS_IS_ERR(status) || !NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("failed to receive HTTP request data (%s)\n",
			   nt_errstr(status)));
		goto failed;
	}

	DEBUG(5, ("WSD HTTP request read (bytes: %lu)\n", nread));

	/* store read data into read buffer */
	if (!data_blob_append(ctx, &ctx->req.read_buffer, buf, nread)) {
		DEBUG (0, ("failed to store data into read buffer\n"));
		goto failed;
	}

	/* parse header lines */
	b = ctx->req.read_buffer;
	while(!ctx->req.endof_headers)
	{
		eol_p = (uint8_t *)memchr(b.data, '\n', b.length);
		if (!eol_p) {
			break;
		}

		if (eol_p[-1] == '\r') {
			const char *hdr = (const char *)b.data;
			eol_p[0] = 0;
			eol_p[-1] = 0;
			status = wsdd_http_parse_header(ctx, hdr);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0, ("error while parsing header line "
					  "\'%s\' (%s)\n",
					  hdr, nt_errstr(status)));
				break;
			}

			DEBUG(10, ("HTTP header processed\n"));
			DEBUGADD(10, ("%s\n", hdr));
		}
		b.length -= (eol_p - b.data) + 1;
		b.data = eol_p+1;
	}

	if (ctx->resp.status >= 400) {
		/* if error during header parse, send SOAP fault and return */	
		const char *estr = (const char *)ctx->resp.error_reason.data;
		call->out = wsd_soap_fault(ctx, ctx->resp.status, estr, estr);
		status =  wsdd_http_resp_header(ctx, ctx->resp.status,
						call->out.length);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("failed to generate HTTP headers of "
				  "SOAP response\n"));
			goto failed;
		}

		TEVENT_FD_NOT_READABLE(conn->event.fde);
		TEVENT_FD_WRITEABLE(conn->event.fde);

		return;
	}

	/* refresh read buffer */
	if (b.length == 0) {
		b.data = NULL;
	}
	
	b = data_blob_talloc(ctx, b.data, b.length);
	data_blob_free(&ctx->req.read_buffer);
	ctx->req.read_buffer = b;

	/* end of body? */
	if (ctx->req.endof_headers &&
	    ctx->req.read_buffer.length >= ctx->req.content_length)
	{
		if (ctx->req.read_buffer.length > ctx->req.content_length) {
			/* discard anything beyond Content-Length */
			ctx->req.read_buffer.data[ctx->req.content_length] = 0;
			ctx->req.read_buffer.length = ctx->req.content_length;
		}

		/* stop reading from descriptor */
		TEVENT_FD_NOT_READABLE(ctx->conn->event.fde);

		if (CHECK_DEBUGLVL(15)) {
			b = ctx->req.read_buffer;
			addr_str = tsocket_address_string(call->src, call);
			pkt_str = wsdd_datablob_printable_string(call, &b);
			pkt_hex = data_blob_hex_string_upper(call, &b);
			DEBUG(15, ("WSD HTTP request successfully read from %s "
				   "(bytes: %lu)\n", addr_str, (long)b.length));
			DEBUGADD(16, ("%s\n", pkt_str));
			DEBUGADD(16, ("%s\n", pkt_hex));
			TALLOC_FREE(addr_str);
			TALLOC_FREE(pkt_str);
			TALLOC_FREE(pkt_hex);
		}

		/* store read buffer into call.in and process request */
		call->in = ctx->req.read_buffer;
		status = wsdd_wsd_handle_request(wsdd, call);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("failed to process WSD HTTP request (%s)\n",
				   nt_errstr(status)));
			goto failed;
		}

		/* build http header and write response */
		ctx->resp.status = 200;
		status = wsdd_http_resp_header(ctx, ctx->resp.status,
					       call->out.length);
		if(!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("failed to generate HTTP headers of "
				  "SOAP response\n"));
			goto failed;
		}
		TEVENT_FD_WRITEABLE(conn->event.fde);
	}

	return;

failed:
	stream_terminate_connection(conn, "wsdd_http_recv: failed");
}

/*
 * wsd http send handler
 */
static void wsdd_http_send(struct stream_connection *conn, uint16_t flags)
{
	struct wsdd_http_ctx *ctx =
		talloc_get_type(conn->private_data, struct wsdd_http_ctx);
	struct wsdd_call *call = ctx->call;
	NTSTATUS status;
	size_t nwrite;
	DATA_BLOB b;
	char *hdr_str, *body_str;
	
	if (ctx->resp.bytes_hdr_sent < ctx->resp.headers.length) {
		b = ctx->resp.headers;
		b.data += ctx->resp.bytes_hdr_sent;
		b.length -= ctx->resp.bytes_hdr_sent;
	} else {
		b = call->out;
		b.data += ctx->resp.bytes_body_sent;
		b.length -= ctx->resp.bytes_body_sent;
	}

	status = socket_send(conn->socket, &b, &nwrite);
	if (NT_STATUS_IS_ERR(status) || !NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("failed to send HTTP response data (%s)\n",
			  nt_errstr(status)));
		stream_terminate_connection(conn, "wsdd_http_send: failed");
		return;
	}

	if (ctx->resp.bytes_hdr_sent < ctx->resp.headers.length) {
		ctx->resp.bytes_hdr_sent += nwrite;
	} else {
		ctx->resp.bytes_body_sent += nwrite;
		if (call->out.length > ctx->resp.bytes_body_sent) {
			return;
		}

		DEBUG(5, ("WSD HTTP response successfully sent\n"));
		if (CHECK_DEBUGLVL(16)) {
			b = ctx->resp.headers;
			hdr_str = wsdd_datablob_printable_string(call, &b);
			DEBUGADD(16, ("Headers:\n%s\n", hdr_str));
			TALLOC_FREE(hdr_str);

			b = call->out;
			body_str = wsdd_datablob_printable_string(call, &b);
			DEBUGADD(16, ("Body:\n%s\n", body_str));
			TALLOC_FREE(body_str);
		}
		TALLOC_FREE(ctx);
		stream_terminate_connection(conn, "wsdd_http_send: "
					    "finished sending");
	}

	return;
}

/* llmnr multicast socket operations */
static struct wsdd_mcast_ops wsdd_llmnr_mcast_ops = {
	.recvfrom_cb = wsdd_mcast_recvfrom_loop,
	.sendto_cb   = wsdd_mcast_sendto_done,
	.process_cb  = wsdd_llmnr_call_process, 
	.destroy_cb  = wsdd_llmnr_destructor,
};

/* wsd multicast socket operations */
static struct wsdd_mcast_ops wsdd_wsd_mcast_ops = {
	.process_cb  = wsdd_wsd_call_process,
	.recvfrom_cb = wsdd_mcast_recvfrom_loop,
	.sendto_cb   = wsdd_mcast_sendto_done,
	.destroy_cb  = wsdd_wsd_destructor,
};

/* wsd http stream ops callback functions */
static struct stream_server_ops wsdd_stream_ops = {
	.name               = "wsdd_http",
	.accept_connection  = wsdd_http_accept,
	.recv_handler       = wsdd_http_recv,
	.send_handler       = wsdd_http_send,
};

/*
 *   once wsdd data has been initialized, startup all wsdd 
 *   subservices (llmnr, wsd and http)
 */
static NTSTATUS wsdd_startup_subservices(struct wsdd_server *wsdd)
{
	NTSTATUS status;
	const struct model_ops *model_ops;
	struct task_server *task = wsdd->task;
	struct wsdd_mcast_socket *wsd_socket;
	DATA_BLOB hello;
	int i, ret;
	uint16_t wsd_http_port = WSD_PORT;
#ifdef HAVE_IPV6
	struct wsdd_mcast_socket *wsd_socket6;
#endif

	/* run the wsdd server as a single process */
	model_ops = process_model_startup("single");
	if (model_ops == NULL) {
		DEBUG(0, ("failed to create the process model\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (wsdd->enable_ipv4) {
		/* setup LLMNR multicast udp4 socket */
		status = wsdd_create_mcast_socket(wsdd, "llmnr-mcast-udp", false,
						  LLMNR_MCAST_ADDR, LLMNR_PORT,
						  &wsdd_llmnr_mcast_ops, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("failed to create LLMNR multicast subservice "
				  "(%s)\n", nt_errstr(status)));
			return status;
		}

		/* setup WSD multicast udp4 socket */
		status = wsdd_create_mcast_socket(wsdd, "wsd-mcast-udp", false,
					WSD_MCAST_ADDR, WSD_PORT,
					&wsdd_wsd_mcast_ops, &wsd_socket);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("failed to create WSD multicast subservice "
				  "(%s)\n", nt_errstr(status)));
			return status;
		}
	}

#ifdef HAVE_IPV6
	if (wsdd->enable_ipv6) {
		/* setup LLMNR multicast udp6 socket */
		status = wsdd_create_mcast_socket(wsdd, "llmnr-mcast6-udp", true,
						  LLMNR_MCAST6_ADDR, LLMNR_PORT,
						  &wsdd_llmnr_mcast_ops, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("failed to create LLMNR multicast6 subservice "
				  "(%s)\n", nt_errstr(status)));
			return status;
		}

		/* setup WSD multicast udp6 socket */
		status = wsdd_create_mcast_socket(wsdd, "wsd-mcast6-udp", true,
					WSD_MCAST6_ADDR, WSD_PORT,
					&wsdd_wsd_mcast_ops, &wsd_socket6);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("failed to create WSD multicast6 subservice "
				  "(%s)\n", nt_errstr(status)));
			return status;
		}
	}
#endif

	/* setup WSD http socket */
	for (i=0; wsdd->ipaddrs[i]; i++) {
		status = stream_setup_socket(wsdd, task->event_ctx,
					     task->lp_ctx, model_ops,
					     &wsdd_stream_ops, "ip", 
					     wsdd->ipaddrs[i], &wsd_http_port,
					     lpcfg_socket_options(task->lp_ctx),
					     wsdd, task->process_context);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("failed to create WSD HTTP subservice\n"));
			DEBUGADD(1,("%s:%u\n", wsdd->ipaddrs[i],
				    (unsigned)wsd_http_port));
			return status;
		}
	}

	DEBUG(5, ("all wsdd subservices succesffully created\n"));

	/* send hello message synchronously */
	hello = wsd_action_hello(wsd_socket, wsdd);
	if (wsdd->enable_ipv4) {
		ret = wsdd_mcast_sendmsg_sync(wsd_socket, hello);
		if (ret < 0) {
			status = map_nt_error_from_unix_common(errno);
			data_blob_clear_free(&hello);
			DEBUG(0, ("failed to send WSD hello message (%s)\n",
				  nt_errstr(status)));
			return status;
		}
	}
#ifdef HAVE_IPV6
	if (wsdd->enable_ipv6) {
		ret = wsdd_mcast_sendmsg_sync(wsd_socket6, hello);
		if (ret < 0) {
			status = map_nt_error_from_unix_common(errno);
			data_blob_clear_free(&hello);
			DEBUG(0, ("failed to send WSD hello message (%s)\n",
				  nt_errstr(status)));
			return status;
		}
	}
#endif
	data_blob_clear_free(&hello);
	DEBUG(5, ("WSD hello message sent out synchronously\n"));

	return NT_STATUS_OK;
}

/*
 * load WSD server endpoint uuid 
 */
static char *wsdd_load_endpoint(TALLOC_CTX *mem_ctx,
				struct loadparm_context *lp_ctx)
{
	char *fname, *s_uuid;
	NTSTATUS status;
	struct tdb_wrap *tdb;
	enum TDB_ERROR err_tdb;
	TDB_DATA data_tdb;
	struct GUID uuid;
	int rc;

	/* open tdb database */
	fname = lpcfg_private_path(mem_ctx, lp_ctx, "wsdd.tdb");
	tdb = tdb_wrap_open(mem_ctx, fname,
			    lpcfg_tdb_hash_size(lp_ctx, fname),
			    lpcfg_tdb_flags(lp_ctx, TDB_DEFAULT),
			    O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(0,("failed to open %s\n", fname));
		talloc_free(fname);
		return NULL;
	}

	DEBUG(5, ("TDB file for WSD service is %s\n", fname));
	TALLOC_FREE(fname);

	/* fetch key WSDD/endpoint */
	data_tdb = tdb_fetch_bystring(tdb->tdb, "WSDD/endpoint");
	err_tdb = tdb_error(tdb->tdb);
	if (err_tdb == TDB_SUCCESS) {
		/* key found so read it */
		s_uuid = talloc_size(mem_ctx, data_tdb.dsize);
		memcpy(s_uuid, data_tdb.dptr, data_tdb.dsize);
		DEBUG(10, ("key WSDD/endpoint found in tdb (%s)\n", s_uuid));
	} else if (err_tdb == TDB_ERR_NOEXIST) {
		/*
		 * entry does not exist so generate an endpoint 
		 * and save it into tdb
		 */
		DEBUG(10, ("key WSDD/endpoint not found in tdb\n"));
		
		uuid = GUID_random();
		s_uuid = GUID_string(mem_ctx, &uuid);
		DEBUGADD(10, ("generated endpoint GUIS is %s\n", s_uuid));

		data_tdb = string_term_tdb_data(s_uuid);
		rc = tdb_store_bystring(tdb->tdb, "WSDD/endpoint", data_tdb, 0);
		if (rc == -1) {
			status = map_nt_error_from_tdb(err_tdb);
			DEBUG(0, ("faled to store endpoint UUID (%s)\n",
				  nt_errstr(status)));
			talloc_free(tdb);
			return NULL;
		}

		DEBUG(10, ("new endpoint GUID saved into tdb\n"));
	} else {
		/* tdb error */
		status = map_nt_error_from_tdb(err_tdb);
		DEBUG(0, ("faled to fetch endpoint UUID (%s)\n",
			  nt_errstr(status)));
		talloc_free(tdb);
		return NULL;
	}

	TALLOC_FREE(tdb);

	return s_uuid;
}

/*
 * load WSD server sequence uuid
 */
static char *wsdd_load_sequence(TALLOC_CTX *mem_ctx)
{
	char *s_uuid;
	struct GUID uuid;

	uuid = GUID_random();
	s_uuid = GUID_string(mem_ctx, &uuid);

	return s_uuid;
}

/*
 *   startup the wsdd server task
 */
static NTSTATUS wsdd_task_init(struct task_server *task)
{
	NTSTATUS status;
	struct wsdd_server *wsdd;
	const char *nbt_name, *workgroup;
	int i, nifaces;

	/* set task title */
	task_server_set_title(task, "task[wsdd]");

	/* wsdd server data init */
	wsdd = talloc_zero(task, struct wsdd_server);
	if (wsdd == NULL) {
		task_server_terminate(task,
				      "wsdd task init: out of memory (wsdd)",
				      true);
		return NT_STATUS_NO_MEMORY;
	}

	task->private_data = wsdd;
	wsdd->task = task;

	/*
	 * notes:
	 * 1) persist wsdd server information into a tdb file
	 *    - endpoint must be generated once and unique per samba server
	 *    - sequence must be generated once whenever wsdd server comes up
	 *    - instance_id must be initialized whenever wsdd server comes up
	 * 2) is it sequence really required? According to WS-Discovery standard
	 *    attribute "SequenceId" is optional
	 */
	wsdd->instance_id = time(NULL);
	wsdd->endpoint = wsdd_load_endpoint(wsdd, task->lp_ctx);
	wsdd->sequence = wsdd_load_sequence(wsdd);

	if (wsdd->instance_id <= 0 || !wsdd->endpoint || !wsdd->sequence) {
		task_server_terminate(task, "failed to init WSD server struct",
				      true);
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(1, ("WSD instance ID initialized to %u\n", wsdd->instance_id));
	DEBUG(1, ("WSD endpoint initialized to %s\n", wsdd->endpoint));
	DEBUG(1, ("WSD sequence initialized to %s\n", wsdd->sequence));

	wsdd->devinfo = talloc_zero(wsdd, struct wsdd_devinfo);
	if (wsdd->devinfo == NULL) {
		task_server_terminate(task,
				      "wsdd task init: out of memory (devinfo)",
				      true);
		return NT_STATUS_NO_MEMORY;
	}

	/* get netbios name parameter */
	nbt_name = lpcfg_netbios_name(task->lp_ctx);
	wsdd->devinfo->name = strlower_talloc(wsdd->devinfo, nbt_name);

	/* read workgroup parameter */
	workgroup = lpcfg_workgroup(task->lp_ctx);
	wsdd->devinfo->workgroup = talloc_strdup(wsdd->devinfo, workgroup);

	DEBUG(1, ("this WSD endpoint will be announced as %s "
		  "in workgroup %s\n", wsdd->devinfo->name,
		  wsdd->devinfo->workgroup));

	/* other computer device struct fields */
	strncpy(wsdd->devinfo->friendly_name, "WSD enabled Samba device",
		sizeof(wsdd->devinfo->friendly_name));
	strncpy(wsdd->devinfo->url, "https://www.samba.org/",
		sizeof(wsdd->devinfo->url));
	strncpy(wsdd->devinfo->manufacturer, "Samba",
		sizeof(wsdd->devinfo->manufacturer));
	strncpy(wsdd->devinfo->model, "wsdd", sizeof(wsdd->devinfo->model));
	strncpy(wsdd->devinfo->serial, "1", sizeof(wsdd->devinfo->serial));
	strncpy(wsdd->devinfo->firmware, "1.0",
		sizeof(wsdd->devinfo->firmware));

	/* local interfaces */
	load_interface_list(wsdd, task->lp_ctx, &wsdd->ifaces);
	wsdd->enable_wcard = !lpcfg_bind_interfaces_only(task->lp_ctx);
	/* wsdd->ipaddrs is a null terminated list of IP address strings */
	if (wsdd->enable_wcard) {
		/* wildcard interfaces */
		wsdd->ipaddrs = iface_list_wildcard(wsdd);
		wsdd->enable_ipv4 = true;
#ifdef HAVE_IPV6
		wsdd->enable_ipv6 = true;
#else
		wsdd->enable_ipv6 = false;
#endif
	} else {
		/* bind to listed interfaces only */
		nifaces = iface_list_count(wsdd->ifaces);
		wsdd->ipaddrs = talloc_zero_array(wsdd, char *, nifaces+1);
		if (wsdd->ipaddrs == NULL) {
			task_server_terminate(task,
					      "wsdd task init: out of memory",
					      true);
			return NT_STATUS_NO_MEMORY;
		}

		for (i=0; i < nifaces; i++) {
			const char *ip = iface_list_n_ip(wsdd->ifaces, i);
			wsdd->ipaddrs[i] = talloc_strdup(wsdd, ip);
		}

		wsdd->enable_ipv4 = iface_list_first_v4(wsdd->ifaces)!=NULL;
#ifdef HAVE_IPV6
		wsdd->enable_ipv6 = iface_list_first_v6(wsdd->ifaces)!=NULL;
#else
		wsdd->enable_ipv6 = false;
#endif
	}

	if (CHECK_DEBUGLVL(5)) {
		DEBUG(5, ("intefaces wsdd service will be listening on:\n"));
		DEBUGADD(5, ("[IPv4 is %s]\n",
			 wsdd->enable_ipv4?"enabled":"disabled"));
#ifdef HAVE_IPV6
		DEBUGADD(5, ("[IPv6 is %s]\n",
			 wsdd->enable_ipv6?"enabled":"disabled"));
#endif
		for (i=0; wsdd->ipaddrs[i]; i++) {
			DEBUGADD(5, ("%s\n", wsdd->ipaddrs[i]));
		}
	}

	/* launch all wsdd subservices */
	status = wsdd_startup_subservices(wsdd);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "failed to start up subservices",
				      true);
		return status;
	}

	/* register the service */
	irpc_add_name(task->msg_ctx, "wsdd_server");

	return NT_STATUS_OK;
}

/* called at smbd startup - register ourselves as a server service */
NTSTATUS server_service_wsdd_init(TALLOC_CTX *ctx)
{
	static const struct service_details details = {
		.inhibit_fork_on_accept = true,
		.inhibit_pre_fork = true,
		.task_init = wsdd_task_init,
		.post_fork = NULL
	};
    return register_server_service(ctx, "wsdd", &details);
}

