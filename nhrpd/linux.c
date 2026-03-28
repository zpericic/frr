// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP daemon Linux specific glue
 * Copyright (c) 2014-2015 Timo Teräs
 */

#include "zebra.h"

#include <fcntl.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/lwtunnel.h>
#include <linux/rtnetlink.h>

#include "nhrpd.h"
#include "nhrp_protocol.h"
#include "os.h"
#include "znl.h"

#ifndef HAVE_STRLCPY
size_t strlcpy(char *__restrict dest,
	       const char *__restrict src, size_t destsize);
#endif

static int nhrp_socket_fd = -1;
static int nhrp_route_fd = -1;

int os_socket(void)
{
	if (nhrp_socket_fd < 0)
		nhrp_socket_fd =
			socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_NHRP));
	return nhrp_socket_fd;
}

int os_sendmsg(const uint8_t *buf, size_t len, int ifindex, const uint8_t *addr,
	       size_t addrlen, uint16_t protocol)
{
	struct sockaddr_ll lladdr;
	struct iovec iov = {
		.iov_base = (void *)buf, .iov_len = len,
	};
	struct msghdr msg = {
		.msg_name = &lladdr,
		.msg_namelen = sizeof(lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int status, fd;

	if (addrlen > sizeof(lladdr.sll_addr))
		return -1;

	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_protocol = htons(protocol);
	lladdr.sll_ifindex = ifindex;
	lladdr.sll_halen = addrlen;
	memcpy(lladdr.sll_addr, addr, addrlen);

	fd = os_socket();
	if (fd < 0)
		return -1;

	status = sendmsg(fd, &msg, 0);
	if (status < 0)
		return -errno;

	return status;
}

int os_recvmsg(uint8_t *buf, size_t *len, int *ifindex, uint8_t *addr,
	       size_t *addrlen)
{
	struct sockaddr_ll lladdr;
	struct iovec iov = {
		.iov_base = buf, .iov_len = *len,
	};
	struct msghdr msg = {
		.msg_name = &lladdr,
		.msg_namelen = sizeof(lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int r;

	r = recvmsg(nhrp_socket_fd, &msg, MSG_DONTWAIT);
	if (r < 0)
		return r;

	*len = r;
	*ifindex = lladdr.sll_ifindex;

	if (lladdr.sll_halen <= *addrlen) {
		if (memcmp(lladdr.sll_addr, "\x00\x00\x00\x00", 4) != 0) {
			memcpy(addr, lladdr.sll_addr, lladdr.sll_halen);
			*addrlen = lladdr.sll_halen;
		} else {
			*addrlen = 0;
		}
	}

	return 0;
}

static int linux_icmp_redirect_off(const char *iface)
{
	char fname[PATH_MAX];
	int fd, ret = -1;

	snprintf(fname, sizeof(fname),
		 "/proc/sys/net/ipv4/conf/%s/send_redirects", iface);
	fd = open(fname, O_WRONLY);
	if (fd < 0)
		return -1;
	if (write(fd, "0\n", 2) == 2)
		ret = 0;
	close(fd);

	return ret;
}

int os_configure_dmvpn(unsigned int ifindex, const char *ifname, int af)
{
	int ret = 0;

	switch (af) {
	case AF_INET:
		ret |= linux_icmp_redirect_off("all");
		ret |= linux_icmp_redirect_off(ifname);
		break;
	}

	return ret;
}

#define RTPROT_NHRP 191

int os_route_socket(void)
{
	if (nhrp_route_fd < 0)
		nhrp_route_fd = znl_open(NETLINK_ROUTE, 0);
	return nhrp_route_fd;
}

void os_route_socket_close(void)
{
	if (nhrp_route_fd >= 0) {
		close(nhrp_route_fd);
		nhrp_route_fd = -1;
	}
}

int os_route_encap_update(int add, int ifindex, const struct prefix *p,
			  const union sockunion *nbma, uint32_t grekey)
{
	uint8_t buf[ZNL_BUFFER_SIZE];
	struct zbuf zb;
	struct nlmsghdr *n;
	struct rtmsg *rtm;
	struct rtattr *encap_nest;
	uint16_t encap_type;
	int ret;

	if (nhrp_route_fd < 0)
		return -1;

	debugf(NHRP_DEBUG_KERNEL,
	       "os_route_encap: %s %pFX dev %d nbma %pSU key %u",
	       add ? "add" : "del", p, ifindex, nbma, grekey);

	zbuf_init(&zb, buf, sizeof(buf), 0);

	n = znl_nlmsg_push(&zb,
			   add ? RTM_NEWROUTE : RTM_DELROUTE,
			   NLM_F_REQUEST | (add ? NLM_F_CREATE | NLM_F_REPLACE : 0));
	if (!n)
		return -1;

	rtm = znl_push(&zb, sizeof(*rtm));
	if (!rtm)
		return -1;

	memset(rtm, 0, sizeof(*rtm));
	rtm->rtm_family = p->family;
	rtm->rtm_dst_len = p->prefixlen;
	rtm->rtm_protocol = RTPROT_NHRP;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;

	/* RTA_DST */
	if (p->family == AF_INET)
		znl_rta_push(&zb, RTA_DST, &p->u.prefix4,
			     sizeof(p->u.prefix4));
	else
		znl_rta_push(&zb, RTA_DST, &p->u.prefix6,
			     sizeof(p->u.prefix6));

	/* RTA_OIF */
	znl_rta_push_u32(&zb, RTA_OIF, ifindex);

	if (add && nbma) {
		/* RTA_ENCAP_TYPE */
		if (sockunion_family(nbma) == AF_INET)
			encap_type = LWTUNNEL_ENCAP_IP;
		else
			encap_type = LWTUNNEL_ENCAP_IP6;
		znl_rta_push(&zb, RTA_ENCAP_TYPE, &encap_type,
			     sizeof(encap_type));

		/* RTA_ENCAP (nested) */
		encap_nest = znl_rta_nested_push(&zb, RTA_ENCAP);
		if (!encap_nest)
			return -1;

		if (sockunion_family(nbma) == AF_INET) {
			znl_rta_push(&zb, LWTUNNEL_IP_DST,
				     sockunion_get_addr(nbma),
				     sizeof(struct in_addr));
			if (grekey) {
				uint64_t id = htobe64((uint64_t)grekey);

				znl_rta_push(&zb, LWTUNNEL_IP_ID,
					     &id, sizeof(id));
			}
		} else {
			znl_rta_push(&zb, LWTUNNEL_IP6_DST,
				     sockunion_get_addr(nbma),
				     sizeof(struct in6_addr));
			if (grekey) {
				uint64_t id = htobe64((uint64_t)grekey);

				znl_rta_push(&zb, LWTUNNEL_IP6_ID,
					     &id, sizeof(id));
			}
		}

		znl_rta_nested_complete(&zb, encap_nest);
	}

	znl_nlmsg_complete(&zb, n);

	ret = send(nhrp_route_fd, buf, n->nlmsg_len, 0);
	if (ret < 0) {
		debugf(NHRP_DEBUG_KERNEL,
		       "os_route_encap: %s %pFX failed: %s",
		       add ? "add" : "del", p, safe_strerror(errno));
		return -errno;
	}

	return 0;
}
