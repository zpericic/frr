// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP daemon Linux specific glue
 * Copyright (c) 2014-2015 Timo Teräs
 */

#include "zebra.h"

#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
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
static int nhrp_gre_fd = -1;
static int nhrp_gre6_fd = -1;

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

/* GRE key flag (bit 2 in flags field) */
#define GRE_KEY_FLAG	0x2000

int os_gre_socket(void)
{
	int fd, on = 1;

	if (nhrp_gre_fd >= 0)
		return nhrp_gre_fd;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
	if (fd < 0) {
		zlog_err("os_gre_socket: socket(): %s", safe_strerror(errno));
		return -1;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
		zlog_err("os_gre_socket: IP_PKTINFO: %s", safe_strerror(errno));
		close(fd);
		return -1;
	}

	nhrp_gre_fd = fd;
	return fd;
}

void os_gre_socket_close(void)
{
	if (nhrp_gre_fd >= 0) {
		close(nhrp_gre_fd);
		nhrp_gre_fd = -1;
	}
	if (nhrp_gre6_fd >= 0) {
		close(nhrp_gre6_fd);
		nhrp_gre6_fd = -1;
	}
}

int os_gre6_socket(void)
{
	int fd, on = 1;

	if (nhrp_gre6_fd >= 0)
		return nhrp_gre6_fd;

	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_GRE);
	if (fd < 0) {
		zlog_err("os_gre6_socket: socket(): %s", safe_strerror(errno));
		return -1;
	}

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		       sizeof(on)) < 0) {
		zlog_err("os_gre6_socket: IPV6_RECVPKTINFO: %s",
			 safe_strerror(errno));
		close(fd);
		return -1;
	}

	nhrp_gre6_fd = fd;
	return fd;
}

static int os_gre_build_hdr(uint8_t *gre_hdr, uint32_t grekey)
{
	if (grekey) {
		uint16_t flags = htons(GRE_KEY_FLAG);
		uint16_t proto = htons(ETH_P_NHRP);
		uint32_t key = htonl(grekey);

		memcpy(gre_hdr, &flags, 2);
		memcpy(gre_hdr + 2, &proto, 2);
		memcpy(gre_hdr + 4, &key, 4);
		return 8;
	}

	uint16_t flags = 0;
	uint16_t proto = htons(ETH_P_NHRP);

	memcpy(gre_hdr, &flags, 2);
	memcpy(gre_hdr + 2, &proto, 2);
	return 4;
}

int os_gre_sendmsg(const uint8_t *buf, size_t len,
		   const union sockunion *src_nbma,
		   const union sockunion *dst_nbma,
		   uint32_t grekey)
{
	uint8_t gre_hdr[8];
	int gre_hdr_len;
	struct iovec iov[2];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int ret, fd;

	debugf(NHRP_DEBUG_KERNEL, "os_gre_sendmsg: %pSU -> %pSU key %u len %zu",
	       src_nbma, dst_nbma, grekey, len);

	gre_hdr_len = os_gre_build_hdr(gre_hdr, grekey);

	iov[0].iov_base = gre_hdr;
	iov[0].iov_len = gre_hdr_len;
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	if (sockunion_family(dst_nbma) == AF_INET) {
		struct sockaddr_in dst;
		uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];

		fd = nhrp_gre_fd;
		if (fd < 0)
			return -1;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = sockunion2ip(dst_nbma);
		msg.msg_name = &dst;
		msg.msg_namelen = sizeof(dst);

		if (sockunion_family(src_nbma) == AF_INET) {
			struct in_pktinfo *pktinfo;

			memset(cmsgbuf, 0, sizeof(cmsgbuf));
			msg.msg_control = cmsgbuf;
			msg.msg_controllen = sizeof(cmsgbuf);
			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = IPPROTO_IP;
			cmsg->cmsg_type = IP_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
			pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			pktinfo->ipi_spec_dst.s_addr = sockunion2ip(src_nbma);
		}

		ret = sendmsg(fd, &msg, 0);
	} else if (sockunion_family(dst_nbma) == AF_INET6) {
		struct sockaddr_in6 dst6;
		uint8_t cmsgbuf6[CMSG_SPACE(sizeof(struct in6_pktinfo))];

		fd = nhrp_gre6_fd;
		if (fd < 0)
			return -1;

		memset(&dst6, 0, sizeof(dst6));
		dst6.sin6_family = AF_INET6;
		dst6.sin6_addr = dst_nbma->sin6.sin6_addr;
		msg.msg_name = &dst6;
		msg.msg_namelen = sizeof(dst6);

		if (sockunion_family(src_nbma) == AF_INET6) {
			struct in6_pktinfo *pktinfo6;

			memset(cmsgbuf6, 0, sizeof(cmsgbuf6));
			msg.msg_control = cmsgbuf6;
			msg.msg_controllen = sizeof(cmsgbuf6);
			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = IPPROTO_IPV6;
			cmsg->cmsg_type = IPV6_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
			pktinfo6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			pktinfo6->ipi6_addr = src_nbma->sin6.sin6_addr;
		}

		ret = sendmsg(fd, &msg, 0);
	} else {
		return -1;
	}

	if (ret < 0) {
		debugf(NHRP_DEBUG_KERNEL, "os_gre_sendmsg: failed: %s",
		       safe_strerror(errno));
		return -errno;
	}

	return 0;
}

int os_gre_recvmsg(uint8_t *buf, size_t *len, union sockunion *src_nbma,
		   int *underlay_ifindex)
{
	uint8_t rxbuf[1600];
	struct iovec iov = { .iov_base = rxbuf, .iov_len = sizeof(rxbuf) };
	uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsgbuf,
		.msg_controllen = sizeof(cmsgbuf),
	};
	struct cmsghdr *cmsg;
	struct in_pktinfo *pktinfo;
	struct iphdr *iph;
	uint16_t gre_flags, gre_proto;
	int r, ip_hdr_len, gre_hdr_len, payload_off;

	r = recvmsg(nhrp_gre_fd, &msg, MSG_DONTWAIT);
	if (r < 0)
		return -1;

	/* Raw socket includes IP header */
	if (r < (int)sizeof(struct iphdr))
		return -1;

	iph = (struct iphdr *)rxbuf;
	ip_hdr_len = iph->ihl * 4;
	if (r < ip_hdr_len + 4)
		return -1;

	/* Parse GRE header */
	memcpy(&gre_flags, rxbuf + ip_hdr_len, 2);
	memcpy(&gre_proto, rxbuf + ip_hdr_len + 2, 2);
	gre_flags = ntohs(gre_flags);
	gre_proto = ntohs(gre_proto);

	if (gre_proto != ETH_P_NHRP)
		return -1;

	gre_hdr_len = 4;
	if (gre_flags & 0x2000) /* Key present */
		gre_hdr_len += 4;
	if (gre_flags & 0x8000) /* Checksum present */
		gre_hdr_len += 4;
	if (gre_flags & 0x1000) /* Sequence present */
		gre_hdr_len += 4;

	payload_off = ip_hdr_len + gre_hdr_len;
	if (r < payload_off)
		return -1;

	/* Copy NHRP payload */
	*len = r - payload_off;
	if (*len > 1500)
		*len = 1500;
	memcpy(buf, rxbuf + payload_off, *len);

	/* Source NBMA from IP header */
	sockunion_set(src_nbma, AF_INET,
		      (uint8_t *)&iph->saddr, sizeof(iph->saddr));

	/* Underlay ifindex from IP_PKTINFO */
	*underlay_ifindex = 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_PKTINFO) {
			pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			*underlay_ifindex = pktinfo->ipi_ifindex;
			break;
		}
	}

	return 0;
}

int os_gre6_recvmsg(uint8_t *buf, size_t *len, union sockunion *src_nbma,
		    int *underlay_ifindex)
{
	uint8_t rxbuf[1600];
	struct sockaddr_in6 src6;
	struct iovec iov = { .iov_base = rxbuf, .iov_len = sizeof(rxbuf) };
	uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct msghdr msg = {
		.msg_name = &src6,
		.msg_namelen = sizeof(src6),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsgbuf,
		.msg_controllen = sizeof(cmsgbuf),
	};
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pktinfo6;
	uint16_t gre_flags, gre_proto;
	int r, gre_hdr_len, payload_off;

	r = recvmsg(nhrp_gre6_fd, &msg, MSG_DONTWAIT);
	if (r < 0)
		return -1;

	/* IPv6 raw socket does NOT prepend IP header — data starts at GRE */
	if (r < 4)
		return -1;

	/* Parse GRE header */
	memcpy(&gre_flags, rxbuf, 2);
	memcpy(&gre_proto, rxbuf + 2, 2);
	gre_flags = ntohs(gre_flags);
	gre_proto = ntohs(gre_proto);

	if (gre_proto != ETH_P_NHRP)
		return -1;

	gre_hdr_len = 4;
	if (gre_flags & 0x2000) /* Key */
		gre_hdr_len += 4;
	if (gre_flags & 0x8000) /* Checksum */
		gre_hdr_len += 4;
	if (gre_flags & 0x1000) /* Sequence */
		gre_hdr_len += 4;

	payload_off = gre_hdr_len;
	if (r < payload_off)
		return -1;

	*len = r - payload_off;
	if (*len > 1500)
		*len = 1500;
	memcpy(buf, rxbuf + payload_off, *len);

	/* Source address from sockaddr */
	sockunion_set(src_nbma, AF_INET6,
		      (uint8_t *)&src6.sin6_addr, sizeof(src6.sin6_addr));

	/* Underlay ifindex from IPV6_PKTINFO */
	*underlay_ifindex = 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == IPV6_PKTINFO) {
			pktinfo6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			*underlay_ifindex = pktinfo6->ipi6_ifindex;
			break;
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
