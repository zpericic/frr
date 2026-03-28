// SPDX-License-Identifier: GPL-2.0-or-later

#include "sockunion.h"
#include "prefix.h"

int os_socket(void);
int os_sendmsg(const uint8_t *buf, size_t len, int ifindex, const uint8_t *addr,
	       size_t addrlen, uint16_t protocol);
int os_recvmsg(uint8_t *buf, size_t *len, int *ifindex, uint8_t *addr,
	       size_t *addrlen);
int os_configure_dmvpn(unsigned int ifindex, const char *ifname, int af);
int os_route_socket(void);
void os_route_socket_close(void);
int os_route_encap_update(int add, int ifindex, const struct prefix *p,
			  const union sockunion *nbma, uint32_t grekey);
