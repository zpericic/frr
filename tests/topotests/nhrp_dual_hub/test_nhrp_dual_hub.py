#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_nhrp_dual_hub.py
#
# Copyright 2026
#
# Test Cisco-style dual-hub single-cloud DMVPN:
#   Hub2 uses nhs to Hub1 (asymmetric).
#   Spokes register with both hubs independently.
#   Verifies hop_count=255 allows hub-to-hub registration forwarding.

import os
import sys
import json
from functools import partial
import pytest
import re

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    required_linux_kernel_version,
    shutdown_bringup_interface,
    retry,
)

"""
test_nhrp_dual_hub.py: Test Cisco-style dual-hub single-cloud DMVPN

+------------+                  +------------+
|            |                  |            |
|   Hub 1    |                  |   Hub 2    |
| (pure hub) |                  |  (nhs to   |
|            |                  |   hub1)    |
+-----+------+                  +-----+------+
      |.1                             |.2
      |          192.168.1.0/24       |
------+-------------------------------+-----------+------
                                                  |
                                                  |.6
                                            +-----+------+
                                            |   Router   |
                                            +-----+------+
                                                  |
               -----------------------------------+------+------
                          192.168.2.0/24          |      |
                                                  |.4    |.5
                                            +-----+--+  +--+-----+
         +------+                           |  NHC 1  |  |  NHC 2 |
         | Host |--10.4.4.0/24--nhc1-eth1   |         |  |        +--10.5.5.0/24
         +------+.7                         +---------+  +--------+
"""

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.nhrpd]


def build_topo(tgen):
    for rname in ["hub1", "hub2", "nhc1", "nhc2", "router", "host"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["hub1"])
    switch.add_link(tgen.gears["hub2"])
    switch.add_link(tgen.gears["router"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["nhc1"])
    switch.add_link(tgen.gears["nhc2"])
    switch.add_link(tgen.gears["router"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["nhc1"])
    switch.add_link(tgen.gears["host"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["nhc2"])


def _populate_iface():
    tgen = get_topogen()
    cmds_hub = [
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 192.168.1.{1} remote 0.0.0.0",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
        "iptables -A FORWARD -i {0}-gre0 -o {0}-gre0"
        " -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1"
        " --hashlimit-mode srcip,dstip --hashlimit-srcmask 24"
        " --hashlimit-dstmask 24 --hashlimit-name loglimit-0"
        " -j NFLOG --nflog-group 1 --nflog-size 128",
    ]

    cmds_spoke = [
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 192.168.2.{1} remote 0.0.0.0",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
    ]

    for cmd in cmds_hub:
        for name, idx in [("hub1", "1"), ("hub2", "2")]:
            output = tgen.net[name].cmd(cmd.format(name, idx))
            logger.info("cmd: %s -> %s", cmd.format(name, idx), output)

    for cmd in cmds_spoke:
        for name, idx in [("nhc1", "4"), ("nhc2", "5")]:
            output = tgen.net[name].cmd(cmd.format(name, idx))
            logger.info("cmd: %s -> %s", cmd.format(name, idx), output)


def _verify_iptables():
    tgen = get_topogen()
    rc, _, _ = tgen.net["hub1"].cmd_status("iptables -V")
    return rc == 0


def ping_test(source_router, target_ip, count=1000, description=""):
    tgen = get_topogen()
    logger.info(
        "Ping %s -> %s %s", source_router.name, target_ip, description
    )
    output = source_router.run("ping {} -f -c {}".format(target_ip, count))
    logger.info(output)
    match = re.search(
        r"(\d+) packets transmitted, (\d+) received(?:, \+\d+ errors)?, ([\d.]+)% packet loss",
        output,
    )
    if not match:
        assert 0, "Could not parse ping output"
    loss_pct = float(match.group(3))
    if loss_pct > 90:
        assert 0, "Ping loss {}% > 90%".format(loss_pct)
    return True


def _wait_convergence():
    """Wait for full NHRP cache convergence on all hubs and spokes."""
    tgen = get_topogen()
    for rname in ["hub1", "hub2", "nhc1", "nhc2"]:
        router = tgen.gears[rname]
        json_file = "{}/{}/nhrp_cache.json".format(CWD, rname)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip nhrp cache json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
        assert result is None, '"{}" NHRP cache did not converge'.format(rname)


def setup_module(mod):
    result = required_linux_kernel_version("4.18")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _populate_iface()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Verify NHRP cache and routes converge on all hubs and spokes.
    Hub1 should have hub2 as dynamic (from hub2's registration).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking NHRP cache convergence")
    for rname in ["hub1", "hub2", "nhc1", "nhc2"]:
        router = tgen.gears[rname]
        json_file = "{}/{}/nhrp_cache.json".format(CWD, rname)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip nhrp cache json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip nhrp cache")
        logger.info(output)

        if result is not None:
            log = router.net.cmd_raises(
                "cat /tmp/{}/var/log/frr/frr.log 2>/dev/null | tail -100 || true".format(rname)
            )
            logger.info("Last 100 log lines on %s:\n%s", rname, log)
        assertmsg = '"{}" NHRP cache mismatch'.format(rname)
        assert result is None, assertmsg

    logger.info("Checking NHRP route convergence")
    for rname in ["hub1", "hub2", "nhc1", "nhc2"]:
        router = tgen.gears[rname]
        json_file = "{}/{}/nhrp_route.json".format(CWD, rname)
        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip route nhrp json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip route nhrp")
        logger.info(output)

        assertmsg = '"{}" NHRP route mismatch'.format(rname)
        assert result is None, assertmsg

    # Ping connectivity
    hub1 = tgen.gears["hub1"]
    ping_test(hub1, "172.16.1.4", 1000, "nhc1")
    ping_test(hub1, "172.16.1.5", 1000, "nhc2")

    nhc1 = tgen.gears["nhc1"]
    ping_test(nhc1, "172.16.1.1", 1000, "hub1")
    ping_test(nhc1, "172.16.1.2", 1000, "hub2")


def test_no_hop_count_errors():
    """
    Verify no 'hop count exceeded' errors in nhrpd logs.
    This was the original bug with hop_count=1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["hub1", "hub2", "nhc1", "nhc2"]:
        router = tgen.gears[rname]
        log = router.net.cmd_raises(
            "grep -c 'hop count exceeded' /tmp/{}/var/log/frr/frr.log || true".format(
                rname
            )
        ).strip()
        count = int(log) if log.isdigit() else 0
        assertmsg = '"{}" has {} hop count exceeded errors'.format(rname, count)
        assert count == 0, assertmsg


def test_static_map_override():
    """
    Add a static map on hub2 for hub1 and verify the cache entry
    changes from 'nhs' to 'static'. This is the Cisco-style pattern
    where both map + nhs are used together.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    hub2 = tgen.gears["hub2"]

    hub2.vtysh_cmd(
        "configure terminal\n"
        "interface hub2-gre0\n"
        "ip nhrp map 172.16.1.1 192.168.1.1\n"
        "end"
    )

    expected = {
        "table": [
            {
                "interface": "hub2-gre0",
                "type": "static",
                "protocol": "172.16.1.1",
                "nbma": "192.168.1.1",
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        hub2,
        "show ip nhrp cache json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assertmsg = '"hub2" static map cache entry not found'
    assert result is None, assertmsg

    # Remove it so subsequent tests run with nhs-only
    hub2.vtysh_cmd(
        "configure terminal\n"
        "interface hub2-gre0\n"
        "no ip nhrp map 172.16.1.1 192.168.1.1\n"
        "end"
    )


def test_cross_hub_shortcut():
    """
    Each spoke can only reach one hub (no prior spoke-to-spoke state):
      nhc1 -> hub1 only
      nhc2 -> hub2 only

    Trigger traffic host(behind nhc1) -> nhc2 LAN.
    Transit path: host -> nhc1 -> hub1 -> hub2 -> nhc2
    Hub1 sends redirect to nhc1, nhc1 sends resolution request to hub1,
    hub1 forwards resolution to hub2 (or resolves from its own cache),
    reply comes back, nhc1 creates spoke-to-spoke shortcut to nhc2.

    This is the definitive test: spoke-to-spoke shortcut established
    through cross-hub NHRP forwarding, with no prior shortcut state.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if not _verify_iptables():
        pytest.skip("iptables not installed")

    nhc1 = tgen.gears["nhc1"]
    nhc2 = tgen.gears["nhc2"]

    # Ensure no shortcuts exist from prior tests
    expected_no_shortcuts = {"attr": {"entriesCount": 0}}
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip nhrp shortcut json",
        expected_no_shortcuts,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assertmsg = '"nhc1" has residual shortcuts before cross-hub test'
    assert result is None, assertmsg

    # nhc1: remove nhs for hub2 — can only reach hub1
    logger.info("Restricting nhc1 to hub1 only, nhc2 to hub2 only")
    nhc1.vtysh_cmd(
        "configure terminal\n"
        "interface nhc1-gre0\n"
        "no ip nhrp nhs dynamic nbma 192.168.1.2\n"
        "end"
    )

    # nhc2: remove nhs for hub1 — can only reach hub2
    nhc2.vtysh_cmd(
        "configure terminal\n"
        "interface nhc2-gre0\n"
        "no ip nhrp nhs dynamic nbma 192.168.1.1\n"
        "end"
    )

    # Wait for caches to settle — each spoke should have only one NHS
    for rname, hub_proto in [("nhc1", "172.16.1.1"), ("nhc2", "172.16.1.2")]:
        router = tgen.gears[rname]
        expected = {
            "table": [
                {
                    "interface": "{}-gre0".format(rname),
                    "type": "local",
                },
                {
                    "interface": "{}-gre0".format(rname),
                    "type": "nhs",
                    "protocol": hub_proto,
                },
            ]
        }
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip nhrp cache json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip nhrp cache")
        logger.info("Cache on %s (single hub):\n%s", rname, output)
        assertmsg = '"{}" did not settle to single NHS'.format(rname)
        assert result is None, assertmsg

    # Trigger traffic: host -> nhc1 -> hub1 -> hub2 -> nhc2
    host = tgen.gears["host"]
    ping_test(host, "10.5.5.5", 1000, "cross-hub: host->nhc1->hub1->hub2->nhc2")

    # Verify spoke-to-spoke shortcut was created on nhc1.
    # This proves nhc1 resolved nhc2's NBMA address through the
    # cross-hub NHRP forwarding chain (no prior shortcut existed).
    json_file = "{}/{}/nhrp_shortcut_present.json".format(CWD, "nhc1")
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, nhc1, "show ip nhrp shortcut json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

    output = nhc1.vtysh_cmd("show ip nhrp shortcut")
    logger.info("Shortcut on nhc1 (cross-hub):\n%s", output)
    assertmsg = '"nhc1" no spoke-to-spoke shortcut via cross-hub forwarding'
    assert result is None, assertmsg

    # Verify no hop count exceeded errors
    for rname in ["hub1", "hub2", "nhc1", "nhc2"]:
        router = tgen.gears[rname]
        log = router.net.cmd_raises(
            "grep -c 'hop count exceeded' /tmp/{}/var/log/frr/frr.log || true".format(
                rname
            )
        ).strip()
        count = int(log) if log.isdigit() else 0
        assertmsg = '"{}" has {} hop count exceeded errors'.format(rname, count)
        assert count == 0, assertmsg

    # Restore NHS entries for subsequent tests
    logger.info("Restoring NHS entries")
    nhc1.vtysh_cmd(
        "configure terminal\n"
        "interface nhc1-gre0\n"
        "ip nhrp nhs dynamic nbma 192.168.1.2\n"
        "end"
    )
    nhc2.vtysh_cmd(
        "configure terminal\n"
        "interface nhc2-gre0\n"
        "ip nhrp nhs dynamic nbma 192.168.1.1\n"
        "end"
    )


def test_hub1_down_spoke_failover():
    """
    Bring down hub1. Verify spokes failover to hub2 and connectivity works.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if not _verify_iptables():
        pytest.skip("iptables not installed")

    logger.info("Bringing down hub1-gre0")
    shutdown_bringup_interface(tgen, "hub1", "hub1-gre0", False)

    # Verify spokes lose hub1 from cache
    for rname in ["nhc1", "nhc2"]:
        router = tgen.gears[rname]
        expected = {
            "table": [
                {
                    "interface": "{}-gre0".format(rname),
                    "type": "local",
                },
                {
                    "interface": "{}-gre0".format(rname),
                    "type": "nhs",
                    "protocol": "172.16.1.2",
                    "nbma": "192.168.1.2",
                },
            ]
        }
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip nhrp cache json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip nhrp cache")
        logger.info("Cache on %s after hub1 down:\n%s", rname, output)
        assertmsg = '"{}" still has hub1 in cache'.format(rname)
        assert result is None, assertmsg

    # Verify hub2 still has spoke registrations
    hub2 = tgen.gears["hub2"]
    expected = {
        "table": [
            {
                "interface": "hub2-gre0",
                "type": "dynamic",
                "protocol": "172.16.1.4",
            },
            {
                "interface": "hub2-gre0",
                "type": "dynamic",
                "protocol": "172.16.1.5",
            },
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        hub2,
        "show ip nhrp cache json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assertmsg = '"hub2" lost spoke registrations'
    assert result is None, assertmsg

    # Wait for hub1's NHRP route to be withdrawn
    nhc1 = tgen.gears["nhc1"]
    expected_no_hub1_route = {"172.16.1.1/32": None}
    test_func = partial(
        topotest.router_json_cmp,
        nhc1,
        "show ip route nhrp json",
        expected_no_hub1_route,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assertmsg = '"nhc1" still has hub1 NHRP route'
    assert result is None, assertmsg

    # Verify connectivity via hub2
    host = tgen.gears["host"]
    ping_test(host, "10.5.5.5", 1000, "via hub2 after hub1 down")


def test_purge_on_clear():
    """
    Clear cache on nhc1, verify Purge-Request sent to NHS,
    hub sees it, and nhc1 re-registers.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Bring hub1 back up if down from previous test
    shutdown_bringup_interface(tgen, "hub1", "hub1-gre0", True)

    nhc1 = tgen.gears["nhc1"]
    hub1 = tgen.gears["hub1"]

    # Wait for nhc1 registered on hub1
    expected_nhc1 = {
        "table": [
            {
                "interface": "hub1-gre0",
                "type": "dynamic",
                "protocol": "172.16.1.4",
            },
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        hub1,
        "show ip nhrp cache json",
        expected_nhc1,
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assertmsg = '"hub1" does not have nhc1 registered before purge test'
    assert result is None, assertmsg

    logger.info("Clearing NHRP cache on nhc1")
    nhc1.vtysh_cmd("clear ip nhrp cache")

    # Verify hub1 logs show Purge-Request received
    def check_purge_log(router, rname):
        log = router.net.cmd_raises(
            "grep -c 'Purge-Request' /tmp/{}/var/log/frr/frr.log || true".format(
                rname
            )
        ).strip()
        count = int(log) if log.isdigit() else 0
        if count > 0:
            return None
        return "no Purge-Request in log"

    _, result = topotest.run_and_expect(
        partial(check_purge_log, hub1, "hub1"), None, count=20, wait=0.5
    )
    assertmsg = '"hub1" did not receive Purge-Request from nhc1'
    assert result is None, assertmsg

    # Verify nhc1 re-registers with hub1
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assertmsg = '"hub1" nhc1 did not re-register after cache clear'
    assert result is None, assertmsg


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
