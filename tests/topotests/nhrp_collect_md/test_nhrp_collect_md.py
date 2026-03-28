#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_nhrp_collect_md.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2024 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_nhrp_collect_md.py: Test NHRP with GRE collect_md (external) mode.

Uses LWT encap routes instead of neighbor entries. Same topology as nhrp_topo
but tunnels are created with 'ip link add type gre external' and nhrpd is
configured with 'ip nhrp collect-md'.
"""

import os
import sys
import json
from functools import partial
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

pytestmark = [pytest.mark.nhrpd]


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r4"])


def _populate_iface():
    tgen = get_topogen()

    # Hub: GRE external + NFLOG for redirect
    cmds_hub = [
        "ip link add {0}-gre0 type gre external",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
        "iptables -A FORWARD -i {0}-gre0 -o {0}-gre0"
        " -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1"
        " --hashlimit-mode srcip,dstip --hashlimit-srcmask 24"
        " --hashlimit-dstmask 24 --hashlimit-name loglimit-0"
        " -j NFLOG --nflog-group 1 --nflog-range 128",
    ]

    # Spokes: GRE external
    cmds_spoke = [
        "ip link add {0}-gre0 type gre external",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
    ]

    for cmd in cmds_hub:
        input = cmd.format("r2")
        logger.info("input: " + input)
        output = tgen.net["r2"].cmd(input)
        logger.info("output: " + output)

    for cmd in cmds_spoke:
        for rname in ("r1", "r4"):
            input = cmd.format(rname)
            logger.info("input: " + input)
            output = tgen.net[rname].cmd(input)
            logger.info("output: " + output)


def setup_module(mod):
    logger.info("NHRP collect_md Topology")
    result = required_linux_kernel_version("4.18")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _populate_iface()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
        )
        if rname in ("r1", "r2", "r4"):
            router.load_config(
                TopoRouter.RD_NHRP,
                os.path.join(CWD, "{}/nhrpd.conf".format(rname)),
            )

    logger.info("Launching NHRP (collect_md)")
    for name in tgen.routers():
        tgen.gears[name].start()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_protocols_convergence():
    """Assert that NHRP cache populates correctly in collect_md mode."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking NHRP cache convergence (collect_md)")

    for rname, router in tgen.routers().items():
        if rname == "r3":
            continue

        json_file = "{}/{}/nhrp4_cache.json".format(CWD, rname)
        if not os.path.isfile(json_file):
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip nhrp cache json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip nhrp cache")
        logger.info(output)

        if result is not None:
            logger.info("{}: show ip nhrp nhs:\n{}".format(
                rname, router.vtysh_cmd("show ip nhrp nhs")))
            logger.info("{}: ip route show proto 191:\n{}".format(
                rname, router.run("ip route show proto 191")))

        assertmsg = '"{}" NHRP cache mismatch'.format(rname)
        assert result is None, assertmsg

    # Check GRE interface flags
    for rname, router in tgen.routers().items():
        if rname == "r3":
            continue

        expected = {
            "{}-gre0".format(rname): {
                "flags": "<UP,LOWER_UP,RUNNING>",
            }
        }
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show interface {}-gre0 json".format(rname),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)

        assertmsg = '"{}-gre0" interface flags incorrect'.format(rname)
        assert result is None, assertmsg


def test_encap_routes():
    """Verify that NHRP installed LWT encap routes via RTPROT_NHRP (191)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking encap routes (proto 191)")

    def _check_encap_route(router, dst, nbma):
        """Check that 'ip route show proto 191' contains an encap route."""
        output = router.run("ip route show proto 191")
        logger.info("{}: ip route show proto 191:\n{}".format(router.name, output))
        if dst not in output:
            return "{}: missing route for {}".format(router.name, dst)
        if "encap ip" not in output or nbma not in output:
            return "{}: missing encap for {} -> {}".format(router.name, dst, nbma)
        return None

    # R1 should have encap route to hub (10.255.255.2 -> 10.2.1.2)
    test_func = partial(
        _check_encap_route, tgen.gears["r1"], "10.255.255.2", "10.2.1.2"
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assert result is None, result

    # R4 should have encap route to hub (10.255.255.2 -> 10.2.1.2)
    test_func = partial(
        _check_encap_route, tgen.gears["r4"], "10.255.255.2", "10.2.1.2"
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assert result is None, result

    # R2 (hub) should have encap routes to both spokes
    test_func = partial(
        _check_encap_route, tgen.gears["r2"], "10.255.255.1", "10.1.1.1"
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assert result is None, result

    test_func = partial(
        _check_encap_route, tgen.gears["r2"], "10.255.255.4", "10.1.1.4"
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assert result is None, result


def test_nhrp_connection():
    """Assert that spokes can reach the hub via collect_md encap routes."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing NHRP connectivity (collect_md)")

    # Spoke R1 -> Hub R2
    output = tgen.gears["r1"].run("ping 10.255.255.2 -f -c 100")
    logger.info(output)
    assert " 0% packet loss" in output, "R1->R2 ping failed: {}".format(output)

    # Spoke R4 -> Hub R2
    output = tgen.gears["r4"].run("ping 10.255.255.2 -f -c 100")
    logger.info(output)
    assert " 0% packet loss" in output, "R4->R2 ping failed: {}".format(output)


def test_no_neighbor_entries():
    """Verify no neighbor entries on GRE interfaces in collect_md mode."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking that no neighbor entries exist on GRE interfaces")

    for rname in ("r1", "r2", "r4"):
        router = tgen.gears[rname]
        output = router.run("ip neigh show dev {}-gre0".format(rname))
        logger.info("{}: ip neigh show dev {}-gre0: {}".format(rname, rname, output))
        # In collect_md mode, there should be no REACHABLE/STALE neighbor entries
        assert "REACHABLE" not in output, (
            "{}: unexpected REACHABLE neighbor on {}-gre0".format(rname, rname)
        )


def test_memory_leak():
    """Run the memory leak test."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
