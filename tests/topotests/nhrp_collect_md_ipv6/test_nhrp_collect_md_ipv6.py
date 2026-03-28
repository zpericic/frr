#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_nhrp_collect_md_ipv6.py: Test NHRP with collect_md over IPv6 underlay.

IPv4 overlay (10.255.255.x/32) over IPv6 underlay (fd00:x:x::/64).
All tunnels use 'ip link add type ip6gre external' with 'ip nhrp collect-md'.
This is the primary use case for collect_md — IPv6 NBMA addresses don't fit
in the kernel's 8-byte neighbor entry on traditional GRE.
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

    # Hub: ip6gre external + NFLOG
    cmds_hub = [
        "ip link add {0}-gre0 type ip6gre external",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "iptables -A FORWARD -i {0}-gre0 -o {0}-gre0"
        " -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1"
        " --hashlimit-mode srcip,dstip --hashlimit-srcmask 24"
        " --hashlimit-dstmask 24 --hashlimit-name loglimit-0"
        " -j NFLOG --nflog-group 1 --nflog-range 128",
    ]

    # Spokes: ip6gre external
    cmds_spoke = [
        "ip link add {0}-gre0 type ip6gre external",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
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
    logger.info("NHRP collect_md IPv6 underlay Topology")
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

    logger.info("Launching NHRP (collect_md IPv6)")
    for name in tgen.routers():
        tgen.gears[name].start()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_protocols_convergence():
    """Assert that NHRP cache populates with IPv6 NBMA addresses."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking NHRP cache convergence (IPv6 underlay)")

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
            logger.info("{}: show run:\n{}".format(
                rname, router.vtysh_cmd("show run")))
            logger.info("{}: ip -d link show {}-gre0:\n{}".format(
                rname, rname, router.run(
                    "ip -d link show {}-gre0".format(rname))))
            logger.info("{}: show interface {}-gre0:\n{}".format(
                rname, rname, router.vtysh_cmd(
                    "show interface {}-gre0".format(rname))))
            logger.info("{}: ip route show proto 191:\n{}".format(
                rname, router.run("ip route show proto 191")))
            logger.info("{}: ping6 hub underlay:\n{}".format(
                rname, router.run("ping6 -c2 -W1 fd00:2:1::2")))
            logger.info("{}: nhrpd.log (last 80 lines):\n{}".format(
                rname, router.run(
                    "tail -80 nhrpd.log 2>/dev/null || echo 'no log'")))
            hub = tgen.gears["r2"]
            logger.info("r2: nhrpd.log (last 40 lines):\n{}".format(
                hub.run("tail -40 nhrpd.log 2>/dev/null || echo 'no log'")))
            logger.info("r2: show ip nhrp cache:\n{}".format(
                hub.vtysh_cmd("show ip nhrp cache")))

        assertmsg = '"{}" NHRP cache mismatch'.format(rname)
        assert result is None, assertmsg


def test_encap_routes():
    """Verify LWT encap routes use LWTUNNEL_ENCAP_IP6."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking IPv6 encap routes (proto 191)")

    def _check_encap_route(router, dst, nbma):
        output = router.run("ip route show proto 191")
        logger.info("{}: proto 191:\n{}".format(router.name, output))
        if dst not in output:
            return "{}: missing route for {}".format(router.name, dst)
        if "encap ip6" not in output or nbma not in output:
            return "{}: missing encap ip6 for {} -> {}".format(
                router.name, dst, nbma)
        return None

    # R1 -> hub
    test_func = partial(
        _check_encap_route, tgen.gears["r1"], "10.255.255.2", "fd00:2:1::2"
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assert result is None, result

    # R2 -> spoke R1
    test_func = partial(
        _check_encap_route, tgen.gears["r2"], "10.255.255.1", "fd00:1:1::1"
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assert result is None, result


def test_nhrp_connection():
    """Assert spoke-to-hub ping over IPv6 underlay."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = tgen.gears["r1"].run("ping 10.255.255.2 -f -c 100")
    logger.info(output)
    assert " 0% packet loss" in output, "R1->R2 ping failed"


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
