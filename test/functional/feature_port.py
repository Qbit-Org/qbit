#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test the -port option and its interactions with
-bind.
"""

import socket

from test_framework.test_node import (
    ErrorMatch,
)
from test_framework.test_framework import (
    BitcoinTestFramework,
)
from test_framework.netutil import (
    test_ipv6_local,
)
from test_framework.util import (
    p2p_port,
    rpc_port,
)

def ipv6_wildcard_is_dual_stack():
    if not test_ipv6_local() or not hasattr(socket, "IPV6_V6ONLY"):
        return False

    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.bind(("::", 0))
            return sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
    except OSError:
        return False


class PortTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        # Avoid any -bind= on the command line.
        self.bind_to_localhost_only = False
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        node.has_explicit_bind = True
        port1 = p2p_port(self.num_nodes)
        port2 = p2p_port(self.num_nodes + 5)
        collision_port = rpc_port(0) - 1
        collision_warning = (
            f"Skipping implicit onion bind on 127.0.0.1:{collision_port + 1} "
            "because it conflicts with an RPC bind on the same endpoint."
        )

        self.log.info("When starting with -port, bitcoind binds to it and uses port + 1 for an onion bind")
        with node.assert_debug_log(expected_msgs=[f'Bound to 0.0.0.0:{port1}', f'Bound to 127.0.0.1:{port1 + 1}']):
            self.restart_node(0, extra_args=["-listen", f"-port={port1}"])

        self.log.info("When specifying -port multiple times, only the last one is taken")
        with node.assert_debug_log(expected_msgs=[f'Bound to 0.0.0.0:{port2}', f'Bound to 127.0.0.1:{port2 + 1}'], unexpected_msgs=[f'Bound to 0.0.0.0:{port1}']):
            self.restart_node(0, extra_args=["-listen", f"-port={port1}", f"-port={port2}"])

        self.log.info("When specifying ports with both -port and -bind, the one from -port is ignored")
        with node.assert_debug_log(expected_msgs=[f'Bound to 0.0.0.0:{port2}'], unexpected_msgs=[f'Bound to 0.0.0.0:{port1}']):
            self.restart_node(0, extra_args=["-listen", f"-port={port1}", f"-bind=0.0.0.0:{port2}"])

        self.log.info("When -bind specifies no port, the values from -port and -bind are combined")
        with self.nodes[0].assert_debug_log(expected_msgs=[f'Bound to 0.0.0.0:{port1}']):
            self.restart_node(0, extra_args=["-listen", f"-port={port1}", "-bind=0.0.0.0"])

        self.log.info("When an onion bind specifies no port, the value from -port, incremented by 1, is taken")
        with self.nodes[0].assert_debug_log(expected_msgs=[f'Bound to 127.0.0.1:{port1 + 1}']):
            self.restart_node(0, extra_args=["-listen", f"-port={port1}", "-bind=127.0.0.1=onion"])

        self.log.info("When the implicit onion bind collides with an RPC bind, startup succeeds and the implicit bind is skipped")
        with node.assert_debug_log(
            expected_msgs=[f'Bound to 0.0.0.0:{collision_port}', collision_warning],
            unexpected_msgs=[f'Bound to 127.0.0.1:{collision_port + 1}'],
        ):
            self.restart_node(0, extra_args=["-listen", "-listenonion=0", f"-port={collision_port}"])

        self.log.info("When the onion bind is explicit, the collision remains fatal")
        self.stop_node(0, expected_stderr=f"Warning: {collision_warning}")
        with node.assert_debug_log(
            expected_msgs=[f'Unable to bind to 127.0.0.1:{collision_port + 1}', "Failed to listen on any port"],
            unexpected_msgs=[collision_warning],
        ):
            node.assert_start_raises_init_error(
                extra_args=["-listen", "-listenonion=0", f"-port={collision_port}", f"-bind=127.0.0.1:{collision_port + 1}=onion"],
                expected_msg="Failed to listen on any port",
                match=ErrorMatch.PARTIAL_REGEX,
            )

        original_rpchost = node.rpchost
        if test_ipv6_local():
            self.log.info("An IPv6-only RPC bind does not suppress the implicit IPv4 onion bind")
            node.rpchost = "[::1]"
            with node.assert_debug_log(
                expected_msgs=[f'Bound to 127.0.0.1:{collision_port + 1}'],
                unexpected_msgs=[collision_warning],
            ):
                self.start_node(0, extra_args=["-listen", "-listenonion=0", f"-port={collision_port}", "-rpcallowip=::1", "-rpcbind=[::1]"])
            # Stop over IPv6 explicitly so the CLI path does not fall back to 127.0.0.1.
            node.cli("-rpcconnect=::1").stop(wait=0)
            node.wait_until_stopped()
            node.rpchost = original_rpchost

        if ipv6_wildcard_is_dual_stack():
            self.log.info("A dual-stack IPv6 wildcard RPC bind suppresses the implicit IPv4 onion bind")
            node.rpchost = "[::1]"
            with node.assert_debug_log(
                expected_msgs=[collision_warning],
                unexpected_msgs=[f'Bound to 127.0.0.1:{collision_port + 1}'],
            ):
                self.start_node(0, extra_args=["-listen", "-listenonion=0", f"-port={collision_port}", "-rpcallowip=::1", "-rpcbind=[::]"])
            # Stop over IPv6 explicitly so the CLI path does not fall back to 127.0.0.1.
            node.cli("-rpcconnect=::1").stop(wait=0)
            node.wait_until_stopped(expected_stderr=f"Warning: {collision_warning}")
            node.rpchost = original_rpchost

        self.log.info("A wildcard IPv4 RPC bind suppresses the implicit IPv4 onion bind")
        with node.assert_debug_log(
            expected_msgs=[collision_warning],
            unexpected_msgs=[f'Bound to 127.0.0.1:{collision_port + 1}'],
        ):
            self.start_node(0, extra_args=["-listen", "-listenonion=0", f"-port={collision_port}", "-rpcallowip=127.0.0.1", "-rpcbind=0.0.0.0"])
        self.stop_node(0, expected_stderr=f"Warning: {collision_warning}")

        self.log.info("Invalid values for -port raise errors")
        node.assert_start_raises_init_error(extra_args=["-listen", "-port=65536"], expected_msg="Error: Invalid port specified in -port: '65536'")
        node.assert_start_raises_init_error(extra_args=["-listen", "-port=0"], expected_msg="Error: Invalid port specified in -port: '0'")


if __name__ == '__main__':
    PortTest(__file__).main()
