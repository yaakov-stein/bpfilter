#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# Hook definition for BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6.
# Cgroup-based connect(2) filter for IPv6. Only TCP and UDP (no ICMP).
# Traffic flows from namespace → host via cgroup-enrolled connect(2).
# Uses Python sockets because /dev/tcp does not support IPv6.

HOOK_STR="BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6"

HOST_IP6_ADDR="fd00::1"
NS_IP6_ADDR="fd00::2"

CGROUP_PATH="/sys/fs/cgroup/bftest_${_TEST_NAME}"

hook_opts() { echo "cgpath=${CGROUP_PATH}"; }

hook_extra_setup() {
    mkdir -p "${CGROUP_PATH}"
    ip addr add "${HOST_IP6_ADDR}/64" dev "${VETH_HOST}" nodad
    ip netns exec "${NETNS_NAME}" ip addr add "${NS_IP6_ADDR}/64" dev "${VETH_NS}" nodad
}

hook_extra_teardown() {
    rmdir "${CGROUP_PATH}" 2>/dev/null
}

hook_set_traffic_vars() {
    TRAFFIC_SRC_IP6="${NS_IP6_ADDR}"
    TRAFFIC_DST_IP6="${HOST_IP6_ADDR}"
    MATCH_PORT=9990
    TRAFFIC_L3_PROTO="ipv6"
    TRAFFIC_L3_PROTO_NOT="ipv4"
}

hook_send_tcp6() {
    ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(0.5)
s.connect(('${HOST_IP6_ADDR}', ${MATCH_PORT}))
s.close()
" 2>/dev/null
}

hook_send_udp6() {
    ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(0.5)
s.connect(('${HOST_IP6_ADDR}', ${MATCH_PORT}))
s.send(b'x')
s.close()
" 2>/dev/null
}
