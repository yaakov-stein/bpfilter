#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# Hook definition for BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4.
# Cgroup-based connect(2) filter for IPv4. Only TCP and UDP (no ICMP).
# Traffic flows from namespace → host via cgroup-enrolled connect(2).

HOOK_STR="BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4"

CGROUP_PATH="/sys/fs/cgroup/bftest_${_TEST_NAME}"

hook_opts() { echo "cgpath=${CGROUP_PATH}"; }

hook_extra_setup() {
    mkdir -p "${CGROUP_PATH}"
}

hook_extra_teardown() {
    rmdir "${CGROUP_PATH}" 2>/dev/null
}

hook_set_traffic_vars() {
    TRAFFIC_SRC_IP="${NS_IP_ADDR}"
    TRAFFIC_DST_IP="${HOST_IP_ADDR}"
    MATCH_PORT=9990
    TRAFFIC_L3_PROTO="ipv4"
    TRAFFIC_L3_PROTO_NOT="ipv6"
}

hook_send_tcp4() {
    ${FROM_NS} bash -c "echo \$\$ > ${CGROUP_PATH}/cgroup.procs && echo > /dev/tcp/${HOST_IP_ADDR}/${MATCH_PORT}" 2>/dev/null
}

hook_send_udp4() {
    ${FROM_NS} bash -c "echo \$\$ > ${CGROUP_PATH}/cgroup.procs && echo > /dev/udp/${HOST_IP_ADDR}/${MATCH_PORT}" 2>/dev/null
}
