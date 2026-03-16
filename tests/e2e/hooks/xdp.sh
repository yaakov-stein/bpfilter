#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# Hook definition for BF_HOOK_XDP.
# Traffic flows from host → namespace, filter is on the namespace's veth.

HOOK_STR="BF_HOOK_XDP"

HOST_IP6_ADDR="fd00::1"
NS_IP6_ADDR="fd00::2"

hook_opts() { echo "ifindex=${NS_IFINDEX}"; }

hook_extra_setup() {
    ip addr add "${HOST_IP6_ADDR}/64" dev "${VETH_HOST}" nodad
    ip netns exec "${NETNS_NAME}" ip addr add "${NS_IP6_ADDR}/64" dev "${VETH_NS}" nodad

    local ns_mac host_mac
    ns_mac=$(ip netns exec "${NETNS_NAME}" cat /sys/class/net/"${VETH_NS}"/address)
    host_mac=$(cat /sys/class/net/"${VETH_HOST}"/address)
    ip neigh add "${NS_IP6_ADDR}" lladdr "${ns_mac}" dev "${VETH_HOST}" nud permanent
    ip netns exec "${NETNS_NAME}" ip neigh add "${HOST_IP6_ADDR}" lladdr "${host_mac}" dev "${VETH_NS}" nud permanent
}

hook_set_traffic_vars() {
    TRAFFIC_SRC_IP="${HOST_IP_ADDR}"
    TRAFFIC_DST_IP="${NS_IP_ADDR}"
    TRAFFIC_SRC_IP6="${HOST_IP6_ADDR}"
    TRAFFIC_DST_IP6="${NS_IP6_ADDR}"
    MATCH_IFACE="${VETH_NS}"
    MATCH_PORT=9990
    TRAFFIC_L3_PROTO="ipv4"
    TRAFFIC_L3_PROTO_NOT="ipv6"
}

hook_send_icmp4()  { ping -c 1 -W 0.2 "${NS_IP_ADDR}"; }
hook_send_tcp4()   { timeout 0.05 bash -c "echo | nc -w1 ${NS_IP_ADDR} ${MATCH_PORT}" 2>/dev/null; }
hook_send_udp4()   { timeout 0.05 bash -c "echo | nc -u -w1 ${NS_IP_ADDR} ${MATCH_PORT}" 2>/dev/null; }
hook_send_icmp6()  { ping -6 -c 1 -W 0.2 "${NS_IP6_ADDR}"; }
hook_send_tcp6()   { timeout 0.05 bash -c "echo | nc -6 -w1 ${NS_IP6_ADDR} ${MATCH_PORT}" 2>/dev/null; }
hook_send_udp6()   { timeout 0.05 bash -c "echo | nc -6 -u -w1 ${NS_IP6_ADDR} ${MATCH_PORT}" 2>/dev/null; }
