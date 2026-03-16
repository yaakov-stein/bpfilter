#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# Hook test driver. Runs all matcher definitions against a single hook.
#
# Usage: driver.sh <hook_file>
#
# The hook file must define:
#   HOOK_STR        — e.g. "BF_HOOK_TC_INGRESS"
#   hook_opts()     — returns hook options string (e.g. "ifindex=${NS_IFINDEX}")
#   hook_set_traffic_vars() — sets TRAFFIC_SRC_IP, TRAFFIC_DST_IP, MATCH_PORT, etc.
#   hook_send_*()   — traffic primitives (tcp4, udp4, icmp4, tcp6, udp6, icmp6)
#
# Optional:
#   hook_extra_setup()    — extra setup after make_sandbox (e.g. IPv6 addrs, cgroups)
#   hook_extra_teardown() — extra cleanup

HOOK_FILE="$1"
if [[ -z "${HOOK_FILE}" || ! -f "${HOOK_FILE}" ]]; then
    echo "Usage: $0 <hook_file>"
    exit 1
fi

# Set _TEST_NAME before sourcing e2e_test_util.sh so namespace/workdir
# names are derived from the hook, not from "driver".
_TEST_NAME=$(basename "${HOOK_FILE}" .sh)

. "$(dirname "$0")"/../e2e_test_util.sh
. "$(dirname "$0")"/hook_util.sh
. "${HOOK_FILE}"

CHAIN_NAME="hook_test"

make_sandbox
if type -t hook_extra_setup &>/dev/null; then
    hook_extra_setup
fi
if type -t hook_extra_teardown &>/dev/null; then
    trap 'ret=$?; hook_extra_teardown; cleanup; exit ${ret}' EXIT
fi
# Initialize all traffic vars so hooks only override what they support.
# Empty defaults prevent "unbound variable" errors from set -u when
# defs reference vars the hook doesn't provide (e.g. IPv4 vars on CONNECT6).
TRAFFIC_SRC_IP=""
TRAFFIC_DST_IP=""
TRAFFIC_SRC_IP6=""
TRAFFIC_DST_IP6=""
MATCH_IFACE=""
MATCH_PORT=""
TRAFFIC_L3_PROTO=""
TRAFFIC_L3_PROTO_NOT=""
hook_set_traffic_vars
start_bpfilter

# Build the full hook string once (handles hooks with no opts like NF).
_hook_opts_str=$(hook_opts)
if [[ -n "${_hook_opts_str}" ]]; then
    HOOK_FULL="${HOOK_STR}{${_hook_opts_str}}"
else
    HOOK_FULL="${HOOK_STR}"
fi

for def in "${MATCHERS_DIR}"/*.def; do
    [[ -f "$def" ]] || continue

    matcher_name=$(basename "$def" .def)

    # Reset per-matcher variables
    TRAFFIC=""
    MATCH_RULE=""
    NOMATCH_RULE=""

    # Unset optional callbacks from previous iteration
    unset -f matcher_pre_test 2>/dev/null || true
    unset -f matcher_post_test 2>/dev/null || true

    . "$def"

    # Evaluate rule fragments with traffic variables
    eval "MATCH_RULE=\"${MATCH_RULE}\""
    if [[ -n "${NOMATCH_RULE}" ]]; then
        eval "NOMATCH_RULE=\"${NOMATCH_RULE}\""
    fi

    # Dry-run probe: if matcher is unsupported on this hook, skip
    if ! bfcli ruleset set --dry-run --from-str "chain test ${HOOK_STR} ACCEPT rule ${MATCH_RULE} counter DROP" 2>/dev/null; then
        log_pass "${matcher_name} (unsupported)"
        continue
    fi

    # Select the first traffic type this hook can send.
    _traffic=""
    for _t in ${TRAFFIC}; do
        if hook_has "${_t}"; then
            _traffic="${_t}"
            break
        fi
    done
    if [[ -z "${_traffic}" ]]; then
        log_fail "${matcher_name}" "no traffic primitive from: ${TRAFFIC}"
        continue
    fi

    # Match test
    if type -t matcher_pre_test &>/dev/null; then
        matcher_pre_test
    fi

    ${FROM_NS} bfcli chain set --from-str "chain ${CHAIN_NAME} ${HOOK_FULL} ACCEPT rule ${MATCH_RULE} counter DROP"
    "hook_send_${_traffic}" || true
    counter=$(get_counter "${CHAIN_NAME}")
    if [[ "${counter}" -ge 1 ]]; then
        log_pass "${matcher_name}"
    else
        log_fail "${matcher_name}" "counter=${counter}, expected >=1"
    fi
    ${FROM_NS} bfcli ruleset flush

    # Nomatch test
    if [[ -n "${NOMATCH_RULE}" ]]; then
        ${FROM_NS} bfcli chain set --from-str "chain ${CHAIN_NAME} ${HOOK_FULL} ACCEPT rule ${NOMATCH_RULE} counter DROP"
        "hook_send_${_traffic}" || true
        counter=$(get_counter "${CHAIN_NAME}")
        if [[ "${counter}" -eq 0 ]]; then
            log_pass "${matcher_name} (nomatch)"
        else
            log_fail "${matcher_name} (nomatch)" "counter=${counter}, expected 0"
        fi
        ${FROM_NS} bfcli ruleset flush
    fi

    if type -t matcher_post_test &>/dev/null; then
        matcher_post_test
    fi
done

echo ""
echo "Results: ${_PASS} passed, ${_FAIL} failed"
exit ${_FAIL}
