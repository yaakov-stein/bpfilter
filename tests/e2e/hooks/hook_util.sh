#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# Shared utilities for hook tests. Sourced by driver.sh after e2e_test_util.sh.

MATCHERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/matchers" && pwd)"

_PASS=0
_FAIL=0
_SKIP=0

log_pass() { echo "  PASS  $1"; _PASS=$((_PASS + 1)); }
log_fail() { echo "  FAIL  $1: $2"; _FAIL=$((_FAIL + 1)); }
log_skip() { echo "  SKIP  $1"; _SKIP=$((_SKIP + 1)); }

# Check if hook provides a given traffic primitive.
hook_has() { type -t "hook_send_$1" &>/dev/null; }

# Get the packet counter from the first rule of a chain.
# Usage: get_counter <chain_name>
get_counter() {
    ${FROM_NS} bfcli chain get --name "$1" | awk '/^ *counters [0-9]/{print $2; exit}'
}
