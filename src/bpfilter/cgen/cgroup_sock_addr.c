/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgroup_sock_addr.h"

#include <linux/bpf_common.h>
#include <linux/if_ether.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/verdict.h>

#include "cgen/program.h"
#include "cgen/swich.h"
#include "filter.h"
#include "linux/bpf.h"

// Forward definition to avoid headers complications
uint16_t htons(uint16_t hostshort);

static int _bf_cgroup_sock_addr_gen_inline_prologue(struct bf_program *program)
{
    int r;

    assert(program);

    // pkt_size = 0: no packet data for sock_addr programs
    EMIT(program, BPF_ST_MEM(BPF_DW, BPF_REG_10, BF_PROG_CTX_OFF(pkt_size), 0));

    // ifindex = 0: no interface for sock_addr programs
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(ifindex), 0));

    /* Read bpf_sock_addr.family and convert to ethertype for R7.
     * Same pattern as BF_FLAVOR_CGROUP. */
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct bpf_sock_addr, family)));

    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_2);

        EMIT_SWICH_OPTION(&swich, AF_INET,
                          BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IP)));
        EMIT_SWICH_OPTION(&swich, AF_INET6,
                          BPF_MOV64_IMM(BPF_REG_7, htons(ETH_P_IPV6)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_7, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }

    // Read bpf_sock_addr.protocol into R8
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1,
                              offsetof(struct bpf_sock_addr, protocol)));

    return 0;
}

static int _bf_cgroup_sock_addr_gen_inline_epilogue(struct bf_program *program)
{
    (void)program;

    return 0;
}

static int _bf_cgroup_sock_addr_gen_inline_set_mark(struct bf_program *program,
                                                    uint32_t mark)
{
    (void)program;
    (void)mark;

    return -ENOTSUP;
}

static int _bf_cgroup_sock_addr_gen_inline_get_mark(struct bf_program *program,
                                                    int reg)
{
    (void)program;
    (void)reg;

    return -ENOTSUP;
}

static int _bf_cgroup_sock_addr_gen_inline_get_skb(struct bf_program *program,
                                                   int reg)
{
    (void)program;
    (void)reg;

    return -ENOTSUP;
}

/**
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @return Return code corresponding to the verdict, as an integer.
 */
static int _bf_cgroup_sock_addr_get_verdict(enum bf_verdict verdict)
{
    switch (verdict) {
    case BF_VERDICT_ACCEPT:
        return 1;
    case BF_VERDICT_DROP:
        return 0;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_cgroup_sock_addr = {
    .gen_inline_prologue = _bf_cgroup_sock_addr_gen_inline_prologue,
    .gen_inline_epilogue = _bf_cgroup_sock_addr_gen_inline_epilogue,
    .gen_inline_set_mark = _bf_cgroup_sock_addr_gen_inline_set_mark,
    .gen_inline_get_mark = _bf_cgroup_sock_addr_gen_inline_get_mark,
    .gen_inline_get_skb = _bf_cgroup_sock_addr_gen_inline_get_skb,
    .get_verdict = _bf_cgroup_sock_addr_get_verdict,
};
