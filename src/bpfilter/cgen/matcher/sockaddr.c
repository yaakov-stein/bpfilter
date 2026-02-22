/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/sockaddr.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "cgen/jmp.h"
#include "cgen/program.h"
#include "cgen/runtime.h"
#include "filter.h"

#define _bf_make32(a, b, c, d)                                                 \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) |    \
     (uint32_t)(d))

static int _bf_matcher_generate_sockaddr_ip4(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    uint32_t *addr = (uint32_t *)bf_matcher_payload(matcher);

    // Load bpf_sock_addr* from runtime context
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10,
                              BF_PROG_CTX_OFF(arg)));

    // Load user_ip4 (network byte order)
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct bpf_sock_addr, user_ip4)));
    EMIT(program, BPF_MOV32_IMM(BPF_REG_3, *addr));

    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_REG(bf_matcher_get_op(matcher) == BF_MATCHER_EQ ? BPF_JNE :
                                                                  BPF_JEQ,
                    BPF_REG_2, BPF_REG_3, 0));

    return 0;
}

static int _bf_matcher_generate_sockaddr_ip6(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    struct bf_jmpctx j0, j1;
    uint8_t *addr = (uint8_t *)bf_matcher_payload(matcher);
    size_t offset = offsetof(struct bpf_sock_addr, user_ip6);

    // Load bpf_sock_addr* from runtime context
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10,
                              BF_PROG_CTX_OFF(arg)));

    // Load user_ip6 as two 64-bit values
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, offset));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offset + 8));

    if (bf_matcher_get_op(matcher) == BF_MATCHER_EQ) {
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr[7], addr[6],
                                                          addr[5], addr[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr[3], addr[2],
                                                          addr[1], addr[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 0));

        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr[15], addr[14],
                                                          addr[13], addr[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr[11], addr[10],
                                                          addr[9], addr[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));
    } else {
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr[7], addr[6],
                                                          addr[5], addr[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr[3], addr[2],
                                                          addr[1], addr[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));

        j0 = bf_jmpctx_get(program,
                           BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 0));

        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr[15], addr[14],
                                                          addr[13], addr[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr[11], addr[10],
                                                          addr[9], addr[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));

        j1 = bf_jmpctx_get(program,
                           BPF_JMP_REG(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));

        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

        bf_jmpctx_cleanup(&j0);
        bf_jmpctx_cleanup(&j1);
    }

    return 0;
}

static int _bf_matcher_generate_sockaddr_port(struct bf_program *program,
                                               const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    uint16_t *port = (uint16_t *)bf_matcher_payload(matcher);

    // Load bpf_sock_addr* from runtime context
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10,
                              BF_PROG_CTX_OFF(arg)));

    // Load user_port (network byte order, stored as __u32)
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct bpf_sock_addr, user_port)));

    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_IMM(bf_matcher_get_op(matcher) == BF_MATCHER_EQ ? BPF_JNE :
                                                                  BPF_JEQ,
                    BPF_REG_2, *port, 0));

    return 0;
}

int bf_matcher_generate_sockaddr(struct bf_program *program,
                                 const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    int r;

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_SOCKADDR_IP4:
        r = _bf_matcher_generate_sockaddr_ip4(program, matcher);
        break;
    case BF_MATCHER_SOCKADDR_IP6:
        r = _bf_matcher_generate_sockaddr_ip6(program, matcher);
        break;
    case BF_MATCHER_SOCKADDR_PORT:
        r = _bf_matcher_generate_sockaddr_port(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    };

    if (r)
        return r;

    return 0;
}
