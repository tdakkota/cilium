/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __EPT_H_
#define __EPT_H_

#include <bpf/ctx/ctx.h>

#include "common.h"
#include "time.h"
#include "maps.h"

/* From XDP layer, we neither go through an egress hook nor qdisc
 * from here, hence nothing to be set.
 */
#if defined(ENABLE_PRIORITY_MANAGER) && __ctx_is == __ctx_skb
static __always_inline void ept_set_aggregate(struct __ctx_buff *ctx,
					      __u32 aggregate)
{
	/* 16 bit as current used aggregate, and preserved in host ns. */
	ctx->queue_mapping = aggregate;
}

static __always_inline __u32 ept_get_aggregate(struct __ctx_buff *ctx)
{
	__u32 aggregate = ctx->queue_mapping;
	return aggregate;
}

static __always_inline int ept_set_priority(struct __ctx_buff *ctx)
{
	struct ept_id aggregate;
    struct ept_info *info;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;
	if (proto != bpf_htons(ETH_P_IP) &&
	    proto != bpf_htons(ETH_P_IPV6))
		return CTX_ACT_OK;

	aggregate.id = ept_get_aggregate(ctx);
	if (!aggregate.id)
		return CTX_ACT_OK;

	info = map_lookup_elem(&PRIORITY_MAP, &aggregate);
	if (!info)
		return CTX_ACT_OK;

	ctx->priority = info.priority;
	return CTX_ACT_OK;
}
#else
static __always_inline void
ept_set_aggregate(struct __ctx_buff *ctx __maybe_unused,
		  __u32 aggregate __maybe_unused)
{
}
#endif /* ENABLE_PRIORITY_MANAGER */
#endif /* __EPT_H_ */
