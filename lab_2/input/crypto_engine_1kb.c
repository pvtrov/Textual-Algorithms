// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Handle async block request by crypto hardware engine.
 *
 * Copyright (C) 2016 Linaro, Inc.
 *
 * Author: Baolin Wang <baolin.wang@linaro.org>
 */

#include <linux/err.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <crypto/engine.h>
#include <uapi/linux/sched/types.h>
#include "internal.h"

#define CRYPTO_ENGINE_MAX_QLEN 10

/**
 * crypto_finalize_request - finalize one request if the request is done
 * @engine: the hardware engine
 * @req: the request need to be finalized
 * @err: error number
 */
static void crypto_finalize_request(struct crypto_engine *engine,
				    struct crypto_async_request *req, int err)
{
	unsigned long flags;
	bool finalize_req = false;
	int ret;
	struct crypto_engine_ctx *enginectx;

	/*
	 * If hardware cannot enqueue more requests
	 * and retry mechanism is not supported
	 * make sure we are completing the current request
	 */
	if (!engine->retry_support) {
		spin_lock_irqsave(&engine->queue_lock, flags);
		if (en