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
		if (engine->cur_req == req) {
			finalize_req = true;
			engine->cur_req = NULL;
		}
		spin_unlock_irqrestore(&engine->queue_lock, flags);
	}

	if (finalize_req || engine->retry_support) {
		enginectx = crypto_tfm_ctx(req->tfm);
		if (enginectx->op.prepare_request &&
		    enginectx->op.unprepare_request) {
			ret = enginectx->op.unprepare_request(engine, req);
			if (ret)
				dev_err(engine->dev, "failed to unprepare request\n");
		}
	}
	lockdep_assert_in_softirq();
	crypto_request_complete(req, err);

	kthread_queue_work(engine->kworker, &engine->pump_requests);
}

/**
 * crypto_pump_requests - dequeue one request from engine queue to process
 * @engine: the hardware engine
 * @in_kthread: true if we are in the context of the request pump thread
 *
 * This function checks if there is any request in the engine queue that
 * needs processing and if so call out to the driver to initialize hardware
 * and handle each request.
 */
static void crypto_pump_requests(struct crypto_engine *engine,
				 bool in_kthread)
{
	struct crypto_async_request *async_req, *backlog;
	unsigned long flags;
	bool was_busy = false;
	int ret;
	struct crypto_engine_ctx *enginectx;

	spin_lock_irqsave(&engine->queue_lock, flags);

	/* Make sure we are not already running a request */
	if (!engine->retry_support && engine->cur_req)
		goto out;

	/* If another context is idling then defer */
	if (engine->idling) {
		kthread_queue_work(engine->kworker, &engine->pump_requests);
		goto out;
	}

	/* Check if the engine queue is idle */
	if (!crypto_queue_len(&engine->queue) || !engine->running) {
		if (!engine->busy)
			goto out;

		/* Only do teardown in the thread */
		if (!in_kthread) {
			kthread_queue_work(engine->kworker,
					   &engine->pump_requests);
			goto out;
		}

		engine->busy = false;
		engine->idling = true;
		spin_unlock_irqrestore(&engine->queue_lock, flags);

		if (engine->unprepare_crypt_hardware &&
		    engine->unprepare_crypt_hardware(engine))
			dev_err(engine->dev, "failed to unprepare crypt hardware\n");

		spin_lock_irqsave(&engine->queue_lock, flags);
		engine->idling = false;
		goto out;
	}

start_request:
	/* Get the fist request from the engine queue to handle */
	backlog = crypto_get_backlog(&engine->queue);
	async_req = crypto_dequeue_request(&engine->queue);
	if (!async_req)
		goto out;

	/*
	 * If hardware doesn't support the retry mechanism,
	 * keep track of the request we are processing now.
	 * We'll need it on completion (crypto_finalize_request).
	 */
	if (!engine->retry_support)
		engine->cur_req = async_req;

	if (backlog)
		crypto_request_complete(backlog, -EINPROGRESS);

	if (engine->busy)
		was_busy = true;
	else
		engine->busy = true;

	spin_unlock_irqrestore(&engine->queue_lock, flags);

	/* Until here we get the request need to be encrypted successfully */
	if (!was_busy && engine->prepare_crypt_hardware) {
		ret = engine->prepare_crypt_hardware(engine);
		if (ret) {
			dev_err(engine->dev, "failed to prepare crypt hardware\n");
			goto req_err_2;
		}
	}

	enginectx = crypto_tfm_ctx(async_req->tfm);

	if (enginectx->op.prepare_request) {
		ret = enginectx->op.prepare_request(engine, async_req);
		if (ret) {
			dev_err(engine->dev, "failed to prepare request: %d\n",
				ret);
			goto req_err_2;
		}
	}
	if (!enginectx->op.do_one_request) {
		dev_err(engine->dev, "failed to do request\n");
		ret = -EINVAL;
		goto req_err_1;
	}

	ret = enginectx->op.do_one_request(engine, async_req);

	/* Request unsuccessfully executed by hardware */
	if (ret < 0) {
		/*
		 * If hardware queue is full (-ENOSPC), requeue request
		 * regardless of backlog flag.
		 * Otherwise, unprepare and complete the request.
		 */
		if (!engine->retry_support ||
		    (ret != -ENOSPC)) {
			dev_err(engine->dev,
				"Failed to do one request from queue: %d\n",
				ret);
			goto req_err_1;
		}
		/*
		 * If retry mechanism is supported,
		 * unprepare current request and
		 * enqueue it back into crypto-engine queue.
		 */
		if (enginectx->op.unprepare_request) {
			ret = enginectx->op.unprepare_request(engine,
							      async_req);
			if (ret)
				dev_err(engine->dev,
					"failed to unprepare request\n");
		}
		spin_lock_irqsave(&engine->queue_lock, flags);
		/*
		 * If hardware was unable to execute request, enqueue it
		 * back in front of crypto-engine queue, to keep the order
		 * of requests.
		 */
		crypto_enqueue_request_head(&engine->queue, async_req);

		kthread_queue_work(engine->kworker, &engine->pump_requests);
		goto out;
	}

	goto retry;

req_err_1:
	if (enginectx->op.unprepare_request) {
		ret = enginectx->op.unprepare_request(engine, async_req);
		if (ret)
			dev_err(engine->dev, "failed to unprepare request\n");
	}

req_err_2:
	crypto_request_complete(async_req, ret);

retry:
	/* If retry mechanism is supported, send new requests to engine */
	if (engine->retry_support) {
		spin_lock_irqsave(&engine->queue_lock, flags);
		goto start_request;
	}
	return;

out:
	spin_unlock_irqrestore(&engine->queue_lock, flags);

	/*
	 * Batch requests is possible only if
	 * hardware can enqueue multiple requests
	 */
	if (engine->do_batch_requests) {
		ret = engine->do_batch_requests(engine);
		if (ret)
			dev_err(engine->dev, "failed to do batch requests: %d\n",
				ret);
	}

	return;
}

static void crypto_pump_work(struct kthread_work *work)
{
	struct crypto_engine *engine =
		container_of(work, struct crypto_engine, pump_requests);

	crypto_pump_requests(engine, true);
}

/**
 * crypto_transfer_request - transfer the new request into the engine queue
 * @engine: the hardware engine
 * @req: the request need to be listed into the engine queue
 * @need_pump: indicates whether queue the pump of request to kthread_work
 */
static int crypto_transfer_request(struct crypto_engine *engine,
				   struct crypto_async_request *req,
				   bool need_pump)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&engine->queue_lock, flags);

	if (!engine->running) {
		spin_unlock_irqrestore(&engine->queue_lock, flags);
		return -ESHUTDOWN;
	}

	ret = crypto_enqueue_request(&engine->queue, req);

	if (!engine->busy && need_pump)
		kthread_queue_work(engine->kworker, &engine->pump_requests);

	spin_unlock_irqrestore(&engine->queue_lock, flags);
	return ret;
}

/**
 * crypto_transfer_request_to_engine - transfer one request to list
 * into the engine queue
 * @engine: the hardware engine
 * @req: the request need to be listed into the engine queue
 */
static int crypto_transfer_request_to_engine(struct crypto_engine *engine,
					     struct crypto_async_request *req)
{
	return crypto_transfer_request(engine, req, true);
}

/**
 * crypto_transfer_aead_request_to_engine - transfer one aead_request
 * to list into the engine queue
 * @engine: the hardware engine
 * @req: the request need to be listed into the engine queue
 */
int crypto_transfer_aead_request_to_engine(struct crypto_engine *engine,
					   struct aead_request *req)
{
	return crypto_transfer_request_to_engine(engine, &req->base);
}
EXPORT_SYMBOL_GPL(crypto_transfer_aead_request_to_engine);

/**
 * crypto_transfer_akcipher_request_to_engine - transfer one akcipher_request
 * to list into the engine queue
 * @engine: the hardware engine
 * @req: the request need to be listed into the engine queue
 */
int crypto_transfer_akcipher_request_to_engine(struct crypto_engine *engine,
					       struct akcipher_request *req)
{
	return crypto_transfer_request_to_engine(engine, &req->base);
}
EXPORT_SYMBOL_GPL(crypto_transfer_akcipher_request_to_engine);

/**
 * crypto_transfer_hash_request_to_engine - transfer one ahash_request
 * to list into the engine queue
 * @engine: the hardware engine
 * @req: the request need to be listed into the engine queue
 */
int crypto_transfer_hash_request_to_engine(struct crypto_engine *engine,
					   struct ahash_request *req)
{
	return crypto_transfer_request_to_engine(engine, &req->base);
}
EXPORT_SYMBOL_GPL(crypto_transfer_hash_request_to_engine);

/**
 * crypto_transfer_kpp_request_to_engine - transfer one kpp_request to list
 * into the engine queue
 * @engine: the hardware engine
 * @req: the request need to be listed into the engine queue
 */
int crypto_transfer_kpp_request_to_engine(struct crypto_engine *engine,
					  struct kpp_request *req)
{
	return crypto_transfer_request_to_engine(engine, &req->base);
}
EXPORT_SYMBOL_GPL(crypto_transfer_kpp_request_to_engine);

/**
 * crypto_transfer_skcipher_request_to_engine - transfer one skcipher_request
 * to list into the engine queue
 * @engine: the hardware engine
 * @req: the request need to be listed into the engine queue
 */
int crypto_transfer_skcipher_request_to_engine(struct crypto_engine *engine,
					       struct skcipher_request *req)
{
	return crypto_transfer_request_to_engine(engine, &req->base);
}
EXPORT_SYMBOL_GPL(crypto_transfer_skcipher_request_to_engine);

/**
 * crypto_finalize_aead_request - finalize one aead_request if
 * the request is done
 * @engine: the hardware engine
 * @req: the request need to be finalized
 * @err: error number
 */
void crypto_finalize_aead_request(struct crypto_engine *engine,
				  struct aead_request *req, int err)
{
	return crypto_finalize_request(engine, &req->base, err);
}
EXPORT_S