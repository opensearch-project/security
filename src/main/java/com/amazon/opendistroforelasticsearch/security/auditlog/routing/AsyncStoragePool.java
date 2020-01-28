/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auditlog.routing;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditMessage;
import com.amazon.opendistroforelasticsearch.security.auditlog.sink.AuditLogSink;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

public class AsyncStoragePool {

	protected final Logger log = LogManager.getLogger(this.getClass());

	private static final int DEFAULT_THREAD_POOL_SIZE = 10;
	private static final int DEFAULT_THREAD_POOL_MAX_QUEUE_LEN = 100 * 1000;

	// package private for unit tests
	final ExecutorService pool;

	int threadPoolSize;
	int threadPoolMaxQueueLen;

	public AsyncStoragePool(final Settings settings) {
		this.threadPoolSize = settings.getAsInt(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE, DEFAULT_THREAD_POOL_SIZE).intValue();
		this.threadPoolMaxQueueLen = settings.getAsInt(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN, DEFAULT_THREAD_POOL_MAX_QUEUE_LEN).intValue();

		if (threadPoolSize <= 0) {
			threadPoolSize = DEFAULT_THREAD_POOL_SIZE;
		}

		if (threadPoolMaxQueueLen <= 0) {
			threadPoolMaxQueueLen = DEFAULT_THREAD_POOL_MAX_QUEUE_LEN;
		}

		this.pool = createExecutor(threadPoolSize, threadPoolMaxQueueLen);
	}

	public void submit(AuditMessage message, AuditLogSink sink) {
		try {
			pool.submit(() -> {
				sink.store(message);
				if (log.isTraceEnabled()) {
					log.trace("stored on delegate {} asynchronously", sink.getClass().getSimpleName());
				}
			});
		} catch (Exception ex) {
			log.error("Could not submit audit message {} to thread pool for delegate '{}' due to '{}'", message, sink.getClass().getSimpleName(), ex.getMessage());
			if (sink.getFallbackSink() != null) {
				sink.getFallbackSink().store(message);
			}
		}
	}

	private ThreadPoolExecutor createExecutor(final int threadPoolSize, final int maxQueueLen) {
		if (log.isDebugEnabled()) {
			log.debug("Create new executor with threadPoolSize: {} and maxQueueLen: {}", threadPoolSize, maxQueueLen);
		}
		return new ThreadPoolExecutor(threadPoolSize, threadPoolSize, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<Runnable>(maxQueueLen));
	}

	public void close() {

		if (pool != null) {
			pool.shutdown(); // Disable new tasks from being submitted

			try {
				// Wait a while for existing tasks to terminate
				if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
					pool.shutdownNow(); // Cancel currently executing tasks
					// Wait a while for tasks to respond to being cancelled
					if (!pool.awaitTermination(60, TimeUnit.SECONDS))
						log.error("Pool did not terminate");
				}
			} catch (InterruptedException ie) {
				// (Re-)Cancel if current thread also interrupted
				pool.shutdownNow();
				// Preserve interrupt status
				Thread.currentThread().interrupt();
			}
		}
	}
}
