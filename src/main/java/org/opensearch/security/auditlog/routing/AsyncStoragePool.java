/*
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.auditlog.routing;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.opensearch.security.auditlog.config.ThreadPoolConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.sink.AuditLogSink;

public class AsyncStoragePool {
	private static final Logger log = LogManager.getLogger(AsyncStoragePool.class);
	private final ExecutorService pool;
	private final ThreadPoolConfig threadPoolConfig;

	public AsyncStoragePool(final ThreadPoolConfig threadPoolConfig) {
		this.threadPoolConfig = threadPoolConfig;
		this.pool = createExecutor(threadPoolConfig);
	}

	public ThreadPoolConfig getConfig() {
		return this.threadPoolConfig;
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

	private static ThreadPoolExecutor createExecutor(final ThreadPoolConfig config) {
		if (log.isDebugEnabled()) {
			log.debug("Create new executor with threadPoolSize: {} and maxQueueLen: {}",
					config.getThreadPoolSize(),
					config.getThreadPoolMaxQueueLen());
		}
		return new ThreadPoolExecutor(
				config.getThreadPoolSize(),
				config.getThreadPoolSize(),
				0L,
				TimeUnit.MILLISECONDS,
				new LinkedBlockingQueue<>(config.getThreadPoolMaxQueueLen()));
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
