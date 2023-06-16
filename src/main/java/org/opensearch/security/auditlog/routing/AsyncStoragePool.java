/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.auditlog.routing;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.auditlog.config.ThreadPoolConfig;
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
            log.error(
                "Could not submit audit message {} to thread pool for delegate '{}' due to '{}'",
                message,
                sink.getClass().getSimpleName(),
                ex.getMessage()
            );
            if (sink.getFallbackSink() != null) {
                sink.getFallbackSink().store(message);
            }
        }
    }

    private static ThreadPoolExecutor createExecutor(final ThreadPoolConfig config) {
        if (log.isDebugEnabled()) {
            log.debug(
                "Create new executor with threadPoolSize: {} and maxQueueLen: {}",
                config.getThreadPoolSize(),
                config.getThreadPoolMaxQueueLen()
            );
        }
        return new ThreadPoolExecutor(
            config.getThreadPoolSize(),
            config.getThreadPoolSize(),
            0L,
            TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(config.getThreadPoolMaxQueueLen())
        );
    }

    public void close() {

        if (pool != null) {
            pool.shutdown(); // Disable new tasks from being submitted

            try {
                // Wait a while for existing tasks to terminate
                if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
                    pool.shutdownNow(); // Cancel currently executing tasks
                    // Wait a while for tasks to respond to being cancelled
                    if (!pool.awaitTermination(60, TimeUnit.SECONDS)) log.error("Pool did not terminate");
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
