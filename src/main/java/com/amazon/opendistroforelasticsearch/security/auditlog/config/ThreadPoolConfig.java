package com.amazon.opendistroforelasticsearch.security.auditlog.config;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.elasticsearch.common.settings.Settings;

public class ThreadPoolConfig {
    private static final int DEFAULT_THREAD_POOL_SIZE = 10;
    private static final int DEFAULT_THREAD_POOL_MAX_QUEUE_LEN = 100_000;

    private final int threadPoolSize;
    private final int threadPoolMaxQueueLen;

    public ThreadPoolConfig(int threadPoolSize, int threadPoolMaxQueueLen) {
        if (threadPoolSize <= 0) {
            throw new IllegalArgumentException("Incorrect thread pool size: " + threadPoolSize + " configured for audit logging.");
        }

        if (threadPoolMaxQueueLen <= 0) {
            throw new IllegalArgumentException("Incorrect thread pool queue length: " + threadPoolMaxQueueLen + " configured for audit logging.");
        }

        this.threadPoolSize = threadPoolSize;
        this.threadPoolMaxQueueLen = threadPoolMaxQueueLen;
    }

    public int getThreadPoolSize() {
        return threadPoolSize;
    }

    public int getThreadPoolMaxQueueLen() {
        return threadPoolMaxQueueLen;
    }

    public static ThreadPoolConfig getConfig(Settings settings) {
        int threadPoolSize = settings.getAsInt(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE, DEFAULT_THREAD_POOL_SIZE);
        int threadPoolMaxQueueLen = settings.getAsInt(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN, DEFAULT_THREAD_POOL_MAX_QUEUE_LEN);

        return new ThreadPoolConfig(threadPoolSize, threadPoolMaxQueueLen);
    }
}
