package com.amazon.opendistroforelasticsearch.security.auditlog.routing;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.elasticsearch.common.settings.Settings;

public class AsyncStoragePoolConfig {
    private static final int DEFAULT_THREAD_POOL_SIZE = 10;
    private static final int DEFAULT_THREAD_POOL_MAX_QUEUE_LEN = 100 * 1000;

    private final int threadPoolSize;
    private final int threadPoolMaxQueueLen;

    public AsyncStoragePoolConfig(int threadPoolSize, int threadPoolMaxQueueLen) {
        if (threadPoolSize <= 0) {
            threadPoolSize = DEFAULT_THREAD_POOL_SIZE;
        }

        if (threadPoolMaxQueueLen <= 0) {
            threadPoolMaxQueueLen = DEFAULT_THREAD_POOL_MAX_QUEUE_LEN;
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

    public static AsyncStoragePoolConfig getConfig(Settings settings) {
        int threadPoolSize = settings.getAsInt(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE, DEFAULT_THREAD_POOL_SIZE);
        int threadPoolMaxQueueLen = settings.getAsInt(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN, DEFAULT_THREAD_POOL_MAX_QUEUE_LEN);

        return new AsyncStoragePoolConfig(threadPoolSize, threadPoolMaxQueueLen);
    }
}
