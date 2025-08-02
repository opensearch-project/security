/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.transport;

import java.io.IOException;

import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.transport.TransportResponse;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.stream.StreamTransportResponse;

/**
 * A wrapper for StreamTransportResponse that restores the thread context for each response.
 * This ensures that security context is maintained throughout the streaming response lifecycle.
 */
public class SecureStreamTransportResponse<T extends TransportResponse> implements StreamTransportResponse<T> {
    private final StreamTransportResponse<T> delegate;
    private final ThreadContext.StoredContext storedContext;
    private final ThreadPool threadPool;
    private final SecurityInterceptor securityInterceptor;

    /**
     * Creates a new secure stream transport response.
     *
     * @param delegate the delegate stream response
     * @param storedContext the stored thread context to restore for each response
     * @param threadPool the thread pool for accessing thread context
     */
    public SecureStreamTransportResponse(
        StreamTransportResponse<T> delegate,
        ThreadContext.StoredContext storedContext,
        ThreadPool threadPool,
        SecurityInterceptor securityInterceptor
    ) {
        this.delegate = delegate;
        this.storedContext = storedContext;
        this.threadPool = threadPool;
        this.securityInterceptor = securityInterceptor;
    }

    @Override
    public T nextResponse() {
        T response = delegate.nextResponse();
        // TODO: validate if it can be restored multiple times
        storedContext.restore();
        securityInterceptor.processResponseHeaders(response, threadPool.getThreadContext());
        return response;
    }

    @Override
    public void cancel(String reason, Throwable cause) {
        storedContext.restore();
        delegate.cancel(reason, cause);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
