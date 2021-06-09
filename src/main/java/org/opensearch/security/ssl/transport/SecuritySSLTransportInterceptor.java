/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package org.opensearch.security.ssl.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportInterceptor;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;

import org.opensearch.security.ssl.SslExceptionHandler;

public final class SecuritySSLTransportInterceptor implements TransportInterceptor {
    
    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final ThreadPool threadPool;
    protected final PrincipalExtractor principalExtractor;
    protected final SslExceptionHandler errorHandler;
    protected final SSLConfig SSLConfig;

    public SecuritySSLTransportInterceptor(final Settings settings, final  ThreadPool threadPool,
            PrincipalExtractor principalExtractor, final SSLConfig SSLConfig,
                                                     final SslExceptionHandler errorHandler) {
        this.threadPool = threadPool;
        this.principalExtractor = principalExtractor;
        this.errorHandler = errorHandler;
        this.SSLConfig = SSLConfig;
    }

    @Override
    public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(String action, String executor, boolean forceExecution,
            TransportRequestHandler<T> actualHandler) {
        return new SecuritySSLRequestHandler<T>(action, actualHandler, threadPool, principalExtractor, SSLConfig, errorHandler);
    }
    
    
}
