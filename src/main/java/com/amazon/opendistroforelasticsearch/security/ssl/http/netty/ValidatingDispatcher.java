/*
 * Copyright 2017 floragunn GmbH
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

package com.amazon.opendistroforelasticsearch.security.ssl.http.netty;

import java.nio.file.Path;

import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.HttpServerTransport.Dispatcher;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.amazon.opendistroforelasticsearch.security.ssl.SslExceptionHandler;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ExceptionUtils;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLRequestHelper;

public class ValidatingDispatcher implements Dispatcher {

    private static final Logger logger = LogManager.getLogger(ValidatingDispatcher.class);

    private final ThreadContext threadContext;
    private final Dispatcher originalDispatcher;
    private final SslExceptionHandler errorHandler;
    private final Settings settings;
    private final Path configPath;

    public ValidatingDispatcher(final ThreadContext threadContext, final Dispatcher originalDispatcher, 
            final Settings settings, final Path configPath, final SslExceptionHandler errorHandler) {
        super();
        this.threadContext = threadContext;
        this.originalDispatcher = originalDispatcher;
        this.settings = settings;
        this.configPath = configPath;
        this.errorHandler = errorHandler;
    }

    @Override
    public void dispatchRequest(RestRequest request, RestChannel channel, ThreadContext threadContext) {
        checkRequest(request, channel);
        originalDispatcher.dispatchRequest(request, channel, threadContext);
    }

    @Override
    public void dispatchBadRequest(RestRequest request, RestChannel channel, ThreadContext threadContext, Throwable cause) {
        checkRequest(request, channel);
        originalDispatcher.dispatchBadRequest(request, channel, threadContext, cause);
    }
    
    protected void checkRequest(final RestRequest request, final RestChannel channel) {
        
        if(SSLRequestHelper.containsBadHeader(threadContext, "_opendistro_security_ssl_")) {
            final ElasticsearchException exception = ExceptionUtils.createBadHeaderException();
            errorHandler.logError(exception, request, 1);
            throw exception;
        }
        
        try {
            if(SSLRequestHelper.getSSLInfo(settings, configPath, request, null) == null) {
                logger.error("Not an SSL request");
                throw new ElasticsearchSecurityException("Not an SSL request", RestStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (SSLPeerUnverifiedException e) {
            logger.error("No client certificates found but such are needed (SG 8).");
            errorHandler.logError(e, request, 0);
            throw ExceptionsHelper.convertToElastic(e);
        }
    }
}
