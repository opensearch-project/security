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

package com.floragunn.searchguard.http;

import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.ssl.SearchGuardKeyStore;
import com.floragunn.searchguard.ssl.SslExceptionHandler;
import com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyHttpServerTransport;
import com.floragunn.searchguard.ssl.http.netty.ValidatingDispatcher;

public class SearchGuardHttpServerTransport extends SearchGuardSSLNettyHttpServerTransport {
    
    public SearchGuardHttpServerTransport(final Settings settings, final NetworkService networkService, 
            final BigArrays bigArrays, final ThreadPool threadPool, final SearchGuardKeyStore sgks, 
            final SslExceptionHandler sslExceptionHandler, final NamedXContentRegistry namedXContentRegistry, final ValidatingDispatcher dispatcher) {
        super(settings, networkService, bigArrays, threadPool, sgks, namedXContentRegistry, dispatcher, sslExceptionHandler);
    }
}
