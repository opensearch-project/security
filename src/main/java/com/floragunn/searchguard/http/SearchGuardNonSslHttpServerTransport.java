/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;

import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.threadpool.ThreadPool;

public class SearchGuardNonSslHttpServerTransport extends Netty4HttpServerTransport {

    //https://github.com/floragunncom/search-guard/issues/256
    private final ThreadContext threadContext;
    
    public SearchGuardNonSslHttpServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
            ThreadPool threadPool) {
        super(settings, networkService, bigArrays, threadPool);
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public ChannelHandler configureServerChannelHandler() {
        return new HttpChannelHandler(this);
    }

    protected class HttpChannelHandler extends Netty4HttpServerTransport.HttpChannelHandler {
        
        protected HttpChannelHandler(Netty4HttpServerTransport transport) {
            super(transport, SearchGuardNonSslHttpServerTransport.this.detailedErrorsEnabled, SearchGuardNonSslHttpServerTransport.this.threadContext);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
        }
    }

    @Override
    protected void dispatchRequest(final RestRequest request, final RestChannel channel) {
        super.dispatchRequest(request, channel);
    }
}
