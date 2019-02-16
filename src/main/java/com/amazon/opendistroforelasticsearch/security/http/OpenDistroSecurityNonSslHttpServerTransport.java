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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.http;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;

import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.threadpool.ThreadPool;

public class OpenDistroSecurityNonSslHttpServerTransport extends Netty4HttpServerTransport {

    private final ThreadContext threadContext;
    
    public OpenDistroSecurityNonSslHttpServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
            final ThreadPool threadPool, final NamedXContentRegistry namedXContentRegistry, final Dispatcher dispatcher) {
        super(settings, networkService, bigArrays, threadPool, namedXContentRegistry, dispatcher);
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public ChannelHandler configureServerChannelHandler() {
        return new NonSslHttpChannelHandler(this);
    }

    protected class NonSslHttpChannelHandler extends Netty4HttpServerTransport.HttpChannelHandler {
        
        protected NonSslHttpChannelHandler(Netty4HttpServerTransport transport) {
            super(transport, OpenDistroSecurityNonSslHttpServerTransport.this.detailedErrorsEnabled, OpenDistroSecurityNonSslHttpServerTransport.this.threadContext);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
        }
    }
}
