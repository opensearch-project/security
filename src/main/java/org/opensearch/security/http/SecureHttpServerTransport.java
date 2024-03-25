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

package org.opensearch.security.http;

import java.util.Set;

import org.opensearch.common.network.NetworkService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.http.netty4.ssl.SecureNetty4HttpServerTransport;
import org.opensearch.plugins.SecureTransportSettingsProvider;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.ssl.http.netty.Netty4ConditionalDecompressor;
import org.opensearch.security.ssl.http.netty.Netty4HttpRequestHeaderVerifier;
import org.opensearch.security.ssl.http.netty.ValidatingDispatcher;
import org.opensearch.telemetry.tracing.Tracer;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.SharedGroupFactory;

import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.AttributeKey;

public class SecureHttpServerTransport extends SecureNetty4HttpServerTransport {

    public static final AttributeKey<SecurityResponse> EARLY_RESPONSE = AttributeKey.newInstance("opensearch-http-early-response");
    public static final AttributeKey<Set<String>> UNCONSUMED_PARAMS = AttributeKey.newInstance("opensearch-http-request-consumed-params");
    public static final AttributeKey<ThreadContext.StoredContext> CONTEXT_TO_RESTORE = AttributeKey.newInstance(
        "opensearch-http-request-thread-context"
    );
    public static final AttributeKey<Boolean> SHOULD_DECOMPRESS = AttributeKey.newInstance("opensearch-http-should-decompress");
    public static final AttributeKey<Boolean> IS_AUTHENTICATED = AttributeKey.newInstance("opensearch-http-is-authenticated");

    private final ChannelInboundHandlerAdapter headerVerifier;

    public SecureHttpServerTransport(
        final Settings settings,
        final NetworkService networkService,
        final BigArrays bigArrays,
        final ThreadPool threadPool,
        final NamedXContentRegistry namedXContentRegistry,
        final ValidatingDispatcher dispatcher,
        final ClusterSettings clusterSettings,
        SharedGroupFactory sharedGroupFactory,
        final SecureTransportSettingsProvider secureTransportSettingsProvider,
        Tracer tracer,
        SecurityRestFilter restFilter
    ) {
        super(
            settings,
            networkService,
            bigArrays,
            threadPool,
            namedXContentRegistry,
            dispatcher,
            clusterSettings,
            sharedGroupFactory,
            secureTransportSettingsProvider,
            tracer
        );

        headerVerifier = new Netty4HttpRequestHeaderVerifier(restFilter, threadPool, settings);
    }

    @Override
    protected ChannelInboundHandlerAdapter createHeaderVerifier() {
        return headerVerifier;
    }

    @Override
    protected ChannelInboundHandlerAdapter createDecompressor() {
        return new Netty4ConditionalDecompressor();
    }
}
