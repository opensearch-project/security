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
 * Portions Copyright OpenSearch Contributors
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

package org.opensearch.security.http;

import org.opensearch.security.ssl.http.netty.SecuritySSLNettyHttpServerTransport;
import org.opensearch.common.network.NetworkService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.SharedGroupFactory;

import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.http.netty.ValidatingDispatcher;

public class SecurityHttpServerTransport extends SecuritySSLNettyHttpServerTransport {
    
    public SecurityHttpServerTransport(final Settings settings, final NetworkService networkService,
                                       final BigArrays bigArrays, final ThreadPool threadPool, final SecurityKeyStore odsks,
                                       final SslExceptionHandler sslExceptionHandler, final NamedXContentRegistry namedXContentRegistry, final ValidatingDispatcher dispatcher, final ClusterSettings clusterSettings, SharedGroupFactory sharedGroupFactory) {
        super(settings, networkService, bigArrays, threadPool, odsks, namedXContentRegistry, dispatcher, sslExceptionHandler, clusterSettings, sharedGroupFactory);
    }
}
