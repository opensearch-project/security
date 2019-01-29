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

package com.amazon.opendistrosecurity.http;

import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistrosecurity.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistrosecurity.ssl.SslExceptionHandler;
import com.amazon.opendistrosecurity.ssl.http.netty.OpenDistroSecuritySSLNettyHttpServerTransport;
import com.amazon.opendistrosecurity.ssl.http.netty.ValidatingDispatcher;

public class OpenDistroSecurityHttpServerTransport extends OpenDistroSecuritySSLNettyHttpServerTransport {
    
    public OpenDistroSecurityHttpServerTransport(final Settings settings, final NetworkService networkService, 
            final BigArrays bigArrays, final ThreadPool threadPool, final OpenDistroSecurityKeyStore sgks, 
            final SslExceptionHandler sslExceptionHandler, final NamedXContentRegistry namedXContentRegistry, final ValidatingDispatcher dispatcher) {
        super(settings, networkService, bigArrays, threadPool, sgks, namedXContentRegistry, dispatcher, sslExceptionHandler);
    }
}
