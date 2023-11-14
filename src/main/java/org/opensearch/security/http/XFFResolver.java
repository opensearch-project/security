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

import java.net.InetSocketAddress;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import org.greenrobot.eventbus.Subscribe;

public class XFFResolver {

    protected final Logger log = LogManager.getLogger(this.getClass());
    private volatile boolean enabled;
    private volatile RemoteIpDetector detector;
    private final ThreadContext threadContext;

    public XFFResolver(final ThreadPool threadPool) {
        super();
        this.threadContext = threadPool.getThreadContext();
    }

    public TransportAddress resolve(final SecurityRequest request) throws OpenSearchSecurityException {
        final boolean isTraceEnabled = log.isTraceEnabled();
        if (isTraceEnabled) {
            log.trace("resolve {}", request.getRemoteAddress().orElse(null));
        }

        if (enabled && request.getRemoteAddress().isPresent()) {
            final InetSocketAddress remoteAddress = request.getRemoteAddress().get();
            final InetSocketAddress isa = new InetSocketAddress(detector.detect(request, threadContext), remoteAddress.getPort());

            if (isa.isUnresolved()) {
                throw new OpenSearchSecurityException("Cannot resolve address " + isa.getHostString());
            }

            if (isTraceEnabled) {
                if (threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_XFF_DONE) == Boolean.TRUE) {
                    log.trace("xff resolved {} to {}", remoteAddress, isa);
                } else {
                    log.trace("no xff done for {}", request.getClass());
                }
            }
            return new TransportAddress(isa);
        } else if (request.getRemoteAddress().isPresent()) {
            if (isTraceEnabled) {
                log.trace("no xff done (enabled or no netty request) {},{},{},{}", enabled, request.getClass());
            }
            return new TransportAddress(request.getRemoteAddress().get());
        } else {
            throw new OpenSearchSecurityException(
                "Cannot handle this request. Remote address is "
                    + request.getRemoteAddress().orElse(null)
                    + " with request class "
                    + request.getClass()
            );
        }
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        enabled = dcm.isXffEnabled();
        if (enabled) {
            detector = new RemoteIpDetector();
            detector.setInternalProxies(dcm.getInternalProxies());
            detector.setRemoteIpHeader(dcm.getRemoteIpHeader());
        } else {
            detector = null;
        }
    }
}
