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

package com.floragunn.searchguard.filter;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.netty.NettyHttpRequest;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;
import org.jboss.netty.handler.ssl.SslHandler;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.support.HeaderHelper;

public class SearchGuardRestFilter extends RestFilter {

    private final BackendRegistry registry;
    private final AuditLog auditLog;
    private final ThreadContext threadContext;

    @Inject
    public SearchGuardRestFilter(final BackendRegistry registry, final AuditLog auditLog, final ThreadPool threadPool) {
        super();
        this.registry = registry;
        this.auditLog = auditLog;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel, final RestFilterChain filterChain) throws Exception {

        try {
            HeaderHelper.checkSGHeader(this.threadContext);
        } catch (final Exception e) {
            auditLog.logBadHeaders(request);
            channel.sendResponse(new BytesRestResponse(channel, RestStatus.FORBIDDEN, e));
            return;
        }

        if (request instanceof NettyHttpRequest) {
            final NettyHttpRequest nettyRequest = (NettyHttpRequest) request;
            final SslHandler sslHandler = (SslHandler) nettyRequest.getChannel().getPipeline().get("ssl_http");

            if (sslHandler != null) {
                
                threadContext.putTransient("_sg_ssl_protocol", sslHandler.getEngine().getSession().getProtocol());
                threadContext.putTransient("_sg_ssl_cipher", sslHandler.getEngine().getSession().getCipherSuite());
                

                if (sslHandler.getEngine().getNeedClientAuth() || sslHandler.getEngine().getWantClientAuth()) {

                    try {
                        final Certificate[] certs = sslHandler.getEngine().getSession().getPeerCertificates();

                        if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                            final X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
                            final X500Principal principal = x509Certs[0].getSubjectX500Principal();
                            threadContext.putTransient("_sg_ssl_principal", principal == null ? null : principal.getName());
                            threadContext.putTransient("_sg_ssl_peer_certificates", x509Certs);
                        } else if (sslHandler.getEngine().getNeedClientAuth()) {
                            final ElasticsearchException ex = new ElasticsearchException(
                                    "No client certificates found but such are needed (SG 9).");
                            // errorThrown(ex, nettyHttpRequest);
                            throw ex;
                        }

                    } catch (final SSLPeerUnverifiedException e) {
                        if (sslHandler.getEngine().getNeedClientAuth()) {
                            // logger.error("No client certificates found but such are needed (SG 8).");
                            // errorThrown(e, nettyHttpRequest);
                            throw ExceptionsHelper.convertToElastic(e);
                        }
                    } catch (final Exception e) {
                        // logger.error("Unknow error (SG 8) : "+e,e);
                        // errorThrown(e, nettyHttpRequest);
                        throw ExceptionsHelper.convertToElastic(e);
                    }
                }
            }
        }

        if (!registry.authenticate(request, channel, threadContext)) {
            // another roundtrip
            return;
        }

        filterChain.continueProcessing(request, channel);
    }

}
