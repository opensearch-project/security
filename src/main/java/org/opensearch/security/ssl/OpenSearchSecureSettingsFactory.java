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

package org.opensearch.security.ssl;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

import org.opensearch.common.settings.Settings;
import org.opensearch.http.HttpServerTransport;
import org.opensearch.http.netty4.ssl.SecureNetty4HttpServerTransport;
import org.opensearch.plugins.SecureHttpTransportSettingsProvider;
import org.opensearch.plugins.SecureSettingsFactory;
import org.opensearch.plugins.SecureTransportSettingsProvider;
import org.opensearch.plugins.TransportExceptionHandler;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.ssl.http.netty.Netty4ConditionalDecompressor;
import org.opensearch.security.ssl.http.netty.Netty4HttpRequestHeaderVerifier;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Transport;
import org.opensearch.transport.TransportAdapterProvider;

import io.netty.channel.ChannelInboundHandlerAdapter;

public class OpenSearchSecureSettingsFactory implements SecureSettingsFactory {
    private final ThreadPool threadPool;
    private final SecurityKeyStore sks;
    private final SslExceptionHandler sslExceptionHandler;
    private final SecurityRestFilter restFilter;

    public OpenSearchSecureSettingsFactory(
        ThreadPool threadPool,
        SecurityKeyStore sks,
        SslExceptionHandler sslExceptionHandler,
        SecurityRestFilter restFilter
    ) {
        this.threadPool = threadPool;
        this.sks = sks;
        this.sslExceptionHandler = sslExceptionHandler;
        this.restFilter = restFilter;
    }

    @Override
    public Optional<SecureTransportSettingsProvider> getSecureTransportSettingsProvider(Settings settings) {
        return Optional.of(new SecureTransportSettingsProvider() {
            @Override
            public Optional<TransportExceptionHandler> buildServerTransportExceptionHandler(Settings settings, Transport transport) {
                return Optional.of(new TransportExceptionHandler() {
                    @Override
                    public void onError(Throwable t) {
                        sslExceptionHandler.logError(t, false);
                    }
                });
            }

            @Override
            public Optional<SSLEngine> buildSecureServerTransportEngine(Settings settings, Transport transport) throws SSLException {
                return Optional.of(sks.createServerTransportSSLEngine());
            }

            @Override
            public Optional<SSLEngine> buildSecureClientTransportEngine(Settings settings, String hostname, int port) throws SSLException {
                return Optional.of(sks.createClientTransportSSLEngine(hostname, port));
            }
        });
    }

    @Override
    public Optional<SecureHttpTransportSettingsProvider> getSecureHttpTransportSettingsProvider(Settings settings) {
        return Optional.of(new SecureHttpTransportSettingsProvider() {
            @Override
            public Collection<TransportAdapterProvider<HttpServerTransport>> getHttpTransportAdapterProviders(Settings settings) {
                return List.of(new TransportAdapterProvider<HttpServerTransport>() {
                    @Override
                    public String name() {
                        return SecureNetty4HttpServerTransport.REQUEST_DECOMPRESSOR;
                    }

                    @SuppressWarnings("unchecked")
                    @Override
                    public <C> Optional<C> create(Settings settings, HttpServerTransport transport, Class<C> adapterClass) {
                        if (transport instanceof SecureNetty4HttpServerTransport
                            && ChannelInboundHandlerAdapter.class.isAssignableFrom(adapterClass)) {
                            return Optional.of((C) new Netty4ConditionalDecompressor());
                        } else {
                            return Optional.empty();
                        }
                    }
                }, new TransportAdapterProvider<HttpServerTransport>() {
                    @Override
                    public String name() {
                        return SecureNetty4HttpServerTransport.REQUEST_HEADER_VERIFIER;
                    }

                    @SuppressWarnings("unchecked")
                    @Override
                    public <C> Optional<C> create(Settings settings, HttpServerTransport transport, Class<C> adapterClass) {
                        if (transport instanceof SecureNetty4HttpServerTransport
                            && ChannelInboundHandlerAdapter.class.isAssignableFrom(adapterClass)) {
                            return Optional.of((C) new Netty4HttpRequestHeaderVerifier(restFilter, threadPool, settings));
                        } else {
                            return Optional.empty();
                        }
                    }
                });
            }

            @Override
            public Optional<TransportExceptionHandler> buildHttpServerExceptionHandler(Settings settings, HttpServerTransport transport) {
                return Optional.of(new TransportExceptionHandler() {
                    @Override
                    public void onError(Throwable t) {
                        sslExceptionHandler.logError(t, true);
                    }
                });
            }

            @Override
            public Optional<SSLEngine> buildSecureHttpServerEngine(Settings settings, HttpServerTransport transport) throws SSLException {
                return Optional.of(sks.createHTTPSSLEngine());
            }
        });
    }
}
