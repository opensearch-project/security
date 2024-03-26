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

import java.util.Optional;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

import org.opensearch.common.settings.Settings;
import org.opensearch.http.HttpServerTransport;
import org.opensearch.plugins.SecureSettingsFactory;
import org.opensearch.plugins.SecureTransportSettingsProvider;
import org.opensearch.transport.TcpTransport;

public class OpenSearchSecureSettingsFactory implements SecureSettingsFactory {
    private final Settings settings;
    private final SecurityKeyStore sks;
    private final SslExceptionHandler sslExceptionHandler;

    public OpenSearchSecureSettingsFactory(Settings settings, SecurityKeyStore sks, SslExceptionHandler sslExceptionHandler) {
        this.settings = settings;
        this.sks = sks;
        this.sslExceptionHandler = sslExceptionHandler;
    }

    @Override
    public Optional<SecureTransportSettingsProvider> getSecureTransportSettingsProvider(Settings settings) {
        return Optional.of(new SecureTransportSettingsProvider() {
            @Override
            public Optional<ServerExceptionHandler> buildHttpServerExceptionHandler(Settings settings, HttpServerTransport transport) {
                return Optional.of(new ServerExceptionHandler() {
                    @Override
                    public void onError(Throwable t) {
                        sslExceptionHandler.logError(t, true);
                    }
                });
            }

            @Override
            public Optional<ServerExceptionHandler> buildServerTransportExceptionHandler(Settings settings, TcpTransport transport) {
                return Optional.of(new ServerExceptionHandler() {
                    @Override
                    public void onError(Throwable t) {
                        sslExceptionHandler.logError(t, false);
                    }
                });
            }

            @Override
            public Optional<SSLEngine> buildSecureHttpServerEngine(Settings settings, HttpServerTransport transport) throws SSLException {
                return Optional.of(sks.createHTTPSSLEngine());
            }

            @Override
            public Optional<SSLEngine> buildSecureServerTransportEngine(Settings settings, TcpTransport transport) throws SSLException {
                return Optional.of(sks.createServerTransportSSLEngine());
            }

            @Override
            public Optional<SSLEngine> buildSecureClientTransportEngine(Settings settings, String hostname, int port) throws SSLException {
                return Optional.of(sks.createClientTransportSSLEngine(hostname, port));
            }
        });
    }
}
