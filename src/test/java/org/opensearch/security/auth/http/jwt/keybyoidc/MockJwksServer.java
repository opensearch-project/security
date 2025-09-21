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

package org.opensearch.security.auth.http.jwt.keybyoidc;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.apache.hc.core5.function.Callback;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.impl.bootstrap.HttpServer;
import org.apache.hc.core5.http.impl.bootstrap.ServerBootstrap;
import org.apache.hc.core5.http.impl.io.DefaultBHttpServerConnection;
import org.apache.hc.core5.http.io.HttpConnectionFactory;
import org.apache.hc.core5.http.io.HttpRequestHandler;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.protocol.HttpContext;

import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.network.SocketUtils;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * Mock JWKS server for testing direct JWKS endpoint access.
 * This server only serves JWKS endpoints, unlike MockIpdServer which serves both OIDC discovery and JWKS.
 */
class MockJwksServer implements Closeable {
    final static String CTX_JWKS = "/jwks";

    private final HttpServer httpServer;
    private final int port;
    private final String uri;
    private final boolean ssl;
    private final JWKSet jwks;

    MockJwksServer(JWKSet jwks) throws IOException {
        this(jwks, SocketUtils.findAvailableTcpPort(), false);
    }

    MockJwksServer(JWKSet jwks, int port, boolean ssl) throws IOException {
        this.port = port;
        this.uri = (ssl ? "https" : "http") + "://localhost:" + port;
        this.ssl = ssl;
        this.jwks = jwks;

        ServerBootstrap serverBootstrap = ServerBootstrap.bootstrap().setListenerPort(port).setRequestRouter((request, context) -> {
            if (request.getRequestUri().startsWith(CTX_JWKS)) {
                return new HttpRequestHandler() {
                    @Override
                    public void handle(ClassicHttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                        IOException {
                        handleJwksRequest(request, response, context);
                    }
                };
            } else {
                return null;
            }
        });

        if (ssl) {
            serverBootstrap = serverBootstrap.setSslContext(createSSLContext()).setSslSetupHandler(new Callback<SSLParameters>() {
                @Override
                public void execute(SSLParameters object) {
                    object.setNeedClientAuth(true);
                }
            }).setConnectionFactory(new HttpConnectionFactory<DefaultBHttpServerConnection>() {
                @Override
                public DefaultBHttpServerConnection createConnection(final Socket socket) throws IOException {
                    final DefaultBHttpServerConnection conn = new DefaultBHttpServerConnection(ssl ? "https" : "http", Http1Config.DEFAULT);
                    conn.bind(socket);
                    return conn;
                }
            });
        }

        this.httpServer = serverBootstrap.create();
        httpServer.start();
    }

    @Override
    public void close() throws IOException {
        httpServer.stop();
    }

    public HttpServer getHttpServer() {
        return httpServer;
    }

    public String getUri() {
        return uri;
    }

    public String getJwksUri() {
        return uri + CTX_JWKS;
    }

    public int getPort() {
        return port;
    }

    protected void handleJwksRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
        IOException {
        response.setCode(200);
        // Return the actual JWKSet that was passed to the constructor
        String jwksResponse = jwks.toString();
        response.setEntity(new StringEntity(jwksResponse));
    }

    private SSLContext createSSLContext() {
        if (!this.ssl) {
            return null;
        }

        try {
            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            final KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream trustStream = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath("jwt/truststore.jks").toFile());
            trustStore.load(trustStream, "changeit".toCharArray());
            tmf.init(trustStore);

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            final KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream keyStream = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath("jwt/node-0-keystore.jks").toFile());

            keyStore.load(keyStream, "changeit".toCharArray());
            kmf.init(keyStore, "changeit".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return sslContext;
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
