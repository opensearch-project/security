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

package com.amazon.dlic.auth.http.jwt.keybyoidc;

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
import org.apache.hc.core5.http.Header;
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

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;

import static com.amazon.dlic.auth.http.jwt.keybyoidc.TestJwts.MCCOY_SUBJECT;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.TestJwts.TEST_ROLES_STRING;
import static com.amazon.dlic.auth.http.jwt.keybyoidc.TestJwts.createSigned;

class MockIpdServer implements Closeable {
    final static String CTX_DISCOVER = "/discover";
    final static String CTX_USERINFO_SIGNED = "/api/oauth/userinfo/signed";
    final static String CTX_USERINFO = "/api/oauth/userinfo";
    final static String CTX_BADUSERINFO = "/api/oauth/userinfo/bad";
    final static String CTX_KEYS = "/api/oauth/keys";

    private final HttpServer httpServer;
    private final int port;
    private final String uri;
    private final boolean ssl;
    private final JWKSet jwks;

    MockIpdServer(JWKSet jwks) throws IOException {
        this(jwks, SocketUtils.findAvailableTcpPort(), false);
    }

    MockIpdServer(JWKSet jwks, int port, boolean ssl) throws IOException {
        this.port = port;
        this.uri = (ssl ? "https" : "http") + "://localhost:" + port;
        this.ssl = ssl;
        this.jwks = jwks;

        ServerBootstrap serverBootstrap = ServerBootstrap.bootstrap()
            .setListenerPort(port)
            .register(CTX_DISCOVER, new HttpRequestHandler() {

                @Override
                public void handle(ClassicHttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                    IOException {
                    handleDiscoverRequest(request, response, context);
                }
            })
            .register(CTX_KEYS, new HttpRequestHandler() {

                @Override
                public void handle(ClassicHttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                    IOException {
                    handleKeysRequest(request, response, context);
                }
            })
            .register(CTX_USERINFO, new HttpRequestHandler() {

                @Override
                public void handle(ClassicHttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                    IOException {
                    handleUserinfoRequest(request, response, context);
                }
            })
            .register(CTX_USERINFO_SIGNED, new HttpRequestHandler() {

                @Override
                public void handle(ClassicHttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                    IOException {
                    handleUserinfoRequestSigned(request, response, context);
                }
            })
            .register(CTX_BADUSERINFO, new HttpRequestHandler() {

                @Override
                public void handle(ClassicHttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                    IOException {
                    handleBadUserInfoRequest(request, response, context);
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

    public String getDiscoverUri() {
        return uri + CTX_DISCOVER;
    }

    public String getUserinfoUri() {
        return uri + CTX_USERINFO;
    }

    public String getUserinfoSignedUri() {
        return uri + CTX_USERINFO_SIGNED;
    }

    public String getBadUserInfoUri() {
        return uri + CTX_BADUSERINFO;
    }

    public String getJwksUri() {
        return uri + CTX_KEYS;
    }

    public int getPort() {
        return port;
    }

    protected void handleDiscoverRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
        IOException {
        response.setCode(200);
        response.setHeader("Cache-Control", "public, max-age=31536000");
        response.setEntity(
            new StringEntity(
                "{\"jwks_uri\": \"" + uri + CTX_KEYS + "\",\n" + "\"issuer\": \"" + uri + "\", \"unknownPropertyToBeIgnored\": 42}"
            )
        );
    }

    protected void handleUserinfoRequestSigned(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
        IOException {

        Header headers = request.getHeader("Authorization");
        String requestToken;

        String authHeaderValue = headers.getValue();
        if (authHeaderValue.startsWith("Bearer")) {
            requestToken = authHeaderValue.substring(7).trim();
        } else {
            response.setCode(401);
            return;
        }

        response.setCode(200);
        response.setHeader("content-type", ContentType.APPLICATION_JWT);

        // We have to manually form the response content since we don't want to need to pass settings info into the test class

        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("sub", MCCOY_SUBJECT)
            .claim("roles", TEST_ROLES_STRING)
            .claim("iss", "http://www.example.com")
            .claim("aud", "testClient")
            .build();
        String content = createSigned(claims, TestJwk.OCT_1);

        response.setEntity(new StringEntity(content));
    }

    protected void handleUserinfoRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
        IOException {
        Header headers = request.getHeader("Authorization");
        String requestToken;

        String authHeaderValue = headers.getValue();
        if (authHeaderValue.startsWith("Bearer")) {
            requestToken = authHeaderValue.substring(7).trim();
        } else {
            response.setCode(401);
            return;
        }
        response.setCode(200);
        response.setHeader("content-type", ContentType.APPLICATION_JSON);

        // We have to manually form the response content since we don't want to need to pass settings info into the test class
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("sub", MCCOY_SUBJECT).claim("roles", TEST_ROLES_STRING).build();
        response.setEntity(new StringEntity(claims.toString()));
    }

    protected void handleKeysRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
        IOException {
        response.setCode(200);
        response.setEntity(new StringEntity(jwks.toString(false)));
    }

    protected void handleBadUserInfoRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
        IOException {
        response.setCode(401);
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
