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
        // Return a realistic JWKS response like a public endpoint would
        String jwksResponse = "{\n"
            + "    \"keys\": [\n"
            + "        {\n"
            + "            \"kid\": \"14MuZmRLJtgqpRrcATyTeCUpaU3IHm8kwuCzRJbWnyU\",\n"
            + "            \"kty\": \"RSA\",\n"
            + "            \"alg\": \"RSA-OAEP\",\n"
            + "            \"use\": \"enc\",\n"
            + "            \"n\": \"hZFq7mB43U_5uW1qa-l7lI4thQJ9SVVWgcmdHCemX65s20Vn5Fv34TERdDxST1ZbOHLtcRG-7ykTjnb36KLWBEWUU4KIeYqLgltx_Yx-e_4hcxGyWP323xFu9kHH3ZWOpx3Yv99lscCxRBZ0b-bIfENaAWm9e63NPIVnDFbpt6WBGPHm1PNpYqw_sjEn5BGovH75KxTSqZdMPnT5f-jRveKmNO7-dBnZxYL2vpNu6iXfD_2sXhoBQ3P41-zbFTNfy4yXPvnMjRaMPhhp5OtwLH_LWKfJf-7tQ9jPsYFsch2EcMX-o-G42IJyN3GYxMr0XImVWWUB7ILsPrYRp2OZaQ\",\n"
            + "            \"e\": \"AQAB\",\n"
            + "            \"x5c\": [\n"
            + "                \"MIICnzCCAYcCBgGBbRMM2zANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhpbnRlcm5hbDAeFw0yMjA2MTYxNTExMTNaFw0zMjA2MTYxNTEyNTNaMBMxETAPBgNVBAMMCGludGVybmFsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhZFq7mB43U/5uW1qa+l7lI4thQJ9SVVWgcmdHCemX65s20Vn5Fv34TERdDxST1ZbOHLtcRG+7ykTjnb36KLWBEWUU4KIeYqLgltx/Yx+e/4hcxGyWP323xFu9kHH3ZWOpx3Yv99lscCxRBZ0b+bIfENaAWm9e63NPIVnDFbpt6WBGPHm1PNpYqw/sjEn5BGovH75KxTSqZdMPnT5f+jRveKmNO7+dBnZxYL2vpNu6iXfD/2sXhoBQ3P41+zbFTNfy4yXPvnMjRaMPhhp5OtwLH/LWKfJf+7tQ9jPsYFsch2EcMX+o+G42IJyN3GYxMr0XImVWWUB7ILsPrYRp2OZaQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBoDAA4UR4d+C6IxrOu1Hyz0eqg6XELT0ds8E9IsdK9k46xj99bAdJr9yPFaqXx/ZclMfTELHhg4NUevUB2iWMNt3lSjmjZRancNhQG/DhK6mR1/EImWa/4Uz5ss3pE5De1UZaY9UhHD+9hTbFFZwwNR0wILvKK84Ij1It6xbwz/wHwuAzJ76VhizgV5zI6Du6jxP4ifSlT2hnuMIJUdudsSxH1MSDAd7SDUSsbP1OjX2NPBuz+3cIEMJwDTosrUqR2sI9MBUpEmaHE5IcwxRkTGZvfOnDYm+fUj/uyhUwp34JP++BEVlE7bi8SzqwY5inFT8KKjosfTBTS7m4f8dGy\"\n"
            + "            ],\n"
            + "            \"x5t\": \"H8orvE9ANCBucfmMLMfY2VFQdS4\",\n"
            + "            \"x5t#S256\": \"vtuAx3OoWxUUlDxuthIyTLe7gXg9j0KcNOsrBFAREXE\"\n"
            + "        },\n"
            + "        {\n"
            + "            \"kid\": \"UByZvg8-ZmKSjIq5zLiMtmmNXd5ZJSAxb7OyDOcthfM\",\n"
            + "            \"kty\": \"RSA\",\n"
            + "            \"alg\": \"RS256\",\n"
            + "            \"use\": \"sig\",\n"
            + "            \"n\": \"kGGMwI8s7KH82NaID8sBvz6N5DwzsqgSXofhr6P77LkpCXi2vvOpLzyTY2OFz1f6Ecf0-hCEmGHLEji6gCxUk4URr73n-jprL0dXo29z7uODnfzuB_chvbw-IbjOOj6Z7GV7fgw428jhLboygjklbcymLltHaUMfJjj0KuP5vaCu2dlgiyFKh8Imde8NcCR9zX19_76YNqJbvezB9WPeOcMR2NX-Clm5kq-mGfklf1c57IWAVMSb3bufIU5BARKPdM2pZJYt2F4KRf0hbQVOHFJ6Z6JhJUq83yeBUaH6GTIyvCHqekd9Uz7obBolb4vwZzAu0_CUp3BYBATjuNmO1w\",\n"
            + "            \"e\": \"AQAB\",\n"
            + "            \"x5c\": [\n"
            + "                \"MIICnzCCAYcCBgGBbRMMOzANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhpbnRlcm5hbDAeFw0yMjA2MTYxNTExMTNaFw0zMjA2MTYxNTEyNTNaMBMxETAPBgNVBAMMCGludGVybmFsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkGGMwI8s7KH82NaID8sBvz6N5DwzsqgSXofhr6P77LkpCXi2vvOpLzyTY2OFz1f6Ecf0+hCEmGHLEji6gCxUk4URr73n+jprL0dXo29z7uODnfzuB/chvbw+IbjOOj6Z7GV7fgw428jhLboygjklbcymLltHaUMfJjj0KuP5vaCu2dlgiyFKh8Imde8NcCR9zX19/76YNqJbvezB9WPeOcMR2NX+Clm5kq+mGfklf1c57IWAVMSb3bufIU5BARKPdM2pZJYt2F4KRf0hbQVOHFJ6Z6JhJUq83yeBUaH6GTIyvCHqekd9Uz7obBolb4vwZzAu0/CUp3BYBATjuNmO1wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB659gocsQOlPGsY0NXtWRE9U4or37y7LiOdzX2cXPVmW95p58Mt5ehTLWvJe2P1vEtt3wyUBwKWy0WZHsoFSdrOvNI3YZOxkHObgmK9rE8/k1ySZPiFb9KLfmwZxsWvRCNY8gbr705N+HHKiPJEE77IsQfpiyTFzUnRL/BWiDlhU1lHFZnoKFTht6wGDc0F+MtrN6c+i/PRgW4wboDOLMotLhXHfUrOUatx6XONaG+n790FRput+Gf1UsgQnQquGdW2o1dJP6nEsexgeew1nRvzyWoJgQPpT/N5k9smXlUlH7fQmxfaUefrpgL0kkq/YOj0IG6envW+siTpp+8x1yq\"\n"
            + "            ],\n"
            + "            \"x5t\": \"DsEcchxw-CtObqxyfClb8wfyxKI\",\n"
            + "            \"x5t#S256\": \"phCKIqd1tOxxcbSpXvUS8P0Mdw42gu0CLGGWeHlomjs\"\n"
            + "        }\n"
            + "    ]\n"
            + "}";
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
