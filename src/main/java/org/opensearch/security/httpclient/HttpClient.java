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

package org.opensearch.security.httpclient;

import java.io.Closeable;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.google.common.collect.Lists;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.reactor.ssl.SSLBufferMode;
import org.apache.hc.core5.ssl.PrivateKeyDetails;
import org.apache.hc.core5.ssl.PrivateKeyStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson3.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.Refresh;
import org.opensearch.client.opensearch.core.IndexResponse;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5Transport;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;
import org.opensearch.client.transport.httpclient5.internal.Node;

import jakarta.json.stream.JsonParser;

public class HttpClient implements Closeable {

    public static class HttpClientBuilder {

        private KeyStore trustStore;
        private String basicCredentials;
        private KeyStore keystore;
        private String keystoreAlias;
        private char[] keyPassword;
        private boolean verifyHostnames;
        private String[] supportedProtocols = null;
        private String[] supportedCipherSuites = null;

        private final String[] servers;
        private boolean ssl;

        private HttpClientBuilder(final String... servers) {
            super();
            this.servers = Objects.requireNonNull(servers);
            if (this.servers.length == 0) {
                throw new IllegalArgumentException();
            }
        }

        public HttpClientBuilder enableSsl(final KeyStore trustStore, final boolean verifyHostnames) {
            this.ssl = true;
            this.trustStore = Objects.requireNonNull(trustStore);
            this.verifyHostnames = verifyHostnames;
            return this;
        }

        public HttpClientBuilder setBasicCredentials(final String username, final String password) {
            basicCredentials = encodeBasicHeader(Objects.requireNonNull(username), Objects.requireNonNull(password));
            return this;
        }

        public HttpClientBuilder setPkiCredentials(final KeyStore keystore, final char[] keyPassword, final String keystoreAlias) {
            this.keystore = Objects.requireNonNull(keystore);
            this.keyPassword = keyPassword;
            this.keystoreAlias = keystoreAlias;
            return this;
        }

        public HttpClientBuilder setSupportedProtocols(String[] protocols) {
            this.supportedProtocols = protocols;
            return this;
        }

        public HttpClientBuilder setSupportedCipherSuites(String[] cipherSuites) {
            this.supportedCipherSuites = cipherSuites;
            return this;
        }

        public HttpClient build() throws Exception {
            return new HttpClient(
                trustStore,
                basicCredentials,
                keystore,
                keyPassword,
                keystoreAlias,
                verifyHostnames,
                ssl,
                supportedProtocols,
                supportedCipherSuites,
                servers
            );
        }

        private static String encodeBasicHeader(final String username, final String password) {
            return Base64.getEncoder().encodeToString((username + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8));
        }

    }

    public static HttpClientBuilder builder(final String... servers) {
        return new HttpClientBuilder(servers);
    }

    private final KeyStore trustStore;
    private final Logger log = LogManager.getLogger(this.getClass());
    private OpenSearchClient rclient;
    private String basicCredentials;
    private KeyStore keystore;
    private String keystoreAlias;
    private char[] keyPassword;
    private boolean verifyHostnames;
    private boolean ssl;
    private String[] supportedProtocols;
    private String[] supportedCipherSuites;

    private HttpClient(
        final KeyStore trustStore,
        final String basicCredentials,
        final KeyStore keystore,
        final char[] keyPassword,
        final String keystoreAlias,
        final boolean verifyHostnames,
        final boolean ssl,
        String[] supportedProtocols,
        String[] supportedCipherSuites,
        final String... servers
    ) throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException,
        IOException {
        super();
        this.trustStore = trustStore;
        this.basicCredentials = basicCredentials;
        this.keystore = keystore;
        this.keyPassword = keyPassword;
        this.verifyHostnames = verifyHostnames;
        this.ssl = ssl;
        this.supportedProtocols = supportedProtocols;
        this.supportedCipherSuites = supportedCipherSuites;
        this.keystoreAlias = keystoreAlias;

        HttpHost[] hosts = createHosts(servers);
        ApacheHttpClient5TransportBuilder builder = ApacheHttpClient5TransportBuilder.builder(hosts);

        builder.setFailureListener(new ApacheHttpClient5Transport.FailureListener() {
            @Override
            public void onFailure(Node node) {

            }

        });

        builder.setHttpClientConfigCallback(new ApacheHttpClient5TransportBuilder.HttpClientConfigCallback() {
            @Override
            public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
                try {
                    return asyncClientBuilder(httpClientBuilder);
                } catch (Exception e) {
                    log.error("Unable to build http client", e);
                    throw new RuntimeException(e);
                }
            }
        });

        rclient = new OpenSearchClient(builder.setMapper(new JacksonJsonpMapper()).build());
    }

    private HttpHost[] createHosts(String[] servers) {
        return Arrays.stream(servers).map(server -> {
            try {
                server = addSchemeBasedOnSSL(server);
                URI uri = new URI(server);
                return new HttpHost(uri.getScheme(), uri.getHost(), uri.getPort());
            } catch (URISyntaxException e) {
                return null;
            }
        }).filter(Objects::nonNull).collect(Collectors.toList()).toArray(HttpHost[]::new);
    }

    private String addSchemeBasedOnSSL(String server) {
        server = server.replaceAll("https://|http://", "");
        String protocol = ssl ? "https://" : "http://";
        return protocol.concat(server);
    }

    public boolean index(final String content, final String index, final String type, final boolean refresh) {
        final JsonpMapper mapper = rclient._transport().jsonpMapper();
        try (StringReader reader = new StringReader(content); JsonParser parser = mapper.jsonProvider().createParser(reader)) {
            final Map<?, ?> mappings = mapper.deserialize(parser, Map.class);
            final IndexResponse response = rclient.index(
                ir -> ir.index(index).refresh(refresh ? Refresh.True : Refresh.False).document(mappings)
            );

            return response.shards().successful() > 0 && response.shards().failed() == 0;

        } catch (Exception e) {
            log.error(e.toString(), e);
            return false;
        }
    }

    private final HttpAsyncClientBuilder asyncClientBuilder(HttpAsyncClientBuilder httpClientBuilder) throws NoSuchAlgorithmException,
        KeyStoreException, UnrecoverableKeyException, KeyManagementException {

        // basic auth
        // pki auth

        if (ssl) {

            final SSLContextBuilder sslContextBuilder = SSLContexts.custom();

            if (log.isTraceEnabled()) {
                log.trace("Configure HTTP client with SSL");
            }

            if (trustStore != null) {
                sslContextBuilder.loadTrustMaterial(trustStore, null);
            }

            if (keystore != null) {
                sslContextBuilder.loadKeyMaterial(keystore, keyPassword, new PrivateKeyStrategy() {

                    @Override
                    public String chooseAlias(Map<String, PrivateKeyDetails> aliases, SSLParameters sslParameters) {
                        if (aliases == null || aliases.isEmpty()) {
                            return keystoreAlias;
                        }

                        if (keystoreAlias == null || keystoreAlias.isEmpty()) {
                            return aliases.keySet().iterator().next();
                        }

                        return keystoreAlias;
                    }
                });
            }

            final HostnameVerifier hnv = verifyHostnames ? new DefaultHostnameVerifier() : NoopHostnameVerifier.INSTANCE;

            final SSLContext sslContext = sslContextBuilder.build();
            final TlsStrategy tlsStrategy = new DefaultClientTlsStrategy(
                sslContext,
                supportedProtocols,
                supportedCipherSuites,
                SSLBufferMode.STATIC,
                HostnameVerificationPolicy.CLIENT,
                hnv
            );

            final AsyncClientConnectionManager cm = PoolingAsyncClientConnectionManagerBuilder.create().setTlsStrategy(tlsStrategy).build();
            httpClientBuilder.setConnectionManager(cm);
        }

        if (basicCredentials != null) {
            httpClientBuilder.setDefaultHeaders(
                Lists.newArrayList(new BasicHeader(HttpHeaders.AUTHORIZATION, "Basic " + basicCredentials))
            );
        }

        // TODO: set a timeout until we have a proper way to deal with back pressure
        int timeout = 5;

        RequestConfig config = RequestConfig.custom()
            .setConnectTimeout(timeout, TimeUnit.SECONDS)
            .setConnectionRequestTimeout(timeout, TimeUnit.SECONDS)
            .build();

        httpClientBuilder.setDefaultRequestConfig(config);

        return httpClientBuilder;

    }

    @Override
    public void close() throws IOException {
        if (rclient != null) {
            rclient._transport().close();
        }
    }
}
