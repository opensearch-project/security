/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.httpclient;

import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;
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
import java.util.stream.Collectors;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Node;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.XContentType;

import com.google.common.collect.Lists;

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
            return new HttpClient(trustStore, basicCredentials, keystore, keyPassword, keystoreAlias, verifyHostnames, ssl,
                    supportedProtocols, supportedCipherSuites, servers);
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
    private RestHighLevelClient rclient;
    private String basicCredentials;
    private KeyStore keystore;
    private String keystoreAlias;
    private char[] keyPassword;
    private boolean verifyHostnames;
    private boolean ssl;
    private String[] supportedProtocols;
    private String[] supportedCipherSuites;

    private HttpClient(final KeyStore trustStore, final String basicCredentials, final KeyStore keystore,
            final char[] keyPassword, final String keystoreAlias, final boolean verifyHostnames, final boolean ssl, String[] supportedProtocols, String[] supportedCipherSuites, final String... servers)
            throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException,
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

        HttpHost[] hosts = Arrays.stream(servers)
                .map(s->s.split(":"))
                .map(s->new HttpHost(s[0], Integer.parseInt(s[1]),ssl?"https":"http"))
                .collect(Collectors.toList()).toArray(new HttpHost[0]);


        RestClientBuilder builder = RestClient.builder(hosts);
        //builder.setMaxRetryTimeoutMillis(10000);

        builder.setFailureListener(new RestClient.FailureListener() {
            @Override
            public void onFailure(Node node) {

            }

        });

        builder.setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
            @Override
            public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
                try {
                    return asyncClientBuilder(httpClientBuilder);
                } catch (Exception e) {
                    log.error("Unable to build http client",e);
                    throw new RuntimeException(e);
                }
            }
        });

        rclient = new RestHighLevelClient(builder);
    }

    public boolean index(final String content, final String index, final String type, final boolean refresh) {

            try {

                final IndexRequest ir = type==null?new IndexRequest(index):new IndexRequest(index, type);
                
                final IndexResponse response = rclient.index(ir
                              .setRefreshPolicy(refresh?RefreshPolicy.IMMEDIATE:RefreshPolicy.NONE)
                              .source(content, XContentType.JSON), RequestOptions.DEFAULT);

                return response.getShardInfo().getSuccessful() > 0 && response.getShardInfo().getFailed() == 0;

            } catch (Exception e) {
                log.error(e.toString(),e);
                return false;
            }
    }

    private final HttpAsyncClientBuilder asyncClientBuilder(HttpAsyncClientBuilder httpClientBuilder)
            throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {

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
                    public String chooseAlias(Map<String, PrivateKeyDetails> aliases, Socket socket) {
                        if(aliases == null || aliases.isEmpty()) {
                            return keystoreAlias;
                        }

                        if(keystoreAlias == null || keystoreAlias.isEmpty()) {
                            return aliases.keySet().iterator().next();
                        }

                        return keystoreAlias;                    }
                });
            }

            final HostnameVerifier hnv = verifyHostnames?new DefaultHostnameVerifier():NoopHostnameVerifier.INSTANCE;

            final SSLContext sslContext = sslContextBuilder.build();
            httpClientBuilder.setSSLStrategy(new SSLIOSessionStrategy(
                    sslContext,
                    supportedProtocols,
                    supportedCipherSuites,
                    hnv
                    ));
        }

        if (basicCredentials != null) {
            httpClientBuilder.setDefaultHeaders(Lists.newArrayList(new BasicHeader(HttpHeaders.AUTHORIZATION, "Basic " + basicCredentials)));
        }

        // TODO: set a timeout until we have a proper way to deal with back pressure
        int timeout = 5;

        RequestConfig config = RequestConfig.custom()
          .setConnectTimeout(timeout * 1000)
          .setConnectionRequestTimeout(timeout * 1000)
          .setSocketTimeout(timeout * 1000).build();

        httpClientBuilder.setDefaultRequestConfig(config);

        return httpClientBuilder;

    }

    @Override
    public void close() throws IOException {
        if (rclient != null) {
            rclient.close();
        }
    }
}
