/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.commons.rest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManager;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.function.Factory;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.reactor.ssl.TlsDetails;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.ConfigConstants;
import org.opensearch.core.common.Strings;

/**
 * Provides builder to create low-level and high-level REST client to make calls to OpenSearch.
 *
 * Sample usage:
 *      SecureRestClientBuilder builder = new SecureRestClientBuilder(settings).build()
 *      RestClient restClient = builder.build();
 *
 * Other usage:
 *  RestClient restClient = new SecureRestClientBuilder("localhost", 9200, false)
 *                     .setUserPassword("admin", "admin")
 *                     .setTrustCerts(trustStorePath)
 *                     .build();
 *
 *
 * If https is enabled, creates RestClientBuilder using self-signed certificates or passed pem
 * as trusted.
 *
 * If https is not enabled, creates a http based client.
 */
public class SecureRestClientBuilder {

    private final boolean httpSSLEnabled;
    private final String user;
    private final String passwd;
    private final ArrayList<HttpHost> hosts = new ArrayList<>();

    private final Path configPath;
    private final Settings settings;

    private int defaultConnectTimeOutMSecs = 5000;
    private int defaultSoTimeoutMSecs = 10000;
    private int defaultConnRequestTimeoutMSecs = 3 * 60 * 1000; /* 3 mins */
    private int defaultMaxConnPerRoute = RestClientBuilder.DEFAULT_MAX_CONN_PER_ROUTE;
    private int defaultMaxConnTotal = RestClientBuilder.DEFAULT_MAX_CONN_TOTAL;

    private static final Logger log = LogManager.getLogger(SecureRestClientBuilder.class);

    /**
     * ONLY for integration tests.
     * @param host
     * @param port
     * @param httpSSLEnabled
     * @param user
     * @param passWord
     */
    public SecureRestClientBuilder(
        final String host,
        final int port,
        final boolean httpSSLEnabled,
        final String user,
        final String passWord
    ) {
        if (Strings.isNullOrEmpty(user) || Strings.isNullOrEmpty(passWord)) {
            throw new IllegalArgumentException("Invalid user or password");
        }

        this.httpSSLEnabled = httpSSLEnabled;
        this.user = user;
        this.passwd = passWord;
        this.settings = Settings.EMPTY;
        this.configPath = null;
        hosts.add(new HttpHost(httpSSLEnabled ? ConfigConstants.HTTPS : ConfigConstants.HTTP, host, port));
    }

    /**
     * ONLY for integration tests.
     * @param httpHosts
     * @param httpSSLEnabled
     * @param user
     * @param passWord
     */
    public SecureRestClientBuilder(HttpHost[] httpHosts, final boolean httpSSLEnabled, final String user, final String passWord) {

        if (Strings.isNullOrEmpty(user) || Strings.isNullOrEmpty(passWord)) {
            throw new IllegalArgumentException("Invalid user or password");
        }

        this.httpSSLEnabled = httpSSLEnabled;
        this.user = user;
        this.passwd = passWord;
        this.settings = Settings.EMPTY;
        this.configPath = null;
        hosts.addAll(Arrays.asList(httpHosts));
    }

    public SecureRestClientBuilder(Settings settings, Path configPath) {

        this.httpSSLEnabled = settings.getAsBoolean(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_ENABLED, false);
        this.settings = settings;
        this.configPath = configPath;
        this.user = null;
        this.passwd = null;
        String host = ConfigConstants.HOST_DEFAULT;
        int port = settings.getAsInt(ConfigConstants.HTTP_PORT, ConfigConstants.HTTP_PORT_DEFAULT);
        hosts.add(new HttpHost(httpSSLEnabled ? ConfigConstants.HTTPS : ConfigConstants.HTTP, host, port));
    }

    public SecureRestClientBuilder(Settings settings, Path configPath, HttpHost[] httpHosts) {
        this.httpSSLEnabled = settings.getAsBoolean(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_ENABLED, false);
        this.settings = settings;
        this.configPath = configPath;
        this.user = null;
        this.passwd = null;
        hosts.addAll(Arrays.asList(httpHosts));
    }

    /**
     * Creates a low-level Rest client.
     * @return
     * @throws IOException
     */
    public RestClient build() throws IOException {
        return createRestClientBuilder().build();
    }

    public SecureRestClientBuilder setConnectTimeout(int timeout) {
        this.defaultConnectTimeOutMSecs = timeout;
        return this;
    }

    public SecureRestClientBuilder setSocketTimeout(int timeout) {
        this.defaultSoTimeoutMSecs = timeout;
        return this;
    }

    public SecureRestClientBuilder setConnectionRequestTimeout(int timeout) {
        this.defaultConnRequestTimeoutMSecs = timeout;
        return this;
    }

    public SecureRestClientBuilder setMaxConnPerRoute(final int maxConnPerRoute) {
        this.defaultMaxConnPerRoute = maxConnPerRoute;
        return this;
    }

    public SecureRestClientBuilder setMaxConnTotal(final int maxConnTotal) {
        this.defaultMaxConnTotal = maxConnTotal;
        return this;
    }

    private RestClientBuilder createRestClientBuilder() throws IOException {
        RestClientBuilder builder = RestClient.builder(hosts.toArray(new HttpHost[hosts.size()]));

        builder.setRequestConfigCallback(new RestClientBuilder.RequestConfigCallback() {
            @Override
            public RequestConfig.Builder customizeRequestConfig(RequestConfig.Builder requestConfigBuilder) {
                return requestConfigBuilder
                    .setConnectTimeout(Timeout.ofMilliseconds(defaultConnectTimeOutMSecs))
                    .setResponseTimeout(Timeout.ofMilliseconds(defaultSoTimeoutMSecs))
                    .setConnectionRequestTimeout(Timeout.ofMilliseconds(defaultConnRequestTimeoutMSecs));
            }
        });

        final SSLContext sslContext;
        try {
            sslContext = createSSLContext();
        } catch (GeneralSecurityException | IOException ex) {
            throw new IOException(ex);
        }
        final CredentialsProvider credentialsProvider = createCredsProvider();
        builder.setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
            @Override
            public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
                if (sslContext != null) {
                    TlsStrategy tlsStrategy = ClientTlsStrategyBuilder
                        .create()
                        .setSslContext(sslContext)
                        // See please https://issues.apache.org/jira/browse/HTTPCLIENT-2219
                        .setTlsDetailsFactory(new Factory<SSLEngine, TlsDetails>() {
                            @Override
                            public TlsDetails create(final SSLEngine sslEngine) {
                                return new TlsDetails(sslEngine.getSession(), sslEngine.getApplicationProtocol());
                            }
                        })
                        .build();
                    PoolingAsyncClientConnectionManager connectionManager = PoolingAsyncClientConnectionManagerBuilder
                        .create()
                        .setTlsStrategy(tlsStrategy)
                        .setMaxConnPerRoute(defaultMaxConnPerRoute)
                        .setMaxConnTotal(defaultMaxConnTotal)
                        .build();
                    httpClientBuilder.setConnectionManager(connectionManager);
                }
                if (credentialsProvider != null) {
                    httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                }
                return httpClientBuilder;
            }
        });
        return builder;
    }

    private SSLContext createSSLContext() throws IOException, GeneralSecurityException {
        SSLContextBuilder builder = new SSLContextBuilder();
        if (httpSSLEnabled) {
            // Handle trust store
            String pemFile = getTrustPem();
            if (Strings.isNullOrEmpty(pemFile)) {
                builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
            } else {
                String pem = resolve(pemFile, configPath);
                KeyStore trustStore = new TrustStore(pem).create();
                builder.loadTrustMaterial(trustStore, null);
            }

            // Handle key store.
            KeyStore keyStore = getKeyStore();
            if (keyStore != null) {
                builder.loadKeyMaterial(keyStore, getKeystorePasswd().toCharArray());
            }

        }
        return builder.build();
    }

    private CredentialsProvider createCredsProvider() {
        if (Strings.isNullOrEmpty(user) || Strings.isNullOrEmpty(passwd))
            return null;

        final BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(new AuthScope(null, -1), new UsernamePasswordCredentials(user, passwd.toCharArray()));
        return credentialsProvider;
    }

    private String resolve(final String originalFile, final Path configPath) {
        String path = null;
        if (originalFile != null && originalFile.length() > 0) {
            path = configPath.resolve(originalFile).toAbsolutePath().toString();
            log.debug("Resolved {} to {} against {}", originalFile, path, configPath.toAbsolutePath().toString());
        }

        if (path == null || path.length() == 0) {
            throw new OpenSearchException("Empty file path for " + originalFile);
        }

        if (Files.isDirectory(Paths.get(path), LinkOption.NOFOLLOW_LINKS)) {
            throw new OpenSearchException("Is a directory: " + path + " Expected a file for " + originalFile);
        }

        if (!Files.isReadable(Paths.get(path))) {
            throw new OpenSearchException(
                "Unable to read "
                    + path
                    + " ("
                    + Paths.get(path)
                    + "). Please make sure this files exists and is readable regarding to permissions. Property: "
                    + originalFile
            );
        }
        if ("".equals(path)) {
            path = null;
        }
        return path;
    }

    private String getTrustPem() {
        return settings.get(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, null);
    }

    private String getKeystorePasswd() {
        return ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD_SETTING.get(settings).toString();
    }

    private KeyStore getKeyStore() throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("jks");
        String keyStoreFile = settings.get(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, null);
        String passwd = ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD_SETTING.get(settings).toString();
        if (Strings.isNullOrEmpty(keyStoreFile) || Strings.isNullOrEmpty(passwd)) {
            return null;
        }
        String keyStorePath = resolve(keyStoreFile, configPath);
        try (InputStream is = Files.newInputStream(Paths.get(keyStorePath))) {
            keyStore.load(is, passwd.toCharArray());
        }
        return keyStore;
    }
}