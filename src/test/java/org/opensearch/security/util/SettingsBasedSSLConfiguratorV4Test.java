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

package org.opensearch.security.util;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManagerFactory;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.function.Callback;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentLengthStrategy;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.impl.DefaultContentLengthStrategy;
import org.apache.hc.core5.http.impl.bootstrap.HttpServer;
import org.apache.hc.core5.http.impl.bootstrap.ServerBootstrap;
import org.apache.hc.core5.http.impl.io.DefaultBHttpServerConnection;
import org.apache.hc.core5.http.impl.io.DefaultHttpRequestParserFactory;
import org.apache.hc.core5.http.impl.io.DefaultHttpResponseWriterFactory;
import org.apache.hc.core5.http.io.HttpConnectionFactory;
import org.apache.hc.core5.http.io.HttpMessageParserFactory;
import org.apache.hc.core5.http.io.HttpMessageWriterFactory;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.ssl.PrivateKeyDetails;
import org.apache.hc.core5.ssl.PrivateKeyStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.network.SocketUtils;

import com.amazon.dlic.util.SettingsBasedSSLConfiguratorV4;
import com.amazon.dlic.util.SettingsBasedSSLConfiguratorV4.SSLConfig;

import static org.hamcrest.CoreMatchers.either;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.opensearch.security.ssl.SecureSSLSettings.SSLSetting.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD;

public class SettingsBasedSSLConfiguratorV4Test {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testPemTrust() throws Exception {

        try (
            TestServer testServer = new TestServer(
                "sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node1-keystore.jks",
                "secret",
                false
            )
        ) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Assert.assertTrue(rootCaPemPath.toFile().exists());

            Settings settings = Settings.builder()
                .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                .put("prefix.enable_ssl", "true")
                .put("path.home", rootCaPemPath.getParent().toString())
                .build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfiguratorV4 sbsc = new SettingsBasedSSLConfiguratorV4(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();
            SSLConnectionSocketFactory sslConnectionSocketFactory = sslConfig.toSSLConnectionSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.id, sslConnectionSocketFactory)
                .build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);

            try (CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();) {

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    // Success
                }
            }

        }
    }

    @Test
    public void testPemWrongTrust() throws Exception {

        try (
            TestServer testServer = new TestServer(
                "sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node1-keystore.jks",
                "secret",
                false
            )
        ) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/other-root-ca.pem");

            Settings settings = Settings.builder()
                .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                .put("prefix.enable_ssl", "true")
                .put("path.home", rootCaPemPath.getParent().toString())
                .build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfiguratorV4 sbsc = new SettingsBasedSSLConfiguratorV4(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();
            SSLConnectionSocketFactory sslConnectionSocketFactory = sslConfig.toSSLConnectionSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.id, sslConnectionSocketFactory)
                .build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);

            try (CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build()) {

                thrown.expect(SSLHandshakeException.class);

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    Assert.fail("Connection should have failed due to wrong trust");
                }
            }

        }
    }

    @Test
    public void testPemClientAuth() throws Exception {

        try (
            TestServer testServer = new TestServer(
                "sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node1-keystore.jks",
                "secret",
                true
            )
        ) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Settings settings = Settings.builder()
                .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                .put("prefix.enable_ssl", "true")
                .put("path.home", rootCaPemPath.getParent().toString())
                .put("prefix.enable_ssl_client_auth", "true")
                .put("prefix.pemcert_filepath", "kirk.pem")
                .put("prefix.pemkey_filepath", "kirk.key")
                .put("prefix.pemkey_password", "secret")
                .build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfiguratorV4 sbsc = new SettingsBasedSSLConfiguratorV4(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();
            SSLConnectionSocketFactory sslConnectionSocketFactory = sslConfig.toSSLConnectionSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.id, sslConnectionSocketFactory)
                .build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);

            try (CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build()) {

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    // Success
                }
            }

        }
    }

    @Test
    public void testPemClientAuthFailure() throws Exception {

        try (
            TestServer testServer = new TestServer(
                "sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node1-keystore.jks",
                "secret",
                true
            )
        ) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Settings settings = Settings.builder()
                .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                .put("prefix.enable_ssl", "true")
                .put("path.home", rootCaPemPath.getParent().toString())
                .put("prefix.enable_ssl_client_auth", "true")
                .put("prefix.pemcert_filepath", "wrong-kirk.pem")
                .put("prefix.pemkey_filepath", "wrong-kirk.key")
                .put("prefix.pemkey_password", "G0CVtComen4a")
                .build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfiguratorV4 sbsc = new SettingsBasedSSLConfiguratorV4(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();
            SSLConnectionSocketFactory sslConnectionSocketFactory = sslConfig.toSSLConnectionSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.id, sslConnectionSocketFactory)
                .build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
            try (CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build()) {

                // Due to some race condition in Java's internal network stack, this can be one
                // of the following exceptions

                thrown.expect(
                    either(instanceOf(SocketException.class)).or(instanceOf(SSLHandshakeException.class)).or(instanceOf(SSLException.class)) // Java
                    // 11:
                    // javax.net.ssl.SSLException:
                    // readHandshakeRecord
                );

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    Assert.fail("Connection should have failed due to wrong client cert");
                }
            }
        }
    }

    @Test
    public void testPemHostnameVerificationFailure() throws Exception {

        try (
            TestServer testServer = new TestServer(
                "sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node-wrong-hostname-keystore.jks",
                "secret",
                false
            )
        ) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Settings settings = Settings.builder()
                .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                .put("prefix.enable_ssl", "true")
                .put("prefix.verify_hostnames", "true")
                .put("path.home", rootCaPemPath.getParent().toString())
                .build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfiguratorV4 sbsc = new SettingsBasedSSLConfiguratorV4(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();
            SSLConnectionSocketFactory sslConnectionSocketFactory = sslConfig.toSSLConnectionSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.id, sslConnectionSocketFactory)
                .build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
            try (CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build()) {

                thrown.expect(SSLPeerUnverifiedException.class);

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    Assert.fail("Connection should have failed due to wrong hostname");
                }
            }
        }
    }

    @Test
    public void testPemHostnameVerificationOff() throws Exception {

        try (
            TestServer testServer = new TestServer(
                "sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node-wrong-hostname-keystore.jks",
                "secret",
                false
            )
        ) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Settings settings = Settings.builder()
                .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                .put("prefix.enable_ssl", "true")
                .put("prefix.verify_hostnames", "false")
                .put("path.home", rootCaPemPath.getParent().toString())
                .build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfiguratorV4 sbsc = new SettingsBasedSSLConfiguratorV4(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();
            SSLConnectionSocketFactory sslConnectionSocketFactory = sslConfig.toSSLConnectionSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.id, sslConnectionSocketFactory)
                .build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
            try (CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build()) {

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    // Success
                }
            }
        }
    }

    @Test
    public void testJksTrust() throws Exception {

        try (
            TestServer testServer = new TestServer(
                "sslConfigurator/jks/truststore.jks",
                "sslConfigurator/jks/node1-keystore.jks",
                "secret",
                false
            )
        ) {
            Path rootCaJksPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/jks/truststore.jks");

            MockSecureSettings mockSecureSettings = new MockSecureSettings();
            mockSecureSettings.setString(SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD.propertyName, "secret");
            Settings settings = Settings.builder()
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, rootCaJksPath.getFileName().toString())
                .put("prefix.enable_ssl", "true")
                .put("path.home", rootCaJksPath.getParent().toString())
                .setSecureSettings(mockSecureSettings)
                .build();
            Path configPath = rootCaJksPath.getParent();

            SettingsBasedSSLConfiguratorV4 sbsc = new SettingsBasedSSLConfiguratorV4(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();
            SSLConnectionSocketFactory sslConnectionSocketFactory = sslConfig.toSSLConnectionSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.id, sslConnectionSocketFactory)
                .build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
            try (CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build()) {

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    // Success
                }
            }

        }
    }

    @Test
    public void testJksWrongTrust() throws Exception {

        try (
            TestServer testServer = new TestServer(
                "sslConfigurator/jks/truststore.jks",
                "sslConfigurator/jks/node1-keystore.jks",
                "secret",
                false
            )
        ) {
            Path rootCaJksPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/jks/other-root-ca.jks");

            MockSecureSettings mockSecureSettings = new MockSecureSettings();
            mockSecureSettings.setString(SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD.propertyName, "secret");
            Settings settings = Settings.builder()
                .put(SSLConfigConstants.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, rootCaJksPath.getFileName().toString())
                .put("prefix.enable_ssl", "true")
                .put("path.home", rootCaJksPath.getParent().toString())
                .setSecureSettings(mockSecureSettings)
                .build();
            Path configPath = rootCaJksPath.getParent();

            SettingsBasedSSLConfiguratorV4 sbsc = new SettingsBasedSSLConfiguratorV4(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();
            SSLConnectionSocketFactory sslConnectionSocketFactory = sslConfig.toSSLConnectionSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.id, sslConnectionSocketFactory)
                .build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
            try (CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build()) {

                thrown.expect(SSLHandshakeException.class);

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    Assert.fail("Connection should have failed due to wrong trust");
                }
            }
        }
    }

    @Test
    public void testTrustAll() throws Exception {
        try (
            TestServer testServer = new TestServer(
                "sslConfigurator/jks/truststore.jks",
                "sslConfigurator/jks/node1-keystore.jks",
                "secret",
                false
            )
        ) {
            Path rootCaJksPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/jks/other-root-ca.jks");

            Settings settings = Settings.builder()
                .put("prefix.enable_ssl", "true")
                .put("prefix.trust_all", "true")
                .put("path.home", rootCaJksPath.getParent().toString())
                .build();
            Path configPath = rootCaJksPath.getParent();

            SettingsBasedSSLConfiguratorV4 sbsc = new SettingsBasedSSLConfiguratorV4(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();
            SSLConnectionSocketFactory sslConnectionSocketFactory = sslConfig.toSSLConnectionSocketFactory();
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register(URIScheme.HTTPS.id, sslConnectionSocketFactory)
                .build();
            BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(socketFactoryRegistry);
            try (CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build()) {

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    // Success
                }
            }
        }
    }

    static class TestServer implements Closeable {
        private HttpServer httpServer;
        private int port;

        TestServer(String trustStore, String keyStore, String password, boolean clientAuth) throws IOException {
            this.createHttpServer(trustStore, keyStore, password, clientAuth);
        }

        String getUri() {
            return "https://localhost:" + port + "/test";
        }

        private void createHttpServer(String trustStore, String keyStore, String password, boolean clientAuth) throws IOException {
            this.port = SocketUtils.findAvailableTcpPort();

            ServerBootstrap serverBootstrap = ServerBootstrap.bootstrap()
                .setListenerPort(port)
                .setSslContext(createSSLContext(trustStore, keyStore, password))
                .setSslSetupHandler(new Callback<SSLParameters>() {
                    @Override
                    public void execute(SSLParameters object) {
                        if (clientAuth) {
                            object.setNeedClientAuth(true);
                        }
                    }
                })
                .setConnectionFactory(new HttpConnectionFactory<DefaultBHttpServerConnection>() {

                    private ConnectionConfig cconfig = ConnectionConfig.DEFAULT;

                    @Override
                    public DefaultBHttpServerConnection createConnection(final Socket socket) throws IOException {
                        final SSLTestHttpServerConnection conn = new SSLTestHttpServerConnection(
                            "http",
                            Http1Config.DEFAULT,
                            null,
                            null,
                            DefaultContentLengthStrategy.INSTANCE,
                            DefaultContentLengthStrategy.INSTANCE,
                            DefaultHttpRequestParserFactory.INSTANCE,
                            DefaultHttpResponseWriterFactory.INSTANCE
                        );
                        conn.bind(socket);
                        return conn;
                    }
                });

            this.httpServer = serverBootstrap.create();

            httpServer.start();
        }

        @Override
        public void close() throws IOException {
            if (this.httpServer != null) {
                this.httpServer.close(CloseMode.IMMEDIATE);
            }
        }

        private SSLContext createSSLContext(String trustStorePath, String keyStorePath, String password) {

            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                KeyStore trustStore = KeyStore.getInstance("JKS");
                InputStream trustStream = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath(trustStorePath).toFile());
                trustStore.load(trustStream, password.toCharArray());
                tmf.init(trustStore);

                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                KeyStore keyStore = KeyStore.getInstance("JKS");

                Path path = FileHelper.getAbsoluteFilePathFromClassPath(keyStorePath);

                if (path == null) {
                    throw new RuntimeException("Could not find " + keyStorePath);
                }

                InputStream keyStream = new FileInputStream(path.toFile());

                keyStore.load(keyStream, password.toCharArray());
                kmf.init(keyStore, password.toCharArray());

                SSLContextBuilder sslContextBuilder = SSLContexts.custom();

                sslContextBuilder.loadTrustMaterial(trustStore, null);

                sslContextBuilder.loadKeyMaterial(keyStore, password.toCharArray(), new PrivateKeyStrategy() {

                    @Override
                    public String chooseAlias(Map<String, PrivateKeyDetails> aliases, SSLParameters sslParameters) {
                        return "node1";
                    }
                });

                return sslContextBuilder.build();
            } catch (GeneralSecurityException | IOException e) {
                throw new RuntimeException(e);
            }
        }

        static class SSLTestHttpServerConnection extends DefaultBHttpServerConnection {
            public SSLTestHttpServerConnection(
                final String scheme,
                final Http1Config http1Config,
                final CharsetDecoder chardecoder,
                final CharsetEncoder charencoder,
                final ContentLengthStrategy incomingContentStrategy,
                final ContentLengthStrategy outgoingContentStrategy,
                final HttpMessageParserFactory<ClassicHttpRequest> requestParserFactory,
                final HttpMessageWriterFactory<ClassicHttpResponse> responseWriterFactory
            ) {
                super(
                    scheme,
                    http1Config,
                    chardecoder,
                    charencoder,
                    incomingContentStrategy,
                    outgoingContentStrategy,
                    requestParserFactory,
                    responseWriterFactory
                );
            }
        }
    }
}
