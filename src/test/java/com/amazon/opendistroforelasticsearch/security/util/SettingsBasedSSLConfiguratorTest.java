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

package com.amazon.opendistroforelasticsearch.security.util;

import static org.hamcrest.CoreMatchers.either;
import static org.hamcrest.CoreMatchers.instanceOf;

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
import java.security.cert.Certificate;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.HttpConnectionFactory;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.MessageConstraints;
import org.apache.http.entity.ContentLengthStrategy;
import org.apache.http.impl.ConnSupport;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.SSLServerSetupHandler;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.io.HttpMessageParserFactory;
import org.apache.http.io.HttpMessageWriterFactory;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.opensearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.amazon.dlic.util.SettingsBasedSSLConfigurator;
import com.amazon.dlic.util.SettingsBasedSSLConfigurator.SSLConfig;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.network.SocketUtils;

public class SettingsBasedSSLConfiguratorTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testPemTrust() throws Exception {

        try (TestServer testServer = new TestServer("sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node1-keystore.jks", "secret", false)) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Assert.assertTrue(rootCaPemPath.toFile().exists());

            Settings settings = Settings.builder()
                    .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                    .put("prefix.enable_ssl", "true").put("path.home", rootCaPemPath.getParent().toString()).build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfigurator sbsc = new SettingsBasedSSLConfigurator(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory()).build()) {

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    // Success
                }
            }

        }
    }

    @Test
    public void testPemWrongTrust() throws Exception {

        try (TestServer testServer = new TestServer("sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node1-keystore.jks", "secret", false)) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/other-root-ca.pem");

            Settings settings = Settings.builder()
                    .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                    .put("prefix.enable_ssl", "true").put("path.home", rootCaPemPath.getParent().toString()).build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfigurator sbsc = new SettingsBasedSSLConfigurator(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory()).build()) {

                thrown.expect(SSLHandshakeException.class);

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    Assert.fail("Connection should have failed due to wrong trust");
                }
            }

        }
    }

    @Test
    public void testPemClientAuth() throws Exception {

        try (TestServer testServer = new TestServer("sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node1-keystore.jks", "secret", true)) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Settings settings = Settings.builder()
                    .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                    .put("prefix.enable_ssl", "true").put("path.home", rootCaPemPath.getParent().toString())
                    .put("prefix.enable_ssl_client_auth", "true").put("prefix.pemcert_filepath", "kirk.pem")
                    .put("prefix.pemkey_filepath", "kirk.key").put("prefix.pemkey_password", "secret").build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfigurator sbsc = new SettingsBasedSSLConfigurator(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory()).build()) {

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    // Success
                }
            }

        }
    }

    @Test
    public void testPemClientAuthFailure() throws Exception {

        try (TestServer testServer = new TestServer("sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node1-keystore.jks", "secret", true)) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Settings settings = Settings.builder()
                    .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                    .put("prefix.enable_ssl", "true").put("path.home", rootCaPemPath.getParent().toString())
                    .put("prefix.enable_ssl_client_auth", "true").put("prefix.pemcert_filepath", "wrong-kirk.pem")
                    .put("prefix.pemkey_filepath", "wrong-kirk.key").put("prefix.pemkey_password", "G0CVtComen4a")
                    .build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfigurator sbsc = new SettingsBasedSSLConfigurator(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory()).build()) {

                // Due to some race condition in Java's internal network stack, this can be one
                // of the following exceptions

                thrown.expect(either(instanceOf(SocketException.class)).or(instanceOf(SSLHandshakeException.class))
                        .or(instanceOf(SSLException.class)) // Java 11: javax.net.ssl.SSLException: readHandshakeRecord
                );

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    Assert.fail("Connection should have failed due to wrong client cert");
                }
            }
        }
    }

    @Test
    public void testPemHostnameVerificationFailure() throws Exception {

        try (TestServer testServer = new TestServer("sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node-wrong-hostname-keystore.jks", "secret", false)) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Settings settings = Settings.builder()
                    .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                    .put("prefix.enable_ssl", "true").put("prefix.verify_hostnames", "true")
                    .put("path.home", rootCaPemPath.getParent().toString()).build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfigurator sbsc = new SettingsBasedSSLConfigurator(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory()).build()) {

                thrown.expect(SSLPeerUnverifiedException.class);

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    Assert.fail("Connection should have failed due to wrong hostname");
                }
            }
        }
    }

    @Test
    public void testPemHostnameVerificationOff() throws Exception {

        try (TestServer testServer = new TestServer("sslConfigurator/pem/truststore.jks",
                "sslConfigurator/pem/node-wrong-hostname-keystore.jks", "secret", false)) {
            Path rootCaPemPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/pem/root-ca.pem");

            Settings settings = Settings.builder()
                    .put("prefix.pemtrustedcas_filepath", rootCaPemPath.getFileName().toString())
                    .put("prefix.enable_ssl", "true").put("prefix.verify_hostnames", "false")
                    .put("path.home", rootCaPemPath.getParent().toString()).build();
            Path configPath = rootCaPemPath.getParent();

            SettingsBasedSSLConfigurator sbsc = new SettingsBasedSSLConfigurator(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory()).build()) {

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    // Success
                }
            }
        }
    }

    @Test
    public void testJksTrust() throws Exception {

        try (TestServer testServer = new TestServer("sslConfigurator/jks/truststore.jks",
                "sslConfigurator/jks/node1-keystore.jks", "secret", false)) {
            Path rootCaJksPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/jks/truststore.jks");

            Settings settings = Settings.builder()
                    .put("opendistro_security.ssl.transport.truststore_filepath", rootCaJksPath.getFileName().toString())
                    .put("opendistro_security.ssl.transport.truststore_password", "secret").put("prefix.enable_ssl", "true")
                    .put("path.home", rootCaJksPath.getParent().toString()).build();
            Path configPath = rootCaJksPath.getParent();

            SettingsBasedSSLConfigurator sbsc = new SettingsBasedSSLConfigurator(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory()).build()) {

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    // Success
                }
            }

        }
    }

    @Test
    public void testJksWrongTrust() throws Exception {

        try (TestServer testServer = new TestServer("sslConfigurator/jks/truststore.jks",
                "sslConfigurator/jks/node1-keystore.jks", "secret", false)) {
            Path rootCaJksPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/jks/other-root-ca.jks");

            Settings settings = Settings.builder()
                    .put("opendistro_security.ssl.transport.truststore_filepath", rootCaJksPath.getFileName().toString())
                    .put("opendistro_security.ssl.transport.truststore_password", "secret").put("prefix.enable_ssl", "true")
                    .put("path.home", rootCaJksPath.getParent().toString()).build();
            Path configPath = rootCaJksPath.getParent();

            SettingsBasedSSLConfigurator sbsc = new SettingsBasedSSLConfigurator(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory()).build()) {

                thrown.expect(SSLHandshakeException.class);

                try (CloseableHttpResponse response = httpClient.execute(new HttpGet(testServer.getUri()))) {
                    Assert.fail("Connection should have failed due to wrong trust");
                }
            }
        }
    }

    @Test
    public void testTrustAll() throws Exception {
        try (TestServer testServer = new TestServer("sslConfigurator/jks/truststore.jks",
                "sslConfigurator/jks/node1-keystore.jks", "secret", false)) {
            Path rootCaJksPath = FileHelper.getAbsoluteFilePathFromClassPath("sslConfigurator/jks/other-root-ca.jks");

            Settings settings = Settings.builder().put("prefix.enable_ssl", "true").put("prefix.trust_all", "true")
                    .put("path.home", rootCaJksPath.getParent().toString()).build();
            Path configPath = rootCaJksPath.getParent();

            SettingsBasedSSLConfigurator sbsc = new SettingsBasedSSLConfigurator(settings, configPath, "prefix");

            SSLConfig sslConfig = sbsc.buildSSLConfig();

            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslConfig.toSSLConnectionSocketFactory()).build()) {

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

        private void createHttpServer(String trustStore, String keyStore, String password, boolean clientAuth)
                throws IOException {
            this.port = SocketUtils.findAvailableTcpPort();

            ServerBootstrap serverBootstrap = ServerBootstrap.bootstrap().setListenerPort(port).registerHandler("test",
                    new HttpRequestHandler() {

                        @Override
                        public void handle(HttpRequest request, HttpResponse response, HttpContext context)
                                throws HttpException, IOException {

                        }
                    });

            serverBootstrap = serverBootstrap.setSslContext(createSSLContext(trustStore, keyStore, password))
                    .setSslSetupHandler(new SSLServerSetupHandler() {

                        @Override
                        public void initialize(SSLServerSocket socket) throws SSLException {
                            if (clientAuth) {
                                socket.setNeedClientAuth(true);
                            }
                        }
                    }).setConnectionFactory(new HttpConnectionFactory<DefaultBHttpServerConnection>() {

                        private ConnectionConfig cconfig = ConnectionConfig.DEFAULT;

                        @Override
                        public DefaultBHttpServerConnection createConnection(final Socket socket) throws IOException {
                            final SSLTestHttpServerConnection conn = new SSLTestHttpServerConnection(
                                    this.cconfig.getBufferSize(), this.cconfig.getFragmentSizeHint(),
                                    ConnSupport.createDecoder(this.cconfig), ConnSupport.createEncoder(this.cconfig),
                                    this.cconfig.getMessageConstraints(), null, null, null, null);
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
                this.httpServer.shutdown(0, null);
            }
        }

        private SSLContext createSSLContext(String trustStorePath, String keyStorePath, String password) {

            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                KeyStore trustStore = KeyStore.getInstance("JKS");
                InputStream trustStream = new FileInputStream(
                        FileHelper.getAbsoluteFilePathFromClassPath(trustStorePath).toFile());
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
                    public String chooseAlias(Map<String, PrivateKeyDetails> aliases, Socket socket) {
                        return "node1";
                    }
                });

                return sslContextBuilder.build();
            } catch (GeneralSecurityException | IOException e) {
                throw new RuntimeException(e);
            }
        }

        static class SSLTestHttpServerConnection extends DefaultBHttpServerConnection {
            public SSLTestHttpServerConnection(final int buffersize, final int fragmentSizeHint,
                    final CharsetDecoder chardecoder, final CharsetEncoder charencoder,
                    final MessageConstraints constraints, final ContentLengthStrategy incomingContentStrategy,
                    final ContentLengthStrategy outgoingContentStrategy,
                    final HttpMessageParserFactory<HttpRequest> requestParserFactory,
                    final HttpMessageWriterFactory<HttpResponse> responseWriterFactory) {
                super(buffersize, fragmentSizeHint, chardecoder, charencoder, constraints, incomingContentStrategy,
                        outgoingContentStrategy, requestParserFactory, responseWriterFactory);
            }

            public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
                return ((SSLSocket) getSocket()).getSession().getPeerCertificates();
            }
        }
    }
}
