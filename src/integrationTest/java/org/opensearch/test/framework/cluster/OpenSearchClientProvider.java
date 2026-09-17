/*
 * Copyright 2020 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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

package org.opensearch.test.framework.cluster;

import java.io.IOException;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;

import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.jackson3.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.OpenSearchException;
import org.opensearch.client.opensearch.core.FieldCapsRequest;
import org.opensearch.client.opensearch.core.FieldCapsResponse;
import org.opensearch.client.opensearch.generic.Bodies;
import org.opensearch.client.opensearch.generic.Requests;
import org.opensearch.client.opensearch.generic.Requests.JsonBodyBuilder;
import org.opensearch.client.opensearch.generic.Response;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.httpclient5.ApacheHttpClient5TransportBuilder;
import org.opensearch.client.util.ApiTypeHelper;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.support.PemKeyReader;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.certificate.TestCertificates;

import jakarta.json.stream.JsonGenerator;
import reactor.netty.http.HttpProtocol;

import static org.opensearch.security.ssl.util.SSLConfigConstants.DEFAULT_STORE_TYPE;
import static org.opensearch.test.framework.cluster.TestRestClientConfiguration.getBasicAuthHeader;

/**
 * OpenSearchClientProvider provides methods to get a REST client for an underlying cluster or node.
 *
 * This interface is implemented by both LocalCluster and LocalOpenSearchCluster.Node. Thus, it is possible to get a
 * REST client for a whole cluster (without choosing the node it is operating on) or to get a REST client for a specific
 * node.
 */
public interface OpenSearchClientProvider {

    String getClusterName();

    TestCertificates getTestCertificates();

    InetSocketAddress getHttpAddress();

    InetSocketAddress getTransportAddress();

    default URI getHttpAddressAsURI() {
        InetSocketAddress address = getHttpAddress();
        return URI.create("https://" + address.getHostString() + ":" + address.getPort());
    }

    /**
     * Returns a REST client that sends requests with basic authentication for the specified User object. Optionally,
     * additional HTTP headers can be specified which will be sent with each request.
     *
     * This method should be usually preferred. The other getRestClient() methods shall be only used for specific
     * situations.
     */
    default TestRestClient getRestClient(UserCredentialsHolder user, CertificateData useCertificateData, Header... headers) {
        return getRestClient(user.getName(), user.getPassword(), useCertificateData, headers);
    }

    default TestRestClient getRestClient(UserCredentialsHolder user, Header... headers) {
        if (user.isAdminCertUser()) {
            return getRestClient(getTestCertificates().getAdminCertificateData());
        }
        return getRestClient(user.getName(), user.getPassword(), null, headers);
    }

    default TestRestClient getAdminCertRestClient() {
        return getRestClient(getTestCertificates().getAdminCertificateData());
    }

    static final class CloseableOpenSearchClient extends OpenSearchClient implements AutoCloseable {
        public CloseableOpenSearchClient(OpenSearchTransport transport) {
            super(transport);
        }

        @Override
        public FieldCapsResponse fieldCaps(FieldCapsRequest request) throws IOException, OpenSearchException {
            // Awaits https://github.com/opensearch-project/opensearch-java/issues/1792
            final JsonpMapper jsonpMapper = _transport().jsonpMapper();

            final FieldCapsRequest r = FieldCapsRequest.builder()
                .fields(ApiTypeHelper.undefinedList())
                .index(request.index())
                .indexFilter(request.indexFilter())
                .build();

            String indexPrefix = "";
            if (request.index().size() == 1) {
                indexPrefix = "/" + request.index().get(0);
            }

            JsonBodyBuilder builder = Requests.builder()
                .endpoint(indexPrefix + "/_field_caps")
                .method("GET")
                .query(Map.of("fields", request.fields().stream().collect(Collectors.joining(","))));

            try (StringWriter writer = new StringWriter()) {
                try (JsonGenerator generator = jsonpMapper.jsonProvider().createGenerator(writer)) {
                    r.serialize(generator, jsonpMapper);
                }
                builder = builder.body(Bodies.json(writer.toString()));
            }

            final Response resp = generic().execute(builder.build());
            return resp.getBody()
                .map(body -> Bodies.json(body, FieldCapsResponse._DESERIALIZER, jsonpMapper))
                .orElseThrow(() -> new IOException("Response body is required"));
        }

        @Override
        public void close() throws IOException {
            ForkJoinPool.commonPool().submit(() -> {
                // Do the closing of the restClient asynchronously, as it might cause a 5 second delay
                try {
                    _transport().close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    default CloseableOpenSearchClient getClient(String username, String password, Header... headers) {
        return getClient(new UserCredentialsHolder() {
            @Override
            public String getName() {
                return username;
            }

            @Override
            public String getPassword() {
                return password;
            }
        }, Arrays.asList(headers));
    }

    default CloseableOpenSearchClient getClient(UserCredentialsHolder user) {
        return getClient(user, Collections.emptySet());
    }

    default CloseableOpenSearchClient getClient(UserCredentialsHolder user, Collection<? extends Header> defaultHeaders) {

        BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(
            new AuthScope(null, -1),
            new UsernamePasswordCredentials(user.getName(), user.getPassword().toCharArray())
        );

        return getClient(credentialsProvider, defaultHeaders);
    }

    default CloseableOpenSearchClient getClient(Collection<? extends Header> defaultHeaders) {
        return getClient((BasicCredentialsProvider) null, defaultHeaders);
    }

    default CloseableOpenSearchClient getClient(BasicCredentialsProvider credentialsProvider, Collection<? extends Header> defaultHeaders) {
        ApacheHttpClient5TransportBuilder.HttpClientConfigCallback configCallback = httpClientBuilder -> {
            TlsStrategy tlsStrategy = ClientTlsStrategyBuilder.create()
                .setSslContext(getSSLContext())
                .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .buildAsync();

            final AsyncClientConnectionManager cm = PoolingAsyncClientConnectionManagerBuilder.create().setTlsStrategy(tlsStrategy).build();

            if (credentialsProvider != null) {
                httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
            }
            httpClientBuilder.setDefaultHeaders(defaultHeaders);
            httpClientBuilder.setConnectionManager(cm);
            httpClientBuilder.setDefaultHeaders(defaultHeaders);
            return httpClientBuilder;
        };

        InetSocketAddress httpAddress = getHttpAddress();
        ApacheHttpClient5TransportBuilder builder = ApacheHttpClient5TransportBuilder.builder(
            new HttpHost("https", httpAddress.getHostString(), httpAddress.getPort())
        ).setHttpClientConfigCallback(configCallback);

        return new CloseableOpenSearchClient(builder.setMapper(new JacksonJsonpMapper()).build());
    }

    default CloseableHttpClient getClosableHttpClient(String[] supportedCipherSuit) {
        CloseableHttpClientFactory factory = new CloseableHttpClientFactory(getSSLContext(), null, null, supportedCipherSuit);
        return factory.getHTTPClient();
    }

    /**
     * Returns a REST client that sends requests with basic authentication for the specified user name and password. Optionally,
     * additional HTTP headers can be specified which will be sent with each request.
     *
     * Normally, you should use the method with the User object argument instead. Use this only if you need more
     * control over username and password - for example, when you want to send a wrong password.
     */
    default TestRestClient getRestClient(String user, String password, Header... headers) {
        return createGenericClientRestClient(new TestRestClientConfiguration().username(user).password(password).headers(headers));
    }

    default TestRestClient getRestClient(String user, String password, CertificateData useCertificateData, Header... headers) {
        Header basicAuthHeader = getBasicAuthHeader(user, password);
        if (headers != null && headers.length > 0) {
            List<Header> concatenatedHeaders = Stream.concat(Stream.of(basicAuthHeader), Stream.of(headers)).collect(Collectors.toList());
            return getRestClient(concatenatedHeaders, useCertificateData);
        }
        return getRestClient(useCertificateData, basicAuthHeader);
    }

    /**
     * Returns a REST client. You can specify additional HTTP headers that will be sent with each request. Use this
     * method to test non-basic authentication, such as JWT bearer authentication.
     */
    default TestRestClient getRestClient(CertificateData useCertificateData, Header... headers) {
        return getRestClient(Arrays.asList(headers), useCertificateData);
    }

    /**
     * Returns a generic HTTP/1.1/HTTP 2.0/HTTP 3.0 client.
     */
    default ReactorHttpClient getGenericClient(HttpProtocol protocol, boolean secure, Settings settings) {
        return new ReactorHttpClient(protocol, true, secure, settings, getHttpAddress());
    }

    default TestRestClient getRestClient(Header... headers) {
        return getRestClient((CertificateData) null, headers);
    }

    default TestRestClient getRestClient(List<Header> headers) {
        return createGenericClientRestClient(new TestRestClientConfiguration().headers(headers));
    }

    default TestRestClient getRestClient(List<Header> headers, CertificateData useCertificateData) {
        return createGenericClientRestClient(headers, useCertificateData, null);
    }

    default TestRestClient getSecurityDisabledRestClient() {
        return new TestRestClient(getHttpAddress(), List.of(), getSSLContext(null), null, false, false);
    }

    default TestRestClient createGenericClientRestClient(
        List<Header> headers,
        CertificateData useCertificateData,
        InetAddress sourceInetAddress
    ) {
        return new TestRestClient(getHttpAddress(), headers, getSSLContext(useCertificateData), sourceInetAddress, true, false);
    }

    default TestRestClient createGenericClientRestClient(TestRestClientConfiguration configuration) {
        return new TestRestClient(
            getHttpAddress(),
            configuration.getHeaders(),
            getSSLContext(),
            configuration.getSourceInetAddress(),
            true,
            false
        );
    }

    private SSLContext getSSLContext() {
        return getSSLContext(null);
    }

    private SSLContext getSSLContext(CertificateData useCertificateData) {
        X509Certificate[] trustCertificates;

        try {
            trustCertificates = PemKeyReader.loadCertificatesFromFile(getTestCertificates().getRootCertificate());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore ks = KeyStore.getInstance(DEFAULT_STORE_TYPE);

            ks.load(null);

            for (int i = 0; i < trustCertificates.length; i++) {
                ks.setCertificateEntry("caCert-" + i, trustCertificates[i]);
            }
            KeyManager[] keyManagers = null;
            if (useCertificateData != null) {
                Certificate[] chainOfTrust = { useCertificateData.certificate() };
                ks.setKeyEntry("admin-certificate", useCertificateData.getKey(), null, chainOfTrust);
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(ks, null);
                keyManagers = keyManagerFactory.getKeyManagers();
            }

            tmf.init(ks);

            SSLContext sslContext = SSLContext.getInstance("TLS");

            sslContext.init(keyManagers, tmf.getTrustManagers(), null);
            return sslContext;

        } catch (Exception e) {
            throw new RuntimeException("Error loading root CA ", e);
        }
    }

    public interface UserCredentialsHolder {
        String getName();

        String getPassword();

        default boolean isAdminCertUser() {
            return false;
        }
    }

}
