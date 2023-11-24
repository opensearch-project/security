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
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;

import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.security.support.PemKeyReader;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.certificate.TestCertificates;

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
        return getRestClient(user.getName(), user.getPassword(), null, headers);
    }

    default RestHighLevelClient getRestHighLevelClient(String username, String password, Header... headers) {
        return getRestHighLevelClient(new UserCredentialsHolder() {
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

    default RestHighLevelClient getRestHighLevelClient(UserCredentialsHolder user) {
        return getRestHighLevelClient(user, Collections.emptySet());
    }

    default RestHighLevelClient getRestHighLevelClient(UserCredentialsHolder user, Collection<? extends Header> defaultHeaders) {

        BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(new AuthScope(null, -1), new UsernamePasswordCredentials(user.getName(), user.getPassword()));

        return getRestHighLevelClient(credentialsProvider, defaultHeaders);
    }

    default RestHighLevelClient getRestHighLevelClient(Collection<? extends Header> defaultHeaders) {
        return getRestHighLevelClient((BasicCredentialsProvider) null, defaultHeaders);
    }

    default RestHighLevelClient getRestHighLevelClient(
        BasicCredentialsProvider credentialsProvider,
        Collection<? extends Header> defaultHeaders
    ) {
        RestClientBuilder.HttpClientConfigCallback configCallback = httpClientBuilder -> {
            Optional.ofNullable(credentialsProvider).ifPresent(httpClientBuilder::setDefaultCredentialsProvider);
            httpClientBuilder.setSSLStrategy(
                new SSLIOSessionStrategy(
                    getSSLContext(),
                    /* Use default supported protocols */ null,
                    /* Use default supported cipher suites */ null,
                    NoopHostnameVerifier.INSTANCE
                )
            );
            httpClientBuilder.setDefaultHeaders(defaultHeaders);
            return httpClientBuilder;
        };

        InetSocketAddress httpAddress = getHttpAddress();
        RestClientBuilder builder = RestClient.builder(new HttpHost(httpAddress.getHostString(), httpAddress.getPort(), "https"))
            .setHttpClientConfigCallback(configCallback);

        return new RestHighLevelClient(builder);
    }

    default org.apache.http.impl.client.CloseableHttpClient getClosableHttpClient(String[] supportedCipherSuit) {
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

    default TestRestClient getRestClient(Header... headers) {
        return getRestClient((CertificateData) null, headers);
    }

    default TestRestClient getRestClient(List<Header> headers) {
        return createGenericClientRestClient(new TestRestClientConfiguration().headers(headers));

    }

    default TestRestClient getRestClient(List<Header> headers, CertificateData useCertificateData) {
        return createGenericClientRestClient(headers, useCertificateData, null);
    }

    default TestRestClient createGenericClientRestClient(
        List<Header> headers,
        CertificateData useCertificateData,
        InetAddress sourceInetAddress
    ) {
        return new TestRestClient(getHttpAddress(), headers, getSSLContext(useCertificateData), sourceInetAddress);
    }

    default TestRestClient createGenericClientRestClient(TestRestClientConfiguration configuration) {
        return new TestRestClient(getHttpAddress(), configuration.getHeaders(), getSSLContext(), configuration.getSourceInetAddress());
    }

    private SSLContext getSSLContext() {
        return getSSLContext(null);
    }

    private SSLContext getSSLContext(CertificateData useCertificateData) {
        X509Certificate[] trustCertificates;

        try {
            trustCertificates = PemKeyReader.loadCertificatesFromFile(getTestCertificates().getRootCertificate().getAbsolutePath());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

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
    }

}
