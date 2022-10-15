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

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.core5.function.Factory;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.reactor.ssl.TlsDetails;

import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.security.support.PemKeyReader;
import org.opensearch.test.framework.certificate.TestCertificates;

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
	default TestRestClient getRestClient(UserCredentialsHolder user, Header... headers) {
		return getRestClient(user.getName(), user.getPassword(), headers);
	}

	default RestHighLevelClient getRestHighLevelClient(UserCredentialsHolder user) {
		
		BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
		credentialsProvider.setCredentials(new AuthScope(null, -1), new UsernamePasswordCredentials(user.getName(), user.getPassword().toCharArray()));

		return getRestHighLevelClient(credentialsProvider, Collections.emptySet());
	}

	default RestHighLevelClient getRestHighLevelClient(Collection<? extends Header> defaultHeaders) {


		return getRestHighLevelClient(null, defaultHeaders);
	}

	private RestHighLevelClient getRestHighLevelClient(BasicCredentialsProvider credentialsProvider, Collection<? extends Header> defaultHeaders) {
		RestClientBuilder.HttpClientConfigCallback configCallback = httpClientBuilder -> {
			TlsStrategy tlsStrategy = ClientTlsStrategyBuilder
				.create()
				.setSslContext(getSSLContext())
				.setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
				// See please https://issues.apache.org/jira/browse/HTTPCLIENT-2219
				.setTlsDetailsFactory(new Factory<SSLEngine, TlsDetails>() {
					@Override
					public TlsDetails create(final SSLEngine sslEngine) {
						return new TlsDetails(sslEngine.getSession(), sslEngine.getApplicationProtocol());
					}
				})
				.build();

			final AsyncClientConnectionManager cm = PoolingAsyncClientConnectionManagerBuilder.create()
					.setTlsStrategy(tlsStrategy)
					.build();

			if(credentialsProvider != null) {
				httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
			}
			httpClientBuilder.setDefaultHeaders(defaultHeaders);
			httpClientBuilder.setConnectionManager(cm);
			return httpClientBuilder;
		};

		InetSocketAddress httpAddress = getHttpAddress();
		RestClientBuilder builder = RestClient.builder(new HttpHost("https", httpAddress.getHostString(), httpAddress.getPort()))
			.setHttpClientConfigCallback(configCallback);

		return new RestHighLevelClient(builder);
	}

	default CloseableHttpClient getClosableHttpClient(String[] supportedCipherSuit) {
		CloseableHttpClientFactory factory = new CloseableHttpClientFactory(getSSLContext(), null, supportedCipherSuit);
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
		BasicHeader basicAuthHeader = getBasicAuthHeader(user, password);
		if (headers != null && headers.length > 0) {
			List<Header> concatenatedHeaders = Stream.concat(Stream.of(basicAuthHeader), Stream.of(headers)).collect(Collectors.toList());
			return getRestClient(concatenatedHeaders);
		}
		return getRestClient(basicAuthHeader);
	}

	/**
	* Returns a REST client. You can specify additional HTTP headers that will be sent with each request. Use this
	* method to test non-basic authentication, such as JWT bearer authentication.
	*/
	default TestRestClient getRestClient(Header... headers) {
		return getRestClient(Arrays.asList(headers));
	}

	default TestRestClient getRestClient(List<Header> headers) {
		return createGenericClientRestClient(headers);
	}

	default TestRestClient createGenericClientRestClient(List<Header> headers) {
		return new TestRestClient(getHttpAddress(), headers, getSSLContext());
	}

	default BasicHeader getBasicAuthHeader(String user, String password) {
		return new BasicHeader("Authorization",
				"Basic " + Base64.getEncoder().encodeToString((user + ":" + Objects.requireNonNull(password)).getBytes(StandardCharsets.UTF_8)));
	}

	private SSLContext getSSLContext() {
		X509Certificate[] trustCertificates;
					
		try {
			trustCertificates =  PemKeyReader.loadCertificatesFromFile(getTestCertificates().getRootCertificate() );

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());           

			ks.load(null);
			
			for (int i = 0; i < trustCertificates.length; i++) {
				ks.setCertificateEntry("caCert-" + i, trustCertificates[i]);	
			}

			tmf.init(ks);

			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, tmf.getTrustManagers(), null);
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
