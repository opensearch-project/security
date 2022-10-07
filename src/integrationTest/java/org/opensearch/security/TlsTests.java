/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLHandshakeException;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.NoHttpResponseException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.RestClientException;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.instanceOf;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.hasCause;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class TlsTests {

	private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

	public static final String SUPPORTED_CIPHER_SUIT = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
	public static final String NOT_SUPPORTED_CIPHER_SUITE = "TLS_RSA_WITH_AES_128_CBC_SHA";
	public static final String AUTH_INFO_ENDPOINT = "/_opendistro/_security/authinfo?pretty";

	@ClassRule
	public static LocalCluster cluster = new LocalCluster.Builder()
		.clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS).anonymousAuth(false)
		.nodeSettings(Map.of(SECURITY_SSL_HTTP_ENABLED_CIPHERS, List.of(SUPPORTED_CIPHER_SUIT)))
		.authc(AUTHC_HTTPBASIC_INTERNAL).users(USER_ADMIN).build();

	@Test
	public void shouldCreateAuditOnIncomingNonTlsConnection() throws IOException {
		try(CloseableHttpClient httpClient = HttpClients.createDefault()) {
			HttpGet request = new HttpGet("http://localhost:" + cluster.getHttpPort());

			assertThatThrownBy(() -> httpClient.execute(request), instanceOf(NoHttpResponseException.class));
		}
		//TODO check if audit, audit_category = SSL_EXCEPTION
	}

	@Test
	public void shouldSupportClientCipherSuite_positive(){
		try(TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
			HttpGet httpGet = new HttpGet(client.getHttpServerUri() + AUTH_INFO_ENDPOINT);
			String[] ciphers = { SUPPORTED_CIPHER_SUIT };

			HttpResponse httpResponse = client.executeRequest(httpGet, ciphers);

			httpResponse.assertStatusCode(200);
		}
	}

	@Test
	public void shouldSupportClientCipherSuite_negative(){
		try(TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
			HttpGet httpGet = new HttpGet(client.getHttpServerUri() + AUTH_INFO_ENDPOINT);
			String[] ciphers = { NOT_SUPPORTED_CIPHER_SUITE };

			assertThatThrownBy(() -> client.executeRequest(httpGet, ciphers), allOf(
				instanceOf(RestClientException.class),
				hasCause(SSLHandshakeException.class))
			);
		}
	}
}
