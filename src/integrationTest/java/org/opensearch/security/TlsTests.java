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
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.opensearch.security.auditlog.AuditLog.Origin.REST;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED_CIPHERS;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.audit.AuditMessagePredicate.auditPredicate;
import static org.opensearch.test.framework.cluster.TestRestClientConfiguration.getBasicAuthHeader;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class TlsTests {

    private static final User USER_ADMIN = new User("admin").roles(ALL_ACCESS);

    public static final String SUPPORTED_CIPHER_SUIT = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    public static final String NOT_SUPPORTED_CIPHER_SUITE = "TLS_RSA_WITH_AES_128_CBC_SHA";
    public static final String AUTH_INFO_ENDPOINT = "/_opendistro/_security/authinfo?pretty";

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(false)
        .nodeSettings(Map.of(SECURITY_SSL_HTTP_ENABLED_CIPHERS, List.of(SUPPORTED_CIPHER_SUIT)))
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .audit(
            new AuditConfiguration(true).compliance(new AuditCompliance().enabled(true))
                .filters(new AuditFilters().enabledRest(true).enabledTransport(true))
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldCreateAuditOnIncomingNonTlsConnection() throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("http://localhost:" + cluster.getHttpPort());

            assertThatThrownBy(() -> httpClient.execute(request), instanceOf(NoHttpResponseException.class));
        }
        auditLogsRule.assertAtLeast(1, auditPredicate(AuditCategory.SSL_EXCEPTION).withLayer(REST));
    }

    @Test
    public void shouldSupportClientCipherSuite_positive() throws IOException {
        try (CloseableHttpClient client = cluster.getClosableHttpClient(new String[] { SUPPORTED_CIPHER_SUIT })) {
            HttpGet httpGet = new HttpGet("https://localhost:" + cluster.getHttpPort() + AUTH_INFO_ENDPOINT);
            httpGet.addHeader(getBasicAuthHeader(USER_ADMIN.getName(), USER_ADMIN.getPassword()));

            try (CloseableHttpResponse response = client.execute(httpGet)) {

                int responseStatusCode = response.getStatusLine().getStatusCode();
                assertThat(responseStatusCode, equalTo(200));
            }
        }
    }

    @Test
    public void shouldSupportClientCipherSuite_negative() throws IOException {
        try (CloseableHttpClient client = cluster.getClosableHttpClient(new String[] { NOT_SUPPORTED_CIPHER_SUITE })) {
            HttpGet httpGet = new HttpGet("https://localhost:" + cluster.getHttpPort() + AUTH_INFO_ENDPOINT);

            assertThatThrownBy(() -> client.execute(httpGet), instanceOf(SSLHandshakeException.class));
        }
    }
}
