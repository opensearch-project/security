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

package org.opensearch.security.privileges;

import java.util.List;
import java.util.Map;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.http.ApiTokenAuthenticator;
import org.opensearch.test.framework.ApiTokenConfig;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.security.auditlog.impl.AuditCategory.AUTHENTICATED;
import static org.opensearch.security.auditlog.impl.AuditCategory.GRANTED_PRIVILEGES;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

public class ApiTokenAuditTest {

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static final String API_TOKEN_PATH = "_plugins/_security/api/apitokens";
    private static final String TOKEN_PAYLOAD = """
        {
          "name": "audit-test-token",
          "cluster_permissions": ["cluster_monitor"],
          "expiration": 3600000
        }
        """;

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .users(ADMIN_USER)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName()),
                "plugins.security.unsupported.restapi.allow_securityconfig_modification",
                true
            )
        )
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .apiToken(new ApiTokenConfig().enabled(true))
        .audit(
            new AuditConfiguration(true).compliance(new AuditCompliance().enabled(true))
                .filters(new AuditFilters().enabledRest(true).enabledTransport(true))
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void testApiTokenAuthenticationIsAudited() {
        String token;
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(API_TOKEN_PATH, TOKEN_PAYLOAD);
            response.assertStatusCode(HttpStatus.SC_OK);
            token = response.getTextFromJsonBody("/token");
        }

        Header authHeader = new BasicHeader("Authorization", "ApiKey " + token);
        try (TestRestClient client = cluster.getRestClient(authHeader)) {
            TestRestClient.HttpResponse response = client.get("_cluster/health");
            response.assertStatusCode(HttpStatus.SC_OK);
        }

        auditLogsRule.assertExactlyOne(
            (AuditMessage msg) -> msg.getCategory() == AUTHENTICATED
                && msg.getInitiatingUser() != null
                && msg.getInitiatingUser().startsWith(ApiTokenAuthenticator.API_TOKEN_USER_PREFIX)
        );
        auditLogsRule.assertExactlyOne(
            (AuditMessage msg) -> msg.getCategory() == GRANTED_PRIVILEGES
                && msg.getEffectiveUser() != null
                && msg.getEffectiveUser().startsWith(ApiTokenAuthenticator.API_TOKEN_USER_PREFIX)
        );
    }
}
