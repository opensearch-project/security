/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */

package org.opensearch.security.api;

import java.util.List;
import java.util.Map;

import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import tools.jackson.databind.JsonNode;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

public class InternalUserRenameAuditTest {

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static final String API = "_plugins/_security/api";

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .users(ADMIN_USER)
        .nodeSettings(Map.of(SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + ADMIN_USER.getName() + "__" + ALL_ACCESS.getName())))
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .audit(
            new AuditConfiguration(true).compliance(new AuditCompliance().enabled(true).internalConfig(true))
                .filters(new AuditFilters().enabledRest(true).enabledTransport(true))
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void renameIsAuditedOnceWithOldAndNewNames() throws Exception {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson(API + "/internalusers/audit_src", "{\"password\":\"Audit-Test-Passw0rd\"}")
                .assertStatusCode(HttpStatus.SC_CREATED);
            client.putJson(API + "/roles/audit_role", "{\"description\":\"rename audit test\"}").assertStatusCode(HttpStatus.SC_CREATED);
            client.putJson(API + "/rolesmapping/audit_role", "{\"users\":[\"audit_src\"]}").assertStatusCode(HttpStatus.SC_CREATED);

            client.postJson(API + "/internalusers/audit_src/_rename", "{\"new_username\":\"audit_dst\"}")
                .assertStatusCode(HttpStatus.SC_OK);
        }

        auditLogsRule.assertExactlyOne(InternalUserRenameAuditTest::isRenameEvent);
        auditLogsRule.assertExactlyOne(msg -> {
            if (!isRenameEvent(msg)) {
                return false;
            }
            final JsonNode diff = diff(msg);
            assertThat(diff.get("outcome").asText(), is("completed"));
            assertThat(diff.get("previous_username").asText(), is("audit_src"));
            assertThat(diff.get("username").asText(), is("audit_dst"));
            assertThat(diff.get("updated_roles_mapping").get(0).asText(), is("audit_role"));
            assertThat(msg.getEffectiveUser(), is(ADMIN_USER.getName()));
            // The event is written from an async callback; it must still carry the originating request's context.
            assertThat(msg.getAsMap().get(AuditMessage.REMOTE_ADDRESS), notNullValue());
            assertThat(String.valueOf(msg.getAsMap().get(AuditMessage.ORIGIN)), is("REST"));
            return true;
        });
    }

    private static boolean isRenameEvent(final AuditMessage msg) {
        if (msg.getCategory() != AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE) {
            return false;
        }
        final JsonNode diff = diff(msg);
        return diff != null && diff.has("action") && "rename".equals(diff.get("action").asText());
    }

    private static JsonNode diff(final AuditMessage msg) {
        final Object content = msg.getAsMap().get(AuditMessage.COMPLIANCE_DIFF_CONTENT);
        if (content == null) {
            return null;
        }
        try {
            return DefaultObjectMapper.readTree(content.toString());
        } catch (Exception e) {
            return null;
        }
    }
}
