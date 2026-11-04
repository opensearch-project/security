/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security;

import java.util.Map;

import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
 * Multi-node integration tests verifying that audit field enrichment (user_roles, auth_method)
 * survives User serialization across nodes. Uses a 3-node cluster (1 cluster manager + 2 data nodes)
 * to exercise the header-deserialization fallback path in enrichWithUserContext().
 */
public class AuditFieldEnrichmentMultiNodeTest {

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(
        new TestSecurityConfig.Role("all_access").clusterPermissions("*").indexPermissions("*").on("*")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.DEFAULT)
        .users(ADMIN_USER)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .audit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(true)))
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    /**
     * Verifies that user_roles is present on shard-level audit events that fire on data nodes.
     * The User object is serialized to a header on the coordinating node and deserialized on
     * data nodes — securityRoles survives this round-trip because it is in serialPersistentFields.
     * Asserts the concrete auth_method value ("basic") so a null-from-deserialization
     * cannot hide behind a coordinator-side event.
     */
    @Test
    public void shouldCaptureUserRolesOnCrossNodeShardEvents() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            // Create an index with 2 primary shards to ensure distribution across data nodes
            client.putJson("multinode-test-index", "{\"settings\": {\"number_of_shards\": 2, \"number_of_replicas\": 1}}");
            // Index a document — triggers shard-level transport operations on data nodes
            client.putJson("multinode-test-index/_doc/1", "{\"field\": \"value\"}");
        }

        // GRANTED_PRIVILEGES events from shard-level ops should have user_roles and concrete auth_method
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.GRANTED_PRIVILEGES) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object roles = fields.get(AuditMessage.USER_ROLES);
            Object authMethod = fields.get(AuditMessage.AUTH_METHOD);
            return roles != null && roles.toString().contains("all_access") && "basic".equals(String.valueOf(authMethod));
        });
    }

    /**
     * Verifies that auth_method is present on shard-level audit events that fire on data nodes.
     * Before the serialization fix, authenticatedBy was transient and lost during cross-node
     * User serialization — this test pins the corrected behavior by asserting the concrete
     * value ("basic") so a null-from-deserialization cannot hide behind a coordinator-side event.
     */
    @Test
    public void shouldCaptureAuthMethodOnCrossNodeShardEvents() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            // Create an index with 2 primary shards to ensure distribution across data nodes
            client.putJson("multinode-auth-test-index", "{\"settings\": {\"number_of_shards\": 2, \"number_of_replicas\": 1}}");
            // Index a document — triggers shard-level transport operations on data nodes
            client.putJson("multinode-auth-test-index/_doc/1", "{\"field\": \"value\"}");
        }

        // GRANTED_PRIVILEGES events from shard-level ops should have concrete auth_method value
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.GRANTED_PRIVILEGES) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object authMethod = fields.get(AuditMessage.AUTH_METHOD);
            return "basic".equals(String.valueOf(authMethod));
        });
    }

    /**
     * Verifies both user_roles and auth_method are present on GRANTED_PRIVILEGES events triggered
     * by the read-path (search). This exercises the two-arg enrichWithUserContext(msg, user) overload
     * used for pre-resolved User objects in transport audit paths, and filters by the search action
     * to provide distinct coverage beyond the write-path GRANTED_PRIVILEGES tests above.
     */
    @Test
    public void shouldCaptureRolesAndAuthMethodTogetherOnCrossNodeEvents() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson("multinode-combined-test-index", "{\"settings\": {\"number_of_shards\": 2, \"number_of_replicas\": 1}}");
            client.putJson("multinode-combined-test-index/_doc/1", "{\"field\": \"value\"}");
            // Search triggers read-path shard-level fan-out on data nodes
            client.get("multinode-combined-test-index/_search?q=*");
        }

        // Assert on search-path GRANTED_PRIVILEGES — filters by indices:data/read/search action
        // to differentiate from the write-path tests above
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.GRANTED_PRIVILEGES) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object privilege = fields.get(AuditMessage.PRIVILEGE);
            if (privilege == null || !privilege.toString().contains("indices:data/read/search")) return false;
            Object roles = fields.get(AuditMessage.USER_ROLES);
            Object authMethod = fields.get(AuditMessage.AUTH_METHOD);
            return roles != null && roles.toString().contains("all_access") && "basic".equals(String.valueOf(authMethod));
        });
    }
}
