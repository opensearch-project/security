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
 * Integration tests verifying that audit field enrichment adds user_agent,
 * user roles, and auth method to FGAC audit events.
 */
public class AuditFieldEnrichmentTest {

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(
        new TestSecurityConfig.Role("all_access").clusterPermissions("*").indexPermissions("*").on("*")
    );

    private static final TestSecurityConfig.User LIMITED_USER = new TestSecurityConfig.User("limited").roles(
        new TestSecurityConfig.Role("read_only").clusterPermissions("cluster:monitor/*").indexPermissions("indices:data/read/*").on("*")
    );

    private static final TestSecurityConfig.User MULTI_ROLE_USER = new TestSecurityConfig.User("multirole").roles(
        new TestSecurityConfig.Role("role_a").clusterPermissions("*").indexPermissions("*").on("*"),
        new TestSecurityConfig.Role("role_b").clusterPermissions("*").indexPermissions("*").on("*")
    );

    private static final TestSecurityConfig.User NO_ROLES_USER = new TestSecurityConfig.User("noroles");

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .users(ADMIN_USER, LIMITED_USER, MULTI_ROLE_USER, NO_ROLES_USER)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .audit(new AuditConfiguration(true).filters(new AuditFilters().enabledRest(true).enabledTransport(true)))
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void shouldCaptureUserAgentInAuditEvent() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.AUTHENTICATED) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object userAgent = fields.get(AuditMessage.USER_AGENT);
            return userAgent != null;
        });
    }

    @Test
    public void shouldCaptureUserRolesInAuditEvent() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.AUTHENTICATED) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object roles = fields.get(AuditMessage.USER_ROLES);
            if (roles == null) return false;
            return roles.toString().contains("all_access");
        });
    }

    @Test
    public void shouldCaptureAuthMethodInAuditEvent() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.AUTHENTICATED) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object authMethod = fields.get(AuditMessage.AUTH_METHOD);
            return authMethod != null;
        });
    }

    @Test
    public void shouldNotFailOnFailedLogin() {
        // Use wrong credentials — auth fails, User object won't be in ThreadContext
        try (TestRestClient client = cluster.getRestClient("nonexistent", "wrongpassword")) {
            client.get("_cluster/health");
        }

        // FAILED_LOGIN event should have user_agent (from REST headers) but NOT roles/auth (no User object)
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.FAILED_LOGIN) return false;
            Map<String, Object> fields = msg.getAsMap();
            // user_agent comes from headers — available even on failed login
            Object userAgent = fields.get(AuditMessage.USER_AGENT);
            // roles and auth_method come from User object — NOT available on failed login
            Object roles = fields.get(AuditMessage.USER_ROLES);
            Object authMethod = fields.get(AuditMessage.AUTH_METHOD);
            return userAgent != null && roles == null && authMethod == null;
        });
    }

    @Test
    public void shouldCaptureRolesOnMissingPrivileges() {
        try (TestRestClient client = cluster.getRestClient(LIMITED_USER)) {
            // Try to write — should be denied
            client.putJson("forbidden-index/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.MISSING_PRIVILEGES) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object roles = fields.get(AuditMessage.USER_ROLES);
            // Roles should still be present even on denied requests
            return roles != null && roles.toString().contains("read_only");
        });
    }

    @Test
    public void shouldHandleMultipleRoles() {
        try (TestRestClient client = cluster.getRestClient(MULTI_ROLE_USER)) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.AUTHENTICATED) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object roles = fields.get(AuditMessage.USER_ROLES);
            if (roles == null) return false;
            String rolesStr = roles.toString();
            return rolesStr.contains("role_a") && rolesStr.contains("role_b");
        });
    }

    @Test
    public void shouldCaptureRolesAndAuthOnGrantedPrivileges() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.GRANTED_PRIVILEGES) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object roles = fields.get(AuditMessage.USER_ROLES);
            Object authMethod = fields.get(AuditMessage.AUTH_METHOD);
            return roles != null && authMethod != null;
        });
    }

    @Test
    public void shouldCaptureRolesOnIndexEvent() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            // indices:admin/* actions trigger INDEX_EVENT
            client.putJson("enrichment-test-index/_doc/1", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.INDEX_EVENT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object roles = fields.get(AuditMessage.USER_ROLES);
            return roles != null;
        });
    }

    @Test
    public void shouldCaptureRolesOnClusterSettingsChange() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson("_cluster/settings", "{\"transient\": {\"cluster.routing.allocation.enable\": \"all\"}}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.CLUSTER_SETTINGS_CHANGED) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object roles = fields.get(AuditMessage.USER_ROLES);
            Object authMethod = fields.get(AuditMessage.AUTH_METHOD);
            return roles != null && authMethod != null;
        });
    }

    @Test
    public void shouldCaptureRolesOnSecurityIndexAttempt() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            // Attempt to write directly to the security index — triggers OPENDISTRO_SECURITY_INDEX_ATTEMPT
            client.putJson(".opendistro_security/_doc/test", "{\"field\": \"value\"}");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.OPENDISTRO_SECURITY_INDEX_ATTEMPT) return false;
            Map<String, Object> fields = msg.getAsMap();
            Object roles = fields.get(AuditMessage.USER_ROLES);
            return roles != null;
        });
    }

    @Test
    public void shouldHandleAdminCertUserGracefully() {
        // Admin cert-based user bypasses normal auth (admin DN trusted directly)
        try (TestRestClient client = cluster.getRestClient(cluster.getTestCertificates().getAdminCertificateData())) {
            client.get("_cluster/health");
        }

        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.GRANTED_PRIVILEGES) return false;
            Map<String, Object> fields = msg.getAsMap();
            // Admin cert users bypass BackendRegistry — auth_method and roles may be null.
            // Key assertion: no NPE, event is produced with privilege field intact.
            return fields.get(AuditMessage.PRIVILEGE) != null;
        });
    }

    @Test
    public void shouldNotCrashWhenUserHasNoRolesMapped() {
        try (TestRestClient client = cluster.getRestClient(NO_ROLES_USER)) {
            // This will likely get MISSING_PRIVILEGES but should not NPE in enrichment
            client.get("_cluster/health");
        }

        // User authenticated but has no roles — USER_ROLES should be absent (empty set not written)
        auditLogsRule.assertAtLeast(1, (AuditMessage msg) -> {
            if (msg.getCategory() != AuditCategory.AUTHENTICATED && msg.getCategory() != AuditCategory.MISSING_PRIVILEGES) return false;
            Map<String, Object> fields = msg.getAsMap();
            // No roles mapped = field absent (addUserRoles skips empty sets)
            Object roles = fields.get(AuditMessage.USER_ROLES);
            // auth_method should still be present (user DID authenticate successfully)
            Object authMethod = fields.get(AuditMessage.AUTH_METHOD);
            return roles == null && authMethod != null;
        });
    }
}
