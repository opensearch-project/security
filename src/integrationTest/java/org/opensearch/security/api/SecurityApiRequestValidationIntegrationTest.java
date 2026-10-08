/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.api;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SecurityApiRequestValidationIntegrationTest {
    private static final String BASE = "_plugins/_security/api/";
    private static final String EXPRESSION = "${env.SECURITY_API_VALIDATION_TEST:-synthetic}";
    private static final String ROLE_BODY = "{\"cluster_permissions\":[\"cluster:monitor/main\"]}";

    @ClassRule
    public static final LocalCluster CLUSTER = new LocalCluster.Builder().singleNode().build();

    @Test
    public void rejectsBodyExpressionsAcrossEndpoints() throws Exception {
        try (TestRestClient admin = CLUSTER.getAdminCertRestClient()) {
            for (var entry : Map.of(
                "roles",
                Map.of("cluster_permissions", List.of(EXPRESSION)),
                "rolesmapping",
                Map.of("backend_roles", List.of(EXPRESSION)),
                "tenants",
                Map.of("description", EXPRESSION),
                "actiongroups",
                Map.of("allowed_actions", List.of(EXPRESSION)),
                "internalusers",
                Map.of("password", "Synthetic-test-password!42", "attributes", Map.of(EXPRESSION, "value")),
                "authfailurelisteners",
                Map.of("type", "ip", "ignore_hosts", List.of(EXPRESSION))
            ).entrySet()) {
                String path = BASE + entry.getKey() + "/environment_validation_test";
                var original = admin.get(BASE + entry.getKey()).bodyAsJsonNode();
                assertRejected(admin.putJson(path, DefaultObjectMapper.writeValueAsString(entry.getValue(), false)));
                assertEquals(original, admin.get(BASE + entry.getKey()).bodyAsJsonNode());
            }
        }
    }

    @Test
    public void rejectsEncodedRouteNames() {
        try (TestRestClient admin = CLUSTER.getAdminCertRestClient()) {
            String encodedName = URLEncoder.encode(EXPRESSION, StandardCharsets.UTF_8);
            for (var endpoint : Map.of(
                "roles",
                ROLE_BODY,
                "tenants",
                "{\"description\":\"ordinary\"}",
                "authfailurelisteners",
                "{\"type\":\"ip\"}"
            ).entrySet()) {
                String path = BASE + endpoint.getKey() + "/" + encodedName;
                var original = admin.get(BASE + endpoint.getKey()).bodyAsJsonNode();
                assertRejected(admin.putJson(path, endpoint.getValue()));
                assertEquals(original, admin.get(BASE + endpoint.getKey()).bodyAsJsonNode());
            }
        }
    }

    @Test
    public void rejectsEscapedExpressionsAndAsyncWritesWithoutChangingRole() {
        try (TestRestClient admin = CLUSTER.getAdminCertRestClient()) {
            String path = BASE + "roles/environment_validation_test";
            try {
                assertEquals(201, admin.putJson(path, ROLE_BODY).getStatusCode());
                var original = admin.get(path).bodyAsJsonNode();
                for (String suffix : List.of("", "?wait_for_completion=false")) {
                    assertRejected(
                        admin.putJson(path + suffix, "{\"cluster_permissions\":[\"\\u0024{env.SECURITY_API_VALIDATION_TEST:-synthetic}\"]}")
                    );
                    assertEquals(original, admin.get(path).bodyAsJsonNode());
                }
            } finally {
                admin.delete(path);
            }
        }
    }

    @Test
    public void rejectsSingleAndMultiEntityPatchesAtomically() throws Exception {
        try (TestRestClient admin = CLUSTER.getAdminCertRestClient()) {
            String path = BASE + "roles/environment_validation_test";
            try {
                assertEquals(201, admin.putJson(path, ROLE_BODY).getStatusCode());
                var original = admin.get(path).bodyAsJsonNode();
                String singlePatch = DefaultObjectMapper.writeValueAsString(
                    List.of(Map.of("op", "add", "path", "/cluster_permissions/-", "value", EXPRESSION)),
                    false
                );
                assertRejected(admin.patch(path, singlePatch));
                String bulkPatch = DefaultObjectMapper.writeValueAsString(
                    List.of(
                        Map.of("op", "add", "path", "/ordinary_patch_role", "value", Map.of("cluster_permissions", List.of())),
                        Map.of("op", "add", "path", "/" + EXPRESSION, "value", Map.of("cluster_permissions", List.of()))
                    ),
                    false
                );
                assertRejected(admin.patch(BASE + "roles", bulkPatch));
                assertEquals(original, admin.get(path).bodyAsJsonNode());
                assertEquals(404, admin.get(BASE + "roles/ordinary_patch_role").getStatusCode());
            } finally {
                admin.delete(path);
                admin.delete(BASE + "roles/ordinary_patch_role");
            }
        }
    }

    @Test
    public void permitsDlsUserAttributeTemplates() {
        try (TestRestClient admin = CLUSTER.getAdminCertRestClient()) {
            String path = BASE + "roles/environment_validation_template";
            try {
                assertEquals(201, admin.putJson(path, """
                    {"index_permissions":[{"index_patterns":["test"],"allowed_actions":["read"],
                    "dls":"{\\"term\\":{\\"owner\\":\\"${user.name}\\"}}"}]}
                    """).getStatusCode());
            } finally {
                admin.delete(path);
            }
        }
    }

    private void assertRejected(TestRestClient.HttpResponse response) {
        assertEquals(response.getBody(), 400, response.getStatusCode());
        assertTrue(response.getBody(), response.getBody().contains("must not contain environment variable expressions"));
        assertFalse(response.getBody().contains("SECURITY_API_VALIDATION_TEST"));
    }
}
