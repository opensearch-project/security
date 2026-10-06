/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.privileges.dlsfls;

import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.log.LogsRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class FieldMaskingDiagnosticsIntegrationTest {
    @Rule
    public final LogsRule logs = new LogsRule(FieldMaskingDiagnostics.class.getName());
    private static final TestSecurityConfig.User ADMIN = new TestSecurityConfig.User("admin").roles(TestSecurityConfig.Role.ALL_ACCESS);
    private static final TestSecurityConfig.User READER = new TestSecurityConfig.User("masked-reader").roles(
        new TestSecurityConfig.Role("masked-reader").indexPermissions("read").maskedFields("value").on("masking-diagnostic-*")
    );

    @ClassRule
    public static final LocalCluster CLUSTER = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN, READER)
        .build();

    @Test
    public void testKeywordMappingDoesNotMakeNumericSourceAString() throws Exception {
        try (var admin = CLUSTER.getRestClient(ADMIN); var reader = CLUSTER.getRestClient(READER)) {
            assertEquals(
                200,
                admin.putJson("masking-diagnostic-keyword", "{\"mappings\":{\"properties\":{\"value\":{\"type\":\"keyword\"}}}}")
                    .getStatusCode()
            );
            assertEquals(201, admin.putJson("masking-diagnostic-keyword/_doc/1?refresh=true", "{\"value\":42}").getStatusCode());
            assertEquals(201, admin.putJson("masking-diagnostic-keyword/_doc/2?refresh=true", "{\"value\":\"secret\"}").getStatusCode());
            var numeric = reader.get("masking-diagnostic-keyword/_doc/1");
            assertEquals(200, numeric.getStatusCode());
            assertEquals(42, DefaultObjectMapper.objectMapper().readTree(numeric.getBody()).at("/_source/value").asInt());
            logs.assertThatContainExactly(
                "Field masking cannot guarantee protection for index [masking-diagnostic-keyword], field [value], type [VALUE_NUMBER_INT], detected by [_source]. Only string values are masked; use FLS to hide unsupported values. Diagnostics are sampled."
            );
            var string = reader.get("masking-diagnostic-keyword/_doc/2");
            assertEquals(200, string.getStatusCode());
            assertNotEquals("secret", DefaultObjectMapper.objectMapper().readTree(string.getBody()).at("/_source/value").asText());
        }
        try (var admin = CLUSTER.getAdminCertRestClient()) {
            assertEquals(
                200,
                admin.putJson("masking-diagnostic-long", "{\"mappings\":{\"properties\":{\"value\":{\"type\":\"long\"}}}}").getStatusCode()
            );
            String rolePath = "_plugins/_security/api/roles/masking-diagnostic-role";
            String role =
                "{\"index_permissions\":[{\"index_patterns\":[\"masking-diagnostic-*\"],\"allowed_actions\":[\"read\"],\"masked_fields\":[\"value\"]}]}";
            assertEquals(201, admin.putJson(rolePath, role).getStatusCode());
            assertEquals(200, admin.putJson(rolePath, role.replace("masking-diagnostic-*", "future-index-*")).getStatusCode());
            assertEquals(400, admin.putJson(rolePath, role.replace("\"value\"", "\"value::NO_SUCH_HASH\"")).getStatusCode());
        }
    }
}
