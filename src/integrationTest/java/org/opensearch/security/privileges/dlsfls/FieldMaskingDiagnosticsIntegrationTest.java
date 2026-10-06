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

import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.log.LogsRule;

import static org.junit.Assert.assertEquals;

public class FieldMaskingDiagnosticsIntegrationTest {
    @Rule
    public final LogsRule logs = new LogsRule(FieldMaskingDiagnostics.class.getName());
    @ClassRule
    public static final LocalCluster CLUSTER = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .build();

    @Test
    public void testMappingDiagnosticsDoNotRejectValidRoles() throws Exception {
        try (var admin = CLUSTER.getAdminCertRestClient()) {
            assertEquals(
                200,
                admin.putJson("masking-diagnostic-long", "{\"mappings\":{\"properties\":{\"value\":{\"type\":\"long\"}}}}").getStatusCode()
            );
            String rolePath = "_plugins/_security/api/roles/masking-diagnostic-role";
            String role =
                "{\"index_permissions\":[{\"index_patterns\":[\"masking-diagnostic-*\"],\"allowed_actions\":[\"read\"],\"masked_fields\":[\"value\"]}]}";
            assertEquals(201, admin.putJson(rolePath, role).getStatusCode());
            logs.assertThatContainExactly(
                "Field masking cannot guarantee protection for index [masking-diagnostic-long], field [value], type [long], detected by [role mapping inspection]. Only string values are masked; use FLS to hide unsupported values. Diagnostics are sampled."
            );
            assertEquals(200, admin.putJson(rolePath, role.replace("masking-diagnostic-*", "future-index-*")).getStatusCode());
            assertEquals(400, admin.putJson(rolePath, role.replace("\"value\"", "\"value::NO_SUCH_HASH\"")).getStatusCode());
        }
    }
}
