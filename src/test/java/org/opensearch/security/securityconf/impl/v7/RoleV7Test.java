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

package org.opensearch.security.securityconf.impl.v7;

import java.net.URL;

import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class RoleV7Test {

    private URL testYamlUrl;

    @Before
    public void setUp() throws Exception {
        // Create a test YAML file in resources
        testYamlUrl = RoleV7Test.class.getResource("/test-role.yml");
    }

    @Test
    public void testFromYmlFileWithValidInput() throws Exception {
        // Given a valid YAML file with both cluster and index permissions
        // test-role.yml content:
        /*
        cluster_permissions:
          - "cluster:admin/opensearch/monitor"
          - "cluster:admin/opensearch/upgrade"
        index_permissions:
          - index_patterns:
              - "test-*"
              - "index-*"
            allowed_actions:
              - "read"
              - "write"
        */

        // When
        RoleV7 role = RoleV7.fromPluginPermissionsFile(testYamlUrl);

        // Then
        assertNotNull(role);
        assertEquals(2, role.getCluster_permissions().size());
        assertTrue(role.getCluster_permissions().contains("cluster:monitor/health"));
        assertTrue(role.getCluster_permissions().contains("cluster:monitor/shards"));

        assertEquals(1, role.getIndex_permissions().size());
        RoleV7.Index indexPerm = role.getIndex_permissions().get(0);
        assertEquals(2, indexPerm.getIndex_patterns().size());
        assertTrue(indexPerm.getIndex_patterns().contains("test-*"));
        assertTrue(indexPerm.getIndex_patterns().contains("index-*"));
        assertEquals(2, indexPerm.getAllowed_actions().size());
        assertTrue(indexPerm.getAllowed_actions().contains("read"));
        assertTrue(indexPerm.getAllowed_actions().contains("write"));
    }

    @Test
    public void testFromYmlFileWithEmptyPermissions() throws Exception {
        // Given a YAML file with empty permissions
        // test-role-empty.yml content:
        /*
        cluster_permissions: []
        index_permissions: []
        */

        URL emptyYamlUrl = RoleV7Test.class.getResource("/test-role-empty.yml");

        // When
        RoleV7 role = RoleV7.fromPluginPermissionsFile(emptyYamlUrl);

        // Then
        assertNotNull(role);
        assertTrue(role.getCluster_permissions().isEmpty());
        assertTrue(role.getIndex_permissions().isEmpty());
    }

    @Test(expected = UnrecognizedPropertyException.class)
    public void testFromYmlFileWithInvalidYaml() throws Exception {
        // Given an invalid YAML file
        URL invalidYamlUrl = RoleV7Test.class.getResource("/test-role-invalid.yml");

        // When/Then
        RoleV7.fromPluginPermissionsFile(invalidYamlUrl); // Should throw an exception
    }

    @Test
    public void testFromYmlFileWithMissingIndexPermissions() throws Exception {
        // Given a YAML file with only cluster permissions
        // test-role-cluster-only.yml content:
        /*
        cluster_permissions:
          - "cluster:admin/opensearch/monitor"
        */

        URL clusterOnlyYamlUrl = RoleV7Test.class.getResource("/test-role-cluster-only.yml");

        // When
        RoleV7 role = RoleV7.fromPluginPermissionsFile(clusterOnlyYamlUrl);

        // Then
        assertNotNull(role);
        assertEquals(1, role.getCluster_permissions().size());
        assertTrue(role.getCluster_permissions().contains("cluster:monitor/health"));
        assertTrue(role.getIndex_permissions().isEmpty());
    }
}
