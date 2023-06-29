/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.opensearch.security.privileges.PrivilegesEvaluator.isClusterPerm;

public class PrivilegesEvaluatorUnitTest {

    @Test
    public void testClusterPerm() {
        String multiSearchTemplate = "indices:data/read/msearch/template";
        String monitorHealth = "cluster:monitor/health";
        String writeIndex = "indices:data/write/reindex";
        String adminClose = "indices:admin/close";
        String monitorUpgrade = "indices:monitor/upgrade";

        // Cluster Permissions
        assertTrue(isClusterPerm(multiSearchTemplate));
        assertTrue(isClusterPerm(writeIndex));
        assertTrue(isClusterPerm(monitorHealth));

        // Index Permissions
        assertFalse(isClusterPerm(adminClose));
        assertFalse(isClusterPerm(monitorUpgrade));
    }
}
