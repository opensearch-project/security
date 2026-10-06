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

package org.opensearch.security.transport;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.securityconf.NodesDnModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.transport.TransportRequest;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DefaultInterClusterRequestEvaluatorTest {

    private static final String NODE_OID = "1.2.3.4.5.5";

    /**
     * Regression test for https://github.com/opensearch-project/security/issues/6245: a dynamic nodes_dn entry that
     * duplicates the static nodes_dn used to make every inter-node request throw, taking the cluster down.
     */
    @Test
    public void testIsInterClusterRequest_dynamicNodesDnDuplicatesStatic_doesNotThrow() {
        String nodeDn = "CN=node-0.example.com,OU=node,O=node,L=test,C=de";
        Settings settings = Settings.builder()
            .put(ConfigConstants.SECURITY_CERT_OID, NODE_OID)
            .putList(ConfigConstants.SECURITY_NODES_DN, nodeDn)
            .put(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, true)
            .build();
        DefaultInterClusterRequestEvaluator evaluator = new DefaultInterClusterRequestEvaluator(settings);
        NodesDnModel nodesDnModel = mock(NodesDnModel.class);
        when(nodesDnModel.getNodesDn()).thenReturn(Map.of("remote_cluster", WildcardMatcher.from(List.of(nodeDn)).ignoreCase()));
        evaluator.onNodesDnModelChanged(nodesDnModel);

        boolean result = evaluator.isInterClusterRequest(
            mock(TransportRequest.class),
            new X509Certificate[0],
            new X509Certificate[0],
            nodeDn
        );

        assertTrue(result);
    }
}
