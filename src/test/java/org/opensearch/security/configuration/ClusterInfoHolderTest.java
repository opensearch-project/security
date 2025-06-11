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

package org.opensearch.security.configuration;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.Version;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ClusterInfoHolderTest {

    private ClusterInfoHolder clusterInfoHolder;

    @Mock
    private ClusterChangedEvent mockEvent;

    @Mock
    private ClusterState mockClusterState;

    @Mock
    private DiscoveryNodes mockNodes;

    @Mock
    private DiscoveryNode mockNode;

    private static final String TEST_CLUSTER_NAME = "test-cluster";

    @Before
    public void setUp() {
        clusterInfoHolder = new ClusterInfoHolder(TEST_CLUSTER_NAME);
        when(mockEvent.state()).thenReturn(mockClusterState);
        when(mockClusterState.nodes()).thenReturn(mockNodes);
    }

    @Test
    public void testInitialState() {
        assertFalse("Should not be initialized initially", clusterInfoHolder.isInitialized());
        assertNull("Should not have cluster manager status initially", clusterInfoHolder.isLocalNodeElectedClusterManager());
        assertEquals("Should have correct cluster name", TEST_CLUSTER_NAME, clusterInfoHolder.getClusterName());
    }

    @Test
    public void testClusterChanged_NodesChanged() {
        // Execute
        clusterInfoHolder.clusterChanged(mockEvent);

        // Verify
        assertTrue("Should be initialized after nodes change", clusterInfoHolder.isInitialized());
    }

    @Test
    public void testClusterChanged_LocalNodeClusterManager() {
        // Setup
        when(mockEvent.localNodeClusterManager()).thenReturn(Boolean.TRUE);

        // Execute
        clusterInfoHolder.clusterChanged(mockEvent);

        // Verify
        assertTrue("Should be cluster manager", clusterInfoHolder.isLocalNodeElectedClusterManager());
    }

    @Test
    public void testClusterChanged_NotLocalNodeClusterManager() {
        // Setup
        when(mockEvent.localNodeClusterManager()).thenReturn(false);

        // Execute
        clusterInfoHolder.clusterChanged(mockEvent);

        // Verify
        assertFalse("Should not be cluster manager", clusterInfoHolder.isLocalNodeElectedClusterManager());
    }

    @Test
    public void testGetMinNodeVersion_WhenNotInitialized() {
        assertNull("Should return null when not initialized", clusterInfoHolder.getMinNodeVersion());
    }

    @Test
    public void testGetMinNodeVersion_WhenInitialized() {
        // Setup
        Version expectedVersion = Version.CURRENT;
        when(mockNodes.getMinNodeVersion()).thenReturn(expectedVersion);
        clusterInfoHolder.clusterChanged(mockEvent);

        // Execute & Verify
        assertEquals("Should return correct min version", expectedVersion, clusterInfoHolder.getMinNodeVersion());
    }

    @Test
    public void testHasNode_WhenNotInitialized() {
        assertNull("Should return null when not initialized", clusterInfoHolder.hasNode(mockNode));
    }

    @Test
    public void testHasNode_WhenNodeExists() {
        // Setup
        when(mockNodes.nodeExists(mockNode)).thenReturn(true);
        clusterInfoHolder.clusterChanged(mockEvent);

        // Execute & Verify
        assertTrue("Should return true when node exists", clusterInfoHolder.hasNode(mockNode));
    }

    @Test
    public void testHasNode_WhenNodeDoesNotExist() {
        // Setup
        when(mockNodes.nodeExists(mockNode)).thenReturn(false);
        clusterInfoHolder.clusterChanged(mockEvent);

        // Execute & Verify
        assertFalse("Should return false when node doesn't exist", clusterInfoHolder.hasNode(mockNode));
    }

    @Test
    public void testHasClusterManager_WhenNotInitialized() {
        assertFalse("Should return false when not initialized", clusterInfoHolder.hasClusterManager());
    }

    @Test
    public void testHasClusterManager_WhenClusterManagerExists() {
        // Setup
        when(mockNodes.getClusterManagerNode()).thenReturn(mockNode);
        clusterInfoHolder.clusterChanged(mockEvent);

        // Execute & Verify
        assertTrue("Should return true when cluster manager exists", clusterInfoHolder.hasClusterManager());
    }

    @Test
    public void testHasClusterManager_WhenNoClusterManager() {
        // Setup
        when(mockNodes.getClusterManagerNode()).thenReturn(null);
        clusterInfoHolder.clusterChanged(mockEvent);

        // Execute & Verify
        assertFalse("Should return false when no cluster manager", clusterInfoHolder.hasClusterManager());
    }

    @Test
    public void testGetClusterManagerNotPresentStatus() {
        assertEquals("Should return correct status message", "Cluster manager not present", ClusterInfoHolder.CLUSTER_MANAGER_NOT_PRESENT);
    }

    @Test
    public void testMultipleClusterChanges() {
        // First change
        when(mockEvent.nodesChanged()).thenReturn(true);
        when(mockEvent.localNodeClusterManager()).thenReturn(true);
        clusterInfoHolder.clusterChanged(mockEvent);

        assertTrue("Should be initialized", clusterInfoHolder.isInitialized());
        assertTrue("Should be cluster manager", clusterInfoHolder.isLocalNodeElectedClusterManager());

        // Second change
        when(mockEvent.nodesChanged()).thenReturn(false);
        when(mockEvent.localNodeClusterManager()).thenReturn(false);
        clusterInfoHolder.clusterChanged(mockEvent);

        assertTrue("Should still be initialized", clusterInfoHolder.isInitialized());
        assertFalse("Should not be cluster manager anymore", clusterInfoHolder.isLocalNodeElectedClusterManager());
    }
}
