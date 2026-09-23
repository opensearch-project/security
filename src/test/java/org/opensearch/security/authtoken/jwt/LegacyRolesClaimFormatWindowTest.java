/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.authtoken.jwt;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Test;

import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.security.action.onbehalf.CreateOnBehalfOfTokenAction;
import org.opensearch.security.authtoken.jwt.LegacyRolesClaimFormat.PreUpgradeNodeTracker;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.authtoken.jwt.LegacyRolesClaimFormatTest.cluster;

/**
 * The window governs how long a node keeps reading on-behalf-of tokens in the pre-upgrade AES/ECB format.
 * It has to outlast the last pre-upgrade node by one maximum token lifetime, because the tokens that node
 * issued just before it left are still valid. The tracker is fed real cluster state changes, as the cluster
 * service would.
 */
public class LegacyRolesClaimFormatWindowTest {

    private static final long MAX_TOKEN_LIFETIME_MS = TimeUnit.SECONDS.toMillis(CreateOnBehalfOfTokenAction.OBO_MAX_EXPIRY_SECONDS);

    private final AtomicLong clock = new AtomicLong(1_000_000L);
    private final PreUpgradeNodeTracker tracker = new PreUpgradeNodeTracker(clock::get);
    private DiscoveryNodes previous = DiscoveryNodes.EMPTY_NODES;

    /** Publishes a cluster state with these nodes, following the one published before. */
    private void clusterBecomes(final DiscoveryNodes nodes) {
        tracker.clusterChanged(new ClusterChangedEvent("test", state(nodes), state(previous)));
        previous = nodes;
    }

    private static ClusterState state(final DiscoveryNodes nodes) {
        return ClusterState.builder(new ClusterName("test")).nodes(nodes).build();
    }

    @Test
    public void staysOpenWhileTheClusterStateIsUnknown() {
        clock.addAndGet(MAX_TOKEN_LIFETIME_MS * 10);

        assertThat(tracker.legacyFormatReadable(), is(true));
    }

    @Test
    public void staysOpenWhileAPreUpgradeNodeIsInTheCluster() {
        clusterBecomes(cluster(true));

        clock.addAndGet(MAX_TOKEN_LIFETIME_MS * 10);

        assertThat(tracker.legacyFormatReadable(), is(true));
    }

    @Test
    public void outlastsTheLastPreUpgradeNodeByOneTokenLifetime() {
        clusterBecomes(cluster(true));

        // The last pre-upgrade node leaves; the tokens it issued are still valid for one lifetime.
        clusterBecomes(cluster(false));
        clock.addAndGet(MAX_TOKEN_LIFETIME_MS - 1);
        assertThat(tracker.legacyFormatReadable(), is(true));

        clock.addAndGet(1);
        assertThat(tracker.legacyFormatReadable(), is(false));
    }

    /**
     * The window is measured from the change that removed the last pre-upgrade node, not from the last time a
     * legacy token was read or the cluster state changed: a mixed cluster can be quiet for longer than a token
     * lifetime, and the tokens issued just before the node left are still valid afterwards.
     */
    @Test
    public void measuresTheWindowFromTheChangeThatRemovedTheLastPreUpgradeNode() {
        clusterBecomes(cluster(true));

        // no token read, no cluster state change
        clock.addAndGet(MAX_TOKEN_LIFETIME_MS * 10);

        clusterBecomes(cluster(false));
        clock.addAndGet(1_000);
        assertThat(tracker.legacyFormatReadable(), is(true));
    }

    @Test
    public void startsOpenOnANodeThatJoinsAnAlreadyUpgradedCluster() {
        // Such a node never observes the pre-upgrade node, but tokens it issued can still be in flight.
        clusterBecomes(cluster(false));

        assertThat(tracker.legacyFormatReadable(), is(true));

        clock.addAndGet(MAX_TOKEN_LIFETIME_MS);
        assertThat(tracker.legacyFormatReadable(), is(false));
    }

    @Test
    public void reopensWhenAPreUpgradeNodeRejoins() {
        clusterBecomes(cluster(false));
        clock.addAndGet(MAX_TOKEN_LIFETIME_MS);
        assertThat(tracker.legacyFormatReadable(), is(false));

        clusterBecomes(cluster(true));
        assertThat(tracker.legacyFormatReadable(), is(true));
    }
}
