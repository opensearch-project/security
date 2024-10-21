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
package org.opensearch.security.privileges;

import java.util.concurrent.atomic.AtomicReference;

import org.awaitility.Awaitility;
import org.junit.Test;

import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.node.Node;
import org.opensearch.threadpool.ThreadPool;

import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

public class ClusterStateMetadataDependentPrivilegesTest {

    @Test
    public void simpleUpdate() {
        ThreadPool threadPool = threadPool();
        try {
            ConcreteTestSubject subject = new ConcreteTestSubject();
            ClusterState clusterState = clusterState(metadata(1));
            ClusterService clusterService = Mockito.mock(ClusterService.class);
            Mockito.when(clusterService.state()).thenReturn(clusterState);

            subject.updateClusterStateMetadataAsync(clusterService, threadPool);
            Awaitility.await().until(() -> subject.getCurrentlyUsedMetadataVersion() == 1);
            subject.shutdown();
        } finally {
            threadPool.shutdown();
        }
    }

    @Test
    public void frequentUpdates() throws Exception {
        ThreadPool threadPool = threadPool();
        try {
            ConcreteTestSubject subject = new ConcreteTestSubject();
            AtomicReference<ClusterState> clusterStateReference = new AtomicReference<>(clusterState(metadata(1)));
            ClusterService clusterService = Mockito.mock(ClusterService.class);
            Mockito.when(clusterService.state()).thenAnswer((Answer<ClusterState>) invocationOnMock -> clusterStateReference.get());
            subject.updateClusterStateMetadataAsync(clusterService, threadPool);
            subject.updateClusterStateMetadataAsync(clusterService, threadPool);

            for (int i = 2; i <= 100; i++) {
                clusterStateReference.set(clusterState(metadata(i)));
                subject.updateClusterStateMetadataAsync(clusterService, threadPool);
                Thread.sleep(10);
            }

            Awaitility.await().until(() -> subject.getCurrentlyUsedMetadataVersion() == 100);
            subject.shutdown();
        } finally {
            threadPool.shutdown();
        }
    }

    @Test
    public void shutdown() {
        ThreadPool threadPool = threadPool();
        try {
            ConcreteTestSubject subject = new ConcreteTestSubject();
            ClusterState clusterState = clusterState(metadata(1));
            ClusterService clusterService = Mockito.mock(ClusterService.class);
            Mockito.when(clusterService.state()).thenReturn(clusterState);
            subject.updateClusterStateMetadataAsync(clusterService, threadPool);
            subject.shutdown();
        } finally {
            threadPool.shutdown();
        }
    }

    static Metadata metadata(long version) {
        return Metadata.builder().version(version).build();
    }

    static ClusterState clusterState(Metadata metadata) {
        return ClusterState.builder(ClusterState.EMPTY_STATE).metadata(metadata).build();
    }

    static ThreadPool threadPool() {
        return new ThreadPool(Settings.builder().put(Node.NODE_NAME_SETTING.getKey(), "name").build());
    }

    static class ConcreteTestSubject extends ClusterStateMetadataDependentPrivileges {

        private long currentMetadataVersion;

        @Override
        protected void updateClusterStateMetadata(Metadata metadata) {
            // We need to be slow with updates to test the debounce-functionality
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {}

            this.currentMetadataVersion = metadata.version();
        }

        @Override
        protected long getCurrentlyUsedMetadataVersion() {
            return this.currentMetadataVersion;
        }
    }
}
