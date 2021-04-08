/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin;
import com.amazon.opendistroforelasticsearch.security.auditlog.NullAuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import org.apache.lucene.index.IndexCommit;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateUpdateTask;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.metadata.RepositoryMetadata;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.component.Lifecycle;
import org.elasticsearch.common.component.LifecycleListener;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.index.snapshots.IndexShardSnapshotStatus;
import org.elasticsearch.index.store.Store;
import org.elasticsearch.indices.recovery.RecoveryState;
import org.elasticsearch.repositories.*;
import org.elasticsearch.snapshots.SnapshotId;
import org.elasticsearch.snapshots.SnapshotInfo;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;


public class SnapshotRestoreEvaluatorTests {

    private SnapshotRestoreEvaluator snapshotRestoreEvaluator;
    private RestoreSnapshotRequest restoreRequest;
    private Task task;
    private ClusterInfoHolder clusterInfoHolder;
    private PrivilegesEvaluatorResponse presponse;


    private class TestRepository implements Repository {

        private boolean isClosed;
        private boolean isStarted;

        private final RepositoryMetadata metadata;

        private TestRepository(RepositoryMetadata metadata) {
            this.metadata = metadata;
        }

        @Override
        public RepositoryMetadata getMetadata() {
            return metadata;
        }

        @Override
        public SnapshotInfo getSnapshotInfo(SnapshotId snapshotId) {
            return null;
        }

        @Override
        public Metadata getSnapshotGlobalMetadata(SnapshotId snapshotId) {
            return null;
        }

        @Override
        public IndexMetadata getSnapshotIndexMetaData(RepositoryData repositoryData, SnapshotId snapshotId, IndexId index) {
            return null;
        }

        @Override
        public void getRepositoryData(ActionListener<RepositoryData> listener) {
            RepositoryData repositoryData = new RepositoryData(1, new HashMap<>(), new HashMap<>(), new HashMap<>(), new HashMap<>(),
                ShardGenerations.EMPTY, IndexMetaDataGenerations.EMPTY);
            listener.onResponse(repositoryData);
        }

        @Override
        public void initializeSnapshot(SnapshotId snapshotId, List<IndexId> indices, Metadata metadata) {

        }

        @Override
        public void finalizeSnapshot(ShardGenerations shardGenerations, long repositoryStateId, Metadata clusterMetadata,
                                     SnapshotInfo snapshotInfo, Version repositoryMetaVersion,
                                     Function<ClusterState, ClusterState> stateTransformer,
                                     ActionListener<RepositoryData> listener) {
            listener.onResponse(null);
        }

        @Override
        public void deleteSnapshots(Collection<SnapshotId> snapshotIds, long repositoryStateId, Version repositoryMetaVersion,
                                    ActionListener<RepositoryData> listener) {
            listener.onResponse(null);
        }

        @Override
        public long getSnapshotThrottleTimeInNanos() {
            return 0;
        }

        @Override
        public long getRestoreThrottleTimeInNanos() {
            return 0;
        }

        @Override
        public String startVerification() {
            return null;
        }

        @Override
        public void endVerification(String verificationToken) {

        }

        @Override
        public void verify(String verificationToken, DiscoveryNode localNode) {

        }

        @Override
        public boolean isReadOnly() {
            return false;
        }

        @Override
        public void snapshotShard(Store store, MapperService mapperService, SnapshotId snapshotId, IndexId indexId,
                                  IndexCommit snapshotIndexCommit, String shardStateIdentifier, IndexShardSnapshotStatus snapshotStatus,
                                  Version repositoryMetaVersion, Map<String, Object> userMetadata, ActionListener<String> listener) {

        }

        @Override
        public void restoreShard(Store store, SnapshotId snapshotId, IndexId indexId, ShardId snapshotShardId,
                                 RecoveryState recoveryState, ActionListener<Void> listener) {

        }

        @Override
        public IndexShardSnapshotStatus getShardSnapshotStatus(SnapshotId snapshotId, IndexId indexId, ShardId shardId) {
            return null;
        }

        @Override
        public void updateState(final ClusterState state) {
        }

        @Override
        public void executeConsistentStateUpdate(Function<RepositoryData, ClusterStateUpdateTask> createUpdateTask, String source,
                                                 Consumer<Exception> onFailure) {
        }

        @Override
        public void cloneShardSnapshot(SnapshotId source, SnapshotId target, RepositoryShardId shardId, String shardGeneration,
                                       ActionListener<String> listener) {

        }

        @Override
        public Lifecycle.State lifecycleState() {
            return null;
        }

        @Override
        public void addLifecycleListener(LifecycleListener listener) {

        }

        @Override
        public void removeLifecycleListener(LifecycleListener listener) {

        }

        @Override
        public void start() {
            isStarted = true;
        }

        @Override
        public void stop() {

        }

        @Override
        public void close() {
            isClosed = true;
        }
    }

    @Before
    public void init() {
        restoreRequest = Mockito.mock(RestoreSnapshotRequest.class);
        Mockito.when(restoreRequest.includeGlobalState()).thenReturn(true);
        task = Mockito.mock(Task.class);
        clusterInfoHolder = Mockito.mock(ClusterInfoHolder.class);
        Mockito.when(clusterInfoHolder.isLocalNodeElectedMaster()).thenReturn(true);
        presponse = new PrivilegesEvaluatorResponse();
        
        RepositoriesService repositoriesService = Mockito.mock(RepositoriesService.class);
        TestRepository repository = new TestRepository(Mockito.mock(RepositoryMetadata.class));
        Mockito.when(repositoriesService.repository(Mockito.any())).thenReturn(repository);
        TransportService remoteClusterService = Mockito.mock(TransportService.class);
        new OpenDistroSecurityPlugin.GuiceHolder(repositoriesService, remoteClusterService);
    }


    @Test
    public void testSnapshotNotAllowedWithGlobalState() throws Exception {
        final Settings settings = Settings.builder()
            .build();

        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(settings, new NullAuditLog());

        snapshotRestoreEvaluator.evaluate(restoreRequest, task, "action", clusterInfoHolder, presponse);
        Assert.assertFalse(presponse.allowed);
        Assert.assertTrue(PrivilegesEvaluatorResponse.PrivilegesEvaluatorResponseState.COMPLETE.equals(presponse.state));

    }

    @Test
    public void testSnapshotAllowedWithGlobalState() throws Exception {
        final Settings settings = Settings.builder()
            .put("opendistro_security.unsupported.restore.global.state.enabled", true)
            .build();

        snapshotRestoreEvaluator = new SnapshotRestoreEvaluator(settings, new NullAuditLog());

        snapshotRestoreEvaluator.evaluate(restoreRequest, task, "action", clusterInfoHolder, presponse);
        Assert.assertFalse(presponse.allowed);
        Assert.assertTrue(PrivilegesEvaluatorResponse.PrivilegesEvaluatorResponseState.PENDING.equals(presponse.state));
    }

}
