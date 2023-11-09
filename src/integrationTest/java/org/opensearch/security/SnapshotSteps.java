/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.awaitility.Awaitility;

import org.opensearch.action.admin.cluster.repositories.delete.DeleteRepositoryRequest;
import org.opensearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.opensearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.opensearch.action.admin.cluster.snapshots.create.CreateSnapshotResponse;
import org.opensearch.action.admin.cluster.snapshots.delete.DeleteSnapshotRequest;
import org.opensearch.action.admin.cluster.snapshots.get.GetSnapshotsRequest;
import org.opensearch.action.admin.cluster.snapshots.get.GetSnapshotsResponse;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotResponse;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.client.SnapshotClient;
import org.opensearch.snapshots.SnapshotInfo;
import org.opensearch.snapshots.SnapshotState;

import static java.util.Objects.requireNonNull;
import static org.opensearch.client.RequestOptions.DEFAULT;

class SnapshotSteps {

    private final SnapshotClient snapshotClient;

    public SnapshotSteps(RestHighLevelClient restHighLevelClient) {
        this.snapshotClient = requireNonNull(restHighLevelClient, "Rest high level client is required.").snapshot();
    }

    // CS-SUPPRESS-SINGLE: RegexpSingleline It is not possible to use phrase "cluster manager" instead of master here
    public org.opensearch.action.support.master.AcknowledgedResponse createSnapshotRepository(
        String repositoryName,
        String snapshotDirPath,
        String type
    )
        // CS-ENFORCE-SINGLE
        throws IOException {
        PutRepositoryRequest createRepositoryRequest = new PutRepositoryRequest().name(repositoryName)
            .type(type)
            .settings(Map.of("location", snapshotDirPath));
        return snapshotClient.createRepository(createRepositoryRequest, DEFAULT);
    }

    public CreateSnapshotResponse createSnapshot(String repositoryName, String snapshotName, String... indices) throws IOException {
        CreateSnapshotRequest createSnapshotRequest = new CreateSnapshotRequest(repositoryName, snapshotName).indices(indices);
        return snapshotClient.create(createSnapshotRequest, DEFAULT);
    }

    public int waitForSnapshotCreation(String repositoryName, String snapshotName) {
        AtomicInteger count = new AtomicInteger();
        GetSnapshotsRequest getSnapshotsRequest = new GetSnapshotsRequest(repositoryName, new String[] { snapshotName });
        Awaitility.await()
            .pollDelay(250, TimeUnit.MILLISECONDS)
            .pollInterval(2, TimeUnit.SECONDS)
            .alias("wait for snapshot creation")
            .ignoreExceptions()
            .until(() -> {
                count.incrementAndGet();
                GetSnapshotsResponse snapshotsResponse = snapshotClient.get(getSnapshotsRequest, DEFAULT);
                SnapshotInfo snapshotInfo = snapshotsResponse.getSnapshots().get(0);
                return SnapshotState.SUCCESS.equals(snapshotInfo.state());
            });
        return count.get();
    }

    // CS-SUPPRESS-SINGLE: RegexpSingleline It is not possible to use phrase "cluster manager" instead of master here
    public org.opensearch.action.support.master.AcknowledgedResponse deleteSnapshotRepository(String repositoryName) throws IOException {
        // CS-ENFORCE-SINGLE
        DeleteRepositoryRequest request = new DeleteRepositoryRequest(repositoryName);
        return snapshotClient.deleteRepository(request, DEFAULT);
    }

    // CS-SUPPRESS-SINGLE: RegexpSingleline It is not possible to use phrase "cluster manager" instead of master here
    public org.opensearch.action.support.master.AcknowledgedResponse deleteSnapshot(String repositoryName, String snapshotName)
        throws IOException {
        // CS-ENFORCE-SINGLE
        return snapshotClient.delete(new DeleteSnapshotRequest(repositoryName, snapshotName), DEFAULT);
    }

    public RestoreSnapshotResponse restoreSnapshot(
        String repositoryName,
        String snapshotName,
        String renamePattern,
        String renameReplacement
    ) throws IOException {
        RestoreSnapshotRequest restoreSnapshotRequest = new RestoreSnapshotRequest(repositoryName, snapshotName).renamePattern(
            renamePattern
        ).renameReplacement(renameReplacement);
        return snapshotClient.restore(restoreSnapshotRequest, DEFAULT);
    }
}
