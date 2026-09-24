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
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.awaitility.Awaitility;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.snapshot.CreateRepositoryRequest;
import org.opensearch.client.opensearch.snapshot.CreateRepositoryResponse;
import org.opensearch.client.opensearch.snapshot.CreateSnapshotRequest;
import org.opensearch.client.opensearch.snapshot.CreateSnapshotResponse;
import org.opensearch.client.opensearch.snapshot.DeleteRepositoryRequest;
import org.opensearch.client.opensearch.snapshot.DeleteRepositoryResponse;
import org.opensearch.client.opensearch.snapshot.DeleteSnapshotRequest;
import org.opensearch.client.opensearch.snapshot.DeleteSnapshotResponse;
import org.opensearch.client.opensearch.snapshot.GetSnapshotRequest;
import org.opensearch.client.opensearch.snapshot.GetSnapshotResponse;
import org.opensearch.client.opensearch.snapshot.OpenSearchSnapshotClient;
import org.opensearch.client.opensearch.snapshot.RestoreSnapshotRequest;
import org.opensearch.client.opensearch.snapshot.RestoreSnapshotResponse;
import org.opensearch.client.opensearch.snapshot.SnapshotInfo;

import static java.util.Objects.requireNonNull;

class SnapshotSteps {

    private final OpenSearchSnapshotClient snapshotClient;

    public SnapshotSteps(OpenSearchClient client) {
        this.snapshotClient = requireNonNull(client, "Rest high level client is required.").snapshot();
    }

    public CreateRepositoryResponse createSnapshotRepository(String repositoryName, String snapshotDirPath, String type)
        throws IOException {
        CreateRepositoryRequest createRepositoryRequest = CreateRepositoryRequest.of(
            r -> r.name(repositoryName).type(type).settings(s -> s.location(snapshotDirPath))
        );
        return snapshotClient.createRepository(createRepositoryRequest);
    }

    public CreateSnapshotResponse createSnapshot(String repositoryName, String snapshotName, String... indices) throws IOException {
        CreateSnapshotRequest createSnapshotRequest = CreateSnapshotRequest.of(
            r -> r.repository(repositoryName).snapshot(snapshotName).indices(Arrays.asList(indices))
        );
        return snapshotClient.create(createSnapshotRequest);
    }

    public int waitForSnapshotCreation(String repositoryName, String snapshotName) {
        AtomicInteger count = new AtomicInteger();
        GetSnapshotRequest getSnapshotsRequest = GetSnapshotRequest.of(r -> r.repository(repositoryName).snapshot(snapshotName));
        Awaitility.await()
            .pollDelay(250, TimeUnit.MILLISECONDS)
            .pollInterval(2, TimeUnit.SECONDS)
            .alias("wait for snapshot creation")
            .ignoreExceptions()
            .until(() -> {
                count.incrementAndGet();
                GetSnapshotResponse snapshotsResponse = snapshotClient.get(getSnapshotsRequest);
                SnapshotInfo snapshotInfo = snapshotsResponse.snapshots().get(0);
                return "SUCCESS".equals(snapshotInfo.state());
            });
        return count.get();
    }

    public DeleteRepositoryResponse deleteSnapshotRepository(String repositoryName) throws IOException {
        DeleteRepositoryRequest request = DeleteRepositoryRequest.of(r -> r.name(repositoryName));
        return snapshotClient.deleteRepository(request);
    }

    public DeleteSnapshotResponse deleteSnapshot(String repositoryName, String snapshotName) throws IOException {
        return snapshotClient.delete(DeleteSnapshotRequest.of(r -> r.repository(repositoryName).snapshot(snapshotName)));
    }

    public RestoreSnapshotResponse restoreSnapshot(
        String repositoryName,
        String snapshotName,
        String renamePattern,
        String renameReplacement
    ) throws IOException {
        RestoreSnapshotRequest restoreSnapshotRequest = RestoreSnapshotRequest.of(
            r -> r.repository(repositoryName).snapshot(snapshotName).renamePattern(renamePattern).renameReplacement(renameReplacement)
        );
        return snapshotClient.restore(restoreSnapshotRequest);
    }
}
