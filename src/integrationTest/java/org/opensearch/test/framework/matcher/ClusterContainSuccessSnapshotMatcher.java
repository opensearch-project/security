/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.matcher;

import java.util.stream.Collectors;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.admin.cluster.snapshots.get.GetSnapshotsRequest;
import org.opensearch.action.admin.cluster.snapshots.get.GetSnapshotsResponse;
import org.opensearch.client.Client;
import org.opensearch.snapshots.SnapshotMissingException;
import org.opensearch.snapshots.SnapshotState;

import static java.util.Objects.requireNonNull;

class ClusterContainSuccessSnapshotMatcher extends TypeSafeDiagnosingMatcher<Client> {

    private final String repositoryName;
    private final String snapshotName;

    public ClusterContainSuccessSnapshotMatcher(String repositoryName, String snapshotName) {
        this.repositoryName = requireNonNull(repositoryName, "Snapshot repository name is required.");
        this.snapshotName = requireNonNull(snapshotName, "Snapshot name is required.");
    }

    @Override
    protected boolean matchesSafely(Client client, Description mismatchDescription) {
        try {
            GetSnapshotsRequest request = new GetSnapshotsRequest(repositoryName, new String[] { snapshotName });
            GetSnapshotsResponse response = client.admin().cluster().getSnapshots(request).actionGet();
            long count = response.getSnapshots()
                .stream()
                .map(snapshot -> snapshot.state())
                .filter(status -> SnapshotState.SUCCESS.equals(status))
                .count();
            if (count != 1) {
                String snapshotStatuses = response.getSnapshots()
                    .stream()
                    .map(info -> String.format("%s %s", info.snapshotId().getName(), info.state()))
                    .collect(Collectors.joining(", "));
                mismatchDescription.appendText("snapshot is not present or has incorrect state, snapshots statuses ")
                    .appendValue(snapshotStatuses);
                return false;
            }
        } catch (SnapshotMissingException e) {
            mismatchDescription.appendText(" snapshot does not exist");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Cluster contain snapshot ")
            .appendValue(snapshotName)
            .appendText(" in repository ")
            .appendValue(repositoryName)
            .appendText(" with success status");
    }
}
