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

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.admin.cluster.snapshots.get.GetSnapshotsRequest;
import org.opensearch.client.Client;
import org.opensearch.snapshots.SnapshotMissingException;

import static java.util.Objects.requireNonNull;

class SnapshotInClusterDoesNotExist extends TypeSafeDiagnosingMatcher<Client> {
    private final String repositoryName;
    private final String snapshotName;

    public SnapshotInClusterDoesNotExist(String repositoryName, String snapshotName) {
        this.repositoryName = requireNonNull(repositoryName, "Snapshot repository name is required.");
        this.snapshotName = requireNonNull(snapshotName, "Snapshot name is required.");
    }

    @Override
    protected boolean matchesSafely(Client client, Description mismatchDescription) {
        try {
            GetSnapshotsRequest request = new GetSnapshotsRequest(repositoryName, new String[] { snapshotName });
            client.admin().cluster().getSnapshots(request).actionGet();
            mismatchDescription.appendText("snapshot exists");
            return false;
        } catch (SnapshotMissingException e) {
            return true;
        }
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Snapshot ")
            .appendValue(snapshotName)
            .appendText(" does not exist in repository ")
            .appendValue(repositoryName);
    }
}
