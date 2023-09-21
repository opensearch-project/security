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

import java.util.Map;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.admin.cluster.state.ClusterStateRequest;
import org.opensearch.action.admin.cluster.state.ClusterStateResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.test.framework.cluster.LocalCluster;

import static java.util.Objects.requireNonNull;

class IndexStateIsEqualToMatcher extends TypeSafeDiagnosingMatcher<LocalCluster> {

    private final String expectedIndexName;
    private final IndexMetadata.State expectedState;

    IndexStateIsEqualToMatcher(String expectedIndexName, IndexMetadata.State expectedState) {
        this.expectedIndexName = requireNonNull(expectedIndexName);
        this.expectedState = requireNonNull(expectedState);
    }

    @Override
    protected boolean matchesSafely(LocalCluster cluster, Description mismatchDescription) {
        try (Client client = cluster.getInternalNodeClient()) {
            ClusterStateRequest clusterStateRequest = new ClusterStateRequest().indices(expectedIndexName);
            ClusterStateResponse clusterStateResponse = client.admin().cluster().state(clusterStateRequest).actionGet();

            Map<String, IndexMetadata> indicesMetadata = clusterStateResponse.getState().getMetadata().indices();
            if (!indicesMetadata.containsKey(expectedIndexName)) {
                mismatchDescription.appendValue("Index does not exist");
            }
            IndexMetadata indexMetadata = indicesMetadata.get(expectedIndexName);
            if (expectedState != indexMetadata.getState()) {
                mismatchDescription.appendValue("Actual index state is equal to ").appendValue(indexMetadata.getState().name());
                return false;
            }
            return true;
        }
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Index: ")
            .appendValue(expectedIndexName)
            .appendText(" . State should be equal to ")
            .appendValue(expectedState.name());
    }
}
