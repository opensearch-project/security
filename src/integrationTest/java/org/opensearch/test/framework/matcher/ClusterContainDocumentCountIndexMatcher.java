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

import org.opensearch.action.admin.indices.get.GetIndexResponse;
import org.opensearch.client.Client;
import org.opensearch.test.framework.cluster.LocalCluster;

import static java.util.Objects.requireNonNull;

class ClusterContainDocumentCountIndexMatcher extends TypeSafeDiagnosingMatcher<LocalCluster> {

    private final String indexName;
    private final int expectedDocumentCount;

    public ClusterContainDocumentCountIndexMatcher(String indexName, int expectedDocumentCount) {
        this.indexName = requireNonNull(indexName, "Index name is required.");
        this.expectedDocumentCount = expectedDocumentCount;
    }

    @Override
    protected boolean matchesSafely(LocalCluster cluster, Description mismatchDescription) {
        try (Client client = cluster.getInternalNodeClient()) {
            GetIndexResponse response = client.admin().indices().getIndex(null).actionGet();
        }
        return false;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("contains ").appendValue(expectedDocumentCount).appendText(" in index ").appendText(indexName);
    }
}
