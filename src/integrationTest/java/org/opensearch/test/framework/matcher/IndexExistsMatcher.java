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

import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.client.Client;
import org.opensearch.test.framework.cluster.LocalCluster;

import static java.util.Objects.requireNonNull;

class IndexExistsMatcher extends TypeSafeDiagnosingMatcher<LocalCluster> {

    private final String expectedIndexName;

    IndexExistsMatcher(String expectedIndexName) {
        this.expectedIndexName = requireNonNull(expectedIndexName);
    }

    @Override
    protected boolean matchesSafely(LocalCluster cluster, Description mismatchDescription) {
        try (Client client = cluster.getInternalNodeClient()) {
            IndicesExistsResponse indicesExistsResponse = client.admin()
                .indices()
                .exists(new IndicesExistsRequest(expectedIndexName))
                .actionGet();
            if (!indicesExistsResponse.isExists()) {
                mismatchDescription.appendText("Index ").appendValue(expectedIndexName).appendValue(" does not exist");
                return false;
            }
            return true;
        }
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Index ").appendValue(expectedIndexName).appendText(" exists");
    }
}
