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

import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.client.Client;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.test.framework.cluster.LocalCluster;

import static java.util.Objects.isNull;
import static java.util.Objects.requireNonNull;

class IndexMappingIsEqualToMatcher extends TypeSafeDiagnosingMatcher<LocalCluster> {

    private final String expectedIndexName;
    private final Map<String, ?> expectedMapping;

    IndexMappingIsEqualToMatcher(String expectedIndexName, Map<String, ?> expectedMapping) {
        this.expectedIndexName = requireNonNull(expectedIndexName);
        if (isNull(expectedMapping) || expectedMapping.isEmpty()) {
            throw new IllegalArgumentException("expectedMapping cannot be null or empty");
        }
        this.expectedMapping = expectedMapping;
    }

    @Override
    protected boolean matchesSafely(LocalCluster cluster, Description mismatchDescription) {
        try (Client client = cluster.getInternalNodeClient()) {
            GetMappingsResponse response = client.admin()
                .indices()
                .getMappings(new GetMappingsRequest().indices(expectedIndexName))
                .actionGet();

            Map<String, Object> actualIndexMapping = response.getMappings().get(expectedIndexName).sourceAsMap();

            if (!expectedMapping.equals(actualIndexMapping)) {
                mismatchDescription.appendText("Actual mapping ").appendValue(actualIndexMapping).appendText(" does not match expected");
                return false;
            }
            return true;
        } catch (IndexNotFoundException e) {
            mismatchDescription.appendText("Index: ").appendValue(expectedIndexName).appendText(" does not exist");
            return false;
        }
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Index ")
            .appendValue(expectedIndexName)
            .appendText(". Mapping should be equal to: ")
            .appendValue(expectedMapping);
    }
}
