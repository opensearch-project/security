/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.matcher.client;

import java.util.Map;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch.indices.GetIndicesSettingsResponse;
import org.opensearch.client.opensearch.indices.IndexState;

import static java.util.Objects.isNull;

class GetSettingsResponseContainsIndicesMatcher extends TypeSafeDiagnosingMatcher<GetIndicesSettingsResponse> {

    private final String[] expectedIndices;

    GetSettingsResponseContainsIndicesMatcher(String[] expectedIndices) {
        if (isNull(expectedIndices) || 0 == expectedIndices.length) {
            throw new IllegalArgumentException("expectedIndices cannot be null or empty");
        }
        this.expectedIndices = expectedIndices;
    }

    @Override
    protected boolean matchesSafely(GetIndicesSettingsResponse response, Description mismatchDescription) {

        final Map<String, IndexState> indexToSettings = response.result();
        for (String index : expectedIndices) {
            if (!indexToSettings.containsKey(index)) {
                mismatchDescription.appendText("Response contains settings of indices: ").appendValue(indexToSettings.keySet());
                return false;
            }
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response should contain settings of indices: ").appendValue(expectedIndices);
    }
}
