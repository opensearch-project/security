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

import org.opensearch.client.opensearch.indices.GetMappingResponse;
import org.opensearch.client.opensearch.indices.get_mapping.IndexMappingRecord;

import static java.util.Objects.isNull;

class GetMappingsResponseContainsIndicesMatcher extends TypeSafeDiagnosingMatcher<GetMappingResponse> {

    private final String[] expectedIndices;

    GetMappingsResponseContainsIndicesMatcher(String[] expectedIndices) {
        if (isNull(expectedIndices) || 0 == expectedIndices.length) {
            throw new IllegalArgumentException("expectedIndices cannot be null or empty");
        }
        this.expectedIndices = expectedIndices;
    }

    @Override
    protected boolean matchesSafely(GetMappingResponse response, Description mismatchDescription) {
        Map<String, IndexMappingRecord> indicesMappings = response.result();
        for (String index : expectedIndices) {
            if (!indicesMappings.containsKey(index)) {
                mismatchDescription.appendText("Response contains mappings of indices: ").appendValue(indicesMappings.keySet());
                return false;
            }
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response should contain mappings of indices: ").appendValue(expectedIndices);
    }
}
