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

import java.util.Set;
import java.util.stream.Collectors;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch.core.DeleteAllPitsResponse;
import org.opensearch.client.opensearch.core.pit.DeletedPit;

import static java.util.Objects.isNull;

class DeletePitsContainsExactlyIdsResponseMatcher extends TypeSafeDiagnosingMatcher<DeleteAllPitsResponse> {

    private final Set<String> expectedPitIds;

    DeletePitsContainsExactlyIdsResponseMatcher(String[] expectedPitIds) {
        if (isNull(expectedPitIds) || 0 == expectedPitIds.length) {
            throw new IllegalArgumentException("expectedPitIds cannot be null or empty");
        }
        this.expectedPitIds = Set.of(expectedPitIds);
    }

    @Override
    protected boolean matchesSafely(DeleteAllPitsResponse response, Description mismatchDescription) {
        Set<String> actualPitIds = response.pits().stream().map(DeletedPit::pitId).collect(Collectors.toSet());
        if (!actualPitIds.equals(expectedPitIds)) {
            mismatchDescription.appendText("Actual pit ids: ").appendValue(actualPitIds);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Should contain exactly pit with ids: ").appendValue(expectedPitIds);
    }
}
