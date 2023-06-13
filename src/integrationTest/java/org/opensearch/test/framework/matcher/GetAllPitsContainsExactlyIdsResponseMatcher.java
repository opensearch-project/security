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

import java.util.Set;
import java.util.stream.Collectors;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.search.GetAllPitNodesResponse;
import org.opensearch.action.search.ListPitInfo;

import static java.util.Objects.isNull;

class GetAllPitsContainsExactlyIdsResponseMatcher extends TypeSafeDiagnosingMatcher<GetAllPitNodesResponse> {

    private final Set<String> expectedPitIds;

    GetAllPitsContainsExactlyIdsResponseMatcher(String[] expectedPitIds) {
        if (isNull(expectedPitIds) || 0 == expectedPitIds.length) {
            throw new IllegalArgumentException("expectedPitIds cannot be null or empty");
        }
        this.expectedPitIds = Set.of(expectedPitIds);
    }

    @Override
    protected boolean matchesSafely(GetAllPitNodesResponse response, Description mismatchDescription) {
        Set<String> actualPitIds = response.getPitInfos().stream().map(ListPitInfo::getPitId).collect(Collectors.toSet());
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
