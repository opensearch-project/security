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

import org.hamcrest.Matcher;

import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.action.search.DeletePitResponse;
import org.opensearch.action.search.GetAllPitNodesResponse;

public class PitResponseMatchers {

    private PitResponseMatchers() {}

    public static Matcher<CreatePitResponse> isSuccessfulCreatePitResponse() {
        return new SuccessfulCreatePitResponseMatcher();
    }

    public static Matcher<GetAllPitNodesResponse> getAllResponseContainsExactlyPitWithIds(String... expectedPitIds) {
        return new GetAllPitsContainsExactlyIdsResponseMatcher(expectedPitIds);
    }

    public static Matcher<DeletePitResponse> isSuccessfulDeletePitResponse() {
        return new SuccessfulDeletePitResponseMatcher();
    }

    public static Matcher<DeletePitResponse> deleteResponseContainsExactlyPitWithIds(String... expectedPitIds) {
        return new DeletePitContainsExactlyIdsResponseMatcher(expectedPitIds);
    }
}
