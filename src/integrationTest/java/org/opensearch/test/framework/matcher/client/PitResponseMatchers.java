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

import org.hamcrest.Matcher;

import org.opensearch.client.opensearch.core.CreatePitResponse;
import org.opensearch.client.opensearch.core.DeleteAllPitsResponse;
import org.opensearch.client.opensearch.core.DeletePitResponse;
import org.opensearch.client.opensearch.core.GetAllPitsResponse;

public class PitResponseMatchers {

    private PitResponseMatchers() {}

    public static Matcher<CreatePitResponse> isSuccessfulCreatePitResponse() {
        return new SuccessfulCreatePitResponseMatcher();
    }

    public static Matcher<GetAllPitsResponse> getAllResponseContainsExactlyPitWithIds(String... expectedPitIds) {
        return new GetAllPitsContainsExactlyIdsResponseMatcher(expectedPitIds);
    }

    public static Matcher<DeletePitResponse> isSuccessfulDeletePitResponse() {
        return new SuccessfulDeletePitResponseMatcher();
    }

    public static Matcher<DeleteAllPitsResponse> isSuccessfulDeletePitsResponse() {
        return new SuccessfulDeletePitsResponseMatcher();
    }

    public static Matcher<DeletePitResponse> deleteResponseContainsExactlyPitWithIds(String... expectedPitIds) {
        return new DeletePitContainsExactlyIdsResponseMatcher(expectedPitIds);
    }

    public static Matcher<DeleteAllPitsResponse> deletePitsResponseContainsExactlyPitWithIds(String... expectedPitIds) {
        return new DeletePitsContainsExactlyIdsResponseMatcher(expectedPitIds);
    }
}
