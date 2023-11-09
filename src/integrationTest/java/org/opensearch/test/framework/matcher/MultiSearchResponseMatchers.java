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

import org.opensearch.action.search.MultiSearchResponse;

public class MultiSearchResponseMatchers {

    private MultiSearchResponseMatchers() {}

    public static Matcher<MultiSearchResponse> isSuccessfulMultiSearchResponse() {
        return new SuccessfulMultiSearchResponseMatcher();
    }

    public static Matcher<MultiSearchResponse> numberOfSearchItemResponsesIsEqualTo(int expectedNumberOfResponses) {
        return new NumberOfSearchItemResponsesIsEqualToMatcher(expectedNumberOfResponses);
    }

}
