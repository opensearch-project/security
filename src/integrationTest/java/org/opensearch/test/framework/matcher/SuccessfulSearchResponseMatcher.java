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

import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.rest.RestStatus;

class SuccessfulSearchResponseMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

    @Override
    protected boolean matchesSafely(SearchResponse searchResponse, Description mismatchDescription) {
        if (RestStatus.OK.equals(searchResponse.status()) == false) {
            mismatchDescription.appendText("has status ").appendValue(searchResponse.status()).appendText(" which denotes failure.");
            return false;
        }
        if (searchResponse.getShardFailures().length != 0) {
            mismatchDescription.appendText("contains ").appendValue(searchResponse.getShardFailures().length).appendText(" shard failures");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful search response");
    }
}
