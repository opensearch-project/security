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

import org.apache.commons.lang3.StringUtils;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.search.SearchResponse;

class ContainNotEmptyScrollingIdMatcher extends TypeSafeDiagnosingMatcher<SearchResponse> {

    @Override
    protected boolean matchesSafely(SearchResponse searchResponse, Description mismatchDescription) {
        String scrollId = searchResponse.getScrollId();
        if (StringUtils.isEmpty(scrollId)) {
            mismatchDescription.appendText("scrolling id is null or empty");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Search response should contain scrolling id.");
    }
}
