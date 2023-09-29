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

import org.opensearch.action.admin.indices.cache.clear.ClearIndicesCacheResponse;
import org.opensearch.core.rest.RestStatus;

class SuccessfulClearIndicesCacheResponseMatcher extends TypeSafeDiagnosingMatcher<ClearIndicesCacheResponse> {

    @Override
    protected boolean matchesSafely(ClearIndicesCacheResponse response, Description mismatchDescription) {
        if (!RestStatus.OK.equals(response.getStatus())) {
            mismatchDescription.appendText("Status is equal to ").appendValue(response.getStatus());
            return false;
        }
        if (response.getShardFailures().length != 0) {
            mismatchDescription.appendText("Contains ").appendValue(response.getShardFailures().length).appendText(" shard failures");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Successful clear index cache response");
    }
}
