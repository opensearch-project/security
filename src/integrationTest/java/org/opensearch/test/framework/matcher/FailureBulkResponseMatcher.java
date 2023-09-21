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

import org.opensearch.action.bulk.BulkResponse;

class FailureBulkResponseMatcher extends TypeSafeDiagnosingMatcher<BulkResponse> {

    @Override
    protected boolean matchesSafely(BulkResponse response, Description mismatchDescription) {
        if (response.hasFailures() == false) {
            mismatchDescription.appendText(" bulk operation was executed correctly what is not expected.");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("bulk operation failure");
    }
}
