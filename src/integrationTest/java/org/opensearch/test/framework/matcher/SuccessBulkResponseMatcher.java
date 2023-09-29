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

import java.util.Arrays;
import java.util.stream.Collectors;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.core.rest.RestStatus;

class SuccessBulkResponseMatcher extends TypeSafeDiagnosingMatcher<BulkResponse> {

    @Override
    protected boolean matchesSafely(BulkResponse response, Description mismatchDescription) {
        RestStatus status = response.status();
        if (RestStatus.OK.equals(status) == false) {
            mismatchDescription.appendText("incorrect response status ").appendValue(status);
            return false;
        }
        if (response.hasFailures()) {
            String failureDescription = Arrays.stream(response.getItems())
                .filter(BulkItemResponse::isFailed)
                .map(BulkItemResponse::getFailure)
                .map(Object::toString)
                .collect(Collectors.joining(",\n"));
            mismatchDescription.appendText("bulk response contains failures ").appendValue(failureDescription);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("success bulk response");
    }
}
