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

import java.util.stream.Collectors;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch._types.ErrorCause;
import org.opensearch.client.opensearch.core.BulkResponse;
import org.opensearch.client.opensearch.core.bulk.BulkResponseItem;

class SuccessBulkResponseMatcher extends TypeSafeDiagnosingMatcher<BulkResponse> {

    @Override
    protected boolean matchesSafely(BulkResponse response, Description mismatchDescription) {
        if (response.errors()) {
            String failureDescription = response.items()
                .stream()
                .filter(i -> i.error() != null)
                .map(BulkResponseItem::error)
                .map(ErrorCause::reason)
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
