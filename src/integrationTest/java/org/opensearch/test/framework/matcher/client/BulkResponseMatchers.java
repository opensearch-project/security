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

import org.opensearch.client.opensearch._types.ErrorCause;
import org.opensearch.client.opensearch.core.BulkResponse;

public class BulkResponseMatchers {

    private BulkResponseMatchers() {

    }

    public static Matcher<BulkResponse> successBulkResponse() {
        return new SuccessBulkResponseMatcher();
    }

    public static Matcher<BulkResponse> failureBulkResponse() {
        return new FailureBulkResponseMatcher();
    }

    public static Matcher<BulkResponse> bulkResponseContainExceptions(Matcher<ErrorCause> exceptionMatcher) {
        return new BulkResponseContainExceptionsMatcher(exceptionMatcher);
    }

    public static Matcher<BulkResponse> bulkResponseContainExceptions(int index, Matcher<ErrorCause> exceptionMatcher) {
        return new BulkResponseContainExceptionsAtIndexMatcher(index, exceptionMatcher);
    }
}
