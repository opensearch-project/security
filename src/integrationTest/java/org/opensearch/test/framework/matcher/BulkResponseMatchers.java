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

import org.opensearch.action.bulk.BulkResponse;

public class BulkResponseMatchers {

    private BulkResponseMatchers() {

    }

    public static Matcher<BulkResponse> successBulkResponse() {
        return new SuccessBulkResponseMatcher();
    }

    public static Matcher<BulkResponse> failureBulkResponse() {
        return new FailureBulkResponseMatcher();
    }

    public static Matcher<BulkResponse> bulkResponseContainExceptions(Matcher<Throwable> exceptionMatcher) {
        return new BulkResponseContainExceptionsMatcher(exceptionMatcher);
    }

    public static Matcher<BulkResponse> bulkResponseContainExceptions(int index, Matcher<Throwable> exceptionMatcher) {
        return new BulkResponseContainExceptionsAtIndexMatcher(index, exceptionMatcher);
    }
}
