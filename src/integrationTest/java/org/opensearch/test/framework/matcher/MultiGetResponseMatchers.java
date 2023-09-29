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

import org.opensearch.action.get.MultiGetResponse;

public class MultiGetResponseMatchers {

    private MultiGetResponseMatchers() {}

    public static Matcher<MultiGetResponse> isSuccessfulMultiGetResponse() {
        return new SuccessfulMultiGetResponseMatcher();
    }

    public static Matcher<MultiGetResponse> numberOfGetItemResponsesIsEqualTo(int expectedNumberOfResponses) {
        return new NumberOfGetItemResponsesIsEqualToMatcher(expectedNumberOfResponses);
    }

}
