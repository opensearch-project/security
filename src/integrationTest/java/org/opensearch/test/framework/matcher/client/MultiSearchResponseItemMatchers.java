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

import org.opensearch.client.opensearch.core.msearch.MultiSearchResponseItem;

public class MultiSearchResponseItemMatchers {

    private MultiSearchResponseItemMatchers() {}

    public static <T> Matcher<MultiSearchResponseItem<?>> searchHitContainsFieldWithValue(int hitIndex, String fieldName, T expectedValue) {
        return new MultiSearchResponseItemContainsFieldWithValueMatcher<>(hitIndex, fieldName, expectedValue);
    }

    public static Matcher<MultiSearchResponseItem<?>> searchHitsContainDocumentWithId(int hitIndex, String indexName, String documentId) {
        return new MultiSearchResponseItemContainDocumentWithIdMatcher(hitIndex, indexName, documentId);
    }
}
