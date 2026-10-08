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

import org.opensearch.client.opensearch.core.get.GetResult;

public class GetResultMatchers {

    private GetResultMatchers() {}

    public static Matcher<GetResult<?>> containDocument(String indexName, String documentId) {
        return new GetResultContainsDocumentWithIdMatcher(indexName, documentId);
    }

    public static Matcher<GetResult<?>> containOnlyDocumentId(String indexName, String documentId) {
        return new GetResultContainOnlyDocumentIdMatcher(indexName, documentId);
    }

    public static Matcher<GetResult<?>> documentContainField(String fieldName, Object fieldValue) {
        return new GetResultDocumentFieldValueMatcher(fieldName, fieldValue);
    }

    public static Matcher<GetResult<?>> documentDoesNotContainField(String fieldName) {
        return new GetResultDocumentDoesNotContainFieldMatcher(fieldName);
    }
}
