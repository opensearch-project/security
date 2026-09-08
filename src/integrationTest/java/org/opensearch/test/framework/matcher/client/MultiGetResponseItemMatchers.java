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

import org.opensearch.client.opensearch.core.mget.MultiGetResponseItem;

public class MultiGetResponseItemMatchers {

    private MultiGetResponseItemMatchers() {}

    public static Matcher<MultiGetResponseItem<?>> containDocument(String indexName, String documentId) {
        return new MultiGetResponseItemContainsDocumentWithIdMatcher(indexName, documentId);
    }

    public static Matcher<MultiGetResponseItem<?>> containOnlyDocumentId(String indexName, String documentId) {
        return new MultiGetResponseItemContainOnlyDocumentIdMatcher(indexName, documentId);
    }

    public static Matcher<MultiGetResponseItem<?>> documentContainField(String fieldName, Object fieldValue) {
        return new MultiGetResponseItemDocumentFieldValueMatcher(fieldName, fieldValue);
    }

    public static Matcher<MultiGetResponseItem<?>> documentDoesNotContainField(String fieldName) {
        return new MultiGetResponseItemDocumentDoesNotContainFieldMatcher(fieldName);
    }
}
