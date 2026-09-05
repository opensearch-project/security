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

import org.opensearch.client.opensearch.core.FieldCapsResponse;

public class FieldCapsResponseMatchers {

    private FieldCapsResponseMatchers() {}

    public static Matcher<FieldCapsResponse> containsExactlyIndices(String... expectedIndices) {
        return new ContainsExactlyIndicesMatcher(expectedIndices);
    }

    public static Matcher<FieldCapsResponse> containsFieldWithNameAndType(String expectedFieldName, String expectedFieldType) {
        return new ContainsFieldWithTypeMatcher(expectedFieldName, expectedFieldType);
    }

    public static Matcher<FieldCapsResponse> numberOfFieldsIsEqualTo(int expectedNumberOfFields) {
        return new NumberOfFieldsIsEqualToMatcher(expectedNumberOfFields);
    }
}
