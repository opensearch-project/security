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

import org.opensearch.action.fieldcaps.FieldCapabilitiesResponse;

public class FieldCapabilitiesResponseMatchers {

    private FieldCapabilitiesResponseMatchers() {}

    public static Matcher<FieldCapabilitiesResponse> containsExactlyIndices(String... expectedIndices) {
        return new ContainsExactlyIndicesMatcher(expectedIndices);
    }

    public static Matcher<FieldCapabilitiesResponse> containsFieldWithNameAndType(String expectedFieldName, String expectedFieldType) {
        return new ContainsFieldWithTypeMatcher(expectedFieldName, expectedFieldType);
    }

    public static Matcher<FieldCapabilitiesResponse> numberOfFieldsIsEqualTo(int expectedNumberOfFields) {
        return new NumberOfFieldsIsEqualToMatcher(expectedNumberOfFields);
    }

}
