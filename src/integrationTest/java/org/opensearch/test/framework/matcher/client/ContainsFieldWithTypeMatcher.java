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

import java.util.Map;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.client.opensearch.core.FieldCapsResponse;
import org.opensearch.client.opensearch.core.field_caps.FieldCapability;

import static java.util.Objects.requireNonNull;

class ContainsFieldWithTypeMatcher extends TypeSafeDiagnosingMatcher<FieldCapsResponse> {

    private final String expectedFieldName;
    private final String expectedFieldType;

    ContainsFieldWithTypeMatcher(String expectedFieldName, String expectedFieldType) {
        this.expectedFieldName = requireNonNull(expectedFieldName, "Field name is required");
        ;
        this.expectedFieldType = requireNonNull(expectedFieldType, "Field type is required");
        ;
    }

    @Override
    protected boolean matchesSafely(FieldCapsResponse response, Description mismatchDescription) {
        Map<String, Map<String, FieldCapability>> fieldCapabilitiesMap = response.fields();
        if (!fieldCapabilitiesMap.containsKey(expectedFieldName)) {
            mismatchDescription.appendText("Response does not contain field with name ").appendText(expectedFieldName);
            return false;
        }
        if (!fieldCapabilitiesMap.get(expectedFieldName).containsKey(expectedFieldType)) {
            mismatchDescription.appendText("Field type does not match ").appendText(expectedFieldType);
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response contains field with name ")
            .appendValue(expectedFieldName)
            .appendText(" and type ")
            .appendValue(expectedFieldType);
    }
}
