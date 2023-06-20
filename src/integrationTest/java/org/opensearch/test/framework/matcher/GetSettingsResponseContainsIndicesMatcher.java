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

import java.util.Map;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.admin.indices.settings.get.GetSettingsResponse;
import org.opensearch.common.settings.Settings;

import static java.util.Objects.isNull;

class GetSettingsResponseContainsIndicesMatcher extends TypeSafeDiagnosingMatcher<GetSettingsResponse> {

    private final String[] expectedIndices;

    GetSettingsResponseContainsIndicesMatcher(String[] expectedIndices) {
        if (isNull(expectedIndices) || 0 == expectedIndices.length) {
            throw new IllegalArgumentException("expectedIndices cannot be null or empty");
        }
        this.expectedIndices = expectedIndices;
    }

    @Override
    protected boolean matchesSafely(GetSettingsResponse response, Description mismatchDescription) {

        final Map<String, Settings> indexToSettings = response.getIndexToSettings();
        for (String index : expectedIndices) {
            if (!indexToSettings.containsKey(index)) {
                mismatchDescription.appendText("Response contains settings of indices: ").appendValue(indexToSettings.keySet());
                return false;
            }
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Response should contain settings of indices: ").appendValue(expectedIndices);
    }
}
