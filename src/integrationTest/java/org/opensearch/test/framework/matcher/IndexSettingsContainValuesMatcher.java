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

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.admin.indices.settings.get.GetSettingsRequest;
import org.opensearch.action.admin.indices.settings.get.GetSettingsResponse;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.test.framework.cluster.LocalCluster;

import static java.util.Objects.isNull;
import static java.util.Objects.requireNonNull;

class IndexSettingsContainValuesMatcher extends TypeSafeDiagnosingMatcher<LocalCluster> {

    private final String expectedIndexName;
    private final Settings expectedSettings;

    IndexSettingsContainValuesMatcher(String expectedIndexName, Settings expectedSettings) {
        this.expectedIndexName = requireNonNull(expectedIndexName);
        if (isNull(expectedSettings) || expectedSettings.isEmpty()) {
            throw new IllegalArgumentException("expectedSettings cannot be null or empty");
        }
        this.expectedSettings = expectedSettings;
    }

    @Override
    protected boolean matchesSafely(LocalCluster cluster, Description mismatchDescription) {
        try (Client client = cluster.getInternalNodeClient()) {
            GetSettingsResponse response = client.admin()
                .indices()
                .getSettings(new GetSettingsRequest().indices(expectedIndexName))
                .actionGet();

            Settings actualSettings = response.getIndexToSettings().get(expectedIndexName);

            for (String setting : expectedSettings.keySet()) {
                if (isNull(actualSettings.get(setting))) {
                    mismatchDescription.appendValue("Value of ").appendValue(setting).appendText(" property is missing");
                    return false;
                }
                if (!expectedSettings.get(setting).equals(actualSettings.get(setting))) {
                    mismatchDescription.appendText("Actual value of `")
                        .appendValue(setting)
                        .appendText("` property: ")
                        .appendValue(actualSettings.get(setting));
                    return false;
                }
            }
            return true;
        } catch (IndexNotFoundException e) {
            mismatchDescription.appendText("Index: ").appendValue(expectedIndexName).appendText(" does not exist");
            return false;
        }
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Settings of index ")
            .appendValue(expectedIndexName)
            .appendText(" should contain values: ")
            .appendValue(expectedSettings);
    }
}
