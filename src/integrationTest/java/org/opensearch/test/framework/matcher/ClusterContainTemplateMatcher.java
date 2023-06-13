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

import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesRequest;
import org.opensearch.client.Client;

import static java.util.Objects.requireNonNull;

class ClusterContainTemplateMatcher extends TypeSafeDiagnosingMatcher<Client> {

    private final String templateName;

    public ClusterContainTemplateMatcher(String templateName) {
        this.templateName = requireNonNull(templateName, "Index template name is required.");

    }

    @Override
    protected boolean matchesSafely(Client client, Description mismatchDescription) {
        var response = client.admin().indices().getTemplates(new GetIndexTemplatesRequest(templateName)).actionGet();
        if (response.getIndexTemplates().isEmpty()) {
            mismatchDescription.appendText("But template does not exists");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("template ").appendValue(templateName).appendText(" exists");
    }
}
