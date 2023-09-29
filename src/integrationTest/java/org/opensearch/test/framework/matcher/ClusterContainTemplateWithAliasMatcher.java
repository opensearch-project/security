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
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesRequest;
import org.opensearch.action.admin.indices.template.get.GetIndexTemplatesResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.AliasMetadata;

import static java.util.Objects.requireNonNull;

class ClusterContainTemplateWithAliasMatcher extends TypeSafeDiagnosingMatcher<Client> {

    private final String templateName;
    private final String aliasName;

    public ClusterContainTemplateWithAliasMatcher(String templateName, String aliasName) {
        this.templateName = requireNonNull(templateName, "Index template name is required.");
        this.aliasName = requireNonNull(aliasName, "Alias name is required.");
    }

    @Override
    protected boolean matchesSafely(Client client, Description mismatchDescription) {
        var response = client.admin().indices().getTemplates(new GetIndexTemplatesRequest(templateName)).actionGet();
        if (response.getIndexTemplates().isEmpty()) {
            mismatchDescription.appendText("but template does not exists");
            return false;
        }
        Set<String> aliases = getAliases(response);
        if (aliases.contains(aliasName) == false) {
            mismatchDescription.appendText("alias ")
                .appendValue(aliasName)
                .appendText(" is not present in template, other aliases in template ")
                .appendValue(aliases.stream().collect(Collectors.joining(", ")));
            return false;
        }
        return true;
    }

    private Set<String> getAliases(GetIndexTemplatesResponse response) {
        return response.getIndexTemplates()
            .stream()
            .map(metadata -> metadata.getAliases())
            .flatMap(aliasMap -> aliasNames(aliasMap))
            .collect(Collectors.toSet());
    }

    private Stream<String> aliasNames(Map<String, AliasMetadata> aliasMap) {
        Iterable<Map.Entry<String, AliasMetadata>> iterable = () -> aliasMap.entrySet().iterator();
        return StreamSupport.stream(iterable.spliterator(), false).map(entry -> entry.getValue().getAlias());
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("template ").appendValue(templateName).appendText(" exists and ");
    }
}
