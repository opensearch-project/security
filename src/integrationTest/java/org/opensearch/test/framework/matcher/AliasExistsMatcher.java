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

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.admin.indices.alias.get.GetAliasesRequest;
import org.opensearch.action.admin.indices.alias.get.GetAliasesResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.AliasMetadata;

import static java.util.Objects.requireNonNull;
import static java.util.Spliterator.IMMUTABLE;
import static java.util.Spliterators.spliteratorUnknownSize;

class AliasExistsMatcher extends TypeSafeDiagnosingMatcher<Client> {

    private final String aliasName;

    public AliasExistsMatcher(String aliasName) {
        this.aliasName = requireNonNull(aliasName, "Alias name is required");
    }

    @Override
    protected boolean matchesSafely(Client client, Description mismatchDescription) {
        try {
            GetAliasesResponse response = client.admin().indices().getAliases(new GetAliasesRequest(aliasName)).get();

            Map<String, List<AliasMetadata>> aliases = response.getAliases();
            Set<String> actualAliasNames = StreamSupport.stream(spliteratorUnknownSize(aliases.values().iterator(), IMMUTABLE), false)
                .flatMap(Collection::stream)
                .map(AliasMetadata::getAlias)
                .collect(Collectors.toSet());
            if (actualAliasNames.contains(aliasName) == false) {
                String existingAliases = String.join(", ", actualAliasNames);
                mismatchDescription.appendText(" alias does not exist, defined aliases ").appendValue(existingAliases);
                return false;
            }
            return true;
        } catch (InterruptedException | ExecutionException e) {
            mismatchDescription.appendText("Error occurred during checking if cluster contains alias ").appendValue(e);
            return false;
        }
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Cluster should contain ").appendValue(aliasName).appendText(" alias");
    }
}
