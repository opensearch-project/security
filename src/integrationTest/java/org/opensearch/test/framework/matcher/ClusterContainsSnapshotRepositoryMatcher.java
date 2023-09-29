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

import java.util.Set;
import java.util.stream.Collectors;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import org.opensearch.action.admin.cluster.repositories.get.GetRepositoriesRequest;
import org.opensearch.action.admin.cluster.repositories.get.GetRepositoriesResponse;
import org.opensearch.client.Client;
import org.opensearch.client.ClusterAdminClient;
import org.opensearch.repositories.RepositoryMissingException;

import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.joining;

class ClusterContainsSnapshotRepositoryMatcher extends TypeSafeDiagnosingMatcher<Client> {

    private final String repositoryName;

    public ClusterContainsSnapshotRepositoryMatcher(String repositoryName) {
        this.repositoryName = requireNonNull(repositoryName, "Repository name is required.");
    }

    @Override
    protected boolean matchesSafely(Client client, Description mismatchDescription) {
        try {
            ClusterAdminClient adminClient = client.admin().cluster();
            GetRepositoriesRequest request = new GetRepositoriesRequest(new String[] { "*" });
            GetRepositoriesResponse response = adminClient.getRepositories(request).actionGet();
            if (response == null) {
                mismatchDescription.appendText("Cannot check if cluster contain repository");
                return false;
            }
            Set<String> actualRepositoryNames = response.repositories()
                .stream()
                .map(metadata -> metadata.name())
                .collect(Collectors.toSet());
            if (actualRepositoryNames.contains(repositoryName) == false) {
                mismatchDescription.appendText("Cluster does not contain snapshot repository ")
                    .appendValue(repositoryName)
                    .appendText(", but the following repositories are defined in the cluster ")
                    .appendValue(actualRepositoryNames.stream().collect(joining(", ")));
                return false;
            }
        } catch (RepositoryMissingException e) {
            mismatchDescription.appendText(" cluster does not contain any repository.");
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("Cluster contain snapshot repository with name ").appendValue(repositoryName);
    }
}
