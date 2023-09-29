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

import org.hamcrest.Matcher;

import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.framework.cluster.LocalCluster;

public class ClusterMatchers {

    private ClusterMatchers() {

    }

    public static Matcher<Client> clusterContainsDocument(String indexName, String documentId) {
        return new ClusterContainsDocumentMatcher(indexName, documentId);
    }

    public static Matcher<Client> clusterContainsDocumentWithFieldValue(
        String indexName,
        String documentId,
        String fieldName,
        Object fieldValue
    ) {
        return new ClusterContainsDocumentWithFieldValueMatcher(indexName, documentId, fieldName, fieldValue);
    }

    public static Matcher<Client> clusterContainTemplate(String templateName) {
        return new ClusterContainTemplateMatcher(templateName);
    }

    public static Matcher<Client> clusterContainTemplateWithAlias(String templateName, String aliasName) {
        return new ClusterContainTemplateWithAliasMatcher(templateName, aliasName);
    }

    public static Matcher<Client> clusterContainsSnapshotRepository(String repositoryName) {
        return new ClusterContainsSnapshotRepositoryMatcher(repositoryName);
    }

    public static Matcher<Client> clusterContainSuccessSnapshot(String repositoryName, String snapshotName) {
        return new ClusterContainSuccessSnapshotMatcher(repositoryName, snapshotName);
    }

    public static Matcher<Client> snapshotInClusterDoesNotExists(String repositoryName, String snapshotName) {
        return new SnapshotInClusterDoesNotExist(repositoryName, snapshotName);
    }

    public static Matcher<Client> aliasExists(String aliasName) {
        return new AliasExistsMatcher(aliasName);
    }

    public static Matcher<LocalCluster> indexExists(String expectedIndexName) {
        return new IndexExistsMatcher(expectedIndexName);
    }

    public static Matcher<LocalCluster> indexStateIsEqualTo(String expectedIndexName, IndexMetadata.State expectedState) {
        return new IndexStateIsEqualToMatcher(expectedIndexName, expectedState);
    }

    public static Matcher<LocalCluster> indexSettingsContainValues(String expectedIndexName, Settings expectedSettings) {
        return new IndexSettingsContainValuesMatcher(expectedIndexName, expectedSettings);
    }

    public static Matcher<LocalCluster> indexMappingIsEqualTo(String expectedIndexName, Map<String, ?> expectedMapping) {
        return new IndexMappingIsEqualToMatcher(expectedIndexName, expectedMapping);
    }
}
