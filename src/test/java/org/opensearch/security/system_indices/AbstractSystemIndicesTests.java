/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.system_indices;

import java.io.IOException;
import java.util.List;

import org.apache.http.Header;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;

import org.opensearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.opensearch.action.admin.cluster.snapshots.create.CreateSnapshotRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.junit.Assert.assertEquals;

/**
 *  Test for opendistro system indices, to restrict configured indices access to adminDn
 *  Refer:    "plugins.security.system_indices.enabled"
 *            "plugins.security.system_indices.indices";
 */

public abstract class AbstractSystemIndicesTests extends SingleClusterTest {

    static final String ACCESSIBLE_ONLY_BY_SUPER_ADMIN = ".opendistro_security";
    static final String SYSTEM_INDEX_WITH_NO_ASSOCIATED_ROLE_PERMISSIONS = "random_system_index";
    static final List<String> SYSTEM_INDICES = List.of(
        ".system_index_1",
        SYSTEM_INDEX_WITH_NO_ASSOCIATED_ROLE_PERMISSIONS,
        ACCESSIBLE_ONLY_BY_SUPER_ADMIN
    );

    static final List<String> INDICES_FOR_CREATE_REQUEST = List.of(".system_index_2");
    static final String matchAllQuery = "{\n\"query\": {\"match_all\": {}}}";
    static final String allAccessUser = "admin_all_access";
    static final Header allAccessUserHeader = encodeBasicHeader(allAccessUser, allAccessUser);

    static final String normalUser = "normal_user";
    static final Header normalUserHeader = encodeBasicHeader(normalUser, normalUser);

    static final String normalUserWithoutSystemIndex = "normal_user_without_system_index";
    static final Header normalUserWithoutSystemIndexHeader = encodeBasicHeader(normalUserWithoutSystemIndex, normalUserWithoutSystemIndex);

    static final String createIndexSettings = "{\n"
        + "    \"settings\" : {\n"
        + "        \"index\" : {\n"
        + "            \"number_of_shards\" : 3, \n"
        + "            \"number_of_replicas\" : 2 \n"
        + "        }\n"
        + "    }\n"

        + "}";
    static final String updateIndexSettings = "{\n" + "    \"index\" : {\n" + "        \"refresh_interval\" : null\n" + "    }\n" + "}";
    static final String newMappings = "{\"properties\": {" + "\"user_name\": {" + "\"type\": \"text\"" + "}}}";

    void setupWithSsl(boolean isSystemIndexEnabled, boolean isSystemIndexPermissionEnabled) throws Exception {

        Settings systemIndexSettings = Settings.builder()
            .put(ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY, isSystemIndexEnabled)
            .put(ConfigConstants.SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY, isSystemIndexPermissionEnabled)
            .putList(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, SYSTEM_INDICES)
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
            .put("path.repo", repositoryPath.getRoot().getAbsolutePath())
            .build();
        setup(
            Settings.EMPTY,
            new DynamicSecurityConfig().setConfig("system_indices/config.yml")
                .setSecurityRoles("system_indices/roles.yml")
                .setSecurityInternalUsers("system_indices/internal_users.yml")
                .setSecurityRolesMapping("system_indices/roles_mapping.yml"),
            systemIndexSettings,
            true
        );
    }

    /**
     * Creates a set of test indices and indexes one document into each index.
     *
     */
    void createTestIndicesAndDocs() {
        try (Client tc = getClient()) {
            for (String index : SYSTEM_INDICES) {
                // security index is already created
                if (!index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN)) {
                    tc.admin().indices().create(new CreateIndexRequest(index)).actionGet();
                }
                tc.index(
                    new IndexRequest(index).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .id("document1")
                        .source("{ \"foo\": \"bar\" }", XContentType.JSON)
                ).actionGet();
            }
        }
    }

    void createSnapshots() {
        try (Client tc = getClient()) {
            for (String index : SYSTEM_INDICES) {
                tc.admin()
                    .cluster()
                    .putRepository(
                        new PutRepositoryRequest(index).type("fs")
                            .settings(Settings.builder().put("location", repositoryPath.getRoot().getAbsolutePath() + "/" + index))
                    )
                    .actionGet();
                tc.admin()
                    .cluster()
                    .createSnapshot(
                        new CreateSnapshotRequest(index, index + "_1").indices(index).includeGlobalState(true).waitForCompletion(true)
                    )
                    .actionGet();
            }
        }
    }

    RestHelper superAdminRestHelper() {
        RestHelper restHelper = restHelper();
        restHelper.keystore = "kirk-keystore.jks";
        restHelper.enableHTTPClientSSL = true;
        restHelper.trustHTTPServerCertificate = true;
        restHelper.sendAdminCertificate = true;
        return restHelper;
    }

    RestHelper sslRestHelper() {
        RestHelper restHelper = restHelper();
        restHelper.enableHTTPClientSSL = true;
        return restHelper;
    }

    void validateSearchResponse(RestHelper.HttpResponse response, int expectedHits) throws IOException {
        assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());

        XContentParser xcp = XContentType.JSON.xContent()
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getBody());
        SearchResponse searchResponse = SearchResponse.fromXContent(xcp);
        assertEquals(RestStatus.OK, searchResponse.status());
        assertEquals(expectedHits, searchResponse.getHits().getHits().length);
        assertEquals(0, searchResponse.getFailedShards());
        assertEquals(5, searchResponse.getSuccessfulShards());
    }

    String permissionExceptionMessage(String action, String username) {
        return "{\"type\":\"security_exception\",\"reason\":\"no permissions for ["
            + action
            + "] and User [name="
            + username
            + ", backend_roles=[], requestedTenant=null]\"}";
    }

    void validateForbiddenResponse(RestHelper.HttpResponse response, String action, String user) {
        assertEquals(RestStatus.FORBIDDEN.getStatus(), response.getStatusCode());
        MatcherAssert.assertThat(response.getBody(), Matchers.containsStringIgnoringCase(permissionExceptionMessage(action, user)));
    }

    void shouldBeAllowedOnlyForAuthorizedIndices(String index, RestHelper.HttpResponse response, String action, String user) {
        boolean isSecurityIndexRequest = index.equals(ACCESSIBLE_ONLY_BY_SUPER_ADMIN);
        boolean isRequestingAccessToNonAuthorizedSystemIndex = (!user.equals(allAccessUser)
            && index.equals(SYSTEM_INDEX_WITH_NO_ASSOCIATED_ROLE_PERMISSIONS));
        if (isSecurityIndexRequest || isRequestingAccessToNonAuthorizedSystemIndex) {
            validateForbiddenResponse(response, isSecurityIndexRequest ? "" : action, user);
        } else {
            assertEquals(RestStatus.OK.getStatus(), response.getStatusCode());
        }
    }

}
